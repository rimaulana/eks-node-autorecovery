data "aws_availability_zones" "available" {}

# This resource is used to provide a means of mapping an implicit dependency
# between the cluster and the addons.
resource "time_sleep" "this" {
  create_duration = var.create_delay_duration

  triggers = {
    cluster_endpoint  = var.cluster_endpoint
    cluster_name      = var.cluster_name
    custom            = join(",", var.create_delay_dependencies)
    oidc_provider_arn = var.oidc_provider_arn
  }
}

provider "kubernetes" {
  host                   = var.cluster_endpoint
  cluster_ca_certificate = base64decode(var.cluster_certificate)

  exec {
    api_version = "client.authentication.k8s.io/v1beta1"
    command     = "aws"
    # This requires the awscli to be installed locally where Terraform is executed
    args = ["eks", "get-token", "--cluster-name", var.cluster_name]
  }
}

provider "helm" {
  kubernetes {
    host                   = var.cluster_endpoint
    cluster_ca_certificate = base64decode(var.cluster_certificate)

    exec {
      api_version = "client.authentication.k8s.io/v1beta1"
      command     = "aws"
      # This requires the awscli to be installed locally where Terraform is executed
      args = ["eks", "get-token", "--cluster-name", var.cluster_name]
    }
  }
}

provider "kubectl" {
  apply_retry_count      = 5
  host                   = var.cluster_endpoint
  cluster_ca_certificate = base64decode(var.cluster_certificate)
  load_config_file       = false

  exec {
    api_version = "client.authentication.k8s.io/v1beta1"
    command     = "aws"
    # This requires the awscli to be installed locally where Terraform is executed
    args = ["eks", "get-token", "--cluster-name", var.cluster_name]
  }
}

locals {
  name      = basename(path.cwd)
  region    = var.region
  azs       = slice(data.aws_availability_zones.available.names, 0, 3)
  tags      = var.tags
  multus_start_range  = cidrhost(cidrsubnet(var.multus_cidrs[var.selector], 1, 1),0)
  multus_end_range    = cidrhost(var.multus_cidrs[var.selector], -2)
  multus_def_gateway  = cidrhost(var.multus_cidrs[var.selector], 1)
}

resource "aws_security_group" "eni_security_group" {
  description = "ENI Security Group"
  vpc_id      = var.vpc_id

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }
  
  ingress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    security_groups  = [var.cluster_security_group]
    self             = true
  }

  tags = local.tags
}

# resource "aws_security_group_rule" "cluster_security_group_rule" {
#   type              = "ingress"
#   from_port         = 443
#   to_port           = 443
#   protocol          = "tcp"
#   security_group_id = var.cluster_security_group
#   source_security_group_id  = aws_security_group.eni_security_group.id
# }

resource "aws_security_group_rule" "vpce_rule_custom_eni" {
  type              = "ingress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  security_group_id = var.vpce_security_group
  source_security_group_id  = aws_security_group.eni_security_group.id
}

# resource "aws_security_group_rule" "vpce_rule_custom_nodegroup" {
#   type              = "ingress"
#   from_port         = 443
#   to_port           = 443
#   protocol          = "tcp"
#   security_group_id = var.vpce_security_group
#   source_security_group_id  = aws_security_group.self_managed_node_security_group.id
# }

################################################################################
# IRSA for EKS Managed Addons
################################################################################
data "aws_iam_policy_document" "vpc_cni_assume_role_policy" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    effect  = "Allow"

    condition {
      test     = "StringEquals"
      variable = "${replace(var.oidc_provider_arn, "/^(.*provider/)/", "")}:sub"
      values   = ["system:serviceaccount:kube-system:aws-node"]
    }

    principals {
      identifiers = [var.oidc_provider_arn]
      type        = "Federated"
    }
  }
}

resource "aws_iam_role" "vpc_cni_role" {
  assume_role_policy = data.aws_iam_policy_document.vpc_cni_assume_role_policy.json
}

resource "aws_iam_role_policy_attachment" "vpc_cni_role_attachment" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
  role       = aws_iam_role.vpc_cni_role.name
}

################################################################################
# EKS Blueprints Addons
################################################################################

module "eks_blueprints_addons" {
  source  = "aws-ia/eks-blueprints-addons/aws"
  version = "~> 1.0"

  cluster_name      = var.cluster_name
  cluster_endpoint  = var.cluster_endpoint
  cluster_version   = var.cluster_version
  oidc_provider_arn = var.oidc_provider_arn
  
  eks_addons = {
    vpc-cni    = {
      most_recent    = true # To ensure access to the latest settings provided
      service_account_role_arn = aws_iam_role.vpc_cni_role.arn
      configuration_values = jsonencode({
        env = {
          WARM_IP_TARGET        = "1"
          MINIMUM_IP_TARGET     = "5"
          ENI_CONFIG_LABEL_DEF  = "failure-domain.beta.kubernetes.io/zone"
          AWS_VPC_K8S_CNI_CUSTOM_NETWORK_CFG    = "true"
        }
      })
    }
    kube-proxy = {
      most_recent    = true
    }
  }
  
  tags = local.tags
}

resource "aws_security_group_rule" "node_to_cluster" {
  type              = "ingress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  security_group_id = var.cluster_security_group
  source_security_group_id  = aws_security_group.self_managed_node_security_group.id
}

resource "aws_security_group" "self_managed_node_security_group" {
  name        = "${var.cluster_name}-self-managed-node-sg"
  description = "Self managed node security group"
  vpc_id      = var.vpc_id
  
  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }
  
  ingress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    security_groups  = [var.cluster_security_group]
    self             = true
  }

  tags = local.tags
}

resource "aws_iam_role" "self_managed_node_role" {
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = [
            "ec2.amazonaws.com"
          ]
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
  managed_policy_arns = [
    "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore",
    "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy",
    "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly",
    "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
  ]
}

resource "aws_iam_instance_profile" "self_managed_node_profile" {
  role = aws_iam_role.self_managed_node_role.name
}

module "self_managed_node_group" {
  source = "terraform-aws-modules/eks/aws//modules/self-managed-node-group"
  depends_on = [
    kubectl_manifest.eni_config_definitions
  ]
  name                = "${var.cluster_name}-node"
  cluster_name        = var.cluster_name
  cluster_version     = var.cluster_version
  cluster_endpoint    = var.cluster_endpoint
  cluster_auth_base64 = var.cluster_certificate
  cluster_service_cidr= var.cluster_service_cidr
  create_access_entry = true
  create_iam_instance_profile = false
  iam_instance_profile_arn = aws_iam_instance_profile.self_managed_node_profile.arn
  iam_role_arn        = aws_iam_role.self_managed_node_role.arn

  subnet_ids = [var.node_subnet_ids[var.selector]]

  // The following variables are necessary if you decide to use the module outside of the parent EKS module context.
  // Without it, the security groups of the nodes are empty and thus won't join the cluster.
  vpc_security_group_ids = [
    aws_security_group.self_managed_node_security_group.id
  ]

  min_size     = 0
  max_size     = 10
  desired_size = 1

  bootstrap_extra_args = <<-EOT
    --use-max-pods false --kubelet-extra-args '--max-pods=8'
  EOT
  
  pre_bootstrap_user_data = <<-EOT
    cat <<EOF >> /etc/cni/net.d/00-multus.conf
    {
      "cniVersion": "0.4.0",
      "name": "multus-cni-network",
      "type": "multus",
      "capabilities": {"portMappings":true},
      "cniConf": "/host/etc/cni/multus/net.d",
      "kubeconfig": "/etc/cni/net.d/multus.d/multus.kubeconfig",
      "delegates": [
        {"cniVersion":"0.4.0","disableCheck":true,"name":"aws-cni","plugins":[{"mtu":"9001","name":"aws-cni","pluginLogFile":"/var/log/aws-routed-eni/plugin.log","pluginLogLevel":"DEBUG","podSGEnforcingMode":"strict","type":"aws-cni","vethPrefix":"eni"},{"enabled":"false","ipam":{"dataDir":"/run/cni/v4pd/egress-v6-ipam","ranges":[[{"subnet":"fd00::ac:00/118"}]],"routes":[{"dst":"::/0"}],"type":"host-local"},"mtu":"9001","name":"egress-cni","nodeIP":"","pluginLogFile":"/var/log/aws-routed-eni/egress-v6-plugin.log","pluginLogLevel":"DEBUG","randomizeSNAT":"prng","type":"egress-cni"},{"capabilities":{"portMappings":true},"snat":true,"type":"portmap"}]}
      ]
    }
    EOF

    echo "net.ipv4.conf.default.rp_filter = 0" | tee -a /etc/sysctl.conf
    echo "net.ipv4.conf.all.rp_filter = 0" | tee -a /etc/sysctl.conf
    sudo sysctl -p
    sleep 100
    ls /sys/class/net/ > /tmp/ethList;cat /tmp/ethList |while read line ; do sudo ifconfig $line up; done
    grep eth /tmp/ethList |while read line ; do echo "ifconfig $line up" >> /etc/rc.d/rc.local; done
    systemctl enable rc-local
    chmod +x /etc/rc.d/rc.local
  EOT

  launch_template_name   = "${var.cluster_name}-node-lt"
  instance_type          = "m5.large"

  tags = {
    Environment = "dev"
    Terraform   = "true"
    "k8s.io/cluster-autoscaler/enabled" = "true"
    "k8s.io/cluster-autoscaler/${var.cluster_name}" = ""
  }
}

resource "aws_autoscaling_lifecycle_hook" "launch_hook" {
  name                   = "${var.cluster_name}-launch-lifecyclehook"
  autoscaling_group_name = module.self_managed_node_group.autoscaling_group_name
  default_result         = "ABANDON"
  heartbeat_timeout      = 300
  lifecycle_transition   = "autoscaling:EC2_INSTANCE_LAUNCHING"
}

resource "aws_autoscaling_lifecycle_hook" "terminate_hook" {
  name                   = "${var.cluster_name}-terminate-lifecyclehook"
  autoscaling_group_name = module.self_managed_node_group.autoscaling_group_name
  default_result         = "ABANDON"
  heartbeat_timeout      = 300
  lifecycle_transition   = "autoscaling:EC2_INSTANCE_TERMINATING"
}

module lambda_eni {
  source                = "../../modules/lambda_eni"
  name                  = "${var.cluster_name}-node-ip-management"
  multus_subnets        = var.multus_subnet_ids[var.selector]
  multus_security_groups= var.multus_sg_id
  asg_name              = module.self_managed_node_group.autoscaling_group_name
}

resource "kubectl_manifest" "eni_config_definitions" {
  for_each = { for k, v in local.azs : v => var.cni_subnet_ids[(k+1)%3] }
  depends_on = [
    module.eks_blueprints_addons
  ]
  apply_only = true
  yaml_body = <<-YAML
    apiVersion: crd.k8s.amazonaws.com/v1alpha1
    kind: ENIConfig
    metadata: 
      name: ${each.key}
    spec: 
      securityGroups: 
      - ${aws_security_group.eni_security_group.id}
      subnet: ${each.value}
  YAML
}

data "kubectl_path_documents" "manifests-directory-yaml" {
  pattern = "${path.module}/manifests/*.yaml"
}

resource "kubectl_manifest" "directory-yaml" {
  apply_only = true
  server_side_apply = true
  for_each  = data.kubectl_path_documents.manifests-directory-yaml.manifests
  yaml_body = each.value
  depends_on = [
    module.eks_blueprints_addons
  ]
}

resource "kubectl_manifest" "multus_nad" {
  depends_on = [
    kubectl_manifest.directory-yaml
  ]
  apply_only = true
  wait_for_rollout = false
  yaml_body = <<-YAML
    apiVersion: "k8s.cni.cncf.io/v1"
    kind: NetworkAttachmentDefinition
    metadata:
      name: ipvlan-multus
    spec:
      config: '{
                "cniVersion": "0.3.1",
                "type": "ipvlan",
                "LogFile": "/var/log/multus.log",
                "LogLevel": "debug",
                "name": "ipvlan-multus",
                "mtu": 1500,
                "master": "eth1",
                "ipam": {
                  "type": "whereabouts",
                  "datastore": "kubernetes",
                  "range": "${var.multus_cidrs[var.selector]}",
                  "range_start": "${local.multus_start_range}",
                  "range_end": "${local.multus_end_range}",
                  "gateway": "${local.multus_def_gateway}",
                  "log_file": "/tmp/whereabouts.log",
                  "log_level": "debug"
                }
              }'
  YAML
}
################################################################################
# EKS WORKLOAD
################################################################################