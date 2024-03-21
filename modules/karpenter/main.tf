data "aws_availability_zones" "available" {}

# Required for public ECR where Karpenter artifacts are hosted
provider "aws" {
  region = "us-east-1"
  alias  = "virginia"
}

data "aws_ecrpublic_authorization_token" "token" {
  provider = aws.virginia
}

provider "kubernetes" {
  host                   = module.eks.cluster_endpoint
  cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)

  exec {
    api_version = "client.authentication.k8s.io/v1beta1"
    command     = "aws"
    # This requires the awscli to be installed locally where Terraform is executed
    args = ["eks", "get-token", "--cluster-name", var.cluster_name]
  }
}

provider "helm" {
  kubernetes {
    host                   = module.eks.cluster_endpoint
    cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)

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
  host                   = module.eks.cluster_endpoint
  cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)
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

data "aws_ami" "eks_default" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["amazon-eks-node-${var.cluster_version}-v*"]
  }
}
################################################################################
# Cluster
################################################################################

module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 20.2"

  cluster_name                   = var.cluster_name
  cluster_version                = var.cluster_version
  cluster_endpoint_public_access = true

  vpc_id     = var.vpc_id
  control_plane_subnet_ids = var.control_plane_subnet_ids
  
  authentication_mode = "API_AND_CONFIG_MAP"
  enable_cluster_creator_admin_permissions = true
  
  fargate_profiles = {
    default = {
      name = "default"
      selectors = [
        {
          namespace = "kube-system"
          labels = {
            k8s-app = "kube-dns"
          }
        }
      ]
      
      subnet_ids = var.node_subnet_ids
      
      tags = {
        Owner = "default"
      }

      timeouts = {
        create = "20m"
        delete = "20m"
      }
    }
    
    karpenter = {
      name = "karpenter"
      selectors = [
        {
          namespace = "karpenter"
        }
      ]
      
      subnet_ids = var.node_subnet_ids
      
      tags = {
        Owner = "karpenter"
      }

      timeouts = {
        create = "20m"
        delete = "20m"
      }
    }
  }

  tags = merge(local.tags, {
    # NOTE - if creating multiple security groups with this module, only tag the
    # security group that Karpenter should utilize with the following tag
    # (i.e. - at most, only one security group should have this tag in your account)
    "karpenter.sh/discovery" = var.cluster_name
    })
}

resource "aws_security_group_rule" "vpce_rule" {
  type              = "ingress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  security_group_id = var.vpce_sg_id
  source_security_group_id  = module.eks.node_security_group_id
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
    security_groups  = [module.eks.cluster_security_group_id]
    self             = true
  }

  tags = local.tags
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
    security_groups  = [aws_security_group.self_managed_node_security_group.id,module.eks.cluster_security_group_id]
    self             = true
  }

  tags = local.tags
}

resource "aws_security_group_rule" "control_plane_security_group_rule_1" {
  type              = "ingress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  security_group_id = module.eks.cluster_security_group_id
  source_security_group_id  = aws_security_group.self_managed_node_security_group.id
}

# resource "aws_security_group_rule" "control_plane_security_group_rule_2" {
#   type              = "ingress"
#   from_port         = 443
#   to_port           = 443
#   protocol          = "tcp"
#   security_group_id = module.eks.cluster_security_group_id
#   source_security_group_id  = aws_security_group.eni_security_group.id
# }

resource "aws_security_group_rule" "node_security_group_rule_1" {
  type              = "ingress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  security_group_id = aws_security_group.self_managed_node_security_group.id
  source_security_group_id  = aws_security_group.eni_security_group.id
}

################################################################################
# IRSA for EKS Managed Addons
################################################################################
data "aws_iam_policy_document" "vpc_cni_assume_role_policy" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    effect  = "Allow"

    condition {
      test     = "StringEquals"
      variable = "${replace(module.eks.oidc_provider_arn, "/^(.*provider/)/", "")}:sub"
      values   = ["system:serviceaccount:kube-system:aws-node"]
    }

    principals {
      identifiers = [module.eks.oidc_provider_arn]
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

  cluster_name      = module.eks.cluster_name
  cluster_endpoint  = module.eks.cluster_endpoint
  cluster_version   = module.eks.cluster_version
  oidc_provider_arn = module.eks.oidc_provider_arn
  
  # We want to wait for the Fargate profiles to be deployed first
  create_delay_dependencies = [for prof in module.eks.fargate_profiles : prof.fargate_profile_arn]

  # EKS Add-ons
  enable_karpenter = true
  karpenter = {
    repository_username = data.aws_ecrpublic_authorization_token.token.user_name
    repository_password = data.aws_ecrpublic_authorization_token.token.password
  }
  karpenter_node = {
    # Use static name so that it matches what is defined in `karpenter.yaml` example manifest
    iam_role_use_name_prefix = false
  }
  
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
    coredns = {
      configuration_values = jsonencode({
        computeType = "Fargate"
        # Ensure that the we fully utilize the minimum amount of resources that are supplied by
        # Fargate https://docs.aws.amazon.com/eks/latest/userguide/fargate-pod-configuration.html
        # Fargate adds 256 MB to each pod's memory reservation for the required Kubernetes
        # components (kubelet, kube-proxy, and containerd). Fargate rounds up to the following
        # compute configuration that most closely matches the sum of vCPU and memory requests in
        # order to ensure pods always have the resources that they need to run.
        resources = {
          limits = {
            cpu = "0.25"
            # We are targeting the smallest Task size of 512Mb, so we subtract 256Mb from the
            # request/limit to ensure we can fit within that task
            memory = "256M"
          }
          requests = {
            cpu = "0.25"
            # We are targeting the smallest Task size of 512Mb, so we subtract 256Mb from the
            # request/limit to ensure we can fit within that task
            memory = "256M"
          }
        }
      })
    }
  }
  tags = local.tags
}

resource "aws_iam_role" "karpenter_node_role" {
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

resource "aws_iam_instance_profile" "karpenter_node_profile" {
  role = aws_iam_role.karpenter_node_role.name
}

# module "self_managed_node_group" {
#   source = "terraform-aws-modules/eks/aws//modules/self-managed-node-group"

#   name                = "multus-self-mng"
#   cluster_name        = module.eks.cluster_name
#   cluster_version     = module.eks.cluster_version
#   cluster_endpoint    = module.eks.cluster_endpoint
#   cluster_auth_base64 = module.eks.cluster_certificate_authority_data
#   create_access_entry = true
#   create_iam_instance_profile = false
#   iam_instance_profile_arn = aws_iam_instance_profile.self_managed_node_profile.arn
#   iam_role_arn        = aws_iam_role.self_managed_node_role.arn

#   subnet_ids = [var.node_subnet_ids[var.selector]]

#   // The following variables are necessary if you decide to use the module outside of the parent EKS module context.
#   // Without it, the security groups of the nodes are empty and thus won't join the cluster.
#   vpc_security_group_ids = [
#     aws_security_group.self_managed_node_security_group.id
#   ]

#   min_size     = 0
#   max_size     = 10
#   desired_size = 0
  
#   pre_bootstrap_user_data = <<-EOT
#     echo "net.ipv4.conf.default.rp_filter = 0" | tee -a /etc/sysctl.conf
#     echo "net.ipv4.conf.all.rp_filter = 0" | tee -a /etc/sysctl.conf
#     sudo sysctl -p
#     sleep 100
#     ls /sys/class/net/ > /tmp/ethList;cat /tmp/ethList |while read line ; do sudo ifconfig $line up; done
#     grep eth /tmp/ethList |while read line ; do echo "ifconfig $line up" >> /etc/rc.d/rc.local; done
#     systemctl enable rc-local
#     chmod +x /etc/rc.d/rc.local
#   EOT

#   launch_template_name   = "separate-self-mng"
#   instance_type          = "m5.large"

#   tags = {
#     Environment = "dev"
#     Terraform   = "true"
#   }
# }

# resource "aws_autoscaling_lifecycle_hook" "launch_hook" {
#   name                   = "${var.cluster_name}-launch-lifecyclehook"
#   autoscaling_group_name = module.self_managed_node_group.autoscaling_group_name
#   default_result         = "ABANDON"
#   heartbeat_timeout      = 300
#   lifecycle_transition   = "autoscaling:EC2_INSTANCE_LAUNCHING"
# }

# resource "aws_autoscaling_lifecycle_hook" "terminate_hook" {
#   name                   = "${var.cluster_name}-terminate-lifecyclehook"
#   autoscaling_group_name = module.self_managed_node_group.autoscaling_group_name
#   default_result         = "ABANDON"
#   heartbeat_timeout      = 300
#   lifecycle_transition   = "autoscaling:EC2_INSTANCE_TERMINATING"
# }

# module lambda_eni {
#   source                = "../../modules/lambda_eni"
#   name                  = "${var.cluster_name}-node-ip-management"
#   multus_subnets        = var.multus_subnet_ids[var.selector]
#   multus_security_groups= var.multus_sg_id
#   asg_name              = module.self_managed_node_group.autoscaling_group_name
# }

resource "kubectl_manifest" "eni_config_definitions" {
  for_each = { for k, v in local.azs : v => var.cni_subnet_ids[k] }
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

  depends_on = [
    module.eks
  ]
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
    module.eks_blueprints_addons,
    module.eks.fargate_profiles
  ]
}

resource "kubectl_manifest" "multus_nad" {
  depends_on = [
    module.eks,
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

resource "kubectl_manifest" "karpenter_nodeclass" {
  apply_only = true
  wait_for_rollout = false
  yaml_body = <<-YAML
    apiVersion: karpenter.k8s.aws/v1beta1
    kind: EC2NodeClass
    metadata:
      name: default
    spec:
      amiFamily: AL2
      subnetSelectorTerms:
        - tags:
            karpenter.sh/discovery: "${var.cluster_name}"
        - id: ${var.node_subnet_ids[var.selector]}
    
      securityGroupSelectorTerms:
        - tags:
            karpenter.sh/discovery: "${var.cluster_name}"
      instanceProfile: "${aws_iam_instance_profile.karpenter_node_profile.name}"
    
      # Optional, overrides autogenerated userdata with a merge semantic
      userData: |
        echo "net.ipv4.conf.default.rp_filter = 0" | tee -a /etc/sysctl.conf
        echo "net.ipv4.conf.all.rp_filter = 0" | tee -a /etc/sysctl.conf
        sudo sysctl -p
        sleep 100
        ls /sys/class/net/ > /tmp/ethList;cat /tmp/ethList |while read line ; do sudo ifconfig $line up; done
        grep eth /tmp/ethList |while read line ; do echo "ifconfig $line up" >> /etc/rc.d/rc.local; done
        systemctl enable rc-local
        chmod +x /etc/rc.d/rc.local
    
      # Optional, propagates tags to underlying EC2 resources
      tags:
        team: team-a
        app: team-a-app
    
      # Optional, configures IMDS for the instance
      metadataOptions:
        httpEndpoint: enabled
        httpProtocolIPv6: disabled
        httpPutResponseHopLimit: 2
        httpTokens: required
  YAML
}

resource "kubectl_manifest" "karpenter_nodepool" {
  apply_only = true
  wait_for_rollout = false
  yaml_body = <<-YAML
    apiVersion: karpenter.sh/v1beta1
    kind: NodePool
    metadata:
      name: default
    spec:
      template:
        metadata:
          labels:
            billing-team: my-team
          annotations:
            example.com/owner: "my-team"
        spec:
          nodeClassRef:
            apiVersion: karpenter.k8s.aws/v1beta1
            kind: EC2NodeClass
            name: default
          requirements:
            - key: "kubernetes.io/arch"
              operator: In
              values: ["amd64"]
            - key: "karpenter.sh/capacity-type"
              operator: In
              values: ["on-demand"]
          kubelet:
            systemReserved:
              cpu: 100m
              memory: 100Mi
              ephemeral-storage: 1Gi
            kubeReserved:
              cpu: 200m
              memory: 100Mi
              ephemeral-storage: 3Gi
            evictionHard:
              memory.available: 5%
              nodefs.available: 10%
              nodefs.inodesFree: 10%
            evictionSoft:
              memory.available: 500Mi
              nodefs.available: 15%
              nodefs.inodesFree: 15%
            evictionSoftGracePeriod:
              memory.available: 1m
              nodefs.available: 1m30s
              nodefs.inodesFree: 2m
            evictionMaxPodGracePeriod: 60
            imageGCHighThresholdPercent: 85
            imageGCLowThresholdPercent: 80
            cpuCFSQuota: true
            podsPerCore: 2
      disruption:
        consolidationPolicy: WhenUnderutilized
        expireAfter: 2h
      limits:
        cpu: "1000"
        memory: 1000Gi
      weight: 10
  YAML

  depends_on = [
    module.eks
  ]
}