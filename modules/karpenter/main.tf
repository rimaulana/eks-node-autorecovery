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

# Required for public ECR where Karpenter artifacts are hosted
provider "aws" {
  region = "us-east-1"
  alias  = "virginia"
}

data "aws_ecrpublic_authorization_token" "token" {
  provider = aws.virginia
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

resource "aws_security_group_rule" "cluster_security_group_rule" {
  type              = "ingress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  security_group_id = var.cluster_security_group
  source_security_group_id  = aws_security_group.eni_security_group.id
}

resource "aws_security_group_rule" "vpce_rule_custom_eni" {
  type              = "ingress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  security_group_id = var.vpce_security_group
  source_security_group_id  = aws_security_group.eni_security_group.id
}

data "aws_security_group" "fargate_profile" {
  depends_on = [ time_sleep.this ]
  vpc_id = var.vpc_id
  filter {
    name = "tag:aws:eks:cluster-name"
    values = [ var.cluster_name ]
  }
}

resource "aws_security_group_rule" "vpce_rule_fargate_profile" {
  type              = "ingress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  security_group_id = var.vpce_security_group
  source_security_group_id  = data.aws_security_group.fargate_profile.id
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

  # EKS Add-ons
  enable_karpenter = true
  karpenter = {
    repository_username = data.aws_ecrpublic_authorization_token.token.user_name
    repository_password = data.aws_ecrpublic_authorization_token.token.password
    values = [
      <<-EOT
        dnsPolicy: Default
      EOT
    ]
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
    # coredns = {
    #   configuration_values = jsonencode({
    #     computeType = "Fargate"
    #     # Ensure that the we fully utilize the minimum amount of resources that are supplied by
    #     # Fargate https://docs.aws.amazon.com/eks/latest/userguide/fargate-pod-configuration.html
    #     # Fargate adds 256 MB to each pod's memory reservation for the required Kubernetes
    #     # components (kubelet, kube-proxy, and containerd). Fargate rounds up to the following
    #     # compute configuration that most closely matches the sum of vCPU and memory requests in
    #     # order to ensure pods always have the resources that they need to run.
    #     resources = {
    #       limits = {
    #         cpu = "0.25"
    #         # We are targeting the smallest Task size of 512Mb, so we subtract 256Mb from the
    #         # request/limit to ensure we can fit within that task
    #         memory = "256M"
    #       }
    #       requests = {
    #         cpu = "0.25"
    #         # We are targeting the smallest Task size of 512Mb, so we subtract 256Mb from the
    #         # request/limit to ensure we can fit within that task
    #         memory = "256M"
    #       }
    #     }
    #   })
    # }
  }
  tags = local.tags
}

resource "aws_eks_access_entry" "example" {
  cluster_name      = var.cluster_name
  principal_arn     = module.eks_blueprints_addons.karpenter.node_iam_role_arn
  type              = "EC2_LINUX"
}

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

module lambda_eni {
  source                = "../../modules/lambda_eni_karpenter"
  name                  = "${var.cluster_name}-node-ip-management"
  multus_subnets        = var.multus_subnet_ids[var.selector]
  multus_security_groups= var.multus_sg_id
}

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
        - id: ${var.node_subnet_ids[var.selector]}
    
      securityGroupSelectorTerms:
        - tags:
            aws:eks:cluster-name: "${var.cluster_name}"
      instanceProfile: ${module.eks_blueprints_addons.karpenter.node_instance_profile_name}
    
      # Optional, overrides autogenerated userdata with a merge semantic
      userData: |
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
  depends_on = [
    module.eks_blueprints_addons
  ]
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
    module.eks_blueprints_addons
  ]
}