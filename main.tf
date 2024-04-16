provider "aws" {
  region = local.region
}

data "aws_availability_zones" "available" {}
data "aws_caller_identity" "current" {}

locals {
  name     = basename(path.cwd)
  region   = "us-east-2"

  primary_cidr   = "172.20.0.0/22"
  secondary_cidr = "100.64.0.0/20"
  
  azs      = slice(data.aws_availability_zones.available.names, 0, 3)

  tags = {
    blueprint  = local.name
    "auto-delete" = "no"
  }
  scenario_one = "karpenter_solutions"
  scenario_two = "cluster_autoscaler"
  scenario_three = "challenge_1"
  k8s_version = "1.29"
}

# Subnets 
# 1. public for ELB
# 2. private for control plane and VPC endpoints
# 3. 
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.0"

  name                  = local.name
  cidr                  = local.primary_cidr
  secondary_cidr_blocks = [local.secondary_cidr]
  azs                   = local.azs
  private_subnets       = [for k, v in local.azs : cidrsubnet(local.primary_cidr, 3, k)]
  public_subnets        = [for k, v in local.azs : cidrsubnet(local.primary_cidr, 5, k + 12)]
  database_subnets      = [for k, v in local.azs : cidrsubnet(local.primary_cidr, 5, k + 15)]
  intra_subnets         = [for k, v in local.azs : cidrsubnet(local.primary_cidr, 5, k + 18)]
  redshift_subnets      = [for k, v in local.azs : cidrsubnet(local.secondary_cidr, 2, k)]
  enable_nat_gateway    = true
  single_nat_gateway    = true

  public_subnet_tags = {
    "kubernetes.io/role/elb" = 1
    "type" = "public"
  }

  private_subnet_tags = {
    "kubernetes.io/role/internal-elb" = 1
    "type" = "private"
  }

  tags = local.tags
}

resource "aws_ec2_subnet_cidr_reservation" "reservations" {
  for_each         = {for k, v in local.azs : k => module.vpc.intra_subnets[k]}
  cidr_block       = cidrsubnet(module.vpc.intra_subnets_cidr_blocks[each.key], 1, 1)
  reservation_type = "explicit"
  subnet_id        = each.value
}

resource "aws_security_group" "vpce_security_group_1" {
  name        = "vpce_security_group_1"
  description = "VPC Endpoint Security Group"
  vpc_id      = module.vpc.vpc_id

  ingress {
    from_port        = 443
    to_port          = 443
    protocol         = "tcp"
    cidr_blocks      = [local.primary_cidr,local.secondary_cidr]
  }

  tags = local.tags
}

resource "aws_security_group" "vpce_security_group_2" {
  name        = "vpce_security_group_2"
  description = "VPC Endpoint Security Group"
  vpc_id      = module.vpc.vpc_id

  tags = local.tags
}

resource "aws_security_group" "multus_security_group" {
  name        = "multus_security_group"
  description = "Multus ENI Security Group"
  vpc_id      = module.vpc.vpc_id
  
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
    self             = true
  }

  tags = local.tags
}

resource "aws_route" "intra_net_gateway" {
  route_table_id              = module.vpc.intra_route_table_ids[0]
  destination_cidr_block      = "0.0.0.0/0"
  nat_gateway_id              = module.vpc.natgw_ids[0]
}
################################################################################
# VPC Endpoints Module
################################################################################

module "vpc_endpoints" {
  source = "terraform-aws-modules/vpc/aws//modules/vpc-endpoints"
  vpc_id = module.vpc.vpc_id
  
  endpoints = {
    s3 = {
      service         = "s3"
      service_type    = "Gateway"
      route_table_ids = flatten([module.vpc.intra_route_table_ids])
      tags            = { Name = "s3-vpc-endpoint" }
    },
    ecr_api = {
      service             = "ecr.api"
      private_dns_enabled = true
      subnet_ids          = [for k, v in local.azs : module.vpc.private_subnets[k]]
      security_group_ids  = [aws_security_group.vpce_security_group_1.id]
      # policy              = data.aws_iam_policy_document.generic_endpoint_policy.json
    },
    ecr_dkr = {
      service             = "ecr.dkr"
      private_dns_enabled = true
      subnet_ids          = [for k, v in local.azs : module.vpc.private_subnets[k]]
      security_group_ids  = [aws_security_group.vpce_security_group_1.id]
      # policy              = data.aws_iam_policy_document.generic_endpoint_policy.json
    },
    ec2 = {
      service             = "ec2"
      private_dns_enabled = true
      subnet_ids          = [for k, v in local.azs : module.vpc.private_subnets[k]]
      security_group_ids  = [aws_security_group.vpce_security_group_2.id]
      # policy              = data.aws_iam_policy_document.generic_endpoint_policy.json
    },
    sts = {
      service             = "sts"
      private_dns_enabled = true
      subnet_ids          = [for k, v in local.azs : module.vpc.private_subnets[k]]
      security_group_ids  = [aws_security_group.vpce_security_group_1.id]
      # policy              = data.aws_iam_policy_document.generic_endpoint_policy.json
    },
    efs = {
      service             = "elasticfilesystem"
      private_dns_enabled = true
      subnet_ids          = [for k, v in local.azs : module.vpc.private_subnets[k]]
      security_group_ids  = [aws_security_group.vpce_security_group_1.id]
      # policy              = data.aws_iam_policy_document.generic_endpoint_policy.json
    },
  }

  tags = merge(local.tags, {
    Endpoint = "true"
  })
}

################################################################################
# Troubleshooting Scenario Resources
################################################################################
module "scenario_one" {
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 20.2"

  cluster_name                   = local.scenario_one
  cluster_version                = local.k8s_version
  cluster_endpoint_public_access = true

  vpc_id     = module.vpc.vpc_id
  control_plane_subnet_ids = module.vpc.private_subnets
  
  authentication_mode = "API_AND_CONFIG_MAP"
  enable_cluster_creator_admin_permissions = true
  
  fargate_profiles = {
    # default = {
    #   name = "default"
    #   selectors = [
    #     {
    #       namespace = "kube-system"
    #       labels = {
    #         k8s-app = "kube-dns"
    #       }
    #     }
    #   ]
      
    #   subnet_ids = [module.vpc.database_subnets[0]]
      
    #   tags = {
    #     Owner = "default"
    #   }

    #   timeouts = {
    #     create = "20m"
    #     delete = "20m"
    #   }
    # }
    
    karpenter = {
      name = "karpenter"
      selectors = [
        {
          namespace = "karpenter"
        }
      ]
      
      subnet_ids = [module.vpc.database_subnets[0]]
      
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
    "karpenter.sh/discovery" = local.scenario_one
    })
}

module "scenario_two" {
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 20.2"
  cluster_name                   = local.scenario_two
  cluster_version                = local.k8s_version
  cluster_endpoint_public_access = true
  vpc_id     = module.vpc.vpc_id
  control_plane_subnet_ids = module.vpc.private_subnets

  authentication_mode = "API_AND_CONFIG_MAP"
  enable_cluster_creator_admin_permissions = true

  fargate_profiles = {
    cluster_autoscaler = {
      name = "cluster_autoscaler"
      selectors = [
        {
          namespace = "kube-system"
          labels = {
            "app.kubernetes.io/name" = "aws-cluster-autoscaler"
          }
        }
      ]
      
      subnet_ids = [module.vpc.database_subnets[1]]
      
      tags = {
        Owner = "cluster_autoscaler"
      }

      timeouts = {
        create = "20m"
        delete = "20m"
      }
    }
  }

  tags = local.tags
}


module "scenario_three" {
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 20.2"

  cluster_name                   = local.scenario_three
  cluster_version                = local.k8s_version
  cluster_endpoint_public_access = true

  vpc_id     = module.vpc.vpc_id
  control_plane_subnet_ids = module.vpc.private_subnets
  
  authentication_mode = "API_AND_CONFIG_MAP"
  enable_cluster_creator_admin_permissions = true

  tags = local.tags
}

module scenario_one_workload {
  source                    = "./modules/karpenter"
  cluster_name              = local.scenario_one
  cluster_version           = "1.29"
  selector                  = 0
  region                    = local.region
  tags                      = local.tags
  vpc_id                    = module.vpc.vpc_id
  node_subnet_ids           = module.vpc.database_subnets
  cni_subnet_ids            = module.vpc.redshift_subnets
  multus_subnet_ids         = module.vpc.intra_subnets
  multus_sg_id              = aws_security_group.multus_security_group.id
  multus_cidrs              = module.vpc.intra_subnets_cidr_blocks
  vpce_security_group = aws_security_group.vpce_security_group_2.id
  cluster_endpoint = module.scenario_one.cluster_endpoint
  cluster_certificate = module.scenario_one.cluster_certificate_authority_data
  cluster_security_group = module.scenario_one.cluster_primary_security_group_id
  oidc_provider_arn = module.scenario_one.oidc_provider_arn
  create_delay_dependencies = [ for prof in module.scenario_one.fargate_profiles : prof.fargate_profile_arn ]
}

module scenario_two_workload {
  source                    = "./modules/cluster_autoscaler"
  cluster_name              = local.scenario_two
  cluster_version           = "1.29"
  selector                  = 1
  region                    = local.region
  tags                      = local.tags
  vpc_id                    = module.vpc.vpc_id
  node_subnet_ids           = module.vpc.database_subnets
  cni_subnet_ids            = module.vpc.redshift_subnets
  multus_subnet_ids         = module.vpc.intra_subnets
  multus_sg_id              = aws_security_group.multus_security_group.id
  multus_cidrs              = module.vpc.intra_subnets_cidr_blocks
  vpce_security_group = aws_security_group.vpce_security_group_2.id
  cluster_endpoint = module.scenario_two.cluster_endpoint
  cluster_certificate = module.scenario_two.cluster_certificate_authority_data
  cluster_security_group = module.scenario_two.cluster_primary_security_group_id
  oidc_provider_arn = module.scenario_two.oidc_provider_arn
  cluster_service_cidr = module.scenario_two.cluster_service_cidr
  create_delay_dependencies = [ for prof in module.scenario_two.fargate_profiles : prof.fargate_profile_arn ]
}

module scenario_three_workload {
  source                    = "./modules/challenge_1"
  cluster_name              = local.scenario_three
  cluster_version           = "1.29"
  selector                  = 2
  region                    = local.region
  tags                      = local.tags
  vpc_id                    = module.vpc.vpc_id
  node_subnet_ids           = module.vpc.database_subnets
  cni_subnet_ids            = module.vpc.redshift_subnets
  multus_subnet_ids         = module.vpc.intra_subnets
  multus_sg_id              = aws_security_group.multus_security_group.id
  multus_cidrs              = module.vpc.intra_subnets_cidr_blocks
  vpce_security_group = aws_security_group.vpce_security_group_2.id
  cluster_endpoint = module.scenario_three.cluster_endpoint
  cluster_certificate = module.scenario_three.cluster_certificate_authority_data
  cluster_security_group = module.scenario_three.cluster_primary_security_group_id
  oidc_provider_arn = module.scenario_three.oidc_provider_arn
  cluster_service_cidr = module.scenario_three.cluster_service_cidr
}
