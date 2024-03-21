# This resource is used to provide a means of mapping an implicit dependency
# between the cluster and the addons.
resource "time_sleep" "this" {
  create_duration = var.create_delay_duration

  triggers = {
    cluster_endpoint    = var.cluster_endpoint
    cluster_certificate = var.cluster_certificate
    cluster_name        = var.cluster_name
    custom              = join(",", var.create_delay_dependencies)
  }
}

locals {
  cluster_endpoint    = time_sleep.this.triggers["cluster_endpoint"]
  cluster_name        = time_sleep.this.triggers["cluster_name"]
  cluster_certificate = time_sleep.this.triggers["cluster_certificate"]
}

provider "kubernetes" {
  host                   = local.cluster_endpoint
  cluster_ca_certificate = base64decode(local.cluster_certificate)
  exec {
    api_version = "client.authentication.k8s.io/v1beta1"
    command     = "aws"
    # This requires the awscli to be installed locally where Terraform is executed
    args = ["eks", "get-token", "--cluster-name",local.cluster_name]
  }
}

provider "helm" {
  kubernetes {
    host                   = local.cluster_endpoint
    cluster_ca_certificate = base64decode(local.cluster_certificate)

    exec {
      api_version = "client.authentication.k8s.io/v1beta1"
      command     = "aws"
      # This requires the awscli to be installed locally where Terraform is executed
      args = ["eks", "get-token", "--cluster-name", local.cluster_name]
    }
  }
}

provider "kubectl" {
  apply_retry_count      = 5
  host                   = local.cluster_endpoint
  cluster_ca_certificate = base64decode(local.cluster_certificate)
  load_config_file       = false

  exec {
    api_version = "client.authentication.k8s.io/v1beta1"
    command     = "aws"
    # This requires the awscli to be installed locally where Terraform is executed
    args = ["eks", "get-token", "--cluster-name", local.cluster_name]
  }
}

data "kubectl_path_documents" "manifests-directory-yaml" {
  pattern = "${var.manifest_path_directory}"
}

resource "kubectl_manifest" "directory-yaml" {
  apply_only = true
  server_side_apply = true
  for_each  = data.kubectl_path_documents.manifests-directory-yaml.manifests
  yaml_body = each.value
}