variable "cluster_name" {
    type        = string
    description = "The name of EKS cluster"
}

variable "cluster_endpoint" {
    type        = string
    description = "The HTTPS endpoint of the EKS cluster"
}

variable "cluster_certificate" {
    type        = string
    description = "The B64 Encoded EKS cluster certificate"
}

variable "manifest_path_directory" {
    type        = string
    description = "manifest location to be deployed in cluster"
}

variable "create_delay_dependencies" {
  description = "Dependency attribute which must be resolved before starting the `create_delay_duration`"
  type        = list(string)
  default     = []
}

variable "create_delay_duration" {
  description = "The duration to wait before creating resources"
  type        = string
  default     = "30s"
}

variable "template_values" {
    description = "YAML template values"
    type        = map(object)
    default     = {
        yoda    = "jedi"
    }
}