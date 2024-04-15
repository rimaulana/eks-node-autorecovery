variable "create_delay_duration" {
  description = "The duration to wait before creating resources"
  type        = string
  default     = "30s"
}

variable "create_delay_dependencies" {
  description = "Dependency attribute which must be resolved before starting the `create_delay_duration`"
  type        = list(string)
  default     = []
}

variable "oidc_provider_arn" {
  description = "The ARN of the cluster OIDC Provider"
  type        = string
}

variable "cluster_service_cidr" {
  description = "EKS Cluster Service CIDR"
  type        = string
}

variable "cluster_name" {
    type        = string
    description = "The name of EKS cluster"
}

variable "cluster_version" {
    type        = string
    description = "The Kubernetes version of EKS cluster"
}

variable "region" {
    type        = string
    description = "The region of the cluster"
}

variable "tags" {
  description = "Tags to be attached to the cluster"
  type        = map(any)
}

variable "vpc_id" {
  description = "vpc_id for EKS cluster"
  type        = string
}

variable "node_subnet_ids" {
  description = "subnet ids for worker nodes"
  type        = list(string)
}

variable "cni_subnet_ids" {
  description = "subnet ids for CNI custom networking"
  type        = list(string)
}

variable "multus_subnet_ids" {
  description = "subnet ids for multus ENI"
  type        = list(string)
}

variable "multus_sg_id" {
  description = "security group of multus managed eni"
  type        = string
}

variable "multus_cidrs" {
  description = "CIDR for Multus CNI"
  type        = list(string)
}

variable "vpce_security_group" {
  description = "Security group for VPC Endpoint"
  type        = string
}

variable "selector" {
  description = "Integer to select subnet from range"
  type        = number
}

variable "cluster_endpoint" {
  description = "HTTPS endpoint of EKS cluster"
  type = string
}

variable "cluster_certificate" {
  description = "Encrypted EKS cluster's HTTPS certificate"
  type = string
}

variable "cluster_security_group" {
  type = string
}