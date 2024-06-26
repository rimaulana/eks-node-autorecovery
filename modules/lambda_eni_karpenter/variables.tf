variable name {
  type        = string
  description = "The name of the stack"
}

variable multus_subnets {
  type        = string
  description = "Comma separated list of multus subnet to be attached on the node"
}

variable multus_security_groups {
  type        = string
  description = "Comma separated list of multus security group to be attached on the additional eni"
}

variable karpenter_iam_role_arn {
  type        = string
  description = "ARN of Karpenter IAM role to trigger lambda"
}
