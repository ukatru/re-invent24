
locals {
  eks_np_cidr_blocks   = ["10.138.208.0/23"]
  eks_prod_cidr_blocks = ["10.138.208.0/23"]
  security_group_name  = try(coalesce(var.security_group_name, var.name), "")
  security_group_rules_ingress = {
    dev = {
      description = "NFS ingress from EKS worker nodes"
      type        = "ingress"
      from_port   = 2049
      to_port     = 2049
      protocol    = "tcp"
      cidr_blocks = concat(local.eks_np_cidr_blocks, var.source_cidr_blocks)
    }
    prod = {
      description = "NFS ingress from EKS worker nodes"
      type        = "ingress"
      from_port   = 2049
      to_port     = 2049
      protocol    = "tcp"
      cidr_blocks = concat(local.eks_prod_cidr_blocks, var.source_cidr_blocks)
    }
  }
  security_group_rules_egress = {
    all = {
      description = "SG egress to EFS"
      type        = "egress"
      from_port   = 0
      to_port     = 0
      protocol    = "-1"
      cidr_blocks = ["0.0.0.0/0"]
    }
  }
  principal_arns = concat(var.efs_policy_principals, ["arn:aws:iam::${var.aws_account_id}:root"])
}
