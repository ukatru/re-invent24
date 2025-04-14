variable "oidc_provider" {
    type = string
    description = "EKS Cluster oidc provider id"
}

variable "aws_account_id" {
    type = string
    description = "AWS Account id"
}

variable "cluster_name" {
    type = string
    description = "EKS Cluster name"
}