variable "oidc_provider"  {
    type = string
    description = "The OIDC provider id"
}

variable "account_id" {
    type = string
    description = "The AWS account id"
}

variable "cluster_name" {
    type = string
    description = "The EKS cluster name"
}