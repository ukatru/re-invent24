output "cluster_autoscaler_role_arn" {
    value = aws_iam_role.eks_cluster_autoscaler_role.arn
}