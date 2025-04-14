data "aws_iam_policy_document" "cluster_autoscaler" {

  statement {
    actions = [
      "autoscaling:DescribeAutoScalingGroups",
      "autoscaling:DescribeAutoScalingInstances",
      "autoscaling:DescribeLaunchConfigurations",
      "autoscaling:DescribeScalingActivities",
      "autoscaling:DescribeTags",
      "ec2:DescribeLaunchTemplateVersions",
      "ec2:DescribeInstanceTypes",
      "eks:DescribeNodegroup",
      "ec2:DescribeImages",
      "ec2:GetInstanceTypesFromInstanceRequirements"
    ]

    resources = ["*"]
  }

  statement {
    actions = [
      "autoscaling:SetDesiredCapacity",
      "autoscaling:TerminateInstanceInAutoScalingGroup",
      "autoscaling:UpdateAutoScalingGroup",
    ]

    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "autoscaling:ResourceTag/kubernetes.io/cluster/${var.cluster_name}"
      values   = ["owned"]
    }
  }
}

resource "aws_iam_policy" "cluster_autoscaler" {
    name = "${var.cluster_name}-irsa-cluster-autoscaler-policy"
    policy = data.aws_iam_policy_document.cluster_autoscaler.json
}

resource "aws_iam_role" "eks_cluster_autoscaler_role" {
    name = "${var.cluster_name}-irsa-cluster-autoscaler-role"

    assume_role_policy = jsonencode({
        "Version" : "2012-10-17",
        "Statement" : [
            {
                "Effect" : "Allow",
                "Principal" : {
                    "Federated" : "arn:aws:iam::${var.account_id}:oidc-provider/${var.oidc_provider}"
                },
                "Action" : "sts:AssumeRoleWithWebIdentity",
                "Condition" : {
                    "StringEquals" : {
                        "${var.oidc_provider}:aud" : "sts.amazonaws.com",
                        "${var.oidc_provider}:sub" : "system:serviceaccount:kube-system:cluster-autoscaler-sa"
                    }
                }
            }
        ]
    })
    managed_policy_arns = [
        aws_iam_policy.cluster_autoscaler.arn
    ]
}
