data "aws_iam_policy_document" "karpenter_controller_policy" {
  version = "2012-10-17"

  statement {
    sid    = "Karpenter"
    effect = "Allow"
    actions = [
      "ssm:GetParameter",
      "ec2:DescribeImages",
      "ec2:RunInstances",
      "ec2:DescribeSubnets",
      "ec2:DescribeSecurityGroups",
      "ec2:DescribeLaunchTemplates",
      "ec2:DescribeInstances",
      "ec2:DescribeInstanceTypes",
      "ec2:DescribeInstanceTypeOfferings",
      "ec2:DeleteLaunchTemplate",
      "ec2:CreateTags",
      "ec2:CreateLaunchTemplate",
      "ec2:CreateFleet",
      "ec2:DescribeSpotPriceHistory",
      "pricing:GetProducts"
    ]
    resources = ["*"]
  }

  statement {
    sid    = "ConditionalEC2Termination"
    effect = "Allow"
    actions = [
      "ec2:TerminateInstances"
    ]
    resources = ["*"]
    condition {
      test     = "StringLike"
      variable = "ec2:ResourceTag/karpenter.sh/nodepool"
      values   = ["*"]
    }
  }

  statement {
    sid    = "PassNodeIAMRole"
    effect = "Allow"
    actions = [
      "iam:PassRole"
    ]
    resources = ["arn:aws:iam::767397685517:role/default-eks-node-group-20250712165444410600000003"]
  }

  statement {
    sid    = "EKSClusterEndpointLookup"
    effect = "Allow"
    actions = [
      "eks:DescribeCluster"
    ]
    resources = ["arn:aws:eks:${var.aws_region}:${data.aws_caller_identity.current.account_id}:cluster/${module.hub_dev.cluster_name}"]
  }

  statement {
    sid    = "AllowScopedInstanceProfileCreationActions"
    effect = "Allow"
    actions = [
      "iam:CreateInstanceProfile"
    ]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "aws:RequestTag/kubernetes.io/cluster/${module.hub_dev.cluster_name}"
      values   = ["owned"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:RequestTag/topology.kubernetes.io/region"
      values   = ["${var.aws_region}"]
    }
    condition {
      test     = "StringLike"
      variable = "aws:RequestTag/karpenter.k8s.aws/ec2nodeclass"
      values   = ["*"]
    }
  }

  statement {
    sid    = "AllowScopedInstanceProfileTagActions"
    effect = "Allow"
    actions = [
      "iam:TagInstanceProfile"
    ]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "aws:ResourceTag/kubernetes.io/cluster/${module.hub_dev.cluster_name}"
      values   = ["owned"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:ResourceTag/topology.kubernetes.io/region"
      values   = ["${var.aws_region}"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:RequestTag/kubernetes.io/cluster/${module.hub_dev.cluster_name}"
      values   = ["owned"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:RequestTag/topology.kubernetes.io/region"
      values   = ["${var.aws_region}"]
    }
    condition {
      test     = "StringLike"
      variable = "aws:ResourceTag/karpenter.k8s.aws/ec2nodeclass"
      values   = ["*"]
    }
    condition {
      test     = "StringLike"
      variable = "aws:RequestTag/karpenter.k8s.aws/ec2nodeclass"
      values   = ["*"]
    }
  }

  statement {
    sid    = "AllowScopedInstanceProfileActions"
    effect = "Allow"
    actions = [
      "iam:AddRoleToInstanceProfile",
      "iam:RemoveRoleFromInstanceProfile",
      "iam:DeleteInstanceProfile"
    ]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "aws:ResourceTag/kubernetes.io/cluster/${module.hub_dev.cluster_name}"
      values   = ["owned"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:ResourceTag/topology.kubernetes.io/region"
      values   = ["${var.aws_region}"]
    }
    condition {
      test     = "StringLike"
      variable = "aws:ResourceTag/karpenter.k8s.aws/ec2nodeclass"
      values   = ["*"]
    }
  }

  statement {
    sid    = "AllowInstanceProfileReadActions"
    effect = "Allow"
    actions = [
      "iam:GetInstanceProfile"
    ]
    resources = ["*"]
  }
}

# Create the IAM policy using the policy document
resource "aws_iam_policy" "karpenter_controller_policy" {
  name        = "KarpenterControllerPolicy-${module.hub_dev.cluster_name}"
  description = "IAM policy for Karpenter Controller"
  policy      = data.aws_iam_policy_document.karpenter_controller_policy.json
  path = "/appinfra/"
}

# Trust policy for Karpenter IAM role
data "aws_iam_policy_document" "karpenter_trust_policy" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:oidc-provider/${module.hub_dev.oidc_provider}"]
    }
    condition {
      test     = "StringEquals"
      variable = "${module.hub_dev.oidc_provider}:aud"
      values   = ["sts.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "${module.hub_dev.oidc_provider}:sub"
      values   = ["system:serviceaccount:kube-system:karpenter"]
    }
  }
}

# Create the IAM role for Karpenter
resource "aws_iam_role" "karpenter_controller_role" {
  name               = "KarpenterControllerRole-${module.hub_dev.cluster_name}"
  assume_role_policy = data.aws_iam_policy_document.karpenter_trust_policy.json
  path               = "/appinfra/"
  permissions_boundary = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:policy/appinfra-permission-boundary"
}

# Attach the Karpenter controller policy to the role
resource "aws_iam_role_policy_attachment" "karpenter_controller_policy_attachment" {
  role       = aws_iam_role.karpenter_controller_role.name
  policy_arn = aws_iam_policy.karpenter_controller_policy.arn
}


resource "aws_iam_instance_profile" "test_profile" {
  name = "eks-node-group-profile-${module.hub_dev.cluster_name}"
  role = "default-eks-node-group-20250712165444410600000003"
}

output "instance_profile_arn" {
  value = aws_iam_instance_profile.test_profile.arn
}
