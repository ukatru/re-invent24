data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

################################################################################
# Repository
################################################################################

resource "aws_ecr_repository" "this" {

  name                 = var.repository_name
  image_tag_mutability = var.repository_image_tag_mutability

  encryption_configuration {
    encryption_type = var.repository_encryption_type
    kms_key         = var.repository_kms_key
  }

  force_delete = var.repository_force_delete

  image_scanning_configuration {
    scan_on_push = var.repository_image_scan_on_push
  }

  tags = var.tags
}


################################################################################
# Repository Policy
################################################################################

resource "aws_ecr_repository_policy" "this" {

  repository = aws_ecr_repository.this.name
  policy     = var.create_repository_policy ? data.aws_iam_policy_document.repository.json : var.repository_policy
}

################################################################################
# Lifecycle Policy
################################################################################

resource "aws_ecr_lifecycle_policy" "this" {
  count = var.create_lifecycle_policy ? 1 : 0

  repository = aws_ecr_repository.this.name
  policy     = var.repository_lifecycle_policy
}

################################################################################
# Registry Policy
################################################################################

resource "aws_ecr_registry_policy" "this" {
  count =  var.create_registry_policy ? 1 : 0

  policy = var.registry_policy
}

################################################################################
# Registry Pull Through Cache Rule
################################################################################

resource "aws_ecr_pull_through_cache_rule" "this" {
  for_each = { for k, v in var.registry_pull_through_cache_rules : k => v if var.create }

  ecr_repository_prefix      = each.value.ecr_repository_prefix
  upstream_registry_url      = each.value.upstream_registry_url
  #credential_arn             = try(each.value.credential_arn, null)
  #custom_role_arn            = try(each.value.custom_role_arn, null)
  upstream_repository_prefix = try(each.value.upstream_repository_prefix, null)
}

################################################################################
# Registry Scanning Configuration
################################################################################

resource "aws_ecr_registry_scanning_configuration" "this" {
  count = var.create && var.manage_registry_scanning_configuration ? 1 : 0

  scan_type = var.registry_scan_type

  dynamic "rule" {
    for_each = var.registry_scan_rules

    content {
      scan_frequency = rule.value.scan_frequency

      dynamic "repository_filter" {
        for_each = rule.value.filter

        content {
          filter      = repository_filter.value.filter
          filter_type = try(repository_filter.value.filter_type, "WILDCARD")
        }
      }
    }
  }
}