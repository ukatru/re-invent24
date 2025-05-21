################################################################################
# File System
################################################################################
resource "aws_efs_file_system" "efs_file_system" {
  count                           = var.create ? 1 : 0
  availability_zone_name          = var.availability_zone_name
  creation_token                  = var.creation_token
  performance_mode                = var.performance_mode
  encrypted                       = var.encrypted
  provisioned_throughput_in_mibps = var.provisioned_throughput_in_mibps
  throughput_mode                 = var.throughput_mode

  dynamic "lifecycle_policy" {
    for_each = [for k, v in var.lifecycle_policy : { (k) = v }]

    content {
      transition_to_ia                    = try(lifecycle_policy.value.transition_to_ia, null)
      transition_to_archive               = try(lifecycle_policy.value.transition_to_archive, null)
      transition_to_primary_storage_class = try(lifecycle_policy.value.transition_to_primary_storage_class, null)
    }
  }

  tags = merge(
    var.default_tags,
    { Name = var.name },
  )
}

################################################################################
# Security Group
################################################################################

resource "aws_security_group" "efs_security_group" {
  count       = var.create ? 1 : 0
  name        = "${local.security_group_name}-${var.aws_region}-${data.aws_vpc.selected_vpc.id}"
  description = var.security_group_description

  vpc_id = data.aws_vpc.selected_vpc.id

  tags = merge(
    var.default_tags,
    { Name = local.security_group_name },
  )

}

resource "aws_security_group_rule" "efs_security_group_rule_ingress" {
  for_each = { for k, v in local.security_group_rules_ingress : k => v if k == var.env && var.create == true }

  security_group_id = aws_security_group.efs_security_group[0].id

  description              = try(each.value.description, null)
  type                     = try(each.value.type, "ingress")
  from_port                = try(each.value.from_port, 2049)
  to_port                  = try(each.value.to_port, 2049)
  protocol                 = try(each.value.protocol, "tcp")
  cidr_blocks              = lookup(each.value, "cidr_blocks", null)
  ipv6_cidr_blocks         = lookup(each.value, "ipv6_cidr_blocks", null)
  prefix_list_ids          = lookup(each.value, "prefix_list_ids", null)
  self                     = try(each.value.self, null)
  source_security_group_id = lookup(each.value, "source_security_group_id", null)
}

resource "aws_security_group_rule" "efs_security_group_rule_egress" {
  for_each = { for k, v in local.security_group_rules_egress : k => v if var.create == true }

  security_group_id = aws_security_group.efs_security_group[0].id

  description              = try(each.value.description, null)
  type                     = try(each.value.type, "ingress")
  from_port                = try(each.value.from_port, 2049)
  to_port                  = try(each.value.to_port, 2049)
  protocol                 = try(each.value.protocol, "tcp")
  cidr_blocks              = lookup(each.value, "cidr_blocks", null)
  ipv6_cidr_blocks         = lookup(each.value, "ipv6_cidr_blocks", null)
  prefix_list_ids          = lookup(each.value, "prefix_list_ids", null)
  self                     = try(each.value.self, null)
  source_security_group_id = lookup(each.value, "source_security_group_id", null)
}

################################################################################
# Mount Target(s)
################################################################################

resource "aws_efs_mount_target" "efs_mount_target" {
  for_each = { for k, v in var.mount_targets_subnet_ids : k => v if var.create == true }

  file_system_id  = aws_efs_file_system.efs_file_system[0].id
  security_groups = [aws_security_group.efs_security_group[0].id]
  subnet_id       = each.value
}

################################################################################
# Backup Policy
################################################################################

resource "aws_efs_backup_policy" "efs_backup_policy" {
  count = var.create && var.create_backup_policy ? 1 : 0

  file_system_id = aws_efs_file_system.efs_file_system[0].id

  backup_policy {
    status = var.enable_backup_policy ? "ENABLED" : "DISABLED"
  }
}

################################################################################
# Replication Configuration
################################################################################

resource "aws_efs_replication_configuration" "efs_replication_configuration" {
  count = var.create && var.create_replication_configuration ? 1 : 0

  source_file_system_id = aws_efs_file_system.efs_file_system[0].id

  dynamic "destination" {
    for_each = [var.replication_configuration_destination]

    content {
      availability_zone_name = try(destination.value.availability_zone_name, null)
      kms_key_id             = try(destination.value.kms_key_id, null)
      region                 = try(destination.value.region, null)
    }
  }
}


################################################################################
# FileSystem Policy
################################################################################

#resource "aws_efs_file_system_policy" "efs_file_system_policy" {
#  count = var.create ? 1 : 0
#
#  file_system_id = aws_efs_file_system.efs_file_system[0].id
#
#  policy = jsonencode({
#    Version   = "2012-10-17"
#    Statement = [
#      {
#        Effect   = "Allow"
#        Principal =  {
#           AWS = local.principal_arns
#        }
#        Action    = [
#          "elasticfilesystem:ClientMount",
#          "elasticfilesystem:ClientWrite"
#        ]
#      }
#    ]
#  })
#}
#

################################################################################
# File System Policy
################################################################################

data "aws_iam_policy_document" "policy" {
  count = var.create ? 1: 0

  dynamic "statement" {
    for_each = var.policy_statements

    content {
      sid           = try(statement.value.sid, null)
      actions       = try(statement.value.actions, null)
      not_actions   = try(statement.value.not_actions, null)
      effect        = try(statement.value.effect, null)
      resources     = try(statement.value.resources, [aws_efs_file_system.efs_file_system[0].arn], null)
      not_resources = try(statement.value.not_resources, null)

      dynamic "principals" {
        for_each = try(statement.value.principals, [])

        content {
          type        = principals.value.type
          identifiers = principals.value.identifiers
        }
      }

      dynamic "condition" {
        for_each = try(statement.value.conditions, statement.value.condition, [])

        content {
          test     = condition.value.test
          values   = condition.value.values
          variable = condition.value.variable
        }
      }
    }
  }

  dynamic "statement" {
    for_each = var.deny_nonsecure_transport ? [1] : []

    content {
      sid       = "NonSecureTransport"
      effect    = "Deny"
      actions   = ["*"]
      resources = [aws_efs_file_system.efs_file_system[0].arn]

      principals {
        type        = "AWS"
        identifiers = ["*"]
      }

      condition {
        test     = "Bool"
        variable = "aws:SecureTransport"
        values   = ["false"]
      }
    }
  }

  dynamic "statement" {
    for_each = var.deny_nonsecure_transport ? [1] : []

    content {
      sid    = "NonSecureTransportAccessedViaMountTarget"
      effect = "Allow"
      actions = [
        "elasticfilesystem:ClientRootAccess",
        "elasticfilesystem:ClientWrite",
        "elasticfilesystem:ClientMount"
      ]
      resources = [aws_efs_file_system.efs_file_system[0].arn]

      principals {
        type        = "AWS"
        identifiers = ["*"]
      }

      condition {
        test     = "Bool"
        variable = "elasticfilesystem:AccessedViaMountTarget"
        values   = ["true"]
      }
    }
  }
}

resource "aws_efs_file_system_policy" "this" {
  count = var.create ? 1 : 0

  file_system_id                     = aws_efs_file_system.efs_file_system[0].id
  policy                             = data.aws_iam_policy_document.policy[0].json
}
################################################################################
# Access Point(s)
################################################################################

resource "aws_efs_access_point" "efs_access_point" {
  for_each = { for k, v in var.access_points : k => v if var.create }

  file_system_id = aws_efs_file_system.efs_file_system[0].id

  dynamic "posix_user" {
    for_each = try([each.value.posix_user], [])

    content {
      gid            = posix_user.value.gid
      uid            = posix_user.value.uid
      secondary_gids = try(posix_user.value.secondary_gids, null)
    }
  }

  dynamic "root_directory" {
    for_each = try([each.value.root_directory], [])

    content {
      path = try(root_directory.value.path, null)

      dynamic "creation_info" {
        for_each = try([root_directory.value.creation_info], [])

        content {
          owner_gid   = creation_info.value.owner_gid
          owner_uid   = creation_info.value.owner_uid
          permissions = creation_info.value.permissions
        }
      }
    }
  }

  tags = merge(
    var.default_tags,
    try(each.value.tags, {}),
    { Name = try(each.value.name, each.key) },
  )
}
