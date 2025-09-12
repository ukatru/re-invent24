data "aws_s3_bucket" "primary_logging_bucket" {
    provider = "aws.primary"
    bucket = "${var.aws_s3_account_prefix}.accesslog.${var.bucket_env}.${var.aws_primary_region}"
}

data "aws_s3_bucket" "secondary_logging_bucket" {
    provider = "aws.secondary"
    bucket = "${var.aws_s3_account_prefix}.accesslog.${var.bucket_env}.${var.aws_secondary_region}"
}

locals {
  bucket_name_without_dash = replace(var.bucket_name, "-", "")
  primary_bucket_name = "${var.aws_s3_account_prefix}.${var.data_tier}.${var.bucket_name}.${var.bucket_env}.${var.aws_primary_region}"
  secondary_bucket_name = "${var.aws_s3_account_prefix}.${var.data_tier}.${var.bucket_name}.${var.bucket_env}.${var.aws_secondary_region}"
}

################################
#S3 primary bucket
################################

resource "aws_s3_bucket" "primary_bucket"{
    provider = "aws.primary"
    bucket = local.primary_bucket_name
    acl = "private"

    
    logging {
        target_bucket = "${data.aws_s3_bucket.primary_logging_bucket.id}"
        target_prefix = "log/${var.bucket_name}/${var.bucket_env}/"
    }

    versioning {
        enabled = true
    }

    server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm     = "AES256"
        } 
    }
}

   replication_configuration {
    role = aws_iam_role.replication_role.arn

    rules {
      id     = "${var.aws_s3_account_prefix}.${var.data_tier}.${var.bucket_name}.${var.bucket_env}.${var.aws_primary_region}-bucket-replication-rule"
      status = "Enabled"

      destination {
        bucket        = aws_s3_bucket.secondary_bucket.arn
        storage_class = "INTELLIGENT_TIERING"
      }
    }
  } 

tags = "${merge(
    var.default_tags,
    var.application_tags,
    var.data_catalog_tags,
    map("Name", "${var.aws_s3_account_prefix}.${var.data_tier}.${var.bucket_name}.${var.bucket_env}.${var.aws_primary_region}")
    )}"
}

resource "aws_s3_bucket_public_access_block" "primary_bucket_access_block" {
    provider = "aws.primary"
    bucket = "${aws_s3_bucket.primary_bucket.id}"

  block_public_acls         = true
  block_public_policy       = true
  ignore_public_acls        = true
  restrict_public_buckets    = true
}

resource "aws_s3_bucket_metric" "primary_bucket_metrics_enable" {
  count = "${var.enable_metrics ? 1 :0}"
  provider = "aws.primary"
  bucket = "${aws_s3_bucket.primary_bucket.bucket}"
  name = "${var.aws_s3_account_prefix}.${var.data_tier}.${var.bucket_name}.${var.bucket_env}.${var.aws_primary_region}_metrics"

}

################################
#S3 Secondary bucket
################################

resource "aws_s3_bucket" "secondary_bucket"{
    provider = "aws.secondary"
    bucket = local.secondary_bucket_name
    acl = "private"

    
    logging {
        target_bucket = "${data.aws_s3_bucket.secondary_logging_bucket.id}"
        target_prefix = "log/${var.bucket_name}/${var.bucket_env}/"
    }

    versioning {
        enabled = true
    }

    server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm     = "AES256"
        } 
    }
}

tags = "${merge(
    var.default_tags,
    var.application_tags,
    var.data_catalog_tags,
    map("Name", "${var.aws_s3_account_prefix}.${var.data_tier}.${var.bucket_name}.${var.bucket_env}.${var.aws_secondary_region}")
    )}"
}

resource "aws_s3_bucket_public_access_block" "secondary_bucket_access_block" {
    provider = "aws.secondary"
    bucket = "${aws_s3_bucket.secondary_bucket.id}"

  block_public_acls         = true
  block_public_policy       = true
  ignore_public_acls        = true
  restrict_public_buckets    = true
}

resource "aws_s3_bucket_metric" "secondary_bucket_metrics_enable" {
  count = "${var.enable_metrics ? 1 :0}"
  provider = "aws.secondary"
  bucket = "${aws_s3_bucket.secondary_bucket.bucket}"
  name = "${var.aws_s3_account_prefix}.${var.data_tier}.${var.bucket_name}.${var.bucket_env}.${var.aws_secondary_region}_metrics"

}


##################################################################
# Replication IAM Role
##################################################################
data "aws_iam_policy_document" "replication_role_policy_document" {
    provider = "aws.primary"

    statement {
      actions = ["sts:AssumeRole"]

      principals {
          type          = "Service"
          identifiers   = ["s3.amazonaws.com"]
        }
    }
}

resource "aws_iam_role" "replication_role" {
    provider = "aws.primary"
    name = "${var.aws_account_name}-${var.data_tier}-${var.bucket_name}-${var.bucket_env}-repl-role"
    force_detach_policies = var.force_detach_policies
    assume_role_policy = data.aws_iam_policy_document.replication_role_policy_document.json
}

data "aws_iam_policy_document" "replication_policy_document" {
    provider = "aws.primary"

    statement {
        sid = "1"

        actions = [
        "s3:GetReplicationConfiguration",
        "s3:ListBucket",
      ]

      resources = [
          aws_s3_bucket.primary_bucket.arn,
      ]

    }

    statement {
        sid = "2"

        actions = [
        "s3:GetObjectVersion",
        "s3:GetObjectVersionForReplication",
        "s3:GetObjectVersionAcl",
        "s3:GetObjectVersionTagging",
      ]

      resources = [
          "${aws_s3_bucket.primary_bucket.arn}/*",
      ]

    }

    statement {
        sid = "3"

        actions = [
        "s3:ReplicateObject",
        "s3:ReplicateDelete",
        "s3:ReplicateTags",
        "s3:GetObjectVersionTagging"
      ]

      resources = [
          "${aws_s3_bucket.secondary_bucket.arn}/*",
      ]

    }
}

resource "aws_iam_policy" "replication_policy" {
    provider = aws.primary
  name        = "${var.aws_account_name}-${var.data_tier}-${var.bucket_name}-${var.bucket_env}-repl-policy"
  path        = "/"
  policy = data.aws_iam_policy_document.replication_policy_document.json
}

resource "aws_iam_policy_attachment" "replication_policy_attachment" {
    provider = aws.primary
  name = "${var.aws_account_name}-${var.data_tier}-${var.bucket_name}-${var.bucket_env}-repl-policy-attachment"
  roles      = [aws_iam_role.replication_role.name]
  policy_arn = aws_iam_policy.replication_policy.arn
}

##############################################################
# Bucket Read Policy
##############################################################
data "aws_iam_policy_document" "bucket_read_policy_document" {
  statement {
    sid = "${local.bucket_name_without_dash}ReadListObjectsInBucket"
    effect = "Allow"
    actions = [
      "s3:GetBucketLocation",
      "s3:ListBucket",
      "s3:ListBucketMultipartUploads",
      "s3:ListMultipartUploadParts"
    ]
    resources = [
      "${aws_s3_bucket.primary_bucket.arn}",
      "${aws_s3_bucket.secondary_bucket.arn}"
    ]
  }

  statement {
    sid = "${local.bucket_name_without_dash}ReadObjectActions"
    effect = "Allow"
    actions = [
      "s3:GetObject",
      "s3:GetObjectAcl",
    ]
    resources = [
      "${aws_s3_bucket.primary_bucket.arn}/*",
      "${aws_s3_bucket.secondary_bucket.arn}/*"
    ]
  }
}

resource "aws_iam_policy" "bucket_read_policy" {
  provider = aws.primary
  name = "${var.bucket_name}-bucket-read-policy"
  path = "/"
  description = "Read policy to bucket ${var.bucket_name}"

  policy = data.aws_iam_policy_document.bucket_read_policy_document.json
}

##############################################################
# Bucket Write Policy
##############################################################
data "aws_iam_policy_document" "bucket_write_policy_document" {
  statement {
    sid = "${local.bucket_name_without_dash}WriteListObjectsInBucket"
    effect = "Allow"
    actions = [
      "s3:GetBucketLocation",
      "s3:ListBucket",
      "s3:ListBucketMultipartUploads",
      "s3:ListMultipartUploadParts",
      "s3:AbortMultipartUpload"
    ]
    resources = [
      "${aws_s3_bucket.primary_bucket.arn}",
      "${aws_s3_bucket.secondary_bucket.arn}"
    ]
  }

  statement {
    sid = "${local.bucket_name_without_dash}WriteObjectActions"
    effect = "Allow"
    actions = [
      "s3:PutObject",
      "s3:PutObjectAcl",
      "s3:GetObject",
      "s3:GetObjectAcl",
      "s3:DeleteObject",
      "s3:AbortMultipartUpload"
    ]
    resources = [
      "${aws_s3_bucket.primary_bucket.arn}/*",
      "${aws_s3_bucket.secondary_bucket.arn}/*"
    ]
  }
}

resource "aws_iam_policy" "bucket_write_policy" {
  provider = aws.primary
  name = "${var.bucket_name}-bucket-write-policy"
  path = "/"
  description = "write policy to bucket ${var.bucket_name}"

  policy = data.aws_iam_policy_document.bucket_write_policy_document.json
}
