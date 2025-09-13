
locals {
  access_key_name = "${var.account_name}-${aws_iam_user.iam_user.name}-secret-access-key"
}

data "aws_caller_identity" "current" {
}

# ######################################################################
# IAM User
# ######################################################################
resource "aws_iam_user" "iam_user" {
  name     = var.iam_user_name
  path     = "/system/"
}

resource "aws_iam_group" "iam_group" {
  name     = var.iam_group_name
  path     = "/user/"
}

resource "aws_iam_group_membership" "group_member" {
  name     = var.group_membership_name
  group = aws_iam_group.iam_group.name
  users = [
    aws_iam_user.iam_user.name
  ]

}

resource "aws_iam_group_policy" "group_policy" {
  name     = var.group_policy_name
  group    = aws_iam_group.iam_group.id
  policy   = var.group_policy_json
}

# ######################################################################
#  Secrets Manager
# ######################################################################
resource "aws_secretsmanager_secret" "secret_access_key_id" {
  name        = "${local.access_key_name}-id"
  description = "${local.access_key_name}-id"
  
  tags = merge(
    var.tags,
    tomap({module-source = "ssh://git@gitlab002.ukatru.com:7222/cloud/aws/terraform-modules/tree/master/modules/identity/iam_user_w_secretmanager"})
  )
}

resource "random_password" "password" {
  length = 16
  special = true
  override_special = "!#$%&*()-_=+[]{}<>:?"
}

resource "aws_secretsmanager_secret_version" "secret_access_key_id_version" {
  depends_on    = [aws_secretsmanager_secret.secret_access_key_id]
  secret_id     = aws_secretsmanager_secret.secret_access_key_id.id
  secret_string = random_password.password.result

  lifecycle {
    ignore_changes = [
      secret_string
    ]
  }
}

resource "aws_secretsmanager_secret" "secret_access_key" {
  name        = local.access_key_name
  description = local.access_key_name

  tags = merge(
    var.tags,
    tomap({module-source = "ssh://git@gitlab002.ukatru.com:7222/cloud/aws/terraform-modules/tree/master/modules/identity/iam_user_w_secretmanager"})
  )
}

resource "aws_secretsmanager_secret_version" "secret_access_key_version" {
  depends_on    = [aws_secretsmanager_secret.secret_access_key]
  secret_id     = aws_secretsmanager_secret.secret_access_key.id
  secret_string = random_password.password.result


   lifecycle {
    ignore_changes = [
      secret_string
    ]
  }
}

# ######################################################################
#  Secrets rotation
# ######################################################################
resource "aws_secretsmanager_secret_rotation" "default" {
  count = var.enable_secret_rotation == true ? 1: 0
  secret_id           = aws_secretsmanager_secret.secret_access_key_id.id
  rotation_lambda_arn = aws_lambda_function.default[count.index].arn

  rotation_rules {
    automatically_after_days = var.rotation_rules
  }
}

resource "aws_lambda_function" "default" {
  count = var.enable_secret_rotation == true ? 1: 0
  description = "AWS Lambda function to rotate AWS secrets"
  filename = "${path.module}/functions/SecretsManagerRotation.zip"
  source_code_hash  = filebase64sha256("${path.module}/functions/SecretsManagerRotation.zip")
  function_name = "SecretManager_rotation_${var.iam_user_name}"
  handler = "SecretsManagerRotation.lambda_handler"
  runtime = "python3.9"
  timeout = 30
  role = aws_iam_role.lambda.arn

  environment {
    variables = {
      SECRETS_MANAGER_ENDPOINT = "https://secretsmanager.us-west-2.amazonaws.com"
    }
  }

   tags = merge(
    var.tags,
    tomap({module-source = "ssh://git@gitlab002.ukatru.com:7222/cloud/aws/terraform-modules/tree/master/modules/identity/iam_user_w_secretmanager"})
  )
}

resource "aws_lambda_permission" "default" {
  count = var.enable_secret_rotation == true ? 1: 0
  function_name = aws_lambda_function.default[count.index].function_name
  statement_id = "AllowExecutionSecretManager"
  action = "lambda:InvokeFunction"
  principal = "secretsmanager.amazonaws.com"
}

# ###############################################################
# Secret rotation policy
# ###############################################################
# Role for the secretsmanager Lambda rotation function
resource "aws_iam_role" "lambda" {

  name = "${var.account_name}-lambda-${var.iam_user_name}"
  description = "Role for Secrets manager lambda rotate function"

  assume_role_policy = <<POLICY
{
    "Statement": [
      {
        "Effect": "Allow",
        "Action": "sts:AssumeRole",
        "Principal": {
          "Service": "lambda.amazonaws.com"
        }
      }
    ],
    "Version": "2012-10-17"
}
POLICY
tags = var.tags
}

data "aws_iam_policy_document" "Secrets_Manager_Rotation_User_Role_Policy" {

  statement  {
    actions = [
      "secretsmanager:DescribeSecret",
      "secretsmanager:GetSecretValue",
      "secretsmanager:PutSecretValue",
      "secretsmanager:UpdateSecretVersionStage",
    ]

    resources = [
      "arn:aws:secretsmanager:${var.region}:${data.aws_caller_identity.current.account_id}:secret:${local.access_key_name}*",
    ]
  }

  statement  {
    actions = [
      "iam:ListAccountAliases",
    ]

    resources = [
      "*",
    ]
  }

  statement {
    actions = [
      "iam:ListAccessKeys",
      "iam:CreateAccessKey",
      "iam:DeleteAccessKey",
      "iam:UpdateAccessKey",
    ]

    resources = [
      aws_iam_user.iam_user.arn,
    ]
  }
}

resource "aws_iam_policy" "Secrets_Manager_Rotation_User_Role_Policy" {
  name = "Secrets_Manager_Rotation_Role_Policy-${var.iam_user_name}"
  path = "/"
  policy = data.aws_iam_policy_document.Secrets_Manager_Rotation_User_Role_Policy.json
}

resource "aws_iam_policy_attachment" "Secrets_Manager_Rotation_User_Role_Policy" {
  name = "Secrets_Manager_Rotation_Role_Policy-_Attachment"
  roles = [aws_iam_role.lambda.name]
  policy_arn = aws_iam_policy.Secrets_Manager_Rotation_User_Role_Policy.arn
}

resource "aws_iam_role_policy_attachment" "lambda_policy" {
  role = aws_iam_role.lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}



=================
# ########################################################################
# AWS
# ########################################################################
terraform {
    required_providers {
        aws = {
            source = "hashicorp/aws"
        }
    }
}
variable "account_name" {
  description = "AWS Account name"
  type = string
}

variable "region" {
  type = string
  default = "us-west-2"
}

# ########################################################################
# Module configuration
# ########################################################################
variable "group_membership_name" {
  type = string
}

variable "group_policy_name" {
  type = string
}

variable "group_policy_json" {
  type    = string
  default = ""
}

variable "iam_group_name" {
  type = string
}

variable "iam_user_name" {
  type = string
}

variable "tags" {
  description = "A map of tags to add to all resource"
  type = map(any)
}

variable "enable_secret_rotation"{
  default = false
}

variable "rotation_rules"{
  default = 45
}
============

output "iam_group_arn" {
    value = aws_iam_group.iam_group.arn
}

output "iam_user_arn" {
    value = aws_iam_user.iam_user.arn
}

output "iam_user_secret_access_key_id_arn" {
    value = aws_secretsmanager_secret_version.secret_access_key_id_version.arn
}

output "iam_user_secret_access_key_arn" {
    value = aws_secretsmanager_secret_version.secret_access_key_version.arn
}

======================
from builtins import Exception, ValueError, len, print
import json
import boto3
import base64
import datetime
import logging
import os
import sys
import time
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
    arn = event['SecretId']
    token = event['ClientRequestToken']
    step = event['Step']

    # setup the client
    iam = boto3.client('iam')
    service_client = boto3.client('secretsmanager', endpoint_url=os.environ['SECRETS_MANAGER_ENDPOINT'])

    # Make sure the version is staged correctly
    metadata = service_client.describe_secret(SecretId=arn)
    if not metadata['RotationEnabled']:
        logger.error("Access ID %s is not enabled for rotation" % arn)
        raise ValueError("Access ID %s is not enabled for rotation" % arn)
        
    versions = metadata['VersionIdsToStages']
    if token not in versions:
        logger.error("Access Id version %s has no stage for rotation of secret %s." % (token, arn))
        raise ValueError("Access Id version %s has no stage for rotation of secret %s." % (token, arn))
    if "AWSCURRENT" in versions[token]:
        logger.info("Access ID version %s already set as AWSCURRENT for secret %s." % (token, arn))
        return
    elif "AWSPENDING" not in versions[token]:
        logger.info("Access ID version %s not set as AWSPENDING for rotation of secret %s." % (token, arn))
        raise ValueError("Access ID version %s not set as AWSPENDING for rotation of secret %s." % (token, arn))
    
    aws_account_id = arn.split(":")[4]
    logger.info("AWS account id is %s" % aws_account_id)
    aws_account_name = "acloud-guru"
    logger.info("AWS account name is %s" % aws_account_name)
    resource_id = arn.split(":")[6]
    random_str = "-" + resource_id.replace(aws_account_name+"-", "").split('-')[-1]
    key_name = resource_id.replace(aws_account_name+"-", "").replace(random_str, "")
    logger.info("secretsManager key is %s" % key_name)
    secret_name = resource_id.replace(random_str, "").replace("-id", "")
    logger.info("secretsManager secret is %s" % secret_name)

    getsecarn = service_client.get_secret_value(SecretId=secret_name,VersionStage='AWSCURRENT')
    secret_arn = getsecarn['ARN']
    logger.info("secretsManager secret arn is %s" % secret_arn)
    
    if step == "createSecret":
        delete_key(iam, key_name, service_client, arn)
        create_key(iam, key_name, service_client, arn, secret_arn, token)
    elif step == 'setSecret':
        finish_secret(service_client, arn, secret_arn, token)
    elif step == "testSecret":
        pass
    elif step == "finishSecret":
        pass
    else:
        raise ValueError("Invalid Step parameter")
    
def get_account_alias(iam, aws_account_id):
    try:
        account_name = iam.list_account_aliases()['AccountAliases'][0]
        myAccountMap = {}
        if account_name in myAccountMap:
            return myAccountMap[account_name]
        else:
            return account_name
    except Exception as e:
        logger.error("Unknown error occured loading aws account alias")
        logger.exception(e)
        sys.exit(1)

def create_key(iam, key_name, service_client, arn, secret_arn, token):
    # Make sure the current secret exists
    service_client.get_secret_value(SecretId=arn, VersionStage='AWSCURRENT')

    # Now try to get the secret version
    try:
        service_client.get_secret_value(SecretId=arn, VersionId=token, VersionStage="AWSPENDING")
        logger.info("getSecret: Successfully retrieved secret for %s." % arn)
    except service_client.exceptions.ResourceNotFoundException:
        # Create new IAM credential
        IAM_User_Name = key_name.replace("-secret-access-key-id", "")
        logger.info("Iam user is %s" % IAM_User_Name )
        IAMKeyList=iam.list_access_keys(UserName=IAM_User_Name)
        number_keys = 0
        active_keys = []
        inactive_keys = []

        #oldest_key = min(IAMKeyList['AccessKeyMetadata], key=lambda x: x['CreateDate'])
        number_keys = len(IAMKeyList['AccessKeyMetadata'])
        #num_active = len([k for k in IamKeyList['AccessKeyMetadata'] if k['Status] == 'Active'])
        #num_inactive = len([k for k in IamKeyList['AccessKeyMetadata'] if k['Status] != 'Active'])

        if number_keys == 2:
            #2 skeys
            logger.info("Access key per User Exceeded.")
        else:
            response = iam.create_access_key(UserName=IAM_User_Name)
            AccessKey = response['AccessKey']['AccessKeyId']
            SecretKey = response['AccessKey']['SecretAccessKey']

            #put the secretid
            service_client.put_secret_value(SecretId=arn, ClientRequestToken=token, SecretString=AccessKey, VersionStages=['AWSPENDING'])
            logger.info("createSecret: Successfully put secret for ARN %s and version %s." %(arn, token))
            # Put the secret
            service_client.put_secret_value(SecretId=secret_arn, ClientRequestToken=token, SecretString=SecretKey, VersionStages=['AWSPENDING'])
            logger.info("createSecret: Successfully put secret for ARN %s." %(secret_arn))
    
    except ClientError as e:
        print (e)

def delete_key(iam, key_name, service_client, arn):
    # Every 45 days

    # Current SM credential => Age 45 || 200 days

    # if len(credentials) == 2:
    #    for n in credentials
    #        if n != Current:
    #           deactivate
    #           delete
    #           break

    # generate new credentials => age 0
    # update SM

    try:
        GetStr = service_client.get_secret_value(SecretId=arn)
        SecAccessID = GetStr['SecretString']
        logger.info("Secret Manager has: %s" % SecAccessID)
        IAM__User_Name = key_name.replace("-secret-access-key-id", "")

        IamKeyList = iam.list_access_keys(UserName=IAM__User_Name)
        if len(IamKeyList['AccessKeyMetadata']) >= 2:

            for access_key_metadata in IamKeyList['AccessKeyMetadata']:

                accesskeyid = access_key_metadata['AccessKeyId']
                logger.info("Compare Secret ID: %s and Access ID: %s" %(SecAccessID, accesskeyid))
                if accesskeyid != SecAccessID:

                    keystatus = access_key_metadata['Status']
                    if keystatus != "Inactive":
                        iam.update_access_key(AccesKeyId=accesskeyid, Status='Inactive', UserName=IAM__User_Name)
                        logger.info("Set %s to Inactive: %s." % accesskeyid)
                    
                    iam.delete_access_key(AccessKeyId=accesskeyid, UserName=IAM__User_Name)
                    logger.info("Delete Access ID %s." % accesskeyid)

                    break

    except ClientError as e:
        print (e)


def finish_secret(service_client, arn, secret_arn, token):
    metadata = service_client.describe_secret(SecretId=arn)
    key_pending_version = None
    for version in metadata["VersionIdsToStages"]:
        if "AWSCURRENT" in metadata["VersionIdsToStages"][version]:
            if version == token:
                # The correct version is already marked as current, return
                logger.info("finishSecret: Version %s already marked as AWSCURRENT for %s" % (version, arn))
                return
            key_pending_version = version
            logger.info("finishsecret: Set Pending Key Version to %s" % (key_pending_version))
            break
    
    secret_pending_version = None
    secret_metadata = service_client.describe_secret(SecretId=secret_arn)
    for secret_version in secret_metadata["VersionIdsToStages"]:
        if "AWSCURRENT" in secret_metadata["VersionIdsToStages"][secret_version]:
            if secret_version == token:
                # The correct version is already marked as current, return
                logger.info("finishSecret: Version %s already marked as AWSCURRENT for %s" % (secret_version, arn))
                return
            secret_pending_version = secret_version
            logger.info("finishsecret: Set Pending secret Version to %s" % (secret_pending_version))
            break

    # Finalize by staging the secret version current
    service_client.update_secret_version_stage(SecretId=arn, VersionStage="AWSCURRENT", MoveToVersionId=token, RemoveFromVersionId=key_pending_version)
    logger.info("finishSecret: Successfully set AWSCURRENT stage to version %s for secret %s." % (token, arn))
    # Finalize by staging the secret version to current
    service_client.update_secret_version_stage(SecretId=secret_arn, VersionStage="AWSCURRENT", MoveToVersionId=token, RemoveFromVersionId=secret_pending_version)
    logger.info("finishSecret: Successfully set AWSCURRENT stage to version %s for secret %s." % (token, secret_arn))
============================
import boto3
iam = boto3.client('iam', region_name='us-west-2',aws_access_key_id='*****************',
                            aws_secret_access_key='**********************')
import logging
account_name = iam.list_account_aliases()
print (f'account_name: {account_name}')
logger = logging.getLogger()
logger.setLevel(logging.INFO)
service_client = boto3.client('secretsmanager', region_name='us-west-2',aws_access_key_id='AKIA2MKN3YXJ5VPKHNHP',
                            aws_secret_access_key='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')
metadata = service_client.describe_secret(SecretId='arn:aws:secretsmanager:us-west-2:713664742867:secret:acloud-guru-eks-da-user-secret-access-key-id-kMtFNd')
print(metadata['VersionIdsToStages'])
token = '08B4AE8D-A772-44E1-BE6D-DE19C54E7403'
arn = 'arn:aws:secretsmanager:us-west-2:713664742867:secret:acloud-guru-eks-da-user-secret-access-key-id-kMtFNd'
versions = metadata['VersionIdsToStages']
aws_account_id = arn.split(":")[4]
resource_id = arn.split(":")[6]
aws_account_name = 'acloud-guru'
random_str = "-" + resource_id.replace(aws_account_name+"-", "").split('-')[-1]
print(random_str)
key_name = resource_id.replace(aws_account_name+"-", "").replace(random_str, "")
print(key_name)
logger.info("secretsManager key is %s" % key_name)
secret_name = resource_id.replace(random_str, "").replace("-id", "")
print(secret_name)

logger.info("secretsManager secret is %s" % secret_name)
