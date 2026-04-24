from ..base import TerraformModule


class AWSIAMModule(TerraformModule):
    MODULE_TYPE = "iam"
    PROVIDER = "aws"
    DESCRIPTION = "AWS IAM role with least-privilege inline policy, permission boundary, and optional MFA condition"
    PROVIDER_VERSION = "~> 5.0"

    def generate_versions(self) -> str:
        return '''\
terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}
'''

    def generate_main(self) -> str:
        return '''\
# ─── IAM Role ─────────────────────────────────────────────────────────────────

data "aws_iam_policy_document" "assume_role" {
  dynamic "statement" {
    for_each = var.trust_services
    content {
      actions = ["sts:AssumeRole"]
      effect  = "Allow"
      principals {
        type        = "Service"
        identifiers = [statement.value]
      }
    }
  }

  dynamic "statement" {
    for_each = length(var.trust_account_ids) > 0 ? [1] : []
    content {
      actions = ["sts:AssumeRole"]
      effect  = "Allow"
      principals {
        type        = "AWS"
        identifiers = [for id in var.trust_account_ids : "arn:aws:iam::${id}:root"]
      }

      dynamic "condition" {
        for_each = var.require_mfa ? [1] : []
        content {
          test     = "Bool"
          variable = "aws:MultiFactorAuthPresent"
          values   = ["true"]
        }
      }
    }
  }
}

resource "aws_iam_role" "this" {
  name                  = var.role_name
  description           = var.role_description
  path                  = var.role_path
  max_session_duration  = var.max_session_duration
  permissions_boundary  = var.permissions_boundary_arn
  assume_role_policy    = data.aws_iam_policy_document.assume_role.json

  tags = var.tags
}

# ─── Inline Policy ────────────────────────────────────────────────────────────

data "aws_iam_policy_document" "inline" {
  dynamic "statement" {
    for_each = var.policy_statements
    content {
      sid       = lookup(statement.value, "sid", null)
      effect    = lookup(statement.value, "effect", "Allow")
      actions   = statement.value.actions
      resources = statement.value.resources

      dynamic "condition" {
        for_each = lookup(statement.value, "conditions", [])
        content {
          test     = condition.value.test
          variable = condition.value.variable
          values   = condition.value.values
        }
      }
    }
  }
}

resource "aws_iam_role_policy" "inline" {
  count = length(var.policy_statements) > 0 ? 1 : 0

  name   = "${var.role_name}-inline-policy"
  role   = aws_iam_role.this.id
  policy = data.aws_iam_policy_document.inline.json
}

# ─── Managed Policy Attachments ───────────────────────────────────────────────

resource "aws_iam_role_policy_attachment" "managed" {
  for_each = toset(var.managed_policy_arns)

  role       = aws_iam_role.this.name
  policy_arn = each.value
}

# ─── Instance Profile (optional) ──────────────────────────────────────────────

resource "aws_iam_instance_profile" "this" {
  count = var.create_instance_profile ? 1 : 0

  name = "${var.role_name}-profile"
  role = aws_iam_role.this.name

  tags = var.tags
}
'''

    def generate_variables(self) -> str:
        return '''\
variable "role_name" {
  type        = string
  description = "Name of the IAM role."
}

variable "role_description" {
  type        = string
  description = "Description of the IAM role."
  default     = ""
}

variable "role_path" {
  type        = string
  description = "IAM role path for organizing roles."
  default     = "/"
}

variable "max_session_duration" {
  type        = number
  description = "Maximum CLI/API session duration in seconds (900-43200)."
  default     = 3600
}

variable "permissions_boundary_arn" {
  type        = string
  description = "ARN of the permissions boundary policy. Recommended for least-privilege enforcement."
  default     = null
}

variable "trust_services" {
  type        = list(string)
  description = "AWS service principals allowed to assume this role (e.g. ec2.amazonaws.com)."
  default     = []
}

variable "trust_account_ids" {
  type        = list(string)
  description = "AWS account IDs allowed to assume this role (cross-account access)."
  default     = []
}

variable "require_mfa" {
  type        = bool
  description = "Require MFA for cross-account role assumption (applied to account trust)."
  default     = false
}

variable "policy_statements" {
  type = list(object({
    sid       = optional(string)
    effect    = optional(string, "Allow")
    actions   = list(string)
    resources = list(string)
    conditions = optional(list(object({
      test     = string
      variable = string
      values   = list(string)
    })), [])
  }))
  description = "Inline policy statements. Follow least-privilege: specify exact actions and resource ARNs."
  default     = []
}

variable "managed_policy_arns" {
  type        = list(string)
  description = "List of managed policy ARNs to attach. Avoid AdministratorAccess."
  default     = []
}

variable "create_instance_profile" {
  type        = bool
  description = "Create an EC2 instance profile backed by this role."
  default     = false
}

variable "tags" {
  type        = map(string)
  description = "Tags applied to all resources."
  default     = {}
}
'''

    def generate_outputs(self) -> str:
        return '''\
output "role_arn" {
  description = "ARN of the IAM role."
  value       = aws_iam_role.this.arn
}

output "role_name" {
  description = "Name of the IAM role."
  value       = aws_iam_role.this.name
}

output "role_id" {
  description = "Unique ID of the IAM role."
  value       = aws_iam_role.this.unique_id
}

output "instance_profile_arn" {
  description = "ARN of the instance profile (if created)."
  value       = try(aws_iam_instance_profile.this[0].arn, null)
}

output "instance_profile_name" {
  description = "Name of the instance profile (if created)."
  value       = try(aws_iam_instance_profile.this[0].name, null)
}
'''

    def generate_tfvars_example(self) -> str:
        return f'''\
role_name        = "{self.config.get('role_name', self.name + '-role')}"
role_description = "Application role for {self.name}"
trust_services   = ["ec2.amazonaws.com"]

policy_statements = [
  {{
    sid       = "S3ReadAccess"
    effect    = "Allow"
    actions   = ["s3:GetObject", "s3:ListBucket"]
    resources = [
      "arn:aws:s3:::my-app-bucket",
      "arn:aws:s3:::my-app-bucket/*"
    ]
  }},
  {{
    sid       = "SecretsManagerRead"
    effect    = "Allow"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = ["arn:aws:secretsmanager:us-east-1:123456789012:secret:my-app/*"]
  }},
]

create_instance_profile = true

tags = {{
  Environment = "production"
  Project     = "my-project"
  Owner       = "platform-team"
  CostCenter  = "eng-001"
}}
'''
