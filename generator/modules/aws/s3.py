from ..base import TerraformModule


class AWSS3Module(TerraformModule):
    MODULE_TYPE = "s3"
    PROVIDER = "aws"
    DESCRIPTION = "AWS S3 bucket with encryption, versioning, access logging, and HTTPS enforcement"
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
# ─── S3 Bucket ───────────────────────────────────────────────────────────────

resource "aws_s3_bucket" "this" {
  bucket        = var.bucket_name
  force_destroy = var.force_destroy

  tags = merge(var.tags, { Name = var.bucket_name })
}

# Block all public access (CIS-AWS-2.1.5)
resource "aws_s3_bucket_public_access_block" "this" {
  bucket = aws_s3_bucket.this.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Server-side encryption (CIS-AWS-2.1.1)
resource "aws_s3_bucket_server_side_encryption_configuration" "this" {
  bucket = aws_s3_bucket.this.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = var.kms_key_arn != null ? "aws:kms" : "AES256"
      kms_master_key_id = var.kms_key_arn
    }
    bucket_key_enabled = var.kms_key_arn != null
  }
}

# Versioning (CIS-AWS-2.1.3)
resource "aws_s3_bucket_versioning" "this" {
  bucket = aws_s3_bucket.this.id

  versioning_configuration {
    status = var.versioning_enabled ? "Enabled" : "Suspended"
  }
}

# Access logging (CIS-AWS-2.1.2)
resource "aws_s3_bucket_logging" "this" {
  count = var.access_logging_enabled ? 1 : 0

  bucket        = aws_s3_bucket.this.id
  target_bucket = var.logging_target_bucket != null ? var.logging_target_bucket : aws_s3_bucket.this.id
  target_prefix = "access-logs/${var.bucket_name}/"
}

# Enforce HTTPS only (CIS-AWS-2.1.4)
resource "aws_s3_bucket_policy" "this" {
  bucket = aws_s3_bucket.this.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyHTTP"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.this.arn,
          "${aws_s3_bucket.this.arn}/*",
        ]
        Condition = {
          Bool = { "aws:SecureTransport" = "false" }
        }
      },
    ]
  })

  depends_on = [aws_s3_bucket_public_access_block.this]
}

# Lifecycle rules for cost management
resource "aws_s3_bucket_lifecycle_configuration" "this" {
  count = length(var.lifecycle_rules) > 0 ? 1 : 0

  bucket = aws_s3_bucket.this.id

  dynamic "rule" {
    for_each = var.lifecycle_rules
    content {
      id     = rule.value.id
      status = "Enabled"

      dynamic "transition" {
        for_each = lookup(rule.value, "transitions", [])
        content {
          days          = transition.value.days
          storage_class = transition.value.storage_class
        }
      }

      dynamic "expiration" {
        for_each = lookup(rule.value, "expiration_days", null) != null ? [1] : []
        content {
          days = rule.value.expiration_days
        }
      }

      dynamic "noncurrent_version_expiration" {
        for_each = lookup(rule.value, "noncurrent_version_expiration_days", null) != null ? [1] : []
        content {
          noncurrent_days = rule.value.noncurrent_version_expiration_days
        }
      }
    }
  }
}

# Object Lock (for compliance/WORM requirements)
resource "aws_s3_bucket_object_lock_configuration" "this" {
  count = var.object_lock_enabled ? 1 : 0

  bucket = aws_s3_bucket.this.id

  rule {
    default_retention {
      mode = var.object_lock_mode
      days = var.object_lock_days
    }
  }
}
'''

    def generate_variables(self) -> str:
        return '''\
variable "bucket_name" {
  type        = string
  description = "Name of the S3 bucket. Must be globally unique."
}

variable "kms_key_arn" {
  type        = string
  description = "KMS key ARN for SSE-KMS encryption. If null, SSE-S3 (AES256) is used."
  default     = null
}

variable "versioning_enabled" {
  type        = bool
  description = "Enable S3 versioning (required by CIS-AWS-2.1.3)."
  default     = true
}

variable "access_logging_enabled" {
  type        = bool
  description = "Enable S3 server access logging (required by CIS-AWS-2.1.2)."
  default     = true
}

variable "logging_target_bucket" {
  type        = string
  description = "Bucket to store access logs. If null, logs to the same bucket."
  default     = null
}

variable "force_destroy" {
  type        = bool
  description = "Allow bucket deletion even when it contains objects. Set false in production."
  default     = false
}

variable "lifecycle_rules" {
  type = list(object({
    id                                = string
    transitions                       = optional(list(object({ days = number, storage_class = string })), [])
    expiration_days                   = optional(number)
    noncurrent_version_expiration_days = optional(number)
  }))
  description = "Lifecycle rules for object tiering and expiration."
  default     = []
}

variable "object_lock_enabled" {
  type        = bool
  description = "Enable S3 Object Lock (WORM). Requires versioning enabled."
  default     = false
}

variable "object_lock_mode" {
  type        = string
  description = "Object lock retention mode: COMPLIANCE or GOVERNANCE."
  default     = "GOVERNANCE"
  validation {
    condition     = contains(["COMPLIANCE", "GOVERNANCE"], var.object_lock_mode)
    error_message = "object_lock_mode must be COMPLIANCE or GOVERNANCE."
  }
}

variable "object_lock_days" {
  type        = number
  description = "Default object lock retention period in days."
  default     = 30
}

variable "tags" {
  type        = map(string)
  description = "Tags applied to all resources."
  default     = {}
}
'''

    def generate_outputs(self) -> str:
        return '''\
output "bucket_id" {
  description = "Name of the S3 bucket."
  value       = aws_s3_bucket.this.id
}

output "bucket_arn" {
  description = "ARN of the S3 bucket."
  value       = aws_s3_bucket.this.arn
}

output "bucket_domain_name" {
  description = "Bucket domain name."
  value       = aws_s3_bucket.this.bucket_domain_name
}

output "bucket_regional_domain_name" {
  description = "Regional domain name of the bucket."
  value       = aws_s3_bucket.this.bucket_regional_domain_name
}
'''

    def generate_tfvars_example(self) -> str:
        return f'''\
bucket_name            = "{self.config.get('bucket_name', self.name + '-data')}"
versioning_enabled     = true
access_logging_enabled = true
# kms_key_arn          = "arn:aws:kms:us-east-1:123456789012:key/..."

lifecycle_rules = [
  {{
    id = "transition-to-ia"
    transitions = [
      {{ days = 30,  storage_class = "STANDARD_IA" }},
      {{ days = 90,  storage_class = "GLACIER" }},
      {{ days = 365, storage_class = "DEEP_ARCHIVE" }},
    ]
    noncurrent_version_expiration_days = 90
  }}
]

tags = {{
  Environment = "production"
  Project     = "my-project"
  Owner       = "platform-team"
  CostCenter  = "eng-001"
}}
'''
