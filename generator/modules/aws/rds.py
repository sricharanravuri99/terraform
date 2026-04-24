from ..base import TerraformModule


class AWSRDSModule(TerraformModule):
    MODULE_TYPE = "rds"
    PROVIDER = "aws"
    DESCRIPTION = "AWS RDS instance with encryption, Multi-AZ, automated backups, and deletion protection"
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
# ─── DB Subnet Group ─────────────────────────────────────────────────────────

resource "aws_db_subnet_group" "this" {
  name        = "${var.name}-subnet-group"
  description = "Subnet group for ${var.name} RDS instance"
  subnet_ids  = var.subnet_ids

  tags = merge(var.tags, { Name = "${var.name}-subnet-group" })
}

# ─── Security Group ───────────────────────────────────────────────────────────

resource "aws_security_group" "this" {
  name        = "${var.name}-rds-sg"
  description = "Security group for ${var.name} RDS - no direct internet access"
  vpc_id      = var.vpc_id

  dynamic "ingress" {
    for_each = var.allowed_security_group_ids
    content {
      from_port       = var.db_port
      to_port         = var.db_port
      protocol        = "tcp"
      security_groups = [ingress.value]
      description     = "DB access from application security group"
    }
  }

  dynamic "ingress" {
    for_each = length(var.allowed_cidr_blocks) > 0 ? [1] : []
    content {
      from_port   = var.db_port
      to_port     = var.db_port
      protocol    = "tcp"
      cidr_blocks = var.allowed_cidr_blocks
      description = "DB access from allowed CIDRs"
    }
  }

  tags = merge(var.tags, { Name = "${var.name}-rds-sg" })
}

# ─── Parameter Group ──────────────────────────────────────────────────────────

resource "aws_db_parameter_group" "this" {
  name        = "${var.name}-params"
  family      = var.parameter_group_family
  description = "Parameter group for ${var.name}"

  dynamic "parameter" {
    for_each = var.db_parameters
    content {
      name         = parameter.value.name
      value        = parameter.value.value
      apply_method = lookup(parameter.value, "apply_method", "pending-reboot")
    }
  }

  tags = merge(var.tags, { Name = "${var.name}-params" })

  lifecycle {
    create_before_destroy = true
  }
}

# ─── RDS Instance ─────────────────────────────────────────────────────────────

resource "aws_db_instance" "this" {
  identifier = var.name

  engine         = var.engine
  engine_version = var.engine_version
  instance_class = var.instance_class

  db_name  = var.database_name
  username = var.master_username
  password = var.master_password

  db_subnet_group_name   = aws_db_subnet_group.this.name
  vpc_security_group_ids = [aws_security_group.this.id]
  parameter_group_name   = aws_db_parameter_group.this.name
  port                   = var.db_port

  # Storage
  allocated_storage     = var.allocated_storage
  max_allocated_storage = var.max_allocated_storage
  storage_type          = var.storage_type

  # Encryption at rest (CIS-AWS-2.3.1)
  storage_encrypted = true
  kms_key_id        = var.kms_key_arn

  # Network security (CIS-AWS-2.3.2)
  publicly_accessible = false

  # High availability
  multi_az = var.multi_az

  # Backups (CIS-AWS-2.3.3)
  backup_retention_period   = var.backup_retention_days
  backup_window             = var.backup_window
  copy_tags_to_snapshot     = true
  skip_final_snapshot       = false
  final_snapshot_identifier = "${var.name}-final-snapshot"

  # Maintenance
  maintenance_window          = var.maintenance_window
  auto_minor_version_upgrade  = var.auto_minor_version_upgrade
  allow_major_version_upgrade = false

  # Monitoring
  monitoring_interval = var.monitoring_interval
  monitoring_role_arn = var.monitoring_interval > 0 ? aws_iam_role.enhanced_monitoring[0].arn : null

  performance_insights_enabled          = var.performance_insights_enabled
  performance_insights_retention_period = var.performance_insights_enabled ? var.performance_insights_retention_period : null
  performance_insights_kms_key_id       = var.performance_insights_enabled ? var.kms_key_arn : null

  enabled_cloudwatch_logs_exports = var.cloudwatch_logs_exports

  # Protection
  deletion_protection = var.deletion_protection

  apply_immediately = false

  tags = merge(var.tags, { Name = var.name })
}

# ─── Enhanced Monitoring IAM Role ─────────────────────────────────────────────

resource "aws_iam_role" "enhanced_monitoring" {
  count = var.monitoring_interval > 0 ? 1 : 0

  name = "${var.name}-rds-monitoring-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "monitoring.rds.amazonaws.com" }
    }]
  })

  tags = var.tags
}

resource "aws_iam_role_policy_attachment" "enhanced_monitoring" {
  count = var.monitoring_interval > 0 ? 1 : 0

  role       = aws_iam_role.enhanced_monitoring[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole"
}
'''

    def generate_variables(self) -> str:
        engine = self.config.get("engine", "postgres")
        engine_version = self.config.get("engine_version", "15.4")
        family = f"{engine}{engine_version.split('.')[0]}"
        port = 5432 if "postgres" in engine else 3306

        return f'''\
variable "name" {{
  type        = string
  description = "Name identifier for the RDS instance and related resources."
}}

variable "engine" {{
  type        = string
  description = "Database engine (postgres, mysql, mariadb, etc.)."
  default     = "{engine}"
}}

variable "engine_version" {{
  type        = string
  description = "Database engine version."
  default     = "{engine_version}"
}}

variable "instance_class" {{
  type        = string
  description = "RDS instance type."
  default     = "db.t3.medium"
}}

variable "database_name" {{
  type        = string
  description = "Name of the initial database."
}}

variable "master_username" {{
  type        = string
  description = "Master username for the database."
  sensitive   = true
}}

variable "master_password" {{
  type        = string
  description = "Master password for the database. Use AWS Secrets Manager in production."
  sensitive   = true
}}

variable "parameter_group_family" {{
  type        = string
  description = "DB parameter group family (e.g. postgres15, mysql8.0)."
  default     = "{family}"
}}

variable "db_port" {{
  type        = number
  description = "Port the database listens on."
  default     = {port}
}}

variable "vpc_id" {{
  type        = string
  description = "VPC ID for the security group."
}}

variable "subnet_ids" {{
  type        = list(string)
  description = "List of subnet IDs for the DB subnet group. Use database-tier subnets."
}}

variable "allowed_security_group_ids" {{
  type        = list(string)
  description = "Security group IDs allowed to connect to the database."
  default     = []
}}

variable "allowed_cidr_blocks" {{
  type        = list(string)
  description = "CIDR blocks allowed to connect (only use for VPN/peered network access)."
  default     = []
}}

variable "kms_key_arn" {{
  type        = string
  description = "KMS key ARN for storage and performance insights encryption."
  default     = null
}}

variable "allocated_storage" {{
  type        = number
  description = "Initial allocated storage in GiB."
  default     = 100
}}

variable "max_allocated_storage" {{
  type        = number
  description = "Maximum storage for autoscaling (0 to disable)."
  default     = 1000
}}

variable "storage_type" {{
  type        = string
  description = "Storage type (gp3, gp2, io1)."
  default     = "gp3"
}}

variable "multi_az" {{
  type        = bool
  description = "Enable Multi-AZ deployment for high availability."
  default     = true
}}

variable "backup_retention_days" {{
  type        = number
  description = "Number of days to retain automated backups (CIS-AWS-2.3.3 requires >= 7)."
  default     = 14
}}

variable "backup_window" {{
  type        = string
  description = "Preferred backup window (UTC), e.g. 03:00-04:00."
  default     = "03:00-04:00"
}}

variable "maintenance_window" {{
  type        = string
  description = "Preferred maintenance window."
  default     = "sun:05:00-sun:06:00"
}}

variable "auto_minor_version_upgrade" {{
  type        = bool
  description = "Automatically apply minor engine version upgrades."
  default     = true
}}

variable "monitoring_interval" {{
  type        = number
  description = "Enhanced monitoring interval in seconds (0 to disable, 60 recommended)."
  default     = 60
}}

variable "performance_insights_enabled" {{
  type        = bool
  description = "Enable Performance Insights for query-level monitoring."
  default     = true
}}

variable "performance_insights_retention_period" {{
  type        = number
  description = "Performance Insights data retention in days (7 or 731)."
  default     = 7
}}

variable "cloudwatch_logs_exports" {{
  type        = list(string)
  description = "List of log types to export to CloudWatch."
  default     = ["postgresql", "upgrade"]
}}

variable "deletion_protection" {{
  type        = bool
  description = "Prevent accidental database deletion."
  default     = true
}}

variable "db_parameters" {{
  type = list(object({{
    name         = string
    value        = string
    apply_method = optional(string, "pending-reboot")
  }}))
  description = "Database engine parameter overrides."
  default     = []
}}

variable "tags" {{
  type        = map(string)
  description = "Tags applied to all resources."
  default     = {{}}
}}
'''

    def generate_outputs(self) -> str:
        return '''\
output "db_instance_id" {
  description = "RDS instance identifier."
  value       = aws_db_instance.this.id
}

output "db_instance_arn" {
  description = "ARN of the RDS instance."
  value       = aws_db_instance.this.arn
}

output "db_endpoint" {
  description = "Connection endpoint (host:port)."
  value       = aws_db_instance.this.endpoint
}

output "db_host" {
  description = "Database hostname."
  value       = aws_db_instance.this.address
}

output "db_port" {
  description = "Database port."
  value       = aws_db_instance.this.port
}

output "db_name" {
  description = "Database name."
  value       = aws_db_instance.this.db_name
}

output "security_group_id" {
  description = "ID of the RDS security group."
  value       = aws_security_group.this.id
}

output "subnet_group_id" {
  description = "ID of the DB subnet group."
  value       = aws_db_subnet_group.this.id
}
'''

    def generate_tfvars_example(self) -> str:
        engine = self.config.get("engine", "postgres")
        return f'''\
name          = "{self.config.get('name', self.name)}"
engine        = "{engine}"
engine_version = "{self.config.get('engine_version', '15.4')}"
instance_class = "{self.config.get('instance_class', 'db.t3.medium')}"

database_name   = "appdb"
master_username = "dbadmin"
master_password = "REPLACE_WITH_SECRET_MANAGER_REF"

vpc_id     = "vpc-xxxxxxxxxxxxxxxxx"
subnet_ids = ["subnet-xxxxxxxxxxxxxxxxx", "subnet-yyyyyyyyyyyyyyyyy"]

allowed_security_group_ids = ["sg-xxxxxxxxxxxxxxxxx"]

multi_az              = true
backup_retention_days = 14
deletion_protection   = true
monitoring_interval   = 60

# kms_key_arn = "arn:aws:kms:us-east-1:123456789012:key/..."

tags = {{
  Environment = "production"
  Project     = "my-project"
  Owner       = "platform-team"
  CostCenter  = "eng-001"
}}
'''
