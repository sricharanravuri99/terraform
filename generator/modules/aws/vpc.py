from ..base import TerraformModule, ModuleSpec, GeneratedFile
from typing import List


class AWSVPCModule(TerraformModule):
    MODULE_TYPE = "vpc"
    PROVIDER = "aws"
    DESCRIPTION = "AWS VPC with public/private/database subnets, NAT gateway, and VPC Flow Logs (CIS 3.9)"
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
        enable_flow_logs = self.config.get("enable_flow_logs", True)
        enable_nat = self.config.get("enable_nat_gateway", True)

        flow_logs_section = ""
        if enable_flow_logs:
            flow_logs_section = '''
# ─── VPC Flow Logs (CIS-AWS-3.9) ─────────────────────────────────────────────

resource "aws_cloudwatch_log_group" "flow_log" {
  name              = "/aws/vpc/${var.name}/flow-logs"
  retention_in_days = var.flow_log_retention_days
  kms_key_id        = var.kms_key_arn

  tags = var.tags
}

resource "aws_iam_role" "flow_log" {
  name = "${var.name}-vpc-flow-log-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "vpc-flow-logs.amazonaws.com" }
    }]
  })

  tags = var.tags
}

resource "aws_iam_role_policy" "flow_log" {
  name = "${var.name}-vpc-flow-log-policy"
  role = aws_iam_role.flow_log.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams",
      ]
      Resource = "*"
    }]
  })
}

resource "aws_flow_log" "this" {
  iam_role_arn    = aws_iam_role.flow_log.arn
  log_destination = aws_cloudwatch_log_group.flow_log.arn
  traffic_type    = "ALL"
  vpc_id          = aws_vpc.this.id

  tags = merge(var.tags, { Name = "${var.name}-flow-log" })
}
'''

        nat_section = ""
        if enable_nat:
            nat_section = '''
# ─── NAT Gateway (one per AZ for HA) ─────────────────────────────────────────

resource "aws_eip" "nat" {
  count  = length(var.availability_zones)
  domain = "vpc"

  tags = merge(var.tags, { Name = "${var.name}-nat-eip-${count.index}" })

  depends_on = [aws_internet_gateway.this]
}

resource "aws_nat_gateway" "this" {
  count = length(var.availability_zones)

  allocation_id = aws_eip.nat[count.index].id
  subnet_id     = aws_subnet.public[count.index].id

  tags = merge(var.tags, { Name = "${var.name}-nat-${var.availability_zones[count.index]}" })

  depends_on = [aws_internet_gateway.this]
}
'''

        nat_route = "nat_gateway_id = aws_nat_gateway.this[count.index].id" if enable_nat else ""
        nat_route_block = f'''
  dynamic "route" {{
    for_each = var.enable_nat_gateway ? [1] : []
    content {{
      cidr_block     = "0.0.0.0/0"
      {nat_route}
    }}
  }}
''' if enable_nat else ""

        return f'''\
# ─── VPC ─────────────────────────────────────────────────────────────────────

resource "aws_vpc" "this" {{
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = merge(var.tags, {{ Name = var.name }})
}}

resource "aws_internet_gateway" "this" {{
  vpc_id = aws_vpc.this.id

  tags = merge(var.tags, {{ Name = "${{var.name}}-igw" }})
}}

# ─── Subnets ──────────────────────────────────────────────────────────────────

resource "aws_subnet" "public" {{
  count = length(var.public_subnet_cidrs)

  vpc_id                  = aws_vpc.this.id
  cidr_block              = var.public_subnet_cidrs[count.index]
  availability_zone       = var.availability_zones[count.index]
  map_public_ip_on_launch = false

  tags = merge(var.tags, {{
    Name = "${{var.name}}-public-${{var.availability_zones[count.index]}}"
    Tier = "public"
  }})
}}

resource "aws_subnet" "private" {{
  count = length(var.private_subnet_cidrs)

  vpc_id            = aws_vpc.this.id
  cidr_block        = var.private_subnet_cidrs[count.index]
  availability_zone = var.availability_zones[count.index]

  tags = merge(var.tags, {{
    Name = "${{var.name}}-private-${{var.availability_zones[count.index]}}"
    Tier = "private"
  }})
}}

resource "aws_subnet" "database" {{
  count = length(var.database_subnet_cidrs)

  vpc_id            = aws_vpc.this.id
  cidr_block        = var.database_subnet_cidrs[count.index]
  availability_zone = var.availability_zones[count.index]

  tags = merge(var.tags, {{
    Name = "${{var.name}}-database-${{var.availability_zones[count.index]}}"
    Tier = "database"
  }})
}}
{nat_section}
# ─── Route Tables ─────────────────────────────────────────────────────────────

resource "aws_route_table" "public" {{
  vpc_id = aws_vpc.this.id

  route {{
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.this.id
  }}

  tags = merge(var.tags, {{ Name = "${{var.name}}-public-rt" }})
}}

resource "aws_route_table" "private" {{
  count  = length(var.availability_zones)
  vpc_id = aws_vpc.this.id
{nat_route_block}
  tags = merge(var.tags, {{ Name = "${{var.name}}-private-rt-${{var.availability_zones[count.index]}}" }})
}}

resource "aws_route_table" "database" {{
  vpc_id = aws_vpc.this.id

  tags = merge(var.tags, {{ Name = "${{var.name}}-database-rt" }})
}}

resource "aws_route_table_association" "public" {{
  count          = length(var.public_subnet_cidrs)
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}}

resource "aws_route_table_association" "private" {{
  count          = length(var.private_subnet_cidrs)
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private[count.index].id
}}

resource "aws_route_table_association" "database" {{
  count          = length(var.database_subnet_cidrs)
  subnet_id      = aws_subnet.database[count.index].id
  route_table_id = aws_route_table.database.id
}}

# ─── Default Security Group (locked down) ────────────────────────────────────
# Removes all default ingress/egress rules per CIS-AWS-5.4

resource "aws_default_security_group" "this" {{
  vpc_id = aws_vpc.this.id

  tags = merge(var.tags, {{ Name = "${{var.name}}-default-sg-locked" }})
}}
{flow_logs_section}'''

    def generate_variables(self) -> str:
        return '''\
variable "name" {
  type        = string
  description = "Name prefix applied to all resources."
}

variable "vpc_cidr" {
  type        = string
  description = "CIDR block for the VPC."
  default     = "10.0.0.0/16"
}

variable "availability_zones" {
  type        = list(string)
  description = "List of availability zones for subnet distribution."
}

variable "public_subnet_cidrs" {
  type        = list(string)
  description = "CIDR blocks for public subnets (one per AZ)."
  default     = []
}

variable "private_subnet_cidrs" {
  type        = list(string)
  description = "CIDR blocks for private subnets (one per AZ)."
  default     = []
}

variable "database_subnet_cidrs" {
  type        = list(string)
  description = "CIDR blocks for database subnets (one per AZ)."
  default     = []
}

variable "enable_nat_gateway" {
  type        = bool
  description = "Deploy a NAT gateway per AZ for private subnet internet access."
  default     = true
}

variable "enable_flow_logs" {
  type        = bool
  description = "Enable VPC Flow Logs (required by CIS-AWS-3.9)."
  default     = true
}

variable "flow_log_retention_days" {
  type        = number
  description = "Retention period in days for VPC Flow Logs CloudWatch log group."
  default     = 365
}

variable "kms_key_arn" {
  type        = string
  description = "KMS key ARN for encrypting VPC flow log CloudWatch log group."
  default     = null
}

variable "tags" {
  type        = map(string)
  description = "Tags applied to all resources."
  default     = {}
}
'''

    def generate_outputs(self) -> str:
        return '''\
output "vpc_id" {
  description = "ID of the created VPC."
  value       = aws_vpc.this.id
}

output "vpc_cidr" {
  description = "CIDR block of the VPC."
  value       = aws_vpc.this.cidr_block
}

output "public_subnet_ids" {
  description = "List of public subnet IDs."
  value       = aws_subnet.public[*].id
}

output "private_subnet_ids" {
  description = "List of private subnet IDs."
  value       = aws_subnet.private[*].id
}

output "database_subnet_ids" {
  description = "List of database subnet IDs."
  value       = aws_subnet.database[*].id
}

output "internet_gateway_id" {
  description = "ID of the Internet Gateway."
  value       = aws_internet_gateway.this.id
}

output "nat_gateway_ids" {
  description = "List of NAT Gateway IDs."
  value       = try(aws_nat_gateway.this[*].id, [])
}

output "private_route_table_ids" {
  description = "List of private route table IDs."
  value       = aws_route_table.private[*].id
}
'''

    def generate_tfvars_example(self) -> str:
        name = self.config.get("name", self.name)
        return f'''\
name               = "{name}"
vpc_cidr           = "{self.config.get('vpc_cidr', '10.0.0.0/16')}"
availability_zones = ["us-east-1a", "us-east-1b", "us-east-1c"]

public_subnet_cidrs   = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
private_subnet_cidrs  = ["10.0.11.0/24", "10.0.12.0/24", "10.0.13.0/24"]
database_subnet_cidrs = ["10.0.21.0/24", "10.0.22.0/24", "10.0.23.0/24"]

enable_nat_gateway      = true
enable_flow_logs        = true
flow_log_retention_days = 365
# kms_key_arn           = "arn:aws:kms:us-east-1:123456789012:key/..."

tags = {{
  Environment = "production"
  Project     = "my-project"
  Owner       = "platform-team"
  CostCenter  = "eng-001"
}}
'''
