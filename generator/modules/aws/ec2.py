from ..base import TerraformModule


class AWSEC2Module(TerraformModule):
    MODULE_TYPE = "ec2"
    PROVIDER = "aws"
    DESCRIPTION = "AWS EC2 instance with IMDSv2, encrypted EBS, and hardened security group"
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
# ─── Security Group ───────────────────────────────────────────────────────────

resource "aws_security_group" "this" {
  name        = "${var.name}-sg"
  description = "Security group for ${var.name}"
  vpc_id      = var.vpc_id

  dynamic "ingress" {
    for_each = var.ingress_rules
    content {
      from_port   = ingress.value.from_port
      to_port     = ingress.value.to_port
      protocol    = ingress.value.protocol
      cidr_blocks = ingress.value.cidr_blocks
      description = ingress.value.description
    }
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow all outbound traffic"
  }

  tags = merge(var.tags, { Name = "${var.name}-sg" })
}

# ─── IAM Role for SSM Session Manager (replaces SSH) ─────────────────────────

resource "aws_iam_role" "this" {
  name = "${var.name}-instance-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })

  tags = var.tags
}

resource "aws_iam_role_policy_attachment" "ssm" {
  role       = aws_iam_role.this.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_role_policy_attachment" "cloudwatch" {
  role       = aws_iam_role.this.name
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
}

resource "aws_iam_instance_profile" "this" {
  name = "${var.name}-instance-profile"
  role = aws_iam_role.this.name

  tags = var.tags
}

# ─── EC2 Instance ─────────────────────────────────────────────────────────────

resource "aws_instance" "this" {
  ami                         = var.ami_id
  instance_type               = var.instance_type
  subnet_id                   = var.subnet_id
  vpc_security_group_ids      = [aws_security_group.this.id]
  iam_instance_profile        = aws_iam_instance_profile.this.name
  associate_public_ip_address = var.associate_public_ip

  # IMDSv2 required (CIS-AWS-5.6)
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  # EBS root volume encryption (CIS-AWS-2.2.1)
  root_block_device {
    encrypted             = true
    kms_key_id            = var.kms_key_arn
    volume_type           = var.root_volume_type
    volume_size           = var.root_volume_size
    delete_on_termination = true
  }

  monitoring = var.monitoring_enabled

  user_data_base64 = var.user_data_base64

  tags = merge(var.tags, { Name = var.name })

  lifecycle {
    ignore_changes = [ami]
  }
}

# ─── Additional EBS volumes ───────────────────────────────────────────────────

resource "aws_ebs_volume" "data" {
  count = length(var.data_volumes)

  availability_zone = aws_instance.this.availability_zone
  size              = var.data_volumes[count.index].size
  type              = lookup(var.data_volumes[count.index], "type", "gp3")
  encrypted         = true
  kms_key_id        = var.kms_key_arn

  tags = merge(var.tags, { Name = "${var.name}-data-${count.index}" })
}

resource "aws_volume_attachment" "data" {
  count = length(var.data_volumes)

  device_name = var.data_volumes[count.index].device_name
  volume_id   = aws_ebs_volume.data[count.index].id
  instance_id = aws_instance.this.id
}
'''

    def generate_variables(self) -> str:
        return '''\
variable "name" {
  type        = string
  description = "Name prefix applied to all resources."
}

variable "ami_id" {
  type        = string
  description = "AMI ID for the EC2 instance. Use aws_ami data source in production."
}

variable "instance_type" {
  type        = string
  description = "EC2 instance type."
  default     = "t3.micro"
}

variable "subnet_id" {
  type        = string
  description = "Subnet ID where the instance will be launched. Use a private subnet."
}

variable "vpc_id" {
  type        = string
  description = "VPC ID for the security group."
}

variable "associate_public_ip" {
  type        = bool
  description = "Whether to assign a public IP. Should be false for private instances."
  default     = false
}

variable "kms_key_arn" {
  type        = string
  description = "KMS key ARN for EBS volume encryption."
  default     = null
}

variable "root_volume_type" {
  type        = string
  description = "EBS root volume type."
  default     = "gp3"
}

variable "root_volume_size" {
  type        = number
  description = "Root EBS volume size in GiB."
  default     = 20
}

variable "monitoring_enabled" {
  type        = bool
  description = "Enable detailed CloudWatch monitoring (1-minute metrics)."
  default     = true
}

variable "user_data_base64" {
  type        = string
  description = "Base64-encoded user data script."
  default     = null
  sensitive   = true
}

variable "ingress_rules" {
  type = list(object({
    from_port   = number
    to_port     = number
    protocol    = string
    cidr_blocks = list(string)
    description = string
  }))
  description = "List of inbound security group rules. Restrict CIDRs to known ranges."
  default     = []
}

variable "data_volumes" {
  type = list(object({
    size        = number
    device_name = string
    type        = optional(string, "gp3")
  }))
  description = "Additional EBS data volumes to attach."
  default     = []
}

variable "tags" {
  type        = map(string)
  description = "Tags applied to all resources."
  default     = {}
}
'''

    def generate_outputs(self) -> str:
        return '''\
output "instance_id" {
  description = "ID of the EC2 instance."
  value       = aws_instance.this.id
}

output "private_ip" {
  description = "Private IP address of the instance."
  value       = aws_instance.this.private_ip
}

output "public_ip" {
  description = "Public IP address of the instance (if assigned)."
  value       = aws_instance.this.public_ip
}

output "security_group_id" {
  description = "ID of the instance security group."
  value       = aws_security_group.this.id
}

output "iam_role_arn" {
  description = "ARN of the instance IAM role."
  value       = aws_iam_role.this.arn
}

output "instance_profile_name" {
  description = "Name of the IAM instance profile."
  value       = aws_iam_instance_profile.this.name
}
'''

    def generate_tfvars_example(self) -> str:
        return f'''\
name          = "{self.config.get('name', self.name)}"
ami_id        = "ami-0c55b159cbfafe1f0"  # Amazon Linux 2023
instance_type = "{self.config.get('instance_type', 't3.micro')}"
subnet_id     = "subnet-xxxxxxxxxxxxxxxxx"
vpc_id        = "vpc-xxxxxxxxxxxxxxxxx"

associate_public_ip = false
monitoring_enabled  = true
# kms_key_arn       = "arn:aws:kms:us-east-1:123456789012:key/..."

ingress_rules = [
  {{
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
    description = "HTTPS from internal network"
  }}
]

tags = {{
  Environment = "production"
  Project     = "my-project"
  Owner       = "platform-team"
  CostCenter  = "eng-001"
}}
'''
