from ..base import TerraformModule


class AWSEKSModule(TerraformModule):
    MODULE_TYPE = "eks"
    PROVIDER = "aws"
    DESCRIPTION = "AWS EKS private cluster with secrets encryption, OIDC, managed node groups"
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
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
  }
}
'''

    def generate_main(self) -> str:
        return '''\
# ─── EKS Cluster IAM Role ────────────────────────────────────────────────────

resource "aws_iam_role" "cluster" {
  name = "${var.cluster_name}-cluster-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "eks.amazonaws.com" }
    }]
  })

  tags = var.tags
}

resource "aws_iam_role_policy_attachment" "cluster_policy" {
  role       = aws_iam_role.cluster.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
}

# ─── Security Group ───────────────────────────────────────────────────────────

resource "aws_security_group" "cluster" {
  name        = "${var.cluster_name}-cluster-sg"
  description = "EKS cluster security group"
  vpc_id      = var.vpc_id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow all outbound"
  }

  tags = merge(var.tags, { Name = "${var.cluster_name}-cluster-sg" })
}

resource "aws_security_group_rule" "cluster_ingress_nodes" {
  type                     = "ingress"
  from_port                = 443
  to_port                  = 443
  protocol                 = "tcp"
  security_group_id        = aws_security_group.cluster.id
  source_security_group_id = aws_security_group.nodes.id
  description              = "Allow node groups to communicate with cluster API"
}

resource "aws_security_group" "nodes" {
  name        = "${var.cluster_name}-nodes-sg"
  description = "EKS managed node group security group"
  vpc_id      = var.vpc_id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow all outbound"
  }

  tags = merge(var.tags, { Name = "${var.cluster_name}-nodes-sg" })
}

# ─── EKS Cluster ─────────────────────────────────────────────────────────────

resource "aws_eks_cluster" "this" {
  name     = var.cluster_name
  version  = var.kubernetes_version
  role_arn = aws_iam_role.cluster.arn

  vpc_config {
    subnet_ids              = var.subnet_ids
    security_group_ids      = [aws_security_group.cluster.id]
    endpoint_private_access = true
    endpoint_public_access  = var.endpoint_public_access

    dynamic "public_access_cidrs" {
      for_each = var.endpoint_public_access ? [var.public_access_cidrs] : []
      content {}
    }
  }

  # Encrypt Kubernetes secrets with KMS (CIS-AWS-EKS-2)
  encryption_config {
    resources = ["secrets"]
    provider {
      key_arn = var.kms_key_arn
    }
  }

  # Control plane logging (CIS-AWS-EKS-3)
  enabled_cluster_log_types = var.enabled_log_types

  access_config {
    authentication_mode                         = "API_AND_CONFIG_MAP"
    bootstrap_cluster_creator_admin_permissions = false
  }

  tags = merge(var.tags, { Name = var.cluster_name })

  depends_on = [aws_iam_role_policy_attachment.cluster_policy]
}

# ─── OIDC Provider ────────────────────────────────────────────────────────────

data "tls_certificate" "cluster" {
  url = aws_eks_cluster.this.identity[0].oidc[0].issuer
}

resource "aws_iam_openid_connect_provider" "cluster" {
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = [data.tls_certificate.cluster.certificates[0].sha1_fingerprint]
  url             = aws_eks_cluster.this.identity[0].oidc[0].issuer

  tags = var.tags
}

# ─── Node Group IAM Role ──────────────────────────────────────────────────────

resource "aws_iam_role" "node_group" {
  name = "${var.cluster_name}-node-group-role"

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

resource "aws_iam_role_policy_attachment" "node_worker_policy" {
  role       = aws_iam_role.node_group.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
}

resource "aws_iam_role_policy_attachment" "node_cni_policy" {
  role       = aws_iam_role.node_group.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
}

resource "aws_iam_role_policy_attachment" "node_ecr_read" {
  role       = aws_iam_role.node_group.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
}

resource "aws_iam_role_policy_attachment" "node_ssm" {
  role       = aws_iam_role.node_group.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

# ─── Managed Node Groups ──────────────────────────────────────────────────────

resource "aws_launch_template" "node_group" {
  name_prefix = "${var.cluster_name}-ng-"

  # EBS encryption (CIS-AWS-EKS-4)
  block_device_mappings {
    device_name = "/dev/xvda"
    ebs {
      volume_size           = var.node_disk_size
      volume_type           = "gp3"
      encrypted             = true
      kms_key_id            = var.kms_key_arn
      delete_on_termination = true
    }
  }

  # IMDSv2 required
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 2
  }

  monitoring {
    enabled = true
  }

  tag_specifications {
    resource_type = "instance"
    tags          = merge(var.tags, { Name = "${var.cluster_name}-node" })
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_eks_node_group" "this" {
  for_each = var.node_groups

  cluster_name    = aws_eks_cluster.this.name
  node_group_name = each.key
  node_role_arn   = aws_iam_role.node_group.arn
  subnet_ids      = var.subnet_ids

  instance_types = each.value.instance_types
  capacity_type  = lookup(each.value, "capacity_type", "ON_DEMAND")

  launch_template {
    id      = aws_launch_template.node_group.id
    version = aws_launch_template.node_group.latest_version
  }

  scaling_config {
    desired_size = each.value.desired_size
    min_size     = each.value.min_size
    max_size     = each.value.max_size
  }

  update_config {
    max_unavailable_percentage = 33
  }

  labels = lookup(each.value, "labels", {})

  dynamic "taint" {
    for_each = lookup(each.value, "taints", [])
    content {
      key    = taint.value.key
      value  = lookup(taint.value, "value", null)
      effect = taint.value.effect
    }
  }

  tags = merge(var.tags, { Name = "${var.cluster_name}-${each.key}" })

  depends_on = [
    aws_iam_role_policy_attachment.node_worker_policy,
    aws_iam_role_policy_attachment.node_cni_policy,
    aws_iam_role_policy_attachment.node_ecr_read,
  ]

  lifecycle {
    ignore_changes = [scaling_config[0].desired_size]
  }
}
'''

    def generate_variables(self) -> str:
        return '''\
variable "cluster_name" {
  type        = string
  description = "Name of the EKS cluster."
}

variable "kubernetes_version" {
  type        = string
  description = "Kubernetes version for the EKS cluster."
  default     = "1.29"
}

variable "vpc_id" {
  type        = string
  description = "VPC ID for the cluster."
}

variable "subnet_ids" {
  type        = list(string)
  description = "Private subnet IDs for node groups and cluster networking."
}

variable "kms_key_arn" {
  type        = string
  description = "KMS key ARN for secrets encryption and node EBS volumes."
}

variable "endpoint_public_access" {
  type        = bool
  description = "Enable public API server endpoint. Set false for private clusters (CIS-AWS-EKS-1)."
  default     = false
}

variable "public_access_cidrs" {
  type        = list(string)
  description = "CIDRs allowed to access the public API endpoint (if enabled)."
  default     = []
}

variable "enabled_log_types" {
  type        = list(string)
  description = "EKS control plane log types to enable (CIS-AWS-EKS-3)."
  default     = ["api", "audit", "authenticator", "controllerManager", "scheduler"]
}

variable "node_disk_size" {
  type        = number
  description = "Root EBS disk size in GiB for node group instances."
  default     = 50
}

variable "node_groups" {
  type = map(object({
    instance_types = list(string)
    desired_size   = number
    min_size       = number
    max_size       = number
    capacity_type  = optional(string, "ON_DEMAND")
    labels         = optional(map(string), {})
    taints = optional(list(object({
      key    = string
      value  = optional(string)
      effect = string
    })), [])
  }))
  description = "Map of node group configurations."
  default = {
    general = {
      instance_types = ["m5.large"]
      desired_size   = 2
      min_size       = 1
      max_size       = 5
    }
  }
}

variable "tags" {
  type        = map(string)
  description = "Tags applied to all resources."
  default     = {}
}
'''

    def generate_outputs(self) -> str:
        return '''\
output "cluster_name" {
  description = "EKS cluster name."
  value       = aws_eks_cluster.this.name
}

output "cluster_arn" {
  description = "EKS cluster ARN."
  value       = aws_eks_cluster.this.arn
}

output "cluster_endpoint" {
  description = "EKS cluster API server endpoint."
  value       = aws_eks_cluster.this.endpoint
}

output "cluster_certificate_authority_data" {
  description = "Base64-encoded certificate authority data."
  value       = aws_eks_cluster.this.certificate_authority[0].data
}

output "cluster_security_group_id" {
  description = "Security group ID for the EKS cluster."
  value       = aws_security_group.cluster.id
}

output "node_security_group_id" {
  description = "Security group ID for node groups."
  value       = aws_security_group.nodes.id
}

output "oidc_provider_arn" {
  description = "ARN of the OIDC identity provider (for IRSA)."
  value       = aws_iam_openid_connect_provider.cluster.arn
}

output "oidc_provider_url" {
  description = "URL of the OIDC identity provider."
  value       = aws_iam_openid_connect_provider.cluster.url
}
'''

    def generate_tfvars_example(self) -> str:
        return f'''\
cluster_name       = "{self.config.get('cluster_name', self.name)}"
kubernetes_version = "1.29"
vpc_id             = "vpc-xxxxxxxxxxxxxxxxx"
subnet_ids         = ["subnet-xxxxxxxxxxxxxxxxx", "subnet-yyyyyyyyyyyyyyyyy"]
kms_key_arn        = "arn:aws:kms:us-east-1:123456789012:key/..."

endpoint_public_access = false

node_groups = {{
  general = {{
    instance_types = ["m5.large", "m5a.large"]
    desired_size   = 3
    min_size       = 2
    max_size       = 10
    capacity_type  = "ON_DEMAND"
  }}
  spot = {{
    instance_types = ["m5.large", "m4.large", "m5a.large"]
    desired_size   = 2
    min_size       = 0
    max_size       = 20
    capacity_type  = "SPOT"
    labels         = {{ "workload-type" = "spot" }}
  }}
}}

tags = {{
  Environment = "production"
  Project     = "my-project"
  Owner       = "platform-team"
  CostCenter  = "eng-001"
}}
'''
