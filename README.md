# Terraform Module Generator

A Python-based CLI tool that generates production-ready, compliance-checked Terraform modules for **AWS**, **Azure**, and **GCP** — all from a single command or a YAML config file.

Every module it generates is immediately scanned against **CIS Benchmarks**, **PCI-DSS v4.0**, and **HIPAA** rules, and each scan comes with a prioritised list of improvement suggestions.

---

## Table of Contents

- [What This Tool Does](#what-this-tool-does)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Project Structure](#project-structure)
- [Quick Start](#quick-start)
- [CLI Reference](#cli-reference)
  - [list](#list)
  - [generate](#generate)
  - [scan](#scan)
  - [advise](#advise)
- [YAML Config Format](#yaml-config-format)
- [Module Catalog](#module-catalog)
- [Compliance Frameworks](#compliance-frameworks)
- [Understanding the Output](#understanding-the-output)
- [How to Use Generated Modules](#how-to-use-generated-modules)
- [Workflows](#workflows)

---

## What This Tool Does

Most teams write Terraform from scratch or copy-paste from the internet — and end up with modules that miss encryption, skip flow logs, allow public access, or have no tagging strategy. Security reviews then catch these issues late, after code is already in CI.

This generator solves that by treating compliance as the **starting point**, not an afterthought:

1. **You declare what you want** — a VPC, an S3 bucket, an EKS cluster — via a CLI flag or a YAML file.
2. **The tool generates valid Terraform HCL** for that module with all security controls already on: encryption, flow logs, IMDSv2, private access, deletion protection, and more.
3. **It immediately scans** your configuration against CIS, PCI-DSS, HIPAA, and general best-practice rules.
4. **It shows violations** by severity (CRITICAL → INFO) with exact remediation steps.
5. **It suggests improvements** across Security, Cost, Reliability, Performance, and Operational Excellence.

The generated code is not a template with `TODO` comments — it is **deployable HCL** that follows the principle of secure-by-default.

---

## Prerequisites

| Requirement | Version |
|-------------|---------|
| Python | 3.8 or higher |
| pip | any recent version |
| Terraform | 1.5+ (to apply generated code) |

---

## Installation

```bash
# 1. Clone the repo
git clone <repo-url>
cd terraform

# 2. Install Python dependencies (only 2 packages)
pip3 install -r requirements.txt
```

`requirements.txt` contains:
```
rich>=13.0.0    # coloured terminal output
pyyaml>=6.0.0  # YAML config file parsing
```

No cloud credentials are needed to generate or scan modules. Credentials are only required when you run `terraform apply` on the generated output.

---

## Project Structure

```
terraform/
├── generator/
│   ├── main.py                   # CLI entry point — run this
│   ├── core/
│   │   ├── generator.py          # Orchestrates file generation
│   │   └── advisor.py            # Improvement suggestions engine
│   ├── modules/
│   │   ├── base.py               # Base class all modules inherit from
│   │   ├── aws/
│   │   │   ├── vpc.py            # VPC + subnets + NAT + flow logs
│   │   │   ├── ec2.py            # EC2 + IMDSv2 + encrypted EBS + SSM
│   │   │   ├── s3.py             # S3 + encryption + versioning + HTTPS
│   │   │   ├── rds.py            # RDS + Multi-AZ + backups + encryption
│   │   │   ├── iam.py            # IAM role + least-privilege policy
│   │   │   └── eks.py            # EKS private cluster + OIDC + encryption
│   │   ├── azure/
│   │   │   ├── vnet.py           # VNet + NSGs + DDoS + flow logs
│   │   │   ├── storage.py        # Storage account + TLS + CMK + network rules
│   │   │   └── aks.py            # AKS private cluster + RBAC + Azure Policy
│   │   └── gcp/
│   │       ├── vpc.py            # VPC + Cloud NAT + flow logs + IAP firewall
│   │       └── gke.py            # GKE private cluster + Workload Identity + Shielded Nodes
│   └── compliance/
│       ├── models.py             # Severity, Framework, Violation data types
│       ├── cis_aws.py            # CIS AWS Benchmark rules (vpc/ec2/s3/rds/iam/eks)
│       ├── cis_azure.py          # CIS Azure rules (vnet/vm/storage/aks/sql)
│       ├── cis_gcp.py            # CIS GCP rules (vpc/compute/storage/gke/sql)
│       ├── pci_dss.py            # PCI-DSS v4.0 cross-provider rules
│       ├── hipaa.py              # HIPAA Security Rule checks
│       └── general.py            # Tagging, remote state, version-pinning rules
├── examples/
│   ├── aws-webapp.yaml           # AWS: VPC + S3 + RDS + IAM stack
│   ├── azure-webapp.yaml         # Azure: VNet + Storage + AKS stack
│   ├── gcp-webapp.yaml           # GCP: VPC + GKE stack
│   └── multi-cloud.yaml          # AWS primary + GCP DR + Azure archival
├── output/                       # Generated modules land here (git-ignored)
├── requirements.txt
└── README.md
```

Each module Python file generates exactly **5 Terraform files**:

```
output/<module-name>/
├── main.tf                   # Resource definitions
├── variables.tf              # Input variables with types and defaults
├── outputs.tf                # Output values for cross-module references
├── versions.tf               # Required Terraform and provider versions
└── terraform.tfvars.example  # Pre-filled example variable values
```

---

## Quick Start

### Option A — Single module via flags

```bash
# Generate an AWS VPC, scan it, and get improvement suggestions
python3 -m generator.main generate \
  --provider aws \
  --module vpc \
  --name prod-vpc \
  --output ./output \
  --tags "Environment=production,Owner=platform-team,Project=myapp,CostCenter=eng-001"
```

### Option B — Full stack via YAML config

```bash
# Generate a complete AWS web app stack (VPC + S3 + RDS + IAM)
python3 -m generator.main generate \
  --config examples/aws-webapp.yaml \
  --output ./output \
  --compliance cis,pci-dss,hipaa,general
```

### Option C — Scan an existing config without generating

```bash
python3 -m generator.main scan \
  --provider aws \
  --module rds \
  --name prod-db \
  --config-json '{"publicly_accessible": true, "backup_retention_days": 3}'
```

### Option D — Get improvement suggestions only

```bash
python3 -m generator.main advise \
  --provider aws \
  --module eks \
  --config-json '{"endpoint_public_access": true}'
```

---

## CLI Reference

All commands share this base invocation:

```bash
python3 -m generator.main <command> [options]
```

---

### `list`

Lists every available module type across all cloud providers.

```bash
python3 -m generator.main list
```

**Example output:**

```
┌────────────┬──────────────────┬─────────────────────────────────────────────────┐
│ Provider   │ Module Type      │ Description                                     │
├────────────┼──────────────────┼─────────────────────────────────────────────────┤
│ aws        │ ec2              │ AWS EC2 instance with IMDSv2, encrypted EBS...  │
│            │ eks              │ AWS EKS private cluster with secrets encryption │
│            │ iam              │ AWS IAM role with least-privilege inline policy  │
│            │ rds              │ AWS RDS with encryption, Multi-AZ, backups...   │
│            │ s3               │ AWS S3 with encryption, versioning, HTTPS...    │
│            │ vpc              │ AWS VPC with subnets, NAT gateway, Flow Logs    │
│ azure      │ aks              │ Azure AKS private cluster with RBAC...          │
│            │ storage          │ Azure Storage with HTTPS-only, TLS 1.2, CMK... │
│            │ vnet             │ Azure VNet with NSGs, DDoS, flow logs           │
│ gcp        │ gke              │ GCP GKE private cluster, Workload Identity...   │
│            │ vpc              │ GCP VPC with Cloud NAT, flow logs...            │
└────────────┴──────────────────┴─────────────────────────────────────────────────┘
```

---

### `generate`

Generates Terraform files, runs a compliance scan, and prints improvement suggestions.

```
python3 -m generator.main generate [options]
```

| Flag | Description | Default |
|------|-------------|---------|
| `--provider` / `-p` | Cloud provider: `aws`, `azure`, `gcp` | required |
| `--module` / `-m` | Module type (see catalog below) | required |
| `--name` / `-n` | Name used for the output directory and resource prefix | required |
| `--output` / `-o` | Directory to write generated files into | `./output` |
| `--config` / `-c` | Path to a YAML file defining one or more modules | — |
| `--config-json` | Extra module config as an inline JSON string | — |
| `--compliance` | Comma-separated frameworks to check | `cis,general` |
| `--tags` | `key=value,key=value` resource tags | — |
| `--no-suggestions` | Skip the improvement suggestions section | off |

**Single module:**
```bash
python3 -m generator.main generate \
  --provider aws --module s3 --name my-data-lake \
  --output ./output \
  --compliance cis,hipaa \
  --tags "Environment=production,Owner=data-team,Project=lake,CostCenter=data-001"
```

**From YAML (recommended for stacks):**
```bash
python3 -m generator.main generate \
  --config examples/aws-webapp.yaml \
  --output ./output \
  --compliance all
```

**`--compliance` values:**

| Value | What it checks |
|-------|----------------|
| `cis` | CIS Benchmark for the provider (AWS / Azure / GCP) |
| `pci-dss` | PCI-DSS v4.0 cross-cloud rules |
| `hipaa` | HIPAA Security Rule checks |
| `general` | Tagging, remote state, provider version pinning |
| `all` | All of the above |

---

### `scan`

Checks a module configuration against compliance rules without generating any files. Useful in CI pipelines or for auditing existing configs.

```
python3 -m generator.main scan --provider <p> --module <m> --name <n> [options]
```

| Flag | Description |
|------|-------------|
| `--provider` / `-p` | Cloud provider |
| `--module` / `-m` | Module type |
| `--name` / `-n` | Module name (used in violation output) |
| `--config-json` | Module configuration as JSON |
| `--compliance` | Frameworks to check (default: `all`) |

**Example — deliberately bad RDS config:**
```bash
python3 -m generator.main scan \
  --provider aws --module rds --name prod-db \
  --config-json '{
    "publicly_accessible": true,
    "multi_az": false,
    "backup_retention_days": 3,
    "deletion_protection": false
  }'
```

**Example output (truncated):**
```
┌──────────┬───────────────────┬──────────┬─────────────────────────────────┐
│ Severity │ Rule ID           │ Framework│ Title                           │
├──────────┼───────────────────┼──────────┼─────────────────────────────────┤
│ CRITICAL │ CIS-AWS-2.3.2     │ CIS-AWS  │ RDS Instance Publicly Accessible│
│ CRITICAL │ PCI-DSS-1.3       │ PCI-DSS  │ Resource Directly Accessible... │
│ HIGH     │ CIS-AWS-2.3.3     │ CIS-AWS  │ RDS Backup Retention Too Short  │
│ MEDIUM   │ CIS-AWS-RDS-1     │ CIS-AWS  │ RDS Multi-AZ Not Enabled        │
│ MEDIUM   │ CIS-AWS-RDS-2     │ CIS-AWS  │ Deletion Protection Not Enabled │
└──────────┴───────────────────┴──────────┴─────────────────────────────────┘

Remediation steps for CRITICAL/HIGH:
  ● CIS-AWS-2.3.2 — RDS Instance Publicly Accessible
    Fix: Set publicly_accessible: false and use VPC connectivity.
```

**Exit codes (for CI use):**

| Code | Meaning |
|------|---------|
| 0 | Success (violations may exist but command ran correctly) |
| 1 | Bad arguments or import error |

---

### `advise`

Prints improvement suggestions for a module type without scanning for violations or generating files. Good for exploring best practices interactively.

```
python3 -m generator.main advise --provider <p> --module <m> [--config-json <json>]
```

```bash
python3 -m generator.main advise \
  --provider gcp --module gke \
  --config-json '{"release_channel": "NONE", "node_pools": {"default": {}}}'
```

Suggestions are grouped by category and priority:

| Category | Icon | Examples |
|----------|------|---------|
| SECURITY | 🔒 | CMK encryption, permissions boundaries, PSS enforcement |
| COST | 💰 | Spot instances, lifecycle tiering, reserved capacity |
| RELIABILITY | 🔄 | Multi-AZ, 3+ AZs, cross-region replication |
| PERFORMANCE | ⚡ | Read replicas, instance class sizing |
| OPERATIONAL | 🛠️ | Secrets Manager, monitoring, log retention |

---

## YAML Config Format

When you need to generate more than one module at a time, a YAML file is the cleanest approach.

### Global structure

```yaml
# Optional: default provider when not specified per-module
provider: aws

# Optional: tags merged into every module
tags:
  Environment: production
  Project: my-project
  Owner: platform-team
  CostCenter: eng-001

modules:
  - type: vpc          # required: module type
    name: my-vpc       # required: becomes the output directory name

    # Optional: override provider for this module only
    provider: aws

    # All remaining keys are passed as module config
    vpc_cidr: "10.0.0.0/16"
    enable_flow_logs: true
    ...

  - type: rds
    name: my-db
    engine: postgres
    multi_az: true
    ...
```

### Full AWS example (`examples/aws-webapp.yaml`)

```yaml
provider: aws

tags:
  Environment: production
  Project: web-app
  Owner: platform-team
  CostCenter: eng-001

modules:

  - type: vpc
    name: web-app-vpc
    vpc_cidr: "10.0.0.0/16"
    availability_zones: ["us-east-1a", "us-east-1b", "us-east-1c"]
    public_subnet_cidrs:   ["10.0.1.0/24",  "10.0.2.0/24",  "10.0.3.0/24"]
    private_subnet_cidrs:  ["10.0.11.0/24", "10.0.12.0/24", "10.0.13.0/24"]
    database_subnet_cidrs: ["10.0.21.0/24", "10.0.22.0/24", "10.0.23.0/24"]
    enable_nat_gateway: true
    enable_flow_logs: true
    flow_log_retention_days: 365

  - type: s3
    name: web-app-assets
    bucket_name: web-app-assets-prod-unique
    versioning_enabled: true
    access_logging_enabled: true
    enforce_tls: true
    block_public_access: true

  - type: rds
    name: web-app-db
    engine: postgres
    engine_version: "15.4"
    instance_class: db.m6i.large
    database_name: appdb
    multi_az: true
    backup_retention_days: 14
    deletion_protection: true
    publicly_accessible: false

  - type: iam
    name: web-app-ec2-role
    trust_services: ["ec2.amazonaws.com"]
    policy_statements:
      - sid: S3ReadAssets
        actions: ["s3:GetObject", "s3:ListBucket"]
        resources: ["arn:aws:s3:::web-app-assets-prod-unique/*"]
    create_instance_profile: true
```

### Multi-cloud example (`examples/multi-cloud.yaml`)

Per-module `provider` override lets you mix providers in one config:

```yaml
tags:
  Environment: production
  Project: multi-cloud-app

modules:
  - provider: aws         # AWS primary
    type: vpc
    name: primary-vpc
    ...

  - provider: gcp         # GCP disaster recovery
    type: vpc
    name: dr-vpc
    ...

  - provider: azure       # Azure cold archival
    type: storage
    name: compliance-archive
    ...
```

---

## Module Catalog

### AWS

| Module | Key Resources Generated | CIS Rules Enforced |
|--------|------------------------|--------------------|
| `vpc` | VPC, subnets (public/private/DB), NAT GW, IGW, route tables, Flow Logs, locked-down default SG | CIS-AWS-3.9, 5.4 |
| `ec2` | Instance, security group, IAM role (SSM + CloudWatch), instance profile, EBS volumes | CIS-AWS-2.2.1, 5.6 (IMDSv2) |
| `s3` | Bucket, public access block, SSE-KMS, versioning, access logging, HTTPS-only bucket policy, lifecycle | CIS-AWS-2.1.1–2.1.5 |
| `rds` | DB instance, subnet group, security group, parameter group, enhanced monitoring role | CIS-AWS-2.3.1–2.3.3 |
| `iam` | IAM role, inline policy (least-privilege), managed policy attachments, instance profile | CIS-AWS-1.16, 1.17 |
| `eks` | Cluster, OIDC provider, node IAM role, launch template (IMDSv2 + EBS encryption), node groups | CIS-AWS-EKS-1–4 |

### Azure

| Module | Key Resources Generated | CIS Rules Enforced |
|--------|------------------------|--------------------|
| `vnet` | Virtual Network, subnets, NSG per subnet, NSG flow logs, Network Watcher, DDoS plan | CIS-Azure-6.1, 6.5.1 |
| `storage` | Storage account, CMK, blob soft delete, versioning, network rules (Deny default), diagnostics | CIS-Azure-3.1–3.8 |
| `aks` | AKS cluster, system node pool, user node pools, AAD RBAC, OMS agent, Azure Policy add-on | CIS-Azure-8.5, 8.6 |

### GCP

| Module | Key Resources Generated | CIS Rules Enforced |
|--------|------------------------|--------------------|
| `vpc` | VPC (custom mode), subnets with flow logs + Private Google Access, Cloud Router, Cloud NAT, firewall rules | CIS-GCP-3.1, 3.8, 3.9 |
| `gke` | Private cluster, node pools, node SA, Workload Identity, secrets encryption, network policy, Shielded Nodes | CIS-GCP-7.1, 7.3–7.6, 7.10 |

---

## Compliance Frameworks

### CIS Benchmarks (provider-specific)

The Center for Internet Security publishes hardening benchmarks for each cloud. This tool checks:

| Provider | Example rules checked |
|----------|-----------------------|
| AWS | VPC Flow Logs (3.9), EBS encryption (2.2.1), S3 public access block (2.1.5), RDS public access (2.3.2), IMDSv2 (5.6), EKS secrets encryption |
| Azure | HTTPS-only storage (3.1), TLS 1.2 (3.2), NSG flow logs (6.5.1), AKS RBAC (8.5), SQL TDE (4.1.2) |
| GCP | Custom-mode VPC (3.1), flow logs (3.8), Private Google Access (3.9), private GKE (7.1), Workload Identity (7.4) |

### PCI-DSS v4.0 (cross-provider)

Payment Card Industry rules applied to any module:

| Requirement | What is checked |
|-------------|-----------------|
| Req 1.3 | No direct internet connectivity to resources |
| Req 3.5 | Encryption at rest enabled |
| Req 4.2 | TLS/HTTPS enforced for data in transit |
| Req 6.3 | Auto-patching / minor version upgrades enabled |
| Req 10.2 | Audit logging enabled |
| Req 10.7 | Log retention ≥ 365 days |

### HIPAA Security Rule (cross-provider)

| CFR Reference | What is checked |
|---------------|-----------------|
| §164.312(a)(1) | Access control — no public accessibility |
| §164.312(a)(2)(iv) | Encryption and decryption at rest |
| §164.312(e)(1) | Transmission security — TLS enforcement |
| §164.312(b) | Audit controls — logging enabled |
| §164.312(c)(1) | Integrity — deletion protection on databases |
| §164.308(a)(7)(ii)(A) | Data backup plan — backups or versioning enabled |

### GENERAL (cross-provider best practices)

| Rule | Description |
|------|-------------|
| TAG-1 | Required tags: `Environment`, `Owner`, `Project`, `CostCenter` |
| STATE-1 | Remote Terraform backend (S3/GCS/Azure Blob) recommended |
| VER-1 | Provider version pinned in `versions.tf` |
| COST-1 | `CostCenter` tag present for cost allocation |
| DOC-1 | Module has a description field |

---

## Understanding the Output

When you run `generate`, each module produces this directory:

```
output/prod-vpc/
├── versions.tf           # Pins Terraform ≥1.5 and provider version
├── main.tf               # All resource blocks (VPC, subnets, NAT, flow logs…)
├── variables.tf          # Typed, described input variables with sane defaults
├── outputs.tf            # Output values exposing IDs/ARNs for use by other modules
└── terraform.tfvars.example  # Ready-to-edit variable values
```

**The scan report** immediately follows generation:

```
● CRITICAL  CIS-AWS-2.3.2   RDS Instance Publicly Accessible
  Description: RDS instances should not be publicly accessible from the internet.
  Fix: Set publicly_accessible: false and use VPC connectivity.

● HIGH       CIS-AWS-2.3.3   RDS Backup Retention Too Short
  Fix: Set backup_retention_days: 7 or greater.
```

**The suggestions panel** gives you next-level improvements beyond the minimum compliance bar:

```
🔒 [HIGH]   Store Credentials in AWS Secrets Manager  (SECURITY)
   Passing master_password as a variable risks it appearing in state files.
   → Use aws_secretsmanager_secret with rotation, then reference via data source.

💰 [MEDIUM] Add Lifecycle Rules for Object Tiering  (COST)
   → Add transitions to STANDARD_IA (30d), GLACIER (90d), DEEP_ARCHIVE (365d).
```

---

## How to Use Generated Modules

### Step 1 — Review and edit `terraform.tfvars.example`

```bash
cd output/web-app-vpc
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars with your actual values
```

### Step 2 — Add a remote backend (recommended)

Create a `backend.tf` in the module directory:

```hcl
# AWS example
terraform {
  backend "s3" {
    bucket         = "my-tfstate-bucket"
    key            = "web-app/vpc/terraform.tfstate"
    region         = "us-east-1"
    dynamodb_table = "terraform-state-lock"
    encrypt        = true
  }
}
```

### Step 3 — Add the provider block

Create a `provider.tf`:

```hcl
# AWS
provider "aws" {
  region = "us-east-1"
}

# Azure
provider "azurerm" {
  features {}
}

# GCP
provider "google" {
  project = "my-gcp-project"
  region  = "us-central1"
}
```

### Step 4 — Initialise and apply

```bash
terraform init
terraform plan
terraform apply
```

### Step 5 — Reference outputs from other modules

Use `terraform_remote_state` to wire modules together:

```hcl
data "terraform_remote_state" "vpc" {
  backend = "s3"
  config = {
    bucket = "my-tfstate-bucket"
    key    = "web-app/vpc/terraform.tfstate"
    region = "us-east-1"
  }
}

module "rds" {
  source     = "./output/web-app-db"
  vpc_id     = data.terraform_remote_state.vpc.outputs.vpc_id
  subnet_ids = data.terraform_remote_state.vpc.outputs.database_subnet_ids
}
```

---

## Workflows

### Local development

```bash
# See available modules
python3 -m generator.main list

# Generate a module, scan with CIS only
python3 -m generator.main generate \
  --provider aws --module s3 --name dev-assets \
  --output ./output --compliance cis

# Quickly explore suggestions
python3 -m generator.main advise --provider gcp --module gke
```

### Team stack generation

```bash
# Put your stack definition in YAML, check it into git
vim examples/my-stack.yaml

# Generate all modules at once, scan against all frameworks
python3 -m generator.main generate \
  --config examples/my-stack.yaml \
  --output ./infra \
  --compliance all
```

### CI/CD gate

Use `scan` in a pull request check to block deployments with critical violations:

```bash
# In your CI script
python3 -m generator.main scan \
  --provider aws --module rds --name prod-db \
  --config-json "$(cat module-config.json)" \
  --compliance cis,pci-dss

# Non-zero exit on import/arg error; review violations in CI output
```

### Multi-cloud DR setup

```bash
python3 -m generator.main generate \
  --config examples/multi-cloud.yaml \
  --output ./infra \
  --compliance all
```

Generates AWS primary, GCP disaster-recovery, and Azure archival modules in one pass, each scanned independently against the provider-specific CIS rules plus PCI-DSS and HIPAA.
