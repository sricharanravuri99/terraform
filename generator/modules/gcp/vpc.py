from ..base import TerraformModule


class GCPVPCModule(TerraformModule):
    MODULE_TYPE = "vpc"
    PROVIDER = "gcp"
    DESCRIPTION = "GCP VPC with custom subnets, Cloud NAT, flow logs, and Private Google Access"
    PROVIDER_VERSION = "~> 5.0"

    def generate_versions(self) -> str:
        return '''\
terraform {
  required_version = ">= 1.5.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }
}
'''

    def generate_main(self) -> str:
        return '''\
# ─── VPC Network (custom mode, not auto-mode - CIS-GCP-3.1) ──────────────────

resource "google_compute_network" "this" {
  name                    = var.name
  project                 = var.project_id
  auto_create_subnetworks = false
  routing_mode            = var.routing_mode

  delete_default_routes_on_create = false
}

# ─── Subnets ──────────────────────────────────────────────────────────────────

resource "google_compute_subnetwork" "this" {
  for_each = var.subnets

  name          = each.key
  project       = var.project_id
  network       = google_compute_network.this.id
  region        = each.value.region
  ip_cidr_range = each.value.cidr

  # Private Google Access (CIS-GCP-3.9)
  private_ip_google_access = true

  # Secondary ranges for GKE
  dynamic "secondary_ip_range" {
    for_each = lookup(each.value, "secondary_ranges", [])
    content {
      range_name    = secondary_ip_range.value.name
      ip_cidr_range = secondary_ip_range.value.cidr
    }
  }

  # VPC Flow Logs (CIS-GCP-3.8)
  log_config {
    aggregation_interval = "INTERVAL_5_SEC"
    flow_sampling        = 0.5
    metadata             = "INCLUDE_ALL_METADATA"
  }
}

# ─── Cloud Router & NAT ───────────────────────────────────────────────────────

resource "google_compute_router" "this" {
  for_each = toset(distinct([for s in var.subnets : s.region]))

  name    = "${var.name}-router-${each.value}"
  project = var.project_id
  network = google_compute_network.this.id
  region  = each.value
}

resource "google_compute_router_nat" "this" {
  for_each = var.enable_cloud_nat ? toset(distinct([for s in var.subnets : s.region])) : toset([])

  name                               = "${var.name}-nat-${each.value}"
  project                            = var.project_id
  router                             = google_compute_router.this[each.value].name
  region                             = each.value
  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "ALL_SUBNETWORKS_ALL_IP_RANGES"

  log_config {
    enable = true
    filter = "ERRORS_ONLY"
  }
}

# ─── Firewall Rules ───────────────────────────────────────────────────────────

# Deny all ingress from internet by default
resource "google_compute_firewall" "deny_all_ingress" {
  name    = "${var.name}-deny-all-ingress"
  project = var.project_id
  network = google_compute_network.this.name

  direction = "INGRESS"
  priority  = 65534
  deny { protocol = "all" }
  source_ranges = ["0.0.0.0/0"]
  log_config { metadata = "INCLUDE_ALL_METADATA" }
}

# Allow internal traffic
resource "google_compute_firewall" "allow_internal" {
  name    = "${var.name}-allow-internal"
  project = var.project_id
  network = google_compute_network.this.name

  direction = "INGRESS"
  priority  = 1000
  allow { protocol = "all" }
  source_ranges = [for s in var.subnets : s.cidr]
  log_config { metadata = "INCLUDE_ALL_METADATA" }
}

# Allow IAP for SSH/RDP (Google's Identity-Aware Proxy range)
resource "google_compute_firewall" "allow_iap" {
  count = var.enable_iap_firewall ? 1 : 0

  name    = "${var.name}-allow-iap"
  project = var.project_id
  network = google_compute_network.this.name

  direction = "INGRESS"
  priority  = 1000
  allow {
    protocol = "tcp"
    ports    = ["22", "3389"]
  }
  source_ranges = ["35.235.240.0/20"]
  log_config { metadata = "INCLUDE_ALL_METADATA" }
}
'''

    def generate_variables(self) -> str:
        return '''\
variable "name" {
  type        = string
  description = "Name of the VPC network."
}

variable "project_id" {
  type        = string
  description = "GCP project ID."
}

variable "routing_mode" {
  type        = string
  description = "VPC routing mode (REGIONAL or GLOBAL)."
  default     = "REGIONAL"
}

variable "subnets" {
  type = map(object({
    region = string
    cidr   = string
    secondary_ranges = optional(list(object({
      name = string
      cidr = string
    })), [])
  }))
  description = "Map of subnet definitions."
  default     = {}
}

variable "enable_cloud_nat" {
  type        = bool
  description = "Deploy Cloud NAT for private subnet internet access."
  default     = true
}

variable "enable_iap_firewall" {
  type        = bool
  description = "Create firewall rule allowing Google IAP for SSH/RDP."
  default     = true
}
'''

    def generate_outputs(self) -> str:
        return '''\
output "network_id" {
  value       = google_compute_network.this.id
  description = "VPC network resource ID."
}

output "network_name" {
  value       = google_compute_network.this.name
  description = "VPC network name."
}

output "network_self_link" {
  value       = google_compute_network.this.self_link
  description = "VPC network self-link URL."
}

output "subnet_ids" {
  value       = { for k, v in google_compute_subnetwork.this : k => v.id }
  description = "Map of subnet name to subnet ID."
}

output "subnet_self_links" {
  value       = { for k, v in google_compute_subnetwork.this : k => v.self_link }
  description = "Map of subnet name to self-link."
}
'''

    def generate_tfvars_example(self) -> str:
        return f'''\
name       = "{self.name}"
project_id = "my-gcp-project"

subnets = {{
  "app-subnet-us-central1" = {{
    region = "us-central1"
    cidr   = "10.0.1.0/24"
    secondary_ranges = [
      {{ name = "pods",     cidr = "10.100.0.0/18" }},
      {{ name = "services", cidr = "10.101.0.0/20" }},
    ]
  }}
  "db-subnet-us-central1" = {{
    region = "us-central1"
    cidr   = "10.0.11.0/24"
  }}
}}

enable_cloud_nat   = true
enable_iap_firewall = true
'''
