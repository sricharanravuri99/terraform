from ..base import TerraformModule


class GCPGKEModule(TerraformModule):
    MODULE_TYPE = "gke"
    PROVIDER = "gcp"
    DESCRIPTION = "GCP GKE private cluster with Workload Identity, network policy, secrets encryption, and Shielded Nodes"
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
# ─── GKE Cluster ─────────────────────────────────────────────────────────────

resource "google_container_cluster" "this" {
  name     = var.cluster_name
  project  = var.project_id
  location = var.location

  # Private cluster (CIS-GCP-7.1)
  private_cluster_config {
    enable_private_nodes    = true
    enable_private_endpoint = var.enable_private_endpoint
    master_ipv4_cidr_block  = var.master_ipv4_cidr_block
  }

  # Control plane access restriction (CIS-GCP-7.5)
  master_authorized_networks_config {
    dynamic "cidr_blocks" {
      for_each = var.master_authorized_networks
      content {
        cidr_block   = cidr_blocks.value.cidr
        display_name = cidr_blocks.value.name
      }
    }
  }

  network    = var.network_id
  subnetwork = var.subnetwork_id

  ip_allocation_policy {
    cluster_secondary_range_name  = var.pods_range_name
    services_secondary_range_name = var.services_range_name
  }

  # Workload Identity (CIS-GCP-7.4)
  workload_identity_config {
    workload_pool = "${var.project_id}.svc.id.goog"
  }

  # Secrets encryption (CIS-GCP-7.3)
  database_encryption {
    state    = var.secrets_encryption_key != null ? "ENCRYPTED" : "DECRYPTED"
    key_name = var.secrets_encryption_key
  }

  # Network policy (CIS-GCP-7.10)
  network_policy {
    enabled  = true
    provider = "CALICO"
  }

  datapath_provider = "ADVANCED_DATAPATH"

  # Shielded nodes (CIS-GCP-7.6)
  enable_shielded_nodes = true

  # Remove default node pool, manage separately
  remove_default_node_pool = true
  initial_node_count       = 1

  # Disable legacy auth and metadata
  master_auth {
    client_certificate_config {
      issue_client_certificate = false
    }
  }

  # Logging and monitoring
  logging_config {
    enable_components = ["SYSTEM_COMPONENTS", "WORKLOADS"]
  }

  monitoring_config {
    enable_components = ["SYSTEM_COMPONENTS"]
    managed_prometheus {
      enabled = true
    }
  }

  # Auto-upgrade and auto-repair
  release_channel {
    channel = var.release_channel
  }

  addons_config {
    http_load_balancing {
      disabled = false
    }
    horizontal_pod_autoscaling {
      disabled = false
    }
    gce_persistent_disk_csi_driver_config {
      enabled = true
    }
    config_connector_config {
      enabled = false
    }
  }

  resource_labels = var.labels

  deletion_protection = var.deletion_protection
}

# ─── Node Pools ───────────────────────────────────────────────────────────────

resource "google_container_node_pool" "this" {
  for_each = var.node_pools

  name     = each.key
  project  = var.project_id
  location = var.location
  cluster  = google_container_cluster.this.name

  initial_node_count = each.value.min_count

  autoscaling {
    min_node_count = each.value.min_count
    max_node_count = each.value.max_count
  }

  management {
    auto_repair  = true
    auto_upgrade = true
  }

  node_config {
    machine_type = each.value.machine_type
    disk_size_gb = lookup(each.value, "disk_size_gb", 100)
    disk_type    = "pd-ssd"

    # Dedicated service account (CIS-GCP-4.1)
    service_account = google_service_account.node_pool.email

    # Minimal OAuth scopes
    oauth_scopes = [
      "https://www.googleapis.com/auth/cloud-platform",
    ]

    # Workload identity on nodes
    workload_metadata_config {
      mode = "GKE_METADATA"
    }

    # Shielded instance config
    shielded_instance_config {
      enable_secure_boot          = true
      enable_integrity_monitoring = true
    }

    metadata = {
      disable-legacy-endpoints = "true"
    }

    labels = lookup(each.value, "labels", {})
    tags   = lookup(each.value, "tags", [])

    dynamic "taint" {
      for_each = lookup(each.value, "taints", [])
      content {
        key    = taint.value.key
        value  = taint.value.value
        effect = taint.value.effect
      }
    }
  }
}

# ─── Node Pool Service Account ────────────────────────────────────────────────

resource "google_service_account" "node_pool" {
  account_id   = "${var.cluster_name}-node-sa"
  display_name = "GKE Node Pool Service Account for ${var.cluster_name}"
  project      = var.project_id
}

resource "google_project_iam_member" "node_log_writer" {
  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.node_pool.email}"
}

resource "google_project_iam_member" "node_metric_writer" {
  project = var.project_id
  role    = "roles/monitoring.metricWriter"
  member  = "serviceAccount:${google_service_account.node_pool.email}"
}

resource "google_project_iam_member" "node_artifact_reader" {
  project = var.project_id
  role    = "roles/artifactregistry.reader"
  member  = "serviceAccount:${google_service_account.node_pool.email}"
}
'''

    def generate_variables(self) -> str:
        return '''\
variable "cluster_name" {
  type        = string
  description = "Name of the GKE cluster."
}

variable "project_id" {
  type        = string
  description = "GCP project ID."
}

variable "location" {
  type        = string
  description = "GCP zone or region for the cluster."
}

variable "network_id" {
  type        = string
  description = "VPC network ID."
}

variable "subnetwork_id" {
  type        = string
  description = "Subnetwork ID for the cluster nodes."
}

variable "pods_range_name" {
  type        = string
  description = "Secondary range name for pods."
}

variable "services_range_name" {
  type        = string
  description = "Secondary range name for services."
}

variable "master_ipv4_cidr_block" {
  type        = string
  description = "CIDR for the master network (must be /28)."
  default     = "172.16.0.0/28"
}

variable "enable_private_endpoint" {
  type        = bool
  description = "Make the master endpoint private-only (CIS-GCP-7.1)."
  default     = false
}

variable "master_authorized_networks" {
  type = list(object({
    cidr = string
    name = string
  }))
  description = "Networks authorized to access the control plane (CIS-GCP-7.5)."
  default     = []
}

variable "secrets_encryption_key" {
  type        = string
  description = "Cloud KMS key for application-layer secrets encryption (CIS-GCP-7.3)."
  default     = null
}

variable "release_channel" {
  type        = string
  description = "GKE release channel (RAPID, REGULAR, STABLE)."
  default     = "REGULAR"
}

variable "node_pools" {
  type = map(object({
    machine_type = string
    min_count    = number
    max_count    = number
    disk_size_gb = optional(number, 100)
    labels       = optional(map(string), {})
    tags         = optional(list(string), [])
    taints = optional(list(object({
      key    = string
      value  = string
      effect = string
    })), [])
  }))
  description = "Node pool definitions."
  default = {
    default = {
      machine_type = "e2-standard-4"
      min_count    = 2
      max_count    = 10
    }
  }
}

variable "deletion_protection" {
  type        = bool
  description = "Prevent accidental cluster deletion."
  default     = true
}

variable "labels" {
  type        = map(string)
  description = "Resource labels for the cluster."
  default     = {}
}
'''

    def generate_outputs(self) -> str:
        return '''\
output "cluster_id" {
  value       = google_container_cluster.this.id
  description = "GKE cluster ID."
}

output "cluster_name" {
  value       = google_container_cluster.this.name
  description = "GKE cluster name."
}

output "cluster_endpoint" {
  value       = google_container_cluster.this.endpoint
  description = "GKE cluster API server endpoint."
  sensitive   = true
}

output "cluster_ca_certificate" {
  value       = google_container_cluster.this.master_auth[0].cluster_ca_certificate
  description = "Base64-encoded cluster CA certificate."
  sensitive   = true
}

output "node_pool_service_account_email" {
  value       = google_service_account.node_pool.email
  description = "Email of the node pool service account."
}

output "workload_identity_pool" {
  value       = "${var.project_id}.svc.id.goog"
  description = "Workload Identity pool for IRSA-equivalent bindings."
}
'''

    def generate_tfvars_example(self) -> str:
        return f'''\
cluster_name   = "{self.name}"
project_id     = "my-gcp-project"
location       = "us-central1"
network_id     = "projects/my-project/global/networks/{self.name}-vpc"
subnetwork_id  = "projects/my-project/regions/us-central1/subnetworks/app-subnet"

pods_range_name     = "pods"
services_range_name = "services"

master_ipv4_cidr_block = "172.16.0.0/28"
enable_private_endpoint = false

master_authorized_networks = [
  {{ cidr = "10.0.0.0/8",    name = "internal" }},
  {{ cidr = "192.168.1.0/24", name = "vpn-office" }},
]

secrets_encryption_key = "projects/my-project/locations/us-central1/keyRings/gke-keyring/cryptoKeys/gke-key"
release_channel        = "REGULAR"

node_pools = {{
  "general" = {{
    machine_type = "e2-standard-4"
    min_count    = 2
    max_count    = 20
    labels       = {{ "workload" = "general" }}
  }}
}}

labels = {{
  environment = "production"
  project     = "my-project"
  owner       = "platform-team"
}}
'''
