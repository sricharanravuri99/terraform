from ..base import TerraformModule


class AzureAKSModule(TerraformModule):
    MODULE_TYPE = "aks"
    PROVIDER = "azure"
    DESCRIPTION = "Azure Kubernetes Service with private cluster, RBAC, managed identity, and Azure Policy"
    PROVIDER_VERSION = "~> 3.0"

    def generate_versions(self) -> str:
        return '''\
terraform {
  required_version = ">= 1.5.0"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
  }
}
'''

    def generate_main(self) -> str:
        return '''\
resource "azurerm_kubernetes_cluster" "this" {
  name                = var.cluster_name
  location            = var.location
  resource_group_name = var.resource_group_name
  dns_prefix          = var.cluster_name
  kubernetes_version  = var.kubernetes_version
  sku_tier            = var.sku_tier

  # RBAC (CIS-Azure-8.5)
  role_based_access_control_enabled = true

  azure_active_directory_role_based_access_control {
    managed                = true
    azure_rbac_enabled     = true
    admin_group_object_ids = var.admin_group_object_ids
  }

  # Private cluster (CIS-Azure-AKS-1)
  private_cluster_enabled             = var.private_cluster_enabled
  private_cluster_public_fqdn_enabled = false

  # Managed identity
  identity {
    type = "SystemAssigned"
  }

  # Default node pool
  default_node_pool {
    name                   = "system"
    node_count             = var.system_node_count
    vm_size                = var.system_node_vm_size
    vnet_subnet_id         = var.subnet_id
    os_disk_size_gb        = var.node_os_disk_size
    os_disk_type           = "Managed"
    type                   = "VirtualMachineScaleSets"
    enable_auto_scaling    = true
    min_count              = var.system_min_count
    max_count              = var.system_max_count
    only_critical_addons_enabled = true

    upgrade_settings {
      max_surge = "33%"
    }

    node_labels = {
      "node-role" = "system"
    }
  }

  network_profile {
    network_plugin    = "azure"
    network_policy    = "azure"
    load_balancer_sku = "standard"
    outbound_type     = var.outbound_type
  }

  # Monitoring (CIS-Azure-AKS-2)
  oms_agent {
    log_analytics_workspace_id = var.log_analytics_workspace_id
  }

  # Azure Policy add-on (CIS-Azure-8.6)
  azure_policy_enabled = var.azure_policy_enabled

  # Auto-upgrade
  automatic_channel_upgrade = var.automatic_channel_upgrade

  maintenance_window_auto_upgrade {
    frequency   = "Weekly"
    interval    = 1
    duration    = 4
    day_of_week = "Sunday"
    utc_offset  = "+00:00"
    start_time  = "03:00"
  }

  # Key Vault secrets integration
  key_vault_secrets_provider {
    secret_rotation_enabled  = true
    secret_rotation_interval = "2m"
  }

  tags = var.tags
}

# User node pools
resource "azurerm_kubernetes_cluster_node_pool" "user" {
  for_each = var.user_node_pools

  name                  = each.key
  kubernetes_cluster_id = azurerm_kubernetes_cluster.this.id
  vm_size               = each.value.vm_size
  vnet_subnet_id        = var.subnet_id
  os_disk_size_gb       = lookup(each.value, "os_disk_size", 128)
  mode                  = "User"
  enable_auto_scaling   = true
  min_count             = each.value.min_count
  max_count             = each.value.max_count
  node_count            = each.value.min_count

  node_labels = lookup(each.value, "labels", {})
  node_taints = lookup(each.value, "taints", [])

  tags = var.tags
}
'''

    def generate_variables(self) -> str:
        return '''\
variable "cluster_name" {
  type        = string
  description = "Name of the AKS cluster."
}

variable "location" {
  type        = string
  description = "Azure region for the cluster."
}

variable "resource_group_name" {
  type        = string
  description = "Resource group to deploy the cluster into."
}

variable "kubernetes_version" {
  type        = string
  description = "Kubernetes version."
  default     = "1.29"
}

variable "sku_tier" {
  type        = string
  description = "AKS SKU tier (Free or Standard)."
  default     = "Standard"
}

variable "subnet_id" {
  type        = string
  description = "Subnet ID for the cluster nodes."
}

variable "admin_group_object_ids" {
  type        = list(string)
  description = "AAD group object IDs with cluster admin access."
  default     = []
}

variable "private_cluster_enabled" {
  type        = bool
  description = "Enable private cluster mode (CIS-Azure-AKS-1)."
  default     = true
}

variable "system_node_count" {
  type        = number
  description = "Initial node count for system node pool."
  default     = 3
}

variable "system_node_vm_size" {
  type        = string
  description = "VM size for system node pool."
  default     = "Standard_D4s_v3"
}

variable "node_os_disk_size" {
  type        = number
  description = "OS disk size in GB for nodes."
  default     = 128
}

variable "system_min_count" {
  type    = number
  default = 2
}

variable "system_max_count" {
  type    = number
  default = 5
}

variable "outbound_type" {
  type        = string
  description = "Outbound routing type (userDefinedRouting for private clusters with UDR)."
  default     = "userDefinedRouting"
}

variable "log_analytics_workspace_id" {
  type        = string
  description = "Log Analytics workspace ID for OMS agent (CIS-Azure-AKS-2)."
}

variable "azure_policy_enabled" {
  type        = bool
  description = "Enable Azure Policy add-on (CIS-Azure-8.6)."
  default     = true
}

variable "automatic_channel_upgrade" {
  type        = string
  description = "Automatic upgrade channel (none, patch, stable, rapid)."
  default     = "stable"
}

variable "user_node_pools" {
  type = map(object({
    vm_size      = string
    min_count    = number
    max_count    = number
    os_disk_size = optional(number, 128)
    labels       = optional(map(string), {})
    taints       = optional(list(string), [])
  }))
  description = "Additional user node pool definitions."
  default     = {}
}

variable "tags" {
  type        = map(string)
  description = "Tags applied to all resources."
  default     = {}
}
'''

    def generate_outputs(self) -> str:
        return '''\
output "cluster_id" {
  value       = azurerm_kubernetes_cluster.this.id
  description = "AKS cluster resource ID."
}

output "cluster_name" {
  value       = azurerm_kubernetes_cluster.this.name
  description = "AKS cluster name."
}

output "kube_config_raw" {
  value       = azurerm_kubernetes_cluster.this.kube_config_raw
  description = "Raw kubeconfig for cluster access."
  sensitive   = true
}

output "host" {
  value       = azurerm_kubernetes_cluster.this.kube_config[0].host
  description = "Kubernetes API server host."
}

output "kubelet_identity" {
  value       = azurerm_kubernetes_cluster.this.kubelet_identity[0].object_id
  description = "Object ID of the kubelet managed identity."
}

output "oidc_issuer_url" {
  value       = azurerm_kubernetes_cluster.this.oidc_issuer_url
  description = "OIDC issuer URL for workload identity."
}
'''

    def generate_tfvars_example(self) -> str:
        return f'''\
cluster_name        = "{self.name}"
location            = "eastus"
resource_group_name = "rg-{self.name}"
kubernetes_version  = "1.29"
subnet_id           = "<subnet-id>"

private_cluster_enabled    = true
azure_policy_enabled       = true
log_analytics_workspace_id = "<workspace-id>"

system_node_vm_size = "Standard_D4s_v3"
system_min_count    = 2
system_max_count    = 5

user_node_pools = {{
  "app" = {{
    vm_size   = "Standard_D8s_v3"
    min_count = 2
    max_count = 20
    labels    = {{ "workload" = "app" }}
  }}
}}

tags = {{
  Environment = "production"
  Project     = "my-project"
  Owner       = "platform-team"
  CostCenter  = "eng-001"
}}
'''
