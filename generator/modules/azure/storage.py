from ..base import TerraformModule


class AzureStorageModule(TerraformModule):
    MODULE_TYPE = "storage"
    PROVIDER = "azure"
    DESCRIPTION = "Azure Storage Account with HTTPS-only, TLS 1.2, CMK encryption, network restrictions"
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
resource "azurerm_storage_account" "this" {
  name                     = var.storage_account_name
  resource_group_name      = var.resource_group_name
  location                 = var.location
  account_tier             = var.account_tier
  account_replication_type = var.replication_type
  account_kind             = var.account_kind

  # HTTPS only (CIS-Azure-3.1)
  enable_https_traffic_only = true

  # TLS minimum version (CIS-Azure-3.2)
  min_tls_version = "TLS1_2"

  # Infrastructure double encryption (CIS-Azure-3.3)
  infrastructure_encryption_enabled = var.infrastructure_encryption

  # Shared key access (disable for AAD-only auth)
  shared_access_key_enabled = var.shared_access_key_enabled

  blob_properties {
    # Soft delete for blobs (CIS-Azure-3.8)
    delete_retention_policy {
      days = var.blob_soft_delete_days
    }

    container_delete_retention_policy {
      days = var.container_soft_delete_days
    }

    versioning_enabled = var.versioning_enabled
  }

  # Network restrictions (CIS-Azure-3.6)
  network_rules {
    default_action             = var.network_default_action
    ip_rules                   = var.allowed_ip_ranges
    virtual_network_subnet_ids = var.allowed_subnet_ids
    bypass                     = ["AzureServices", "Logging", "Metrics"]
  }

  identity {
    type = "SystemAssigned"
  }

  tags = var.tags
}

# Customer-managed key encryption
resource "azurerm_storage_account_customer_managed_key" "this" {
  count = var.key_vault_key_id != null ? 1 : 0

  storage_account_id = azurerm_storage_account.this.id
  key_vault_id       = var.key_vault_id
  key_name           = var.key_vault_key_name
}

# Diagnostic settings for audit logging
resource "azurerm_monitor_diagnostic_setting" "this" {
  count = var.log_analytics_workspace_id != null ? 1 : 0

  name                       = "${var.storage_account_name}-diag"
  target_resource_id         = azurerm_storage_account.this.id
  log_analytics_workspace_id = var.log_analytics_workspace_id

  metric {
    category = "Transaction"
    enabled  = true
  }
}
'''

    def generate_variables(self) -> str:
        return '''\
variable "storage_account_name" {
  type        = string
  description = "Storage account name (3-24 chars, lowercase alphanumeric)."
}

variable "resource_group_name" {
  type        = string
  description = "Resource group to deploy into."
}

variable "location" {
  type        = string
  description = "Azure region."
}

variable "account_tier" {
  type    = string
  default = "Standard"
}

variable "replication_type" {
  type    = string
  default = "ZRS"
}

variable "account_kind" {
  type    = string
  default = "StorageV2"
}

variable "infrastructure_encryption" {
  type        = bool
  description = "Enable infrastructure-level double encryption (CIS-Azure-3.3)."
  default     = true
}

variable "shared_access_key_enabled" {
  type        = bool
  description = "Allow Shared Key authorization. Disable for AAD-only auth."
  default     = false
}

variable "blob_soft_delete_days" {
  type        = number
  description = "Soft delete retention for blobs in days (CIS-Azure-3.8)."
  default     = 14
}

variable "container_soft_delete_days" {
  type        = number
  description = "Soft delete retention for containers in days."
  default     = 14
}

variable "versioning_enabled" {
  type        = bool
  description = "Enable blob versioning."
  default     = true
}

variable "network_default_action" {
  type        = string
  description = "Default network rule action. Must be Deny for CIS-Azure-3.6."
  default     = "Deny"
}

variable "allowed_ip_ranges" {
  type        = list(string)
  description = "Public IP ranges allowed to access the storage account."
  default     = []
}

variable "allowed_subnet_ids" {
  type        = list(string)
  description = "Subnet IDs allowed to access the storage account."
  default     = []
}

variable "key_vault_id" {
  type        = string
  description = "Key Vault resource ID for customer-managed key."
  default     = null
}

variable "key_vault_key_id" {
  type        = string
  description = "Key Vault key ID for CMK encryption."
  default     = null
}

variable "key_vault_key_name" {
  type        = string
  description = "Key Vault key name."
  default     = null
}

variable "log_analytics_workspace_id" {
  type        = string
  description = "Log Analytics workspace ID for diagnostic settings."
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
output "storage_account_id" {
  value       = azurerm_storage_account.this.id
  description = "Resource ID of the storage account."
}

output "storage_account_name" {
  value       = azurerm_storage_account.this.name
  description = "Name of the storage account."
}

output "primary_blob_endpoint" {
  value       = azurerm_storage_account.this.primary_blob_endpoint
  description = "Primary blob service endpoint."
}

output "primary_connection_string" {
  value       = azurerm_storage_account.this.primary_connection_string
  description = "Primary connection string."
  sensitive   = true
}

output "identity_principal_id" {
  value       = azurerm_storage_account.this.identity[0].principal_id
  description = "Principal ID of the system-assigned managed identity."
}
'''

    def generate_tfvars_example(self) -> str:
        return f'''\
storage_account_name = "{self.name.replace('-', '')[:24]}sa"
resource_group_name  = "rg-{self.name}"
location             = "eastus"
replication_type     = "ZRS"

infrastructure_encryption = true
shared_access_key_enabled = false
versioning_enabled        = true
blob_soft_delete_days     = 14

network_default_action = "Deny"
allowed_subnet_ids = ["<app-subnet-id>"]

tags = {{
  Environment = "production"
  Project     = "my-project"
  Owner       = "platform-team"
  CostCenter  = "eng-001"
}}
'''
