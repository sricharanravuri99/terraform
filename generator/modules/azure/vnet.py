from ..base import TerraformModule


class AzureVNetModule(TerraformModule):
    MODULE_TYPE = "vnet"
    PROVIDER = "azure"
    DESCRIPTION = "Azure Virtual Network with subnets, NSGs, DDoS protection, and NSG flow logs"
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
# ─── DDoS Protection Plan (CIS-Azure-6.1) ────────────────────────────────────

resource "azurerm_network_ddos_protection_plan" "this" {
  count = var.enable_ddos_protection ? 1 : 0

  name                = "${var.name}-ddos-plan"
  location            = var.location
  resource_group_name = var.resource_group_name

  tags = var.tags
}

# ─── Virtual Network ──────────────────────────────────────────────────────────

resource "azurerm_virtual_network" "this" {
  name                = var.name
  location            = var.location
  resource_group_name = var.resource_group_name
  address_space       = var.address_space

  dynamic "ddos_protection_plan" {
    for_each = var.enable_ddos_protection ? [1] : []
    content {
      id     = azurerm_network_ddos_protection_plan.this[0].id
      enable = true
    }
  }

  tags = var.tags
}

# ─── Network Security Groups ──────────────────────────────────────────────────

resource "azurerm_network_security_group" "subnet" {
  for_each = var.subnets

  name                = "${var.name}-${each.key}-nsg"
  location            = var.location
  resource_group_name = var.resource_group_name

  dynamic "security_rule" {
    for_each = lookup(each.value, "nsg_rules", [])
    content {
      name                       = security_rule.value.name
      priority                   = security_rule.value.priority
      direction                  = security_rule.value.direction
      access                     = security_rule.value.access
      protocol                   = security_rule.value.protocol
      source_port_range          = lookup(security_rule.value, "source_port_range", "*")
      destination_port_range     = security_rule.value.destination_port_range
      source_address_prefix      = security_rule.value.source_address_prefix
      destination_address_prefix = security_rule.value.destination_address_prefix
    }
  }

  tags = var.tags
}

# ─── Subnets ──────────────────────────────────────────────────────────────────

resource "azurerm_subnet" "this" {
  for_each = var.subnets

  name                 = each.key
  resource_group_name  = var.resource_group_name
  virtual_network_name = azurerm_virtual_network.this.name
  address_prefixes     = [each.value.address_prefix]

  service_endpoints = lookup(each.value, "service_endpoints", [])

  dynamic "delegation" {
    for_each = lookup(each.value, "delegation", null) != null ? [each.value.delegation] : []
    content {
      name = delegation.value.name
      service_delegation {
        name    = delegation.value.service_name
        actions = lookup(delegation.value, "actions", [])
      }
    }
  }
}

resource "azurerm_subnet_network_security_group_association" "this" {
  for_each = var.subnets

  subnet_id                 = azurerm_subnet.this[each.key].id
  network_security_group_id = azurerm_network_security_group.subnet[each.key].id
}

# ─── NSG Flow Logs (CIS-Azure-6.5.1) ─────────────────────────────────────────

resource "azurerm_log_analytics_workspace" "flow_logs" {
  count = var.enable_flow_logs ? 1 : 0

  name                = "${var.name}-flow-logs-law"
  location            = var.location
  resource_group_name = var.resource_group_name
  sku                 = "PerGB2018"
  retention_in_days   = var.flow_log_retention_days

  tags = var.tags
}

resource "azurerm_network_watcher" "this" {
  count = var.enable_network_watcher ? 1 : 0

  name                = "${var.name}-network-watcher"
  location            = var.location
  resource_group_name = var.resource_group_name

  tags = var.tags
}

resource "azurerm_network_watcher_flow_log" "subnet" {
  for_each = var.enable_flow_logs ? var.subnets : {}

  network_watcher_name = azurerm_network_watcher.this[0].name
  resource_group_name  = var.resource_group_name
  name                 = "${var.name}-${each.key}-flow-log"

  network_security_group_id = azurerm_network_security_group.subnet[each.key].id
  storage_account_id        = var.flow_logs_storage_account_id
  enabled                   = true

  retention_policy {
    enabled = true
    days    = var.flow_log_retention_days
  }

  traffic_analytics {
    enabled               = true
    workspace_id          = azurerm_log_analytics_workspace.flow_logs[0].workspace_id
    workspace_region      = var.location
    workspace_resource_id = azurerm_log_analytics_workspace.flow_logs[0].id
    interval_in_minutes   = 10
  }

  tags = var.tags
}
'''

    def generate_variables(self) -> str:
        return '''\
variable "name" {
  type        = string
  description = "Name prefix for all resources."
}

variable "location" {
  type        = string
  description = "Azure region for deployment."
}

variable "resource_group_name" {
  type        = string
  description = "Resource group to deploy into."
}

variable "address_space" {
  type        = list(string)
  description = "Address space for the virtual network."
  default     = ["10.0.0.0/16"]
}

variable "subnets" {
  type = map(object({
    address_prefix    = string
    service_endpoints = optional(list(string), [])
    nsg_rules = optional(list(object({
      name                       = string
      priority                   = number
      direction                  = string
      access                     = string
      protocol                   = string
      destination_port_range     = string
      source_address_prefix      = string
      destination_address_prefix = string
      source_port_range          = optional(string, "*")
    })), [])
    delegation = optional(object({
      name         = string
      service_name = string
      actions      = optional(list(string), [])
    }))
  }))
  description = "Map of subnet definitions."
  default     = {}
}

variable "enable_ddos_protection" {
  type        = bool
  description = "Enable Azure DDoS Network Protection (CIS-Azure-6.1). Note: incurs additional cost."
  default     = false
}

variable "enable_network_watcher" {
  type        = bool
  description = "Deploy Network Watcher for this region."
  default     = true
}

variable "enable_flow_logs" {
  type        = bool
  description = "Enable NSG flow logs (CIS-Azure-6.5.1)."
  default     = true
}

variable "flow_log_retention_days" {
  type        = number
  description = "Retention period for flow logs in days."
  default     = 90
}

variable "flow_logs_storage_account_id" {
  type        = string
  description = "Storage account ID for NSG flow log storage."
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
output "vnet_id" {
  description = "ID of the virtual network."
  value       = azurerm_virtual_network.this.id
}

output "vnet_name" {
  description = "Name of the virtual network."
  value       = azurerm_virtual_network.this.name
}

output "subnet_ids" {
  description = "Map of subnet name to subnet ID."
  value       = { for k, v in azurerm_subnet.this : k => v.id }
}

output "nsg_ids" {
  description = "Map of subnet name to NSG ID."
  value       = { for k, v in azurerm_network_security_group.subnet : k => v.id }
}
'''

    def generate_tfvars_example(self) -> str:
        return f'''\
name                = "{self.name}"
location            = "eastus"
resource_group_name = "rg-{self.name}"
address_space       = ["10.0.0.0/16"]

subnets = {{
  "app-subnet" = {{
    address_prefix    = "10.0.1.0/24"
    service_endpoints = ["Microsoft.Storage", "Microsoft.KeyVault"]
    nsg_rules = [
      {{
        name                       = "AllowHTTPS"
        priority                   = 100
        direction                  = "Inbound"
        access                     = "Allow"
        protocol                   = "Tcp"
        destination_port_range     = "443"
        source_address_prefix      = "10.0.0.0/8"
        destination_address_prefix = "*"
      }}
    ]
  }}
  "db-subnet" = {{
    address_prefix = "10.0.11.0/24"
    nsg_rules      = []
  }}
}}

enable_ddos_protection = true
enable_flow_logs       = true
flow_log_retention_days = 90

tags = {{
  Environment = "production"
  Project     = "my-project"
  Owner       = "platform-team"
  CostCenter  = "eng-001"
}}
'''
