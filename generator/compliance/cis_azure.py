from typing import Dict, Any, List
from .models import ComplianceViolation, Framework, Severity


def check_vnet(config: Dict[str, Any], name: str) -> List[ComplianceViolation]:
    violations = []

    if not config.get("enable_ddos_protection", False):
        violations.append(ComplianceViolation(
            rule_id="CIS-Azure-6.1",
            framework=Framework.CIS_AZURE,
            severity=Severity.MEDIUM,
            title="Azure DDoS Protection Not Enabled",
            description="Azure DDoS Network Protection provides enhanced mitigation for DDoS attacks.",
            remediation="Set enable_ddos_protection: true for production VNets.",
            module_name=name,
        ))

    if not config.get("enable_network_watcher", True):
        violations.append(ComplianceViolation(
            rule_id="CIS-Azure-6.5",
            framework=Framework.CIS_AZURE,
            severity=Severity.MEDIUM,
            title="Network Watcher Not Enabled",
            description="Network Watcher should be enabled for monitoring and diagnostics.",
            remediation="Set enable_network_watcher: true.",
            module_name=name,
        ))

    if not config.get("enable_flow_logs", True):
        violations.append(ComplianceViolation(
            rule_id="CIS-Azure-6.5.1",
            framework=Framework.CIS_AZURE,
            severity=Severity.HIGH,
            title="NSG Flow Logs Not Enabled",
            description="NSG flow logs should be enabled to capture network traffic information.",
            remediation="Set enable_flow_logs: true.",
            module_name=name,
        ))

    return violations


def check_vm(config: Dict[str, Any], name: str) -> List[ComplianceViolation]:
    violations = []

    if not config.get("disk_encryption", True):
        violations.append(ComplianceViolation(
            rule_id="CIS-Azure-7.2",
            framework=Framework.CIS_AZURE,
            severity=Severity.HIGH,
            title="Azure VM Disk Not Encrypted",
            description="Virtual machine disks should be encrypted with Azure Disk Encryption.",
            remediation="Set disk_encryption: true.",
            module_name=name,
        ))

    if not config.get("boot_diagnostics_enabled", True):
        violations.append(ComplianceViolation(
            rule_id="CIS-Azure-7.4",
            framework=Framework.CIS_AZURE,
            severity=Severity.MEDIUM,
            title="VM Boot Diagnostics Not Enabled",
            description="Boot diagnostics help diagnose VM failures and should be enabled.",
            remediation="Set boot_diagnostics_enabled: true.",
            module_name=name,
        ))

    if config.get("public_ip_enabled", False):
        violations.append(ComplianceViolation(
            rule_id="CIS-Azure-VM-1",
            framework=Framework.CIS_AZURE,
            severity=Severity.HIGH,
            title="VM Has Public IP Attached",
            description="VMs should not have public IPs directly attached. Use a load balancer instead.",
            remediation="Set public_ip_enabled: false and use Azure Load Balancer.",
            module_name=name,
        ))

    if not config.get("managed_identity_enabled", True):
        violations.append(ComplianceViolation(
            rule_id="CIS-Azure-VM-2",
            framework=Framework.CIS_AZURE,
            severity=Severity.LOW,
            title="VM Managed Identity Not Enabled",
            description="Use managed identities to authenticate to Azure services without storing credentials.",
            remediation="Set managed_identity_enabled: true.",
            module_name=name,
        ))

    return violations


def check_storage(config: Dict[str, Any], name: str) -> List[ComplianceViolation]:
    violations = []

    if not config.get("https_traffic_only", True):
        violations.append(ComplianceViolation(
            rule_id="CIS-Azure-3.1",
            framework=Framework.CIS_AZURE,
            severity=Severity.HIGH,
            title="Storage Account Allows HTTP Traffic",
            description="Storage accounts should only allow HTTPS traffic to protect data in transit.",
            remediation="Set https_traffic_only: true.",
            module_name=name,
        ))

    tls_version = config.get("min_tls_version", "TLS1_2")
    if tls_version not in ["TLS1_2", "TLS1_3"]:
        violations.append(ComplianceViolation(
            rule_id="CIS-Azure-3.2",
            framework=Framework.CIS_AZURE,
            severity=Severity.HIGH,
            title="Storage Account Uses Old TLS Version",
            description=f"Minimum TLS version is {tls_version}. CIS requires TLS 1.2 or higher.",
            remediation="Set min_tls_version: TLS1_2.",
            module_name=name,
        ))

    if not config.get("blob_soft_delete_enabled", True):
        violations.append(ComplianceViolation(
            rule_id="CIS-Azure-3.8",
            framework=Framework.CIS_AZURE,
            severity=Severity.MEDIUM,
            title="Blob Soft Delete Not Enabled",
            description="Soft delete protects against accidental blob deletion.",
            remediation="Set blob_soft_delete_enabled: true.",
            module_name=name,
        ))

    if not config.get("infrastructure_encryption", False):
        violations.append(ComplianceViolation(
            rule_id="CIS-Azure-3.3",
            framework=Framework.CIS_AZURE,
            severity=Severity.MEDIUM,
            title="Infrastructure Double Encryption Not Enabled",
            description="Enable infrastructure encryption for a second layer of encryption at rest.",
            remediation="Set infrastructure_encryption: true.",
            module_name=name,
        ))

    network_rules = config.get("network_rules_default_action", "Deny")
    if network_rules != "Deny":
        violations.append(ComplianceViolation(
            rule_id="CIS-Azure-3.6",
            framework=Framework.CIS_AZURE,
            severity=Severity.HIGH,
            title="Storage Account Network Rules Allow All Traffic",
            description="Default network rule action should be Deny to restrict access to known networks.",
            remediation="Set network_rules_default_action: Deny and whitelist specific subnets.",
            module_name=name,
        ))

    return violations


def check_aks(config: Dict[str, Any], name: str) -> List[ComplianceViolation]:
    violations = []

    if not config.get("rbac_enabled", True):
        violations.append(ComplianceViolation(
            rule_id="CIS-Azure-8.5",
            framework=Framework.CIS_AZURE,
            severity=Severity.CRITICAL,
            title="AKS RBAC Not Enabled",
            description="Role-based access control must be enabled on AKS clusters.",
            remediation="Set rbac_enabled: true.",
            module_name=name,
        ))

    if not config.get("azure_policy_enabled", False):
        violations.append(ComplianceViolation(
            rule_id="CIS-Azure-8.6",
            framework=Framework.CIS_AZURE,
            severity=Severity.MEDIUM,
            title="Azure Policy Add-on Not Enabled",
            description="Azure Policy add-on enforces governance at scale on AKS clusters.",
            remediation="Set azure_policy_enabled: true.",
            module_name=name,
        ))

    if config.get("private_cluster_enabled", False) is False:
        violations.append(ComplianceViolation(
            rule_id="CIS-Azure-AKS-1",
            framework=Framework.CIS_AZURE,
            severity=Severity.HIGH,
            title="AKS API Server Not Private",
            description="AKS cluster API server should be private to restrict access from internet.",
            remediation="Set private_cluster_enabled: true.",
            module_name=name,
        ))

    if not config.get("enable_oms_agent", True):
        violations.append(ComplianceViolation(
            rule_id="CIS-Azure-AKS-2",
            framework=Framework.CIS_AZURE,
            severity=Severity.MEDIUM,
            title="Azure Monitor for Containers Not Enabled",
            description="OMS agent should be enabled for monitoring and log collection.",
            remediation="Set enable_oms_agent: true.",
            module_name=name,
        ))

    return violations


def check_sql(config: Dict[str, Any], name: str) -> List[ComplianceViolation]:
    violations = []

    if not config.get("tde_enabled", True):
        violations.append(ComplianceViolation(
            rule_id="CIS-Azure-4.1.2",
            framework=Framework.CIS_AZURE,
            severity=Severity.HIGH,
            title="Azure SQL TDE Not Enabled",
            description="Transparent Data Encryption must be enabled on all SQL databases.",
            remediation="Set tde_enabled: true.",
            module_name=name,
        ))

    if not config.get("threat_detection_enabled", True):
        violations.append(ComplianceViolation(
            rule_id="CIS-Azure-4.1.1",
            framework=Framework.CIS_AZURE,
            severity=Severity.HIGH,
            title="SQL Advanced Threat Detection Not Enabled",
            description="Advanced Threat Detection provides alerts on anomalous database activity.",
            remediation="Set threat_detection_enabled: true.",
            module_name=name,
        ))

    if not config.get("auditing_enabled", True):
        violations.append(ComplianceViolation(
            rule_id="CIS-Azure-4.1.3",
            framework=Framework.CIS_AZURE,
            severity=Severity.HIGH,
            title="SQL Auditing Not Enabled",
            description="SQL auditing tracks database events and writes them to an audit log.",
            remediation="Set auditing_enabled: true.",
            module_name=name,
        ))

    retention = config.get("audit_retention_days", 90)
    if retention < 90:
        violations.append(ComplianceViolation(
            rule_id="CIS-Azure-4.1.4",
            framework=Framework.CIS_AZURE,
            severity=Severity.MEDIUM,
            title="SQL Audit Retention Period Too Short",
            description=f"Audit log retention is {retention} days. CIS requires >= 90 days.",
            remediation="Set audit_retention_days: 90 or greater.",
            module_name=name,
        ))

    return violations


MODULE_CHECKS = {
    "vnet": check_vnet,
    "vm": check_vm,
    "storage": check_storage,
    "aks": check_aks,
    "sql": check_sql,
}
