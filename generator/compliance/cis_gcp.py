from typing import Dict, Any, List
from .models import ComplianceViolation, Framework, Severity


def check_vpc(config: Dict[str, Any], name: str) -> List[ComplianceViolation]:
    violations = []

    if config.get("auto_create_subnetworks", False):
        violations.append(ComplianceViolation(
            rule_id="CIS-GCP-3.1",
            framework=Framework.CIS_GCP,
            severity=Severity.HIGH,
            title="VPC Auto Subnet Creation Enabled",
            description="Auto-mode VPCs automatically create subnets in every region. Use custom mode for better control.",
            remediation="Set auto_create_subnetworks: false and define subnets explicitly.",
            module_name=name,
        ))

    if not config.get("enable_flow_logs", True):
        violations.append(ComplianceViolation(
            rule_id="CIS-GCP-3.8",
            framework=Framework.CIS_GCP,
            severity=Severity.HIGH,
            title="VPC Flow Logs Not Enabled",
            description="VPC Flow Logs capture network traffic for monitoring and forensics.",
            remediation="Set enable_flow_logs: true on all subnets.",
            module_name=name,
        ))

    if not config.get("private_google_access", True):
        violations.append(ComplianceViolation(
            rule_id="CIS-GCP-3.9",
            framework=Framework.CIS_GCP,
            severity=Severity.MEDIUM,
            title="Private Google Access Not Enabled",
            description="Private Google Access allows VM instances without public IPs to access Google APIs.",
            remediation="Set private_google_access: true on private subnets.",
            module_name=name,
        ))

    return violations


def check_compute(config: Dict[str, Any], name: str) -> List[ComplianceViolation]:
    violations = []

    if not config.get("shielded_vm", True):
        violations.append(ComplianceViolation(
            rule_id="CIS-GCP-4.8",
            framework=Framework.CIS_GCP,
            severity=Severity.HIGH,
            title="Shielded VM Not Enabled",
            description="Shielded VMs provide verifiable integrity via Secure Boot, vTPM, and Integrity Monitoring.",
            remediation="Set shielded_vm: true with secure_boot, vtpm, and integrity_monitoring.",
            module_name=name,
        ))

    if config.get("enable_serial_ports", False):
        violations.append(ComplianceViolation(
            rule_id="CIS-GCP-4.5",
            framework=Framework.CIS_GCP,
            severity=Severity.HIGH,
            title="Serial Port Access Enabled",
            description="Serial port access should be disabled as it allows access to boot console.",
            remediation="Set enable_serial_ports: false.",
            module_name=name,
        ))

    if not config.get("disk_encryption_key", False) and not config.get("use_google_managed_key", True):
        violations.append(ComplianceViolation(
            rule_id="CIS-GCP-4.6",
            framework=Framework.CIS_GCP,
            severity=Severity.MEDIUM,
            title="Compute Disk Not Encrypted with CMEK",
            description="Use customer-managed encryption keys (CMEK) for disk encryption.",
            remediation="Provide disk_encryption_key (Cloud KMS key) for CMEK encryption.",
            module_name=name,
        ))

    if not config.get("service_account"):
        violations.append(ComplianceViolation(
            rule_id="CIS-GCP-4.1",
            framework=Framework.CIS_GCP,
            severity=Severity.HIGH,
            title="Compute Instance Using Default Service Account",
            description="VMs should use a dedicated service account, not the default compute service account.",
            remediation="Create a dedicated service account and set service_account in config.",
            module_name=name,
        ))

    scopes = config.get("oauth_scopes", [])
    if "https://www.googleapis.com/auth/cloud-platform" in scopes:
        violations.append(ComplianceViolation(
            rule_id="CIS-GCP-4.2",
            framework=Framework.CIS_GCP,
            severity=Severity.HIGH,
            title="Overly Permissive OAuth Scopes",
            description="Using cloud-platform scope grants full access to all GCP APIs. Use minimal scopes.",
            remediation="Remove cloud-platform scope and specify only required API scopes.",
            module_name=name,
        ))

    if not config.get("no_public_ip", False):
        violations.append(ComplianceViolation(
            rule_id="CIS-GCP-4.9",
            framework=Framework.CIS_GCP,
            severity=Severity.HIGH,
            title="Compute Instance Has External IP",
            description="VM instances should not have external (public) IP addresses.",
            remediation="Set no_public_ip: true and use Cloud NAT for outbound internet access.",
            module_name=name,
        ))

    return violations


def check_storage(config: Dict[str, Any], name: str) -> List[ComplianceViolation]:
    violations = []

    if not config.get("uniform_access", True):
        violations.append(ComplianceViolation(
            rule_id="CIS-GCP-5.2",
            framework=Framework.CIS_GCP,
            severity=Severity.HIGH,
            title="Uniform Bucket-Level Access Not Enabled",
            description="Uniform bucket-level access simplifies ACL management and prevents ACL-based public access.",
            remediation="Set uniform_access: true.",
            module_name=name,
        ))

    if config.get("public_access_prevention", "enforced") != "enforced":
        violations.append(ComplianceViolation(
            rule_id="CIS-GCP-5.1",
            framework=Framework.CIS_GCP,
            severity=Severity.CRITICAL,
            title="Public Access Prevention Not Enforced",
            description="Public access prevention must be enforced to block public access to bucket contents.",
            remediation="Set public_access_prevention: enforced.",
            module_name=name,
        ))

    if not config.get("versioning_enabled", True):
        violations.append(ComplianceViolation(
            rule_id="CIS-GCP-5.3",
            framework=Framework.CIS_GCP,
            severity=Severity.MEDIUM,
            title="Object Versioning Not Enabled",
            description="Object versioning enables recovery from accidental deletion or overwrites.",
            remediation="Set versioning_enabled: true.",
            module_name=name,
        ))

    if not config.get("logging_enabled", True):
        violations.append(ComplianceViolation(
            rule_id="CIS-GCP-5.4",
            framework=Framework.CIS_GCP,
            severity=Severity.MEDIUM,
            title="Bucket Access Logging Not Enabled",
            description="Cloud Storage access logging records access requests for auditing.",
            remediation="Set logging_enabled: true.",
            module_name=name,
        ))

    retention = config.get("retention_period_days", 0)
    if retention == 0:
        violations.append(ComplianceViolation(
            rule_id="CIS-GCP-5.5",
            framework=Framework.CIS_GCP,
            severity=Severity.LOW,
            title="No Retention Policy Configured",
            description="A retention policy protects objects from deletion before the retention period expires.",
            remediation="Set retention_period_days to comply with your data retention policy.",
            module_name=name,
        ))

    return violations


def check_gke(config: Dict[str, Any], name: str) -> List[ComplianceViolation]:
    violations = []

    if not config.get("private_cluster", True):
        violations.append(ComplianceViolation(
            rule_id="CIS-GCP-7.1",
            framework=Framework.CIS_GCP,
            severity=Severity.HIGH,
            title="GKE Cluster Is Not Private",
            description="GKE cluster nodes should not have public IP addresses. Use private cluster mode.",
            remediation="Set private_cluster: true.",
            module_name=name,
        ))

    if not config.get("workload_identity", True):
        violations.append(ComplianceViolation(
            rule_id="CIS-GCP-7.4",
            framework=Framework.CIS_GCP,
            severity=Severity.HIGH,
            title="Workload Identity Not Enabled",
            description="Workload Identity allows pods to use IAM service accounts without static credentials.",
            remediation="Set workload_identity: true.",
            module_name=name,
        ))

    if not config.get("network_policy_enabled", True):
        violations.append(ComplianceViolation(
            rule_id="CIS-GCP-7.10",
            framework=Framework.CIS_GCP,
            severity=Severity.HIGH,
            title="GKE Network Policy Not Enabled",
            description="Network policies enforce pod-to-pod traffic rules for better isolation.",
            remediation="Set network_policy_enabled: true.",
            module_name=name,
        ))

    if not config.get("master_authorized_networks", []):
        violations.append(ComplianceViolation(
            rule_id="CIS-GCP-7.5",
            framework=Framework.CIS_GCP,
            severity=Severity.HIGH,
            title="No Authorized Networks for GKE Master",
            description="Control plane access should be restricted to known CIDR ranges.",
            remediation="Set master_authorized_networks with your trusted CIDRs.",
            module_name=name,
        ))

    if not config.get("secrets_encryption_key"):
        violations.append(ComplianceViolation(
            rule_id="CIS-GCP-7.3",
            framework=Framework.CIS_GCP,
            severity=Severity.HIGH,
            title="GKE Secrets Not Encrypted with CMEK",
            description="Application-layer secrets encryption should use a Cloud KMS key.",
            remediation="Set secrets_encryption_key to a Cloud KMS key resource path.",
            module_name=name,
        ))

    if not config.get("shielded_nodes", True):
        violations.append(ComplianceViolation(
            rule_id="CIS-GCP-7.6",
            framework=Framework.CIS_GCP,
            severity=Severity.MEDIUM,
            title="GKE Shielded Nodes Not Enabled",
            description="Shielded GKE nodes provide strong node identity and integrity guarantees.",
            remediation="Set shielded_nodes: true.",
            module_name=name,
        ))

    return violations


def check_sql(config: Dict[str, Any], name: str) -> List[ComplianceViolation]:
    violations = []

    if config.get("public_ip_enabled", False):
        violations.append(ComplianceViolation(
            rule_id="CIS-GCP-6.2",
            framework=Framework.CIS_GCP,
            severity=Severity.CRITICAL,
            title="Cloud SQL Has Public IP",
            description="Cloud SQL instances should use Private IP only to prevent internet exposure.",
            remediation="Set public_ip_enabled: false and configure private_network.",
            module_name=name,
        ))

    if not config.get("backup_enabled", True):
        violations.append(ComplianceViolation(
            rule_id="CIS-GCP-6.7",
            framework=Framework.CIS_GCP,
            severity=Severity.HIGH,
            title="Cloud SQL Automated Backups Not Enabled",
            description="Automated backups ensure database can be recovered to a point in time.",
            remediation="Set backup_enabled: true.",
            module_name=name,
        ))

    if not config.get("ssl_required", True):
        violations.append(ComplianceViolation(
            rule_id="CIS-GCP-6.3",
            framework=Framework.CIS_GCP,
            severity=Severity.HIGH,
            title="SSL Not Required for Cloud SQL Connections",
            description="Cloud SQL instances should require SSL connections to protect data in transit.",
            remediation="Set ssl_required: true.",
            module_name=name,
        ))

    flags = config.get("database_flags", {})
    if flags.get("log_checkpoints") == "off":
        violations.append(ComplianceViolation(
            rule_id="CIS-GCP-6.8",
            framework=Framework.CIS_GCP,
            severity=Severity.MEDIUM,
            title="PostgreSQL log_checkpoints Flag Disabled",
            description="log_checkpoints flag should be enabled for PostgreSQL Cloud SQL instances.",
            remediation="Remove log_checkpoints: off from database_flags.",
            module_name=name,
        ))

    return violations


MODULE_CHECKS = {
    "vpc": check_vpc,
    "compute": check_compute,
    "storage": check_storage,
    "gke": check_gke,
    "sql": check_sql,
}
