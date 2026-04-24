"""PCI-DSS v4.0 compliance rules applicable across all cloud providers."""
from typing import Dict, Any, List
from .models import ComplianceViolation, Framework, Severity


def check_encryption(config: Dict[str, Any], name: str, module_type: str) -> List[ComplianceViolation]:
    violations = []
    encryption_fields = [
        "encryption_enabled", "encryption_at_rest", "disk_encryption",
        "ebs_encrypted", "tde_enabled",
    ]
    has_encryption = any(config.get(f, True) for f in encryption_fields)
    if not has_encryption:
        violations.append(ComplianceViolation(
            rule_id="PCI-DSS-3.5",
            framework=Framework.PCI_DSS,
            severity=Severity.CRITICAL,
            title="Data Not Encrypted at Rest",
            description="PCI DSS Req 3.5 requires strong cryptography to protect stored cardholder data.",
            remediation="Enable encryption at rest using a customer-managed key.",
            module_name=name,
        ))

    tls_fields = ["https_traffic_only", "enforce_tls", "ssl_required"]
    has_tls = any(config.get(f, True) for f in tls_fields)
    if not has_tls:
        violations.append(ComplianceViolation(
            rule_id="PCI-DSS-4.2",
            framework=Framework.PCI_DSS,
            severity=Severity.CRITICAL,
            title="TLS/HTTPS Not Enforced",
            description="PCI DSS Req 4.2 requires strong cryptography for data in transit.",
            remediation="Enable HTTPS/TLS enforcement on all endpoints.",
            module_name=name,
        ))

    return violations


def check_access_control(config: Dict[str, Any], name: str, module_type: str) -> List[ComplianceViolation]:
    violations = []

    if config.get("publicly_accessible", False) or config.get("public_ip_enabled", False):
        violations.append(ComplianceViolation(
            rule_id="PCI-DSS-1.3",
            framework=Framework.PCI_DSS,
            severity=Severity.CRITICAL,
            title="Resource Directly Accessible from Internet",
            description="PCI DSS Req 1.3 prohibits direct public internet connectivity to cardholder data environment.",
            remediation="Disable public access and route traffic through load balancers with WAF.",
            module_name=name,
        ))

    if config.get("block_public_access") is False:
        violations.append(ComplianceViolation(
            rule_id="PCI-DSS-1.3.1",
            framework=Framework.PCI_DSS,
            severity=Severity.CRITICAL,
            title="Public Access Not Blocked on Storage",
            description="PCI DSS requires cardholder data to not be publicly accessible.",
            remediation="Enable block_public_access on all storage resources.",
            module_name=name,
        ))

    return violations


def check_logging(config: Dict[str, Any], name: str, module_type: str) -> List[ComplianceViolation]:
    violations = []

    log_fields = [
        "enable_flow_logs", "access_logging_enabled", "auditing_enabled",
        "enable_logging", "logging_enabled",
    ]
    has_logging = any(config.get(f, True) for f in log_fields)
    if not has_logging:
        violations.append(ComplianceViolation(
            rule_id="PCI-DSS-10.2",
            framework=Framework.PCI_DSS,
            severity=Severity.HIGH,
            title="Audit Logging Not Enabled",
            description="PCI DSS Req 10.2 requires audit log implementation for all components.",
            remediation="Enable audit/access logging for this resource.",
            module_name=name,
        ))

    retention_fields = ["flow_log_retention_days", "backup_retention_days", "audit_retention_days"]
    for field in retention_fields:
        days = config.get(field, 0)
        if 0 < days < 365:
            violations.append(ComplianceViolation(
                rule_id="PCI-DSS-10.7",
                framework=Framework.PCI_DSS,
                severity=Severity.HIGH,
                title=f"Log Retention Too Short for PCI-DSS ({field}={days}d)",
                description="PCI DSS Req 10.7 requires at least 12 months of audit log history.",
                remediation=f"Set {field} to 365 or greater.",
                module_name=name,
            ))

    return violations


def check_vulnerability_management(config: Dict[str, Any], name: str, module_type: str) -> List[ComplianceViolation]:
    violations = []

    patch_fields = ["auto_minor_version_upgrade", "auto_upgrade", "automatic_channel_upgrade"]
    has_auto_patch = any(config.get(f, True) for f in patch_fields)
    if not has_auto_patch:
        violations.append(ComplianceViolation(
            rule_id="PCI-DSS-6.3",
            framework=Framework.PCI_DSS,
            severity=Severity.MEDIUM,
            title="Automatic Patching Not Enabled",
            description="PCI DSS Req 6.3 requires timely security patch deployment.",
            remediation="Enable automatic minor version upgrades or auto-patching.",
            module_name=name,
        ))

    return violations


def run_all_checks(config: Dict[str, Any], name: str, module_type: str) -> List[ComplianceViolation]:
    violations = []
    violations.extend(check_encryption(config, name, module_type))
    violations.extend(check_access_control(config, name, module_type))
    violations.extend(check_logging(config, name, module_type))
    violations.extend(check_vulnerability_management(config, name, module_type))
    return violations
