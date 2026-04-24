"""HIPAA Security Rule compliance checks applicable across cloud providers."""
from typing import Dict, Any, List
from .models import ComplianceViolation, Framework, Severity


def run_all_checks(config: Dict[str, Any], name: str, module_type: str) -> List[ComplianceViolation]:
    violations = []

    # §164.312(a)(1) - Access Control
    if config.get("publicly_accessible", False) or config.get("public_ip_enabled", False) or config.get("block_public_access") is False:
        violations.append(ComplianceViolation(
            rule_id="HIPAA-164.312(a)(1)",
            framework=Framework.HIPAA,
            severity=Severity.CRITICAL,
            title="Resource Publicly Accessible - PHI Risk",
            description="HIPAA §164.312(a)(1) requires access controls to limit access to ePHI to authorized persons only.",
            remediation="Disable all public access. Route access through private network and VPN/bastion.",
            module_name=name,
        ))

    # §164.312(a)(2)(iv) - Encryption and Decryption
    encryption_fields = [
        "encryption_enabled", "encryption_at_rest", "disk_encryption",
        "ebs_encrypted", "tde_enabled",
    ]
    has_encryption = any(config.get(f, True) for f in encryption_fields)
    if not has_encryption:
        violations.append(ComplianceViolation(
            rule_id="HIPAA-164.312(a)(2)(iv)",
            framework=Framework.HIPAA,
            severity=Severity.CRITICAL,
            title="No Encryption at Rest for Potential PHI",
            description="HIPAA §164.312(a)(2)(iv) addressable spec requires encryption of ePHI at rest.",
            remediation="Enable encryption at rest with a customer-managed KMS key.",
            module_name=name,
        ))

    # §164.312(e)(1) - Transmission Security
    tls_fields = ["https_traffic_only", "enforce_tls", "ssl_required"]
    has_tls = any(config.get(f, True) for f in tls_fields)
    if not has_tls:
        violations.append(ComplianceViolation(
            rule_id="HIPAA-164.312(e)(1)",
            framework=Framework.HIPAA,
            severity=Severity.CRITICAL,
            title="Transmission Security Not Enforced",
            description="HIPAA §164.312(e)(1) requires technical security measures to guard against unauthorized access to ePHI in transit.",
            remediation="Enforce HTTPS/TLS for all data in transit.",
            module_name=name,
        ))

    # §164.312(b) - Audit Controls
    log_fields = ["enable_flow_logs", "access_logging_enabled", "auditing_enabled", "enable_logging", "logging_enabled"]
    has_logging = any(config.get(f, True) for f in log_fields)
    if not has_logging:
        violations.append(ComplianceViolation(
            rule_id="HIPAA-164.312(b)",
            framework=Framework.HIPAA,
            severity=Severity.HIGH,
            title="Audit Logging Not Enabled",
            description="HIPAA §164.312(b) requires hardware, software, and procedural mechanisms to record activity.",
            remediation="Enable comprehensive audit logging for all access to PHI-related resources.",
            module_name=name,
        ))

    # §164.308(a)(7)(ii)(A) - Data Backup
    backup_fields = ["backup_enabled", "versioning_enabled", "multi_az", "blob_soft_delete_enabled"]
    has_backup = any(config.get(f, False) for f in backup_fields)
    if not has_backup:
        violations.append(ComplianceViolation(
            rule_id="HIPAA-164.308(a)(7)(ii)(A)",
            framework=Framework.HIPAA,
            severity=Severity.HIGH,
            title="No Backup or Redundancy Configured",
            description="HIPAA §164.308(a)(7)(ii)(A) requires data backup plans for ePHI.",
            remediation="Enable backups, versioning, or multi-AZ for data redundancy.",
            module_name=name,
        ))

    # §164.312(c)(1) - Integrity Controls
    if not config.get("deletion_protection", False) and module_type in ["rds", "sql"]:
        violations.append(ComplianceViolation(
            rule_id="HIPAA-164.312(c)(1)",
            framework=Framework.HIPAA,
            severity=Severity.MEDIUM,
            title="No Deletion Protection on Database",
            description="HIPAA §164.312(c)(1) requires integrity controls to ensure ePHI is not improperly altered or destroyed.",
            remediation="Set deletion_protection: true on all databases storing PHI.",
            module_name=name,
        ))

    return violations
