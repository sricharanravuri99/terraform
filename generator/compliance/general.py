"""General Terraform best practices and tagging compliance."""
from typing import Dict, Any, List
from .models import ComplianceViolation, Framework, Severity

REQUIRED_TAGS = ["Environment", "Owner", "Project", "CostCenter"]


def run_all_checks(config: Dict[str, Any], name: str, module_type: str, provider: str) -> List[ComplianceViolation]:
    violations = []

    # Tagging compliance
    tags = config.get("tags", {})
    missing_tags = [t for t in REQUIRED_TAGS if t not in tags]
    if missing_tags:
        violations.append(ComplianceViolation(
            rule_id="GENERAL-TAG-1",
            framework=Framework.GENERAL,
            severity=Severity.MEDIUM,
            title=f"Missing Required Tags: {', '.join(missing_tags)}",
            description="All resources must be tagged with standard metadata for cost allocation and ownership.",
            remediation=f"Add these tags to your module config: {', '.join(missing_tags)}.",
            module_name=name,
        ))

    # Remote state check (only relevant at root module level)
    if module_type in ["vpc", "vnet"] and not config.get("remote_state_configured", False):
        violations.append(ComplianceViolation(
            rule_id="GENERAL-STATE-1",
            framework=Framework.GENERAL,
            severity=Severity.MEDIUM,
            title="Remote Terraform State Not Configured",
            description="Terraform state should be stored remotely (S3+DynamoDB, Azure Storage, GCS) with state locking.",
            remediation="Configure a remote backend in your root module.",
            module_name=name,
        ))

    # Provider version pinning
    if not config.get("provider_version_pinned", True):
        violations.append(ComplianceViolation(
            rule_id="GENERAL-VER-1",
            framework=Framework.GENERAL,
            severity=Severity.LOW,
            title="Provider Version Not Pinned",
            description="Provider versions should be pinned to avoid unintended breaking changes.",
            remediation="Pin provider version with ~> constraint in versions.tf.",
            module_name=name,
        ))

    # Cost management
    if not config.get("tags", {}).get("CostCenter"):
        violations.append(ComplianceViolation(
            rule_id="GENERAL-COST-1",
            framework=Framework.GENERAL,
            severity=Severity.LOW,
            title="No CostCenter Tag for Cost Allocation",
            description="CostCenter tag is required for accurate cloud cost allocation and chargeback.",
            remediation="Add CostCenter tag to the tags block.",
            module_name=name,
        ))

    # Module documentation
    if not config.get("description"):
        violations.append(ComplianceViolation(
            rule_id="GENERAL-DOC-1",
            framework=Framework.GENERAL,
            severity=Severity.INFO,
            title="Module Has No Description",
            description="Modules should have a description for documentation purposes.",
            remediation="Add a description field to your module configuration.",
            module_name=name,
        ))

    return violations
