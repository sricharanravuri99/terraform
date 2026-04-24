from typing import Dict, Any, List
from .models import ComplianceViolation, ScanReport, Framework, Severity
from . import cis_aws, cis_azure, cis_gcp, pci_dss, hipaa, general


PROVIDER_CIS_CHECKS = {
    "aws": cis_aws.MODULE_CHECKS,
    "azure": cis_azure.MODULE_CHECKS,
    "gcp": cis_gcp.MODULE_CHECKS,
}

FRAMEWORK_LABELS = {
    "cis": "CIS Benchmark",
    "pci-dss": "PCI-DSS v4.0",
    "hipaa": "HIPAA Security Rule",
    "all": "All Frameworks",
}


def scan_module(
    provider: str,
    module_type: str,
    name: str,
    config: Dict[str, Any],
    frameworks: List[str],
) -> ScanReport:
    report = ScanReport(module_name=name, provider=provider, module_type=module_type)

    run_cis = "cis" in frameworks or "all" in frameworks
    run_pci = "pci-dss" in frameworks or "all" in frameworks
    run_hipaa = "hipaa" in frameworks or "all" in frameworks
    run_general = "general" in frameworks or "all" in frameworks

    if run_cis:
        provider_checks = PROVIDER_CIS_CHECKS.get(provider, {})
        check_fn = provider_checks.get(module_type)
        if check_fn:
            report.violations.extend(check_fn(config, name))

    if run_pci:
        report.violations.extend(pci_dss.run_all_checks(config, name, module_type))

    if run_hipaa:
        report.violations.extend(hipaa.run_all_checks(config, name, module_type))

    if run_general:
        report.violations.extend(general.run_all_checks(config, name, module_type, provider))

    # Deduplicate by rule_id
    seen = set()
    unique = []
    for v in report.violations:
        if v.rule_id not in seen:
            seen.add(v.rule_id)
            unique.append(v)
    report.violations = sorted(unique, key=lambda v: (
        ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].index(v.severity.value), v.rule_id
    ))

    return report
