from dataclasses import dataclass, field
from enum import Enum
from typing import List


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Framework(str, Enum):
    CIS_AWS = "CIS-AWS"
    CIS_AZURE = "CIS-Azure"
    CIS_GCP = "CIS-GCP"
    PCI_DSS = "PCI-DSS"
    HIPAA = "HIPAA"
    GENERAL = "GENERAL"


SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}

SEVERITY_COLORS = {
    Severity.CRITICAL: "bright_red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "blue",
    Severity.INFO: "cyan",
}


@dataclass
class ComplianceViolation:
    rule_id: str
    framework: Framework
    severity: Severity
    title: str
    description: str
    remediation: str
    module_name: str = ""
    auto_fixable: bool = False


@dataclass
class ScanReport:
    module_name: str
    provider: str
    module_type: str
    violations: List[ComplianceViolation] = field(default_factory=list)

    @property
    def critical_count(self) -> int:
        return sum(1 for v in self.violations if v.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for v in self.violations if v.severity == Severity.HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for v in self.violations if v.severity == Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        return sum(1 for v in self.violations if v.severity == Severity.LOW)

    @property
    def passed(self) -> bool:
        return self.critical_count == 0 and self.high_count == 0
