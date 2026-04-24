from typing import Dict, Any, List
from .models import ComplianceViolation, Framework, Severity


def check_vpc(config: Dict[str, Any], name: str) -> List[ComplianceViolation]:
    violations = []

    if not config.get("enable_flow_logs", True):
        violations.append(ComplianceViolation(
            rule_id="CIS-AWS-3.9",
            framework=Framework.CIS_AWS,
            severity=Severity.HIGH,
            title="VPC Flow Logging Not Enabled",
            description="VPC flow logs should be enabled to capture network traffic for auditing.",
            remediation="Set enable_flow_logs: true in your VPC module config.",
            module_name=name,
        ))

    if not config.get("kms_key_arn") and not config.get("kms_key_id"):
        violations.append(ComplianceViolation(
            rule_id="CIS-AWS-3.9.1",
            framework=Framework.CIS_AWS,
            severity=Severity.MEDIUM,
            title="VPC Flow Logs Not Encrypted with KMS",
            description="CloudWatch log group for flow logs should be encrypted with a customer-managed KMS key.",
            remediation="Provide kms_key_arn in your VPC module config.",
            module_name=name,
        ))

    retention = config.get("flow_log_retention_days", 90)
    if retention < 365:
        violations.append(ComplianceViolation(
            rule_id="CIS-AWS-3.9.2",
            framework=Framework.CIS_AWS,
            severity=Severity.LOW,
            title="VPC Flow Log Retention Period Too Short",
            description=f"Flow logs retained for {retention} days. CIS recommends >= 365 days.",
            remediation="Set flow_log_retention_days: 365 or greater.",
            module_name=name,
        ))

    if not config.get("enable_nat_gateway", True) and config.get("private_subnet_cidrs"):
        violations.append(ComplianceViolation(
            rule_id="CIS-AWS-VPC-1",
            framework=Framework.CIS_AWS,
            severity=Severity.MEDIUM,
            title="Private Subnets Without NAT Gateway",
            description="Private subnets are defined but NAT gateway is disabled; resources cannot reach internet for patches.",
            remediation="Set enable_nat_gateway: true.",
            module_name=name,
        ))

    return violations


def check_ec2(config: Dict[str, Any], name: str) -> List[ComplianceViolation]:
    violations = []

    if not config.get("ebs_encrypted", True):
        violations.append(ComplianceViolation(
            rule_id="CIS-AWS-2.2.1",
            framework=Framework.CIS_AWS,
            severity=Severity.HIGH,
            title="EBS Volume Not Encrypted",
            description="EBS volumes must be encrypted at rest to protect sensitive data.",
            remediation="Set ebs_encrypted: true in your EC2 module config.",
            module_name=name,
        ))

    if not config.get("require_imdsv2", True):
        violations.append(ComplianceViolation(
            rule_id="CIS-AWS-5.6",
            framework=Framework.CIS_AWS,
            severity=Severity.HIGH,
            title="IMDSv2 Not Required",
            description="EC2 instance metadata service should require IMDSv2 to prevent SSRF attacks.",
            remediation="Set require_imdsv2: true in your EC2 module config.",
            module_name=name,
        ))

    if config.get("associate_public_ip", False):
        violations.append(ComplianceViolation(
            rule_id="CIS-AWS-5.4",
            framework=Framework.CIS_AWS,
            severity=Severity.HIGH,
            title="EC2 Instance Has Public IP",
            description="Instances should not have public IPs unless explicitly required. Use a load balancer instead.",
            remediation="Set associate_public_ip: false and use a load balancer.",
            module_name=name,
        ))

    if not config.get("monitoring_enabled", True):
        violations.append(ComplianceViolation(
            rule_id="CIS-AWS-EC2-1",
            framework=Framework.CIS_AWS,
            severity=Severity.MEDIUM,
            title="Detailed Monitoring Not Enabled",
            description="EC2 detailed monitoring provides 1-minute metrics for better observability.",
            remediation="Set monitoring_enabled: true.",
            module_name=name,
        ))

    ingress_ports = config.get("ingress_ports", [])
    open_to_world = [p for p in ingress_ports if p.get("cidr") in ["0.0.0.0/0", "::/0"]]
    dangerous_ports = {22, 3389, 3306, 5432, 27017, 6379}
    for rule in open_to_world:
        port = rule.get("port", 0)
        if port in dangerous_ports:
            violations.append(ComplianceViolation(
                rule_id="CIS-AWS-5.2",
                framework=Framework.CIS_AWS,
                severity=Severity.CRITICAL,
                title=f"Port {port} Open to 0.0.0.0/0",
                description=f"Security group allows unrestricted inbound access on port {port} from the internet.",
                remediation=f"Restrict port {port} to known CIDRs or use a bastion host / VPN.",
                module_name=name,
            ))

    return violations


def check_s3(config: Dict[str, Any], name: str) -> List[ComplianceViolation]:
    violations = []

    if not config.get("block_public_access", True):
        violations.append(ComplianceViolation(
            rule_id="CIS-AWS-2.1.5",
            framework=Framework.CIS_AWS,
            severity=Severity.CRITICAL,
            title="S3 Bucket Public Access Not Blocked",
            description="S3 public access block settings must be enabled to prevent accidental public exposure.",
            remediation="Set block_public_access: true.",
            module_name=name,
        ))

    if not config.get("encryption_enabled", True):
        violations.append(ComplianceViolation(
            rule_id="CIS-AWS-2.1.1",
            framework=Framework.CIS_AWS,
            severity=Severity.HIGH,
            title="S3 Bucket Not Encrypted",
            description="S3 buckets must be encrypted with SSE-KMS or SSE-S3.",
            remediation="Set encryption_enabled: true and optionally provide kms_key_arn.",
            module_name=name,
        ))

    if config.get("encryption_enabled", True) and not config.get("kms_key_arn"):
        violations.append(ComplianceViolation(
            rule_id="CIS-AWS-2.1.1.1",
            framework=Framework.CIS_AWS,
            severity=Severity.MEDIUM,
            title="S3 Not Encrypted with Customer-Managed Key",
            description="S3 should use SSE-KMS with a customer-managed key (CMK) for full control over encryption.",
            remediation="Provide kms_key_arn for CMK-based encryption.",
            module_name=name,
        ))

    if not config.get("versioning_enabled", True):
        violations.append(ComplianceViolation(
            rule_id="CIS-AWS-2.1.3",
            framework=Framework.CIS_AWS,
            severity=Severity.HIGH,
            title="S3 Versioning Not Enabled",
            description="S3 versioning protects against accidental deletion and enables point-in-time recovery.",
            remediation="Set versioning_enabled: true.",
            module_name=name,
        ))

    if not config.get("access_logging_enabled", True):
        violations.append(ComplianceViolation(
            rule_id="CIS-AWS-2.1.2",
            framework=Framework.CIS_AWS,
            severity=Severity.MEDIUM,
            title="S3 Access Logging Not Enabled",
            description="S3 server access logging provides detailed records of requests for security auditing.",
            remediation="Set access_logging_enabled: true.",
            module_name=name,
        ))

    if not config.get("enforce_tls", True):
        violations.append(ComplianceViolation(
            rule_id="CIS-AWS-2.1.4",
            framework=Framework.CIS_AWS,
            severity=Severity.HIGH,
            title="S3 Does Not Enforce TLS",
            description="S3 bucket policy should deny HTTP requests and only allow HTTPS.",
            remediation="Set enforce_tls: true.",
            module_name=name,
        ))

    return violations


def check_rds(config: Dict[str, Any], name: str) -> List[ComplianceViolation]:
    violations = []

    if not config.get("encryption_at_rest", True):
        violations.append(ComplianceViolation(
            rule_id="CIS-AWS-2.3.1",
            framework=Framework.CIS_AWS,
            severity=Severity.HIGH,
            title="RDS Storage Not Encrypted",
            description="RDS instances must have storage encryption enabled.",
            remediation="Set encryption_at_rest: true.",
            module_name=name,
        ))

    if config.get("publicly_accessible", False):
        violations.append(ComplianceViolation(
            rule_id="CIS-AWS-2.3.2",
            framework=Framework.CIS_AWS,
            severity=Severity.CRITICAL,
            title="RDS Instance Publicly Accessible",
            description="RDS instances should not be publicly accessible from the internet.",
            remediation="Set publicly_accessible: false and use VPC connectivity.",
            module_name=name,
        ))

    if not config.get("multi_az", False):
        violations.append(ComplianceViolation(
            rule_id="CIS-AWS-RDS-1",
            framework=Framework.CIS_AWS,
            severity=Severity.MEDIUM,
            title="RDS Multi-AZ Not Enabled",
            description="Multi-AZ deployments provide enhanced availability and data durability.",
            remediation="Set multi_az: true for production workloads.",
            module_name=name,
        ))

    backup_retention = config.get("backup_retention_days", 7)
    if backup_retention < 7:
        violations.append(ComplianceViolation(
            rule_id="CIS-AWS-2.3.3",
            framework=Framework.CIS_AWS,
            severity=Severity.HIGH,
            title="RDS Backup Retention Too Short",
            description=f"Backup retention is {backup_retention} days. CIS requires >= 7 days.",
            remediation="Set backup_retention_days: 7 or greater.",
            module_name=name,
        ))

    if not config.get("deletion_protection", True):
        violations.append(ComplianceViolation(
            rule_id="CIS-AWS-RDS-2",
            framework=Framework.CIS_AWS,
            severity=Severity.MEDIUM,
            title="RDS Deletion Protection Not Enabled",
            description="Deletion protection prevents accidental database deletion.",
            remediation="Set deletion_protection: true.",
            module_name=name,
        ))

    if not config.get("auto_minor_version_upgrade", True):
        violations.append(ComplianceViolation(
            rule_id="CIS-AWS-RDS-3",
            framework=Framework.CIS_AWS,
            severity=Severity.LOW,
            title="Auto Minor Version Upgrade Disabled",
            description="Auto minor version upgrades apply security patches automatically.",
            remediation="Set auto_minor_version_upgrade: true.",
            module_name=name,
        ))

    if not config.get("performance_insights_enabled", False):
        violations.append(ComplianceViolation(
            rule_id="CIS-AWS-RDS-4",
            framework=Framework.CIS_AWS,
            severity=Severity.INFO,
            title="Performance Insights Not Enabled",
            description="Performance Insights helps detect database performance issues.",
            remediation="Set performance_insights_enabled: true.",
            module_name=name,
        ))

    return violations


def check_iam(config: Dict[str, Any], name: str) -> List[ComplianceViolation]:
    violations = []

    trust_services = config.get("trust_services", [])
    if not trust_services:
        violations.append(ComplianceViolation(
            rule_id="CIS-AWS-IAM-1",
            framework=Framework.CIS_AWS,
            severity=Severity.MEDIUM,
            title="IAM Role Has No Trust Policy Services",
            description="IAM role must define which AWS services can assume it.",
            remediation="Provide at least one service in trust_services.",
            module_name=name,
        ))

    if config.get("attach_admin_policy", False):
        violations.append(ComplianceViolation(
            rule_id="CIS-AWS-1.16",
            framework=Framework.CIS_AWS,
            severity=Severity.CRITICAL,
            title="IAM Role Attached with Admin Policy",
            description="Roles with AdministratorAccess violate least-privilege principle.",
            remediation="Define specific policies with only required permissions.",
            module_name=name,
        ))

    inline_statements = config.get("policy_statements", [])
    for stmt in inline_statements:
        if stmt.get("Effect") == "Allow" and "*" in stmt.get("Action", []) and "*" in stmt.get("Resource", []):
            violations.append(ComplianceViolation(
                rule_id="CIS-AWS-1.17",
                framework=Framework.CIS_AWS,
                severity=Severity.CRITICAL,
                title="IAM Policy with Wildcard Actions and Resources",
                description="Policy statement allows all actions on all resources (Action: *, Resource: *).",
                remediation="Restrict actions to specific required actions and specific resource ARNs.",
                module_name=name,
            ))
            break

    return violations


def check_eks(config: Dict[str, Any], name: str) -> List[ComplianceViolation]:
    violations = []

    if config.get("endpoint_public_access", True):
        violations.append(ComplianceViolation(
            rule_id="CIS-AWS-EKS-1",
            framework=Framework.CIS_AWS,
            severity=Severity.HIGH,
            title="EKS API Server Endpoint Publicly Accessible",
            description="EKS cluster API endpoint should be private to restrict access to within the VPC.",
            remediation="Set endpoint_public_access: false and endpoint_private_access: true.",
            module_name=name,
        ))

    if not config.get("secrets_encryption", True):
        violations.append(ComplianceViolation(
            rule_id="CIS-AWS-EKS-2",
            framework=Framework.CIS_AWS,
            severity=Severity.HIGH,
            title="EKS Secrets Not Encrypted with KMS",
            description="Kubernetes secrets should be encrypted with a KMS key.",
            remediation="Set secrets_encryption: true and provide kms_key_arn.",
            module_name=name,
        ))

    if not config.get("enable_logging", True):
        violations.append(ComplianceViolation(
            rule_id="CIS-AWS-EKS-3",
            framework=Framework.CIS_AWS,
            severity=Severity.HIGH,
            title="EKS Control Plane Logging Not Enabled",
            description="EKS control plane logging (api, audit, authenticator, controllerManager, scheduler) should be enabled.",
            remediation="Set enable_logging: true.",
            module_name=name,
        ))

    if not config.get("node_group_encryption", True):
        violations.append(ComplianceViolation(
            rule_id="CIS-AWS-EKS-4",
            framework=Framework.CIS_AWS,
            severity=Severity.MEDIUM,
            title="EKS Node Group EBS Not Encrypted",
            description="EKS managed node group launch template should encrypt EBS volumes.",
            remediation="Set node_group_encryption: true.",
            module_name=name,
        ))

    return violations


MODULE_CHECKS = {
    "vpc": check_vpc,
    "ec2": check_ec2,
    "s3": check_s3,
    "rds": check_rds,
    "iam": check_iam,
    "eks": check_eks,
}
