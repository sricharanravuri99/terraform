"""Improvement advisor: produces prioritised, actionable suggestions per module."""
from dataclasses import dataclass
from typing import List, Dict, Any


@dataclass
class Suggestion:
    category: str       # SECURITY | COST | RELIABILITY | PERFORMANCE | OPERATIONAL
    priority: str       # HIGH | MEDIUM | LOW
    title: str
    description: str
    implementation: str


CATEGORY_ICONS = {
    "SECURITY": "🔒",
    "COST": "💰",
    "RELIABILITY": "🔄",
    "PERFORMANCE": "⚡",
    "OPERATIONAL": "🛠️",
}


def _aws_vpc(config: Dict[str, Any]) -> List[Suggestion]:
    suggestions = []

    if not config.get("kms_key_arn"):
        suggestions.append(Suggestion(
            category="SECURITY", priority="MEDIUM",
            title="Encrypt VPC Flow Logs with KMS CMK",
            description="Flow log CloudWatch group uses AWS-managed key by default. A CMK gives full control over key rotation and auditing.",
            implementation="Create an aws_kms_key resource and set kms_key_arn in your VPC config.",
        ))

    azs = config.get("availability_zones", [])
    if len(azs) < 3:
        suggestions.append(Suggestion(
            category="RELIABILITY", priority="HIGH",
            title="Use 3+ Availability Zones",
            description=f"Only {len(azs) or 'unset'} AZ(s) configured. Three AZs provides N-2 redundancy and is the AWS HA best practice.",
            implementation="Set availability_zones to at least 3 AZs (e.g. us-east-1a, us-east-1b, us-east-1c).",
        ))

    if not config.get("database_subnet_cidrs"):
        suggestions.append(Suggestion(
            category="SECURITY", priority="MEDIUM",
            title="Add Dedicated Database Subnets",
            description="Separate database subnets with no route to the internet enforce network-layer isolation for data tiers.",
            implementation="Add database_subnet_cidrs with CIDRs that have no NAT or IGW route.",
        ))

    retention = config.get("flow_log_retention_days", 90)
    if retention < 365:
        suggestions.append(Suggestion(
            category="OPERATIONAL", priority="LOW",
            title=f"Increase Flow Log Retention to 365+ Days",
            description=f"Current retention is {retention} days. Many compliance frameworks require 1 year of network logs.",
            implementation="Set flow_log_retention_days: 365.",
        ))

    return suggestions


def _aws_ec2(config: Dict[str, Any]) -> List[Suggestion]:
    suggestions = []

    if not config.get("kms_key_arn"):
        suggestions.append(Suggestion(
            category="SECURITY", priority="MEDIUM",
            title="Use CMK for EBS Encryption",
            description="Default EBS encryption uses an AWS-managed key. A CMK lets you disable access instantly if a key is compromised.",
            implementation="Create an aws_kms_key and pass its ARN as kms_key_arn.",
        ))

    if config.get("instance_type", "t3.micro").startswith("t"):
        suggestions.append(Suggestion(
            category="PERFORMANCE", priority="LOW",
            title="Consider Burstable Instance Limitations",
            description="T-series instances use CPU credits. Sustained workloads will throttle. Use m5/m6i for predictable performance.",
            implementation="Switch to m5.large or m6i.large for production steady-state workloads.",
        ))

    if not config.get("user_data_base64"):
        suggestions.append(Suggestion(
            category="OPERATIONAL", priority="LOW",
            title="Add User Data for Bootstrap Hardening",
            description="Use user data to install the CloudWatch agent, CIS OS hardening, and enforce SSM parameter store-based secrets on boot.",
            implementation="Encode an install/hardening script and pass it as user_data_base64.",
        ))

    suggestions.append(Suggestion(
        category="SECURITY", priority="MEDIUM",
        title="Use AWS Systems Manager Instead of SSH",
        description="SSM Session Manager removes the need for an SSH key pair and bastion host entirely. Audit logs are automatically captured in CloudTrail.",
        implementation="This module already attaches AmazonSSMManagedInstanceCore. Remove ingress_rules for port 22 and connect via `aws ssm start-session`.",
    ))

    return suggestions


def _aws_s3(config: Dict[str, Any]) -> List[Suggestion]:
    suggestions = []

    if not config.get("kms_key_arn"):
        suggestions.append(Suggestion(
            category="SECURITY", priority="MEDIUM",
            title="Upgrade to SSE-KMS with CMK",
            description="The bucket uses SSE-S3 (AES256). SSE-KMS with a CMK provides CloudTrail-audited key usage and independent key revocation.",
            implementation="Create an aws_kms_key, pass kms_key_arn. Existing objects need re-encryption.",
        ))

    if not config.get("lifecycle_rules"):
        suggestions.append(Suggestion(
            category="COST", priority="HIGH",
            title="Add Lifecycle Rules for Object Tiering",
            description="Without lifecycle rules, all objects remain in S3 Standard forever. Tiering to S3-IA after 30 days and Glacier after 90 saves up to 80% on storage costs.",
            implementation="Add lifecycle_rules with transitions to STANDARD_IA, GLACIER, and DEEP_ARCHIVE.",
        ))

    if not config.get("logging_target_bucket"):
        suggestions.append(Suggestion(
            category="OPERATIONAL", priority="MEDIUM",
            title="Use a Dedicated Access Log Bucket",
            description="Logging to the same bucket creates recursive log entries and inflates storage costs. Use a dedicated bucket with restricted access.",
            implementation="Create a separate S3 bucket for logs and pass it as logging_target_bucket.",
        ))

    suggestions.append(Suggestion(
        category="RELIABILITY", priority="MEDIUM",
        title="Enable Cross-Region Replication for DR",
        description="S3 Cross-Region Replication (CRR) provides geo-redundancy and meets RTO/RPO requirements for regulatory compliance.",
        implementation="Add aws_s3_bucket_replication_configuration pointing to a replica bucket in a secondary region.",
    ))

    return suggestions


def _aws_rds(config: Dict[str, Any]) -> List[Suggestion]:
    suggestions = []

    if not config.get("kms_key_arn"):
        suggestions.append(Suggestion(
            category="SECURITY", priority="MEDIUM",
            title="Use CMK for RDS Encryption",
            description="A CMK enables independent key rotation, CloudTrail key usage logs, and instant access revocation.",
            implementation="Create aws_kms_key and pass kms_key_arn. Note: changing encryption on existing instances requires a snapshot restore.",
        ))

    if config.get("instance_class", "db.t3.medium").startswith("db.t"):
        suggestions.append(Suggestion(
            category="RELIABILITY", priority="MEDIUM",
            title="Avoid Burstable RDS Instance Classes for Production",
            description="db.t* classes use CPU credits. Under sustained DB load they throttle, causing query latency spikes. Use db.m6i or db.r6g.",
            implementation="Switch to db.m6i.large or larger for production workloads.",
        ))

    if not config.get("read_replica_count", 0):
        suggestions.append(Suggestion(
            category="PERFORMANCE", priority="MEDIUM",
            title="Add Read Replicas for Read Scalability",
            description="Read replicas offload SELECT queries from the primary, improving throughput and providing a warm standby for promotion.",
            implementation="Add aws_db_instance resources with replicate_source_db pointing to this instance.",
        ))

    suggestions.append(Suggestion(
        category="SECURITY", priority="HIGH",
        title="Store Credentials in AWS Secrets Manager",
        description="Passing master_password as a Terraform variable risks it appearing in state files and CI logs. Secrets Manager auto-rotates credentials.",
        implementation="Use aws_secretsmanager_secret with aws_secretsmanager_secret_rotation, then reference via data source.",
    ))

    if not config.get("performance_insights_enabled", True):
        suggestions.append(Suggestion(
            category="OPERATIONAL", priority="MEDIUM",
            title="Enable Performance Insights",
            description="Performance Insights provides query-level diagnostics with 7-day free retention. Essential for identifying slow queries without external tooling.",
            implementation="Set performance_insights_enabled: true.",
        ))

    return suggestions


def _aws_eks(config: Dict[str, Any]) -> List[Suggestion]:
    suggestions = []

    if not config.get("secrets_encryption_key") and not config.get("kms_key_arn"):
        suggestions.append(Suggestion(
            category="SECURITY", priority="HIGH",
            title="Enable Kubernetes Secrets Encryption with KMS",
            description="Without envelope encryption, Kubernetes secrets are stored as base64 in etcd. A KMS CMK provides at-rest protection.",
            implementation="Create aws_kms_key, set kms_key_arn in EKS config.",
        ))

    node_groups = config.get("node_groups", {})
    for ng_name, ng in node_groups.items():
        if ng.get("capacity_type", "ON_DEMAND") == "ON_DEMAND":
            suggestions.append(Suggestion(
                category="COST", priority="MEDIUM",
                title=f"Add Spot Instances for Node Group '{ng_name}'",
                description="Spot instances save 60-90% vs On-Demand for stateless, interruption-tolerant workloads like batch processing.",
                implementation=f"Add a second node group with capacity_type: SPOT and instance_types with 3-4 compatible families.",
            ))
            break

    suggestions.append(Suggestion(
        category="SECURITY", priority="HIGH",
        title="Enable Pod Security Standards (PSS)",
        description="Kubernetes Pod Security Standards replace PSPs and enforce baseline/restricted security policies at the namespace level.",
        implementation="Apply namespace labels: pod-security.kubernetes.io/enforce: restricted for sensitive namespaces.",
    ))

    suggestions.append(Suggestion(
        category="OPERATIONAL", priority="MEDIUM",
        title="Deploy Cluster Autoscaler or Karpenter",
        description="Karpenter provides faster, more cost-efficient node provisioning than Cluster Autoscaler by provisioning right-sized nodes on demand.",
        implementation="Deploy Karpenter via Helm using IRSA. Create NodePool and EC2NodeClass resources.",
    ))

    return suggestions


def _aws_iam(config: Dict[str, Any]) -> List[Suggestion]:
    suggestions = []

    if not config.get("permissions_boundary_arn"):
        suggestions.append(Suggestion(
            category="SECURITY", priority="HIGH",
            title="Attach a Permissions Boundary",
            description="Permissions boundaries cap the maximum permissions a role can have, even if broader policies are attached later. Critical for delegated administration.",
            implementation="Create an aws_iam_policy as the boundary and set permissions_boundary_arn.",
        ))

    if not config.get("max_session_duration") or config.get("max_session_duration", 3600) > 3600:
        suggestions.append(Suggestion(
            category="SECURITY", priority="LOW",
            title="Set Session Duration to 1 Hour for Human Roles",
            description="Long-lived sessions increase the blast radius of a leaked token. 1 hour (3600s) is appropriate for service roles; use shorter for human-assumed roles.",
            implementation="Set max_session_duration: 3600.",
        ))

    suggestions.append(Suggestion(
        category="OPERATIONAL", priority="MEDIUM",
        title="Tag IAM Roles for Access Analyzer",
        description="AWS IAM Access Analyzer uses resource tags to scope findings. Tag roles with data-classification and team owner to prioritise remediation.",
        implementation="Add tags like data-classification: confidential and team: platform.",
    ))

    return suggestions


def _azure_vnet(config: Dict[str, Any]) -> List[Suggestion]:
    suggestions = []

    if not config.get("enable_ddos_protection"):
        suggestions.append(Suggestion(
            category="SECURITY", priority="MEDIUM",
            title="Enable Azure DDoS Network Protection",
            description="Azure DDoS Network Protection provides adaptive tuning and real-time mitigation. Required for production public-facing services.",
            implementation="Set enable_ddos_protection: true. Note: ~$2,500/month per plan, shareable across VNets.",
        ))

    suggestions.append(Suggestion(
        category="SECURITY", priority="MEDIUM",
        title="Deploy Azure Firewall for Centralised Egress",
        description="Azure Firewall Premium provides IDPS, TLS inspection, and FQDN-based filtering for all outbound traffic in a hub-spoke topology.",
        implementation="Create an azurerm_firewall in a hub VNet and route all spoke subnet traffic through it via UDR.",
    ))

    suggestions.append(Suggestion(
        category="RELIABILITY", priority="MEDIUM",
        title="Use Availability Zones for Subnet Resources",
        description="Subnets span all AZs in a region, but resources within them don't automatically. Pin VMs and load balancers to AZs explicitly.",
        implementation="Set zones on azurerm_linux_virtual_machine_scale_set and azurerm_lb resources.",
    ))

    return suggestions


def _azure_storage(config: Dict[str, Any]) -> List[Suggestion]:
    suggestions = []

    if not config.get("key_vault_key_id"):
        suggestions.append(Suggestion(
            category="SECURITY", priority="MEDIUM",
            title="Encrypt with Customer-Managed Key from Key Vault",
            description="Microsoft-managed keys are convenient but a CMK lets you revoke access instantly and proves key ownership to auditors.",
            implementation="Create azurerm_key_vault_key and set key_vault_id and key_vault_key_id.",
        ))

    if config.get("shared_access_key_enabled", True):
        suggestions.append(Suggestion(
            category="SECURITY", priority="HIGH",
            title="Disable Shared Access Key Authentication",
            description="Shared keys are long-lived and not tied to identities. Disabling forces use of AAD identities and RBAC, enabling per-identity audit trails.",
            implementation="Set shared_access_key_enabled: false and use managed identities with Storage Blob Data Reader/Contributor roles.",
        ))

    suggestions.append(Suggestion(
        category="COST", priority="MEDIUM",
        title="Enable Lifecycle Management for Blob Tiering",
        description="Automatically tier blobs from Hot to Cool after 30 days and Archive after 90 days to cut storage costs by up to 80%.",
        implementation="Add azurerm_storage_management_policy with tiering rules.",
    ))

    return suggestions


def _azure_aks(config: Dict[str, Any]) -> List[Suggestion]:
    suggestions = []

    if config.get("sku_tier", "Standard") == "Free":
        suggestions.append(Suggestion(
            category="RELIABILITY", priority="HIGH",
            title="Upgrade to Standard Tier for SLA",
            description="Free tier AKS has no SLA on the control plane. Standard tier provides a 99.95% uptime SLA for zone-redundant clusters.",
            implementation="Set sku_tier: Standard.",
        ))

    suggestions.append(Suggestion(
        category="SECURITY", priority="HIGH",
        title="Enable Microsoft Defender for Containers",
        description="Defender for Containers provides runtime threat detection, vulnerability scanning, and Kubernetes audit log analysis.",
        implementation="Enable the Defender add-on via azurerm_security_center_subscription_pricing for ContainerRegistry and KubernetesService.",
    ))

    suggestions.append(Suggestion(
        category="COST", priority="MEDIUM",
        title="Enable Cluster Autoscaler with Spot Node Pools",
        description="Add a spot-priority user node pool for batch/stateless workloads to reduce compute costs by up to 90%.",
        implementation="Add user_node_pool with priority = Spot and eviction_policy = Delete.",
    ))

    suggestions.append(Suggestion(
        category="OPERATIONAL", priority="MEDIUM",
        title="Integrate with Azure Container Registry via Managed Identity",
        description="Attach ACR pull permission to the kubelet identity instead of using imagePullSecrets, removing static credential management.",
        implementation="Add azurerm_role_assignment granting AcrPull on your ACR to the cluster kubelet_identity.",
    ))

    return suggestions


def _gcp_vpc(config: Dict[str, Any]) -> List[Suggestion]:
    suggestions = []

    suggestions.append(Suggestion(
        category="SECURITY", priority="HIGH",
        title="Enable VPC Service Controls",
        description="VPC Service Controls create security perimeters around GCP services to prevent data exfiltration even with IAM misconfigurations.",
        implementation="Configure google_access_context_manager_service_perimeter around your project.",
    ))

    suggestions.append(Suggestion(
        category="OPERATIONAL", priority="MEDIUM",
        title="Enable Packet Mirroring for IDS",
        description="Packet Mirroring clones traffic to a security appliance for deep-packet inspection and intrusion detection.",
        implementation="Add google_compute_packet_mirroring resource pointing to an IDS Collector instance group.",
    ))

    if not config.get("enable_iap_firewall", True):
        suggestions.append(Suggestion(
            category="SECURITY", priority="HIGH",
            title="Enable Identity-Aware Proxy for Admin Access",
            description="IAP provides context-aware, identity-verified SSH/RDP access without a bastion host or VPN.",
            implementation="Set enable_iap_firewall: true and grant IAP-secured Tunnel User role to individuals.",
        ))

    return suggestions


def _gcp_gke(config: Dict[str, Any]) -> List[Suggestion]:
    suggestions = []

    if not config.get("secrets_encryption_key"):
        suggestions.append(Suggestion(
            category="SECURITY", priority="HIGH",
            title="Encrypt Kubernetes Secrets with Cloud KMS",
            description="Application-layer secrets encryption adds a second layer on top of etcd encryption, protecting against etcd snapshot leaks.",
            implementation="Create a Cloud KMS keyring and key, then set secrets_encryption_key to the key resource path.",
        ))

    if config.get("release_channel", "REGULAR") == "NONE":
        suggestions.append(Suggestion(
            category="OPERATIONAL", priority="HIGH",
            title="Enroll in a GKE Release Channel",
            description="Release channels provide automatic upgrades and tested version compatibility. REGULAR channel balances stability and new features.",
            implementation="Set release_channel: REGULAR.",
        ))

    suggestions.append(Suggestion(
        category="SECURITY", priority="MEDIUM",
        title="Enable Binary Authorization",
        description="Binary Authorization enforces that only container images from trusted registries, signed by your CI/CD pipeline, can be deployed.",
        implementation="Enable binary_authorization on the cluster and create an attestor + policy in Cloud Build.",
    ))

    suggestions.append(Suggestion(
        category="COST", priority="MEDIUM",
        title="Enable GKE Cost Allocation and Namespace-Level Cost Breakdown",
        description="GKE cost allocation breaks down Kubernetes resource costs by namespace, label, and team for accurate chargeback.",
        implementation="Enable cost_management_config on the cluster. View in Cloud Billing reports.",
    ))

    node_pools = config.get("node_pools", {})
    has_spot = any(p.get("spot", False) for p in node_pools.values())
    if not has_spot:
        suggestions.append(Suggestion(
            category="COST", priority="MEDIUM",
            title="Add Spot VM Node Pool for Batch Workloads",
            description="Spot VMs cost up to 91% less than standard VMs and are ideal for fault-tolerant batch and stateless workloads.",
            implementation="Add a node pool with spot: true in node_config. Use taints to prevent sensitive workloads from landing there.",
        ))

    return suggestions


_ADVISORS = {
    ("aws", "vpc"): _aws_vpc,
    ("aws", "ec2"): _aws_ec2,
    ("aws", "s3"): _aws_s3,
    ("aws", "rds"): _aws_rds,
    ("aws", "eks"): _aws_eks,
    ("aws", "iam"): _aws_iam,
    ("azure", "vnet"): _azure_vnet,
    ("azure", "storage"): _azure_storage,
    ("azure", "aks"): _azure_aks,
    ("gcp", "vpc"): _gcp_vpc,
    ("gcp", "gke"): _gcp_gke,
}

PRIORITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


def advise(provider: str, module_type: str, config: Dict[str, Any]) -> List[Suggestion]:
    fn = _ADVISORS.get((provider.lower(), module_type.lower()))
    if not fn:
        return []
    suggestions = fn(config)
    return sorted(suggestions, key=lambda s: (PRIORITY_ORDER.get(s.priority, 9), s.category))
