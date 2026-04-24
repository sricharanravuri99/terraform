from .aws.vpc import AWSVPCModule
from .aws.ec2 import AWSEC2Module
from .aws.s3 import AWSS3Module
from .aws.rds import AWSRDSModule
from .aws.iam import AWSIAMModule
from .aws.eks import AWSEKSModule
from .azure.vnet import AzureVNetModule
from .azure.storage import AzureStorageModule
from .azure.aks import AzureAKSModule
from .gcp.vpc import GCPVPCModule
from .gcp.gke import GCPGKEModule

REGISTRY = {
    "aws": {
        "vpc": AWSVPCModule,
        "ec2": AWSEC2Module,
        "s3": AWSS3Module,
        "rds": AWSRDSModule,
        "iam": AWSIAMModule,
        "eks": AWSEKSModule,
    },
    "azure": {
        "vnet": AzureVNetModule,
        "storage": AzureStorageModule,
        "aks": AzureAKSModule,
    },
    "gcp": {
        "vpc": GCPVPCModule,
        "gke": GCPGKEModule,
    },
}


def get_module_class(provider: str, module_type: str):
    provider_modules = REGISTRY.get(provider.lower())
    if not provider_modules:
        raise ValueError(f"Unknown provider '{provider}'. Available: {list(REGISTRY.keys())}")
    cls = provider_modules.get(module_type.lower())
    if not cls:
        available = list(provider_modules.keys())
        raise ValueError(f"Unknown module type '{module_type}' for provider '{provider}'. Available: {available}")
    return cls


def list_modules():
    result = []
    for provider, modules in REGISTRY.items():
        for module_type, cls in modules.items():
            result.append({
                "provider": provider,
                "type": module_type,
                "description": cls.DESCRIPTION,
            })
    return result
