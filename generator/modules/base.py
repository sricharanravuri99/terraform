from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional
from pathlib import Path


@dataclass
class ModuleSpec:
    name: str
    module_type: str
    provider: str
    config: Dict[str, Any] = field(default_factory=dict)
    tags: Dict[str, str] = field(default_factory=dict)
    description: str = ""

    def get(self, key: str, default=None):
        return self.config.get(key, default)


@dataclass
class GeneratedFile:
    filename: str
    content: str


class TerraformModule:
    """Base class for all Terraform module generators."""

    MODULE_TYPE: str = ""
    PROVIDER: str = ""
    DESCRIPTION: str = ""
    PROVIDER_VERSION: str = ""
    TF_VERSION: str = ">= 1.5.0"

    def __init__(self, spec: ModuleSpec):
        self.spec = spec
        self.name = spec.name
        self.config = spec.config
        self.tags = {**spec.tags, **spec.config.get("tags", {})}

    def generate(self) -> List[GeneratedFile]:
        return [
            GeneratedFile("versions.tf", self.generate_versions()),
            GeneratedFile("main.tf", self.generate_main()),
            GeneratedFile("variables.tf", self.generate_variables()),
            GeneratedFile("outputs.tf", self.generate_outputs()),
            GeneratedFile("terraform.tfvars.example", self.generate_tfvars_example()),
        ]

    def generate_versions(self) -> str:
        raise NotImplementedError

    def generate_main(self) -> str:
        raise NotImplementedError

    def generate_variables(self) -> str:
        raise NotImplementedError

    def generate_outputs(self) -> str:
        raise NotImplementedError

    def generate_tfvars_example(self) -> str:
        raise NotImplementedError

    def _tags_hcl(self, indent: int = 2) -> str:
        """Render tags as HCL map content."""
        pad = " " * indent
        lines = [f'{pad}"{k}" = "{v}"' for k, v in self.tags.items()]
        return "\n".join(lines)

    def _variable_block(self, name: str, type_: str, description: str, default=None, sensitive: bool = False) -> str:
        lines = [f'variable "{name}" {{']
        lines.append(f'  type        = {type_}')
        lines.append(f'  description = "{description}"')
        if default is not None:
            if isinstance(default, bool):
                lines.append(f'  default     = {str(default).lower()}')
            elif isinstance(default, str):
                lines.append(f'  default     = "{default}"')
            elif isinstance(default, list):
                lines.append(f'  default     = {default}')
            else:
                lines.append(f'  default     = {default}')
        if sensitive:
            lines.append('  sensitive   = true')
        lines.append('}')
        return "\n".join(lines)
