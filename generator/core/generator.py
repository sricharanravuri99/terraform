import os
from pathlib import Path
from typing import List, Dict, Any

from ..modules import get_module_class
from ..modules.base import ModuleSpec, GeneratedFile


class GeneratorResult:
    def __init__(self, module_name: str, output_dir: Path, files: List[GeneratedFile]):
        self.module_name = module_name
        self.output_dir = output_dir
        self.files = files


def generate_module(
    provider: str,
    module_type: str,
    name: str,
    config: Dict[str, Any],
    tags: Dict[str, str],
    output_dir: str,
) -> GeneratorResult:
    cls = get_module_class(provider, module_type)

    spec = ModuleSpec(
        name=name,
        module_type=module_type,
        provider=provider,
        config=config,
        tags=tags,
        description=config.get("description", ""),
    )

    module = cls(spec)
    files = module.generate()

    target = Path(output_dir) / name
    target.mkdir(parents=True, exist_ok=True)

    for f in files:
        (target / f.filename).write_text(f.content)

    return GeneratorResult(module_name=name, output_dir=target, files=files)


def generate_from_config(config: Dict[str, Any], output_dir: str) -> List[GeneratorResult]:
    """Generate all modules defined in a YAML config file."""
    results = []
    global_tags = config.get("tags", {})

    for mod_def in config.get("modules", []):
        provider = mod_def.get("provider", config.get("provider", "aws"))
        module_type = mod_def["type"]
        name = mod_def["name"]
        mod_config = {k: v for k, v in mod_def.items() if k not in ("type", "name", "provider")}
        mod_tags = {**global_tags, **mod_config.pop("tags", {})}

        result = generate_module(
            provider=provider,
            module_type=module_type,
            name=name,
            config=mod_config,
            tags=mod_tags,
            output_dir=output_dir,
        )
        results.append(result)

    return results
