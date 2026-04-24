#!/usr/bin/env python3
"""
Terraform Module Generator — multi-cloud, compliance-aware, with built-in scanning and improvement advisor.

Usage:
  python -m generator.main generate --provider aws --module vpc --name my-vpc --output ./output
  python -m generator.main generate --config examples/aws-webapp.yaml --output ./output
  python -m generator.main scan    --provider aws --module s3  --name my-bucket --config-json '{...}'
  python -m generator.main advise  --provider aws --module rds --config-json '{...}'
  python -m generator.main list
"""
import argparse
import json
import sys
import os
from pathlib import Path
from typing import Dict, Any, List

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich.rule import Rule
    from rich.columns import Columns
    from rich import box
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

# ── Bootstrap path so this works as  python generator/main.py  from repo root ─
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from generator.modules import list_modules, get_module_class, REGISTRY
from generator.modules.base import ModuleSpec
from generator.core.generator import generate_module, generate_from_config
from generator.compliance import scan_module
from generator.compliance.models import Severity, SEVERITY_COLORS
from generator.core.advisor import advise, CATEGORY_ICONS

console = Console() if HAS_RICH else None


# ─── Formatting helpers ───────────────────────────────────────────────────────

def _print(msg: str, style: str = ""):
    if HAS_RICH:
        console.print(msg, style=style)
    else:
        print(msg)


def _rule(title: str):
    if HAS_RICH:
        console.print(Rule(f"[bold]{title}[/bold]"))
    else:
        print(f"\n{'─' * 60}")
        print(f"  {title}")
        print('─' * 60)


def _panel(content: str, title: str, border_style: str = "blue"):
    if HAS_RICH:
        console.print(Panel(content, title=title, border_style=border_style, expand=False))
    else:
        print(f"\n[{title}]")
        print(content)


def _severity_style(sev: Severity) -> str:
    return SEVERITY_COLORS.get(sev, "white") if HAS_RICH else ""


# ─── Command: list ────────────────────────────────────────────────────────────

def cmd_list(args):
    modules = list_modules()
    _rule("Available Terraform Modules")

    if HAS_RICH:
        table = Table(box=box.ROUNDED, show_header=True, header_style="bold cyan")
        table.add_column("Provider", style="bold yellow", width=10)
        table.add_column("Module Type", style="bold green", width=16)
        table.add_column("Description")

        prev_provider = None
        for m in sorted(modules, key=lambda x: (x["provider"], x["type"])):
            provider_cell = m["provider"] if m["provider"] != prev_provider else ""
            prev_provider = m["provider"]
            table.add_row(provider_cell, m["type"], m["description"])

        console.print(table)
    else:
        for m in sorted(modules, key=lambda x: (x["provider"], x["type"])):
            print(f"  {m['provider']:8s}  {m['type']:14s}  {m['description']}")

    _print(f"\nTotal modules: [bold]{len(modules)}[/bold]")
    _print("\nGenerate a module:\n  python -m generator.main generate --provider <p> --module <m> --name <name> --output ./output")


# ─── Command: generate ────────────────────────────────────────────────────────

def cmd_generate(args):
    output_dir = args.output or "./output"
    frameworks = [f.strip() for f in (args.compliance or "cis,general").split(",")]

    # ── Load modules to generate ─────────────────────────────────────────────
    if args.config:
        if not HAS_YAML:
            _print("[red]pyyaml is required for --config. Run: pip install pyyaml[/red]")
            sys.exit(1)
        with open(args.config) as f:
            file_config = yaml.safe_load(f)
        module_defs = []
        global_tags = file_config.get("tags", {})
        for mod_def in file_config.get("modules", []):
            provider = mod_def.get("provider", file_config.get("provider", "aws"))
            mod_config = {k: v for k, v in mod_def.items() if k not in ("type", "name", "provider")}
            mod_tags = {**global_tags, **mod_config.pop("tags", {})}
            module_defs.append({
                "provider": provider,
                "type": mod_def["type"],
                "name": mod_def["name"],
                "config": mod_config,
                "tags": mod_tags,
            })
    else:
        if not args.provider or not args.module or not args.name:
            _print("[red]--provider, --module, and --name are required when not using --config[/red]")
            sys.exit(1)
        extra_config = {}
        if args.config_json:
            extra_config = json.loads(args.config_json)
        tags = {}
        if args.tags:
            for pair in args.tags.split(","):
                k, _, v = pair.partition("=")
                tags[k.strip()] = v.strip()
        module_defs = [{
            "provider": args.provider,
            "type": args.module,
            "name": args.name,
            "config": extra_config,
            "tags": tags,
        }]

    _rule(f"Generating {len(module_defs)} module(s) → {output_dir}")

    all_violations = []
    all_suggestions = []

    for mod in module_defs:
        provider = mod["provider"]
        module_type = mod["type"]
        name = mod["name"]
        config = mod["config"]
        tags = mod["tags"]

        _print(f"\n  [bold cyan]→[/bold cyan] [bold]{provider}/{module_type}[/bold] — [italic]{name}[/italic]")

        # Generate files
        result = generate_module(provider, module_type, name, config, tags, output_dir)
        for f in result.files:
            _print(f"    [green]✓[/green] {result.output_dir}/{f.filename}")

        # Scan
        report = scan_module(provider, module_type, name, {**config, "tags": tags}, frameworks)
        all_violations.extend(report.violations)

        # Advise
        suggestions = advise(provider, module_type, config)
        all_suggestions.extend(suggestions)

        # Per-module summary
        if report.violations:
            crit = report.critical_count
            high = report.high_count
            med = report.medium_count
            low = report.low_count
            _print(f"    [bold red]CRITICAL: {crit}[/bold red]  [red]HIGH: {high}[/red]  [yellow]MEDIUM: {med}[/yellow]  [blue]LOW: {low}[/blue]")
        else:
            _print("    [green]✓ No compliance violations[/green]")

    # ── Compliance Report ─────────────────────────────────────────────────────
    if all_violations:
        _rule("Compliance Scan Report")
        _print_violations(all_violations)

    # ── Suggestions Report ────────────────────────────────────────────────────
    if all_suggestions and not args.no_suggestions:
        _rule("Improvement Suggestions")
        _print_suggestions(all_suggestions)

    # ── Final summary ─────────────────────────────────────────────────────────
    _rule("Summary")
    total_crits = sum(1 for v in all_violations if v.severity == Severity.CRITICAL)
    total_highs = sum(1 for v in all_violations if v.severity == Severity.HIGH)

    if HAS_RICH:
        console.print(f"  Modules generated : [bold]{len(module_defs)}[/bold]")
        console.print(f"  Output directory  : [bold]{Path(output_dir).resolve()}[/bold]")
        console.print(f"  Violations        : [bold red]{total_crits} CRITICAL[/bold red]  [red]{total_highs} HIGH[/red]  {len(all_violations) - total_crits - total_highs} others")
        console.print(f"  Suggestions       : [bold]{len(all_suggestions)}[/bold]")
        if total_crits > 0:
            console.print("\n  [bold red]⚠ Fix CRITICAL violations before deploying to production.[/bold red]")
        elif total_highs > 0:
            console.print("\n  [yellow]⚠ Review HIGH violations before deploying.[/yellow]")
        else:
            console.print("\n  [green]✓ No critical or high compliance violations. Ready for review.[/green]")
    else:
        print(f"  Modules: {len(module_defs)}  Output: {output_dir}")
        print(f"  Violations: {len(all_violations)}  Suggestions: {len(all_suggestions)}")


# ─── Command: scan ────────────────────────────────────────────────────────────

def cmd_scan(args):
    if not args.provider or not args.module or not args.name:
        _print("[red]--provider, --module, and --name are required[/red]")
        sys.exit(1)

    config = json.loads(args.config_json) if args.config_json else {}
    frameworks = [f.strip() for f in (args.compliance or "all").split(",")]

    _rule(f"Scanning {args.provider}/{args.module} — {args.name}")
    report = scan_module(args.provider, args.module, args.name, config, frameworks)

    if not report.violations:
        _print("\n[green bold]✓ No violations found — fully compliant![/green bold]")
        return

    _print_violations(report.violations)

    if HAS_RICH:
        console.print(f"\nTotal: [bold red]{report.critical_count} CRITICAL[/bold red]  "
                      f"[red]{report.high_count} HIGH[/red]  "
                      f"[yellow]{report.medium_count} MEDIUM[/yellow]  "
                      f"[blue]{report.low_count} LOW[/blue]")
    else:
        print(f"\nCRITICAL:{report.critical_count}  HIGH:{report.high_count}  "
              f"MEDIUM:{report.medium_count}  LOW:{report.low_count}")


# ─── Command: advise ─────────────────────────────────────────────────────────

def cmd_advise(args):
    if not args.provider or not args.module:
        _print("[red]--provider and --module are required[/red]")
        sys.exit(1)

    config = json.loads(args.config_json) if args.config_json else {}
    _rule(f"Improvement Suggestions for {args.provider}/{args.module}")
    suggestions = advise(args.provider, args.module, config)

    if not suggestions:
        _print("[green]No additional suggestions — configuration looks good![/green]")
        return

    _print_suggestions(suggestions)


# ─── Shared render helpers ────────────────────────────────────────────────────

def _print_violations(violations):
    if not violations:
        return

    if HAS_RICH:
        table = Table(box=box.ROUNDED, show_header=True, header_style="bold white", expand=True)
        table.add_column("Severity", width=10)
        table.add_column("Rule ID", width=18)
        table.add_column("Framework", width=12)
        table.add_column("Title")
        table.add_column("Module", width=20)

        for v in violations:
            sev_text = Text(v.severity.value, style=_severity_style(v.severity))
            table.add_row(sev_text, v.rule_id, v.framework.value, v.title, v.module_name)
        console.print(table)

        # Print remediation for CRITICAL and HIGH
        crits_highs = [v for v in violations if v.severity in (Severity.CRITICAL, Severity.HIGH)]
        if crits_highs:
            console.print("\n[bold]Remediation steps for CRITICAL/HIGH:[/bold]")
            for v in crits_highs:
                sev_style = _severity_style(v.severity)
                console.print(f"\n  [{sev_style}]● {v.rule_id} — {v.title}[/{sev_style}]")
                console.print(f"    [dim]{v.description}[/dim]")
                console.print(f"    [green]Fix:[/green] {v.remediation}")
    else:
        for v in violations:
            print(f"  [{v.severity.value:8s}] {v.rule_id:18s} {v.title}")
            if v.severity.value in ("CRITICAL", "HIGH"):
                print(f"            Fix: {v.remediation}")


def _print_suggestions(suggestions):
    if not suggestions:
        return

    if HAS_RICH:
        for s in suggestions:
            icon = CATEGORY_ICONS.get(s.category, "•")
            priority_style = {"HIGH": "bold red", "MEDIUM": "yellow", "LOW": "dim"}.get(s.priority, "")
            console.print(f"\n  {icon} [{priority_style}][{s.priority}][/{priority_style}] [bold]{s.title}[/bold]  [dim]({s.category})[/dim]")
            console.print(f"     [dim]{s.description}[/dim]")
            console.print(f"     [cyan]→ {s.implementation}[/cyan]")
    else:
        for s in suggestions:
            print(f"\n  [{s.priority}] {s.title} ({s.category})")
            print(f"    {s.description}")
            print(f"    → {s.implementation}")


# ─── CLI entry point ──────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="terraform-gen",
        description="Multi-cloud Terraform module generator with compliance scanning and improvement advisor.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # List all available modules
  python -m generator.main list

  # Generate a single AWS VPC module
  python -m generator.main generate --provider aws --module vpc --name prod-vpc --output ./output

  # Generate from a YAML config file
  python -m generator.main generate --config examples/aws-webapp.yaml --output ./output

  # Generate with specific compliance frameworks
  python -m generator.main generate --provider aws --module s3 --name my-bucket \\
      --output ./output --compliance cis,pci-dss,hipaa

  # Scan an existing config against all frameworks
  python -m generator.main scan --provider aws --module rds --name prod-db \\
      --config-json '{"multi_az": false, "publicly_accessible": true}'

  # Get improvement suggestions
  python -m generator.main advise --provider gcp --module gke \\
      --config-json '{"cluster_name": "prod", "release_channel": "NONE"}'
""",
    )

    sub = parser.add_subparsers(dest="command", metavar="COMMAND")
    sub.required = True

    # list
    sub.add_parser("list", help="List all available module types across providers.")

    # generate
    gen = sub.add_parser("generate", help="Generate Terraform module files.")
    gen.add_argument("--provider", "-p", choices=list(REGISTRY.keys()), help="Cloud provider (aws|azure|gcp).")
    gen.add_argument("--module",   "-m", help="Module type (vpc, ec2, s3, rds, iam, eks, vnet, storage, aks, gke, ...).")
    gen.add_argument("--name",     "-n", help="Module name (used as directory name and resource prefix).")
    gen.add_argument("--output",   "-o", default="./output", help="Output directory (default: ./output).")
    gen.add_argument("--config",   "-c", help="YAML config file defining one or more modules.")
    gen.add_argument("--config-json", help="Extra config as inline JSON (merged with defaults).")
    gen.add_argument("--compliance", default="cis,general",
                     help="Comma-separated compliance frameworks: cis,pci-dss,hipaa,general,all (default: cis,general).")
    gen.add_argument("--tags", help="Resource tags as key=value,key=value pairs.")
    gen.add_argument("--no-suggestions", action="store_true", help="Skip the improvement suggestions section.")

    # scan
    sc = sub.add_parser("scan", help="Scan a module configuration for compliance violations.")
    sc.add_argument("--provider",    "-p", required=True, choices=list(REGISTRY.keys()))
    sc.add_argument("--module",      "-m", required=True)
    sc.add_argument("--name",        "-n", required=True)
    sc.add_argument("--config-json", help="Module configuration as JSON.")
    sc.add_argument("--compliance",  default="all", help="Frameworks to check (default: all).")

    # advise
    ad = sub.add_parser("advise", help="Get improvement suggestions for a module configuration.")
    ad.add_argument("--provider",    "-p", required=True, choices=list(REGISTRY.keys()))
    ad.add_argument("--module",      "-m", required=True)
    ad.add_argument("--config-json", help="Module configuration as JSON.")

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    if HAS_RICH:
        console.print(Panel.fit(
            "[bold cyan]Terraform Module Generator[/bold cyan]\n"
            "[dim]Multi-cloud · Compliance-aware · Self-scanning[/dim]",
            border_style="cyan",
        ))

    dispatch = {"list": cmd_list, "generate": cmd_generate, "scan": cmd_scan, "advise": cmd_advise}
    dispatch[args.command](args)


if __name__ == "__main__":
    main()
