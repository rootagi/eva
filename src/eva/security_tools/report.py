from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
from pathlib import Path

from rich.console import Console
from rich.table import Table

from eva.security_tools.models import Finding
from eva.security_tools.normalizers import findings_to_sarif
from eva.security_tools.utils import write_json_artifact, write_text_artifact


def load_findings_data(findings: Iterable[Finding]) -> list[dict]:
    return [finding.model_dump(mode="json") for finding in findings]


def render_terminal(findings: list[Finding], console: Console | None = None) -> None:
    target_console = console or Console()
    counts = Counter(f.severity for f in findings)
    target_console.print(
        f"[bold cyan]Eva security findings:[/bold cyan] {len(findings)} "
        f"(critical={counts['critical']}, high={counts['high']}, medium={counts['medium']}, low={counts['low']}, info={counts['info']})"
    )
    if not findings:
        return
    table = Table(title="Normalized Findings")
    table.add_column("Severity", style="yellow")
    table.add_column("Tool", style="cyan")
    table.add_column("Rule")
    table.add_column("Location")
    table.add_column("Title")
    for finding in findings[:100]:
        location = finding.file or finding.target or ""
        if finding.line_start:
            location = f"{location}:{finding.line_start}"
        table.add_row(finding.severity, finding.tool, finding.rule_id, location, finding.title)
    target_console.print(table)
    if len(findings) > 100:
        target_console.print(f"[dim]Showing first 100 of {len(findings)} findings.[/dim]")


def render_markdown(findings: list[Finding]) -> str:
    lines = ["# Eva Security Report", "", f"Total findings: {len(findings)}", ""]
    counts = Counter(f.severity for f in findings)
    lines.append("| Severity | Count |")
    lines.append("| --- | ---: |")
    for severity in ("critical", "high", "medium", "low", "info", "unknown"):
        lines.append(f"| {severity} | {counts[severity]} |")
    lines.extend(["", "| Severity | Tool | Rule | Location | Title |", "| --- | --- | --- | --- | --- |"])
    for finding in findings:
        location = finding.file or finding.target or ""
        if finding.line_start:
            location = f"{location}:{finding.line_start}"
        title = finding.title.replace("|", "\\|")
        lines.append(f"| {finding.severity} | {finding.tool} | {finding.rule_id} | {location} | {title} |")
    lines.append("")
    return "\n".join(lines)


def write_reports(findings: list[Finding], run_dir: Path, formats: list[str]) -> dict[str, str]:
    written: dict[str, str] = {}
    if "json" in formats:
        path = run_dir / "findings.json"
        write_json_artifact(path, {"findings": load_findings_data(findings)}, "findings-json")
        written["json"] = str(path)
    if "markdown" in formats or "md" in formats:
        path = run_dir / "report.md"
        write_text_artifact(path, render_markdown(findings), "report-markdown")
        written["markdown"] = str(path)
    if "sarif" in formats:
        path = run_dir / "report.sarif"
        write_json_artifact(path, findings_to_sarif(findings), "report-sarif")
        written["sarif"] = str(path)
    return written
