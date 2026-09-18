from __future__ import annotations

from pathlib import Path
from typing import Annotated, Any

import typer
from rich.console import Console
from rich.table import Table

from eva.security_tools.aegis import SAFE_AEGIS_OPERATIONS
from eva.security_tools.elf_analyzer import analyze_elf
from eva.security_tools.entropy import analyze_file_entropy
from eva.security_tools.intel_client import IntelClient, extract_iocs
from eva.security_tools.models import Finding, RunContext
from eva.security_tools.normalizers import normalize_report
from eva.security_tools.pe_analyzer import analyze_pe
from eva.security_tools.registry import get_adapter, list_adapters
from eva.security_tools.report import render_terminal, write_reports
from eva.security_tools.scope import ScopeError, assert_zap_authorized, load_scope_file
from eva.security_tools.strings_analyzer import extract_and_analyze_strings
from eva.security_tools.utils import (
    artifact_record,
    ensure_run_dir,
    hash_input_path,
    new_run_id,
    write_json_artifact,
)
from eva.security_tools.workflow import ingest_report, run_security_workflow
from eva.security_tools.yara_scanner import compile_yara_rules, get_default_rules_path, scan_with_yara
from eva.ui.formatter import print_error, print_info, print_success

sec_app = typer.Typer(help="Authorized security assessment and evidence analysis.")
media_app = typer.Typer(help="Defensive media forensics through Aegis.")
yara_app = typer.Typer(help="Defensive YARA rule compilation and scanning.")
binary_app = typer.Typer(help="Static binary analysis and malware inspection (PE, ELF, entropy, strings).")
intel_app = typer.Typer(help="Threat intelligence enrichment and IOC extraction.")

sec_app.add_typer(media_app, name="media")
sec_app.add_typer(yara_app, name="yara")
sec_app.add_typer(binary_app, name="binary")
sec_app.add_typer(intel_app, name="intel")

console = Console()
err_console = Console(stderr=True)


def _formats(values: list[str] | None) -> list[str]:
    return values or ["terminal", "json", "markdown", "sarif"]


def _render_and_write(findings: list[Finding], run_dir: Path, formats: list[str]) -> dict[str, str]:
    if "terminal" in formats:
        render_terminal(findings, console)
    return write_reports(findings, run_dir, [fmt for fmt in formats if fmt != "terminal"])


def _new_context(artifacts_dir: Path, *, dry_run: bool = False, scope_id: str | None = None) -> RunContext:
    run_id = new_run_id("sec")
    run_dir = ensure_run_dir(artifacts_dir, run_id)
    return RunContext(
        run_id=run_id,
        root=Path.cwd(),
        artifacts_dir=artifacts_dir,
        run_dir=run_dir,
        dry_run=dry_run,
        scope_id=scope_id,
    )


@sec_app.command("doctor")
def doctor_cmd():
    """Detect optional security tools and print install guidance."""
    table = Table(title="Eva Sec Tooling")
    table.add_column("Adapter", style="cyan")
    table.add_column("Executable")
    table.add_column("Installed")
    table.add_column("Version / Guidance")
    seen = set()
    for key, adapter in sorted(list_adapters().items()):
        if adapter.metadata.name in seen:
            continue
        seen.add(adapter.metadata.name)
        status = adapter.status()
        table.add_row(
            key,
            status.executable,
            "yes" if status.installed else "no",
            status.version or status.error or status.install_hint,
        )
    console.print(table)


@sec_app.command("assess")
def assess_cmd(
    path: Annotated[Path, typer.Argument(help="Repository or filesystem path to assess")] = Path("."),
    include_osv: Annotated[bool, typer.Option("--include-osv", help="Run optional OSV-Scanner")] = False,
    include_syft: Annotated[bool, typer.Option("--include-syft", help="Run optional Syft SBOM generation")] = False,
    dry_run: Annotated[bool, typer.Option("--dry-run", help="Show adapter argv without executing tools")] = False,
    artifacts_dir: Annotated[Path, typer.Option("--artifacts-dir", help="Artifact root directory")] = Path(
        ".eva/artifacts"
    ),
    formats: Annotated[
        list[str] | None, typer.Option("--format", "-f", help="Report format: terminal, json, markdown, sarif")
    ] = None,
):
    """Run a local repository security assessment with optional third-party tools."""
    context = _new_context(artifacts_dir, dry_run=dry_run)
    context.artifacts.append(write_json_artifact(context.run_dir / "input-manifest.json", hash_input_path(path)))
    steps = [
        ("trivy.filesystem", {"path": str(path), "scanners": ["vuln", "secret", "misconfig", "license"]}),
        ("semgrep.scan", {"path": str(path), "config": "auto"}),
        ("gitleaks.scan", {"path": str(path)}),
    ]
    if include_osv:
        steps.append(("osv.scan", {"path": str(path)}))
    if include_syft:
        steps.append(("syft.sbom", {"path": str(path)}))

    findings: list[Finding] = []
    executions = []
    for name, params in steps:
        adapter = get_adapter(name)
        operation = name.split(".", 1)[1]
        try:
            result = adapter.execute(
                operation,
                params,
                cwd=Path.cwd(),
                run_dir=context.run_dir,
                run_id=context.run_id,
                dry_run=dry_run,
            )
        except Exception as exc:  # noqa: BLE001
            print_error(f"{name} failed before execution: {exc}")
            continue
        executions.append(result.model_dump(mode="json"))
        if result.missing:
            print_info(f"{adapter.metadata.executable} not installed; skipped {name}.")
            continue
        if result.output_path and Path(result.output_path).exists():
            context.artifacts.append(artifact_record(result.output_path, f"{name}-output"))
            findings.extend(adapter.parse_output(Path(result.output_path), result.stdout))
    context.artifacts.append(write_json_artifact(context.run_dir / "executions.json", {"executions": executions}))
    report_paths = _render_and_write(findings, context.run_dir, _formats(formats))
    write_json_artifact(
        context.run_dir / "run-summary.json",
        {
            "run_id": context.run_id,
            "artifacts": [item.model_dump() for item in context.artifacts],
            "findings_count": len(findings),
            "reports": report_paths,
        },
        "run-summary",
    )
    print_success(f"Security assessment run {context.run_id} complete. Artifacts: {context.run_dir}")


@media_app.command("analyze")
def media_analyze_cmd(
    file: Annotated[Path, typer.Argument(help="Evidence image or media file")],
    dry_run: Annotated[bool, typer.Option("--dry-run", help="Show Aegis argv without executing")] = False,
    artifacts_dir: Annotated[Path, typer.Option("--artifacts-dir", help="Artifact root directory")] = Path(
        ".eva/artifacts"
    ),
    formats: Annotated[
        list[str] | None, typer.Option("--format", "-f", help="Report format: terminal, json, markdown, sarif")
    ] = None,
):
    """Run Aegis defensive forensic analysis and normalize its report."""
    _run_aegis_media("analyze", {"path": str(file)}, dry_run, artifacts_dir, _formats(formats), file)


def _run_aegis_media(
    operation: str,
    params: dict,
    dry_run: bool,
    artifacts_dir: Path,
    formats: list[str],
    input_path: Path | None = None,
) -> None:
    if operation not in SAFE_AEGIS_OPERATIONS:
        print_error(f"Aegis operation is not exposed by eva sec: {operation}")
        raise typer.Exit(1)
    context = _new_context(artifacts_dir, dry_run=dry_run)
    if input_path and Path(input_path).exists():
        context.artifacts.append(
            write_json_artifact(context.run_dir / "input-manifest.json", hash_input_path(input_path))
        )
    adapter = get_adapter(f"aegis.{operation}")
    try:
        result = adapter.execute(
            operation,
            params,
            cwd=Path.cwd(),
            run_dir=context.run_dir,
            run_id=context.run_id,
            dry_run=dry_run,
        )
    except Exception as exc:
        print_error(str(exc))
        raise typer.Exit(1) from exc
    if result.missing:
        print_error("Aegis is not installed. Install from https://github.com/rootagi/Aegis")
    if result.return_code not in (0, None):
        if result.stderr:
            print_error(result.stderr)
        raise typer.Exit(result.return_code or 1)
    findings = []
    if result.stdout:
        console.print(result.stdout)
    if result.output_path and Path(result.output_path).exists():
        context.artifacts.append(artifact_record(result.output_path, f"aegis.{operation}-output"))
        findings = adapter.parse_output(Path(result.output_path), result.stdout)
    elif result.stdout:
        findings = adapter.parse_output(context.run_dir / "aegis-stdout.txt", result.stdout)
    _render_and_write(findings, context.run_dir, formats)
    print_success(f"Aegis {operation} run {context.run_id} complete. Artifacts: {context.run_dir}")


@media_app.command("detect-stego")
def media_detect_stego_cmd(file: Path, dry_run: bool = False):
    """Run Aegis steganography detection."""
    _run_aegis_media("detect-stego", {"path": str(file)}, dry_run, Path(".eva/artifacts"), ["terminal", "json"], file)


@media_app.command("scan-structure")
def media_scan_structure_cmd(file: Path, dry_run: bool = False):
    """Run Aegis image structure validation."""
    _run_aegis_media("scan-structure", {"path": str(file)}, dry_run, Path(".eva/artifacts"), ["terminal", "json"], file)


@media_app.command("extract-hidden")
def media_extract_hidden_cmd(file: Path, output_path: Path | None = None, dry_run: bool = False):
    """Extract appended data when Aegis structure analysis identifies it."""
    params = {"path": str(file)}
    if output_path:
        params["output_path"] = str(output_path)
    _run_aegis_media("extract-hidden", params, dry_run, Path(".eva/artifacts"), ["terminal", "json"], file)


@media_app.command("sign")
def media_sign_cmd(
    file: Path, key: Annotated[str, typer.Option("--key", prompt=True, hide_input=True)], dry_run: bool = False
):
    """Create an Aegis HMAC evidence signature."""
    _run_aegis_media(
        "sign", {"path": str(file), "key": key}, dry_run, Path(".eva/artifacts"), ["terminal", "json"], file
    )


@media_app.command("verify")
def media_verify_cmd(
    file: Path,
    signature: str,
    key: Annotated[str, typer.Option("--key", prompt=True, hide_input=True)],
    dry_run: bool = False,
):
    """Verify an Aegis HMAC evidence signature."""
    _run_aegis_media(
        "verify",
        {"path": str(file), "signature": signature, "key": key},
        dry_run,
        Path(".eva/artifacts"),
        ["terminal", "json"],
        file,
    )


@media_app.command("slice-bitplanes")
def media_slice_bitplanes_cmd(
    file: Annotated[Path, typer.Argument(help="Image file to slice into bitplanes")],
    output_dir: Annotated[Path, typer.Argument(help="Directory to save bitplane images")],
    dry_run: bool = False,
):
    """Deconstruct an image into its binary bit-planes."""
    _run_aegis_media(
        "slice-bitplanes",
        {"path": str(file), "output_dir": str(output_dir)},
        dry_run,
        Path(".eva/artifacts"),
        ["terminal", "json"],
        file,
    )


@media_app.command("sanitize")
def media_sanitize_cmd(
    file: Annotated[Path, typer.Argument(help="Image file to sanitize")],
    output: Annotated[Path, typer.Argument(help="Output path for cleaned image")],
    dry_run: bool = False,
):
    """Strip metadata, ICC profiles, and residual trace data from an image."""
    _run_aegis_media(
        "sanitize",
        {"path": str(file), "output_path": str(output)},
        dry_run,
        Path(".eva/artifacts"),
        ["terminal", "json"],
        file,
    )


@media_app.command("keygen")
def media_keygen_cmd(
    output_dir: Annotated[Path, typer.Argument(help="Directory to save generated Ed25519 keys")] = Path("."),
    dry_run: bool = False,
):
    """Generate an Ed25519 key pair for asymmetric image signing."""
    _run_aegis_media(
        "keygen",
        {"output_dir": str(output_dir)},
        dry_run,
        Path(".eva/artifacts"),
        ["terminal", "json"],
    )


@media_app.command("sign-asymmetric")
def media_sign_asymmetric_cmd(
    file: Annotated[Path, typer.Argument(help="Image file to sign")],
    priv_key: Annotated[Path, typer.Option("--priv-key", help="Path to Ed25519 private key PEM file")],
    dry_run: bool = False,
):
    """Sign an image hash asymmetrically using an Ed25519 private key."""
    _run_aegis_media(
        "sign-asymmetric",
        {"path": str(file), "priv_key": str(priv_key)},
        dry_run,
        Path(".eva/artifacts"),
        ["terminal", "json"],
        file,
    )


@media_app.command("verify-asymmetric")
def media_verify_asymmetric_cmd(
    file: Annotated[Path, typer.Argument(help="Image file to verify")],
    signature: Annotated[str, typer.Argument(help="Ed25519 signature string")],
    pub_key: Annotated[Path, typer.Option("--pub-key", help="Path to Ed25519 public key PEM file")],
    dry_run: bool = False,
):
    """Verify an asymmetric Ed25519 image signature using a public key."""
    _run_aegis_media(
        "verify-asymmetric",
        {"path": str(file), "pub_key": str(pub_key), "signature": signature},
        dry_run,
        Path(".eva/artifacts"),
        ["terminal", "json"],
        file,
    )


@media_app.command("embed")
def media_embed_cmd(
    carrier: Annotated[Path, typer.Argument(help="Carrier image file")],
    payload: Annotated[Path, typer.Argument(help="Payload file to embed")],
    output: Annotated[Path, typer.Argument(help="Output path for steganographic image")],
    algo: Annotated[str, typer.Option("--algo", help="Algorithm: adaptive, f5, or j_uniward")] = "adaptive",
    password: Annotated[str | None, typer.Option("--password", help="Encryption password")] = None,
    dry_run: bool = False,
):
    """Embed a payload into a carrier image via steganography."""
    params: dict[str, Any] = {
        "carrier": str(carrier),
        "payload": str(payload),
        "output_path": str(output),
        "algo": algo,
    }
    if password:
        params["password"] = password
    _run_aegis_media("embed", params, dry_run, Path(".eva/artifacts"), ["terminal", "json"], carrier)


@media_app.command("extract")
def media_extract_cmd(
    carrier: Annotated[Path, typer.Argument(help="Stego image file")],
    output: Annotated[Path, typer.Argument(help="Output path for extracted payload")],
    algo: Annotated[str, typer.Option("--algo", help="Algorithm: adaptive, f5, or j_uniward")] = "adaptive",
    password: Annotated[str | None, typer.Option("--password", help="Decryption password")] = None,
    dry_run: bool = False,
):
    """Extract a payload from a steganographic image."""
    params: dict[str, Any] = {
        "carrier": str(carrier),
        "output_path": str(output),
        "algo": algo,
    }
    if password:
        params["password"] = password
    _run_aegis_media("extract", params, dry_run, Path(".eva/artifacts"), ["terminal", "json"], carrier)


@media_app.command("palette-embed")
def media_palette_embed_cmd(
    carrier: Annotated[Path, typer.Argument(help="Carrier palette/indexed image")],
    payload: Annotated[Path, typer.Argument(help="Payload file to embed")],
    output: Annotated[Path, typer.Argument(help="Output stego image path")],
    password: Annotated[str | None, typer.Option("--password", help="Encryption password")] = None,
    dry_run: bool = False,
):
    """Embed payload into image colour palette."""
    params: dict[str, Any] = {"carrier": str(carrier), "payload": str(payload), "output_path": str(output)}
    if password:
        params["password"] = password
    _run_aegis_media(
        "palette-embed",
        params,
        dry_run,
        Path(".eva/artifacts"),
        ["terminal", "json"],
        carrier,
    )


@media_app.command("palette-extract")
def media_palette_extract_cmd(
    carrier: Annotated[Path, typer.Argument(help="Stego image with palette payload")],
    output: Annotated[Path, typer.Argument(help="Output path for recovered payload")],
    password: Annotated[str | None, typer.Option("--password", help="Decryption password")] = None,
    dry_run: bool = False,
):
    """Extract payload from image colour palette."""
    params: dict[str, Any] = {"carrier": str(carrier), "output_path": str(output)}
    if password:
        params["password"] = password
    _run_aegis_media(
        "palette-extract",
        params,
        dry_run,
        Path(".eva/artifacts"),
        ["terminal", "json"],
        carrier,
    )


@media_app.command("meta-embed")
def media_meta_embed_cmd(
    carrier: Annotated[Path, typer.Argument(help="Carrier image")],
    payload: Annotated[Path, typer.Argument(help="Payload file")],
    output: Annotated[Path, typer.Argument(help="Output image path")],
    channel: Annotated[str, typer.Option("--channel", help="Metadata channel: gps, icc, xmp")] = "gps",
    password: Annotated[str | None, typer.Option("--password", help="Encryption password")] = None,
    dry_run: bool = False,
):
    """Embed payload into image metadata channels."""
    params: dict[str, Any] = {
        "carrier": str(carrier),
        "payload": str(payload),
        "output_path": str(output),
        "channel": channel,
    }
    if password:
        params["password"] = password
    _run_aegis_media(
        "meta-embed",
        params,
        dry_run,
        Path(".eva/artifacts"),
        ["terminal", "json"],
        carrier,
    )


@media_app.command("meta-extract")
def media_meta_extract_cmd(
    carrier: Annotated[Path, typer.Argument(help="Carrier image")],
    output: Annotated[Path, typer.Argument(help="Output path for payload")],
    channel: Annotated[str, typer.Option("--channel", help="Metadata channel: gps, icc, xmp")] = "gps",
    password: Annotated[str | None, typer.Option("--password", help="Decryption password")] = None,
    dry_run: bool = False,
):
    """Extract payload from image metadata channels."""
    params: dict[str, Any] = {
        "carrier": str(carrier),
        "output_path": str(output),
        "channel": channel,
    }
    if password:
        params["password"] = password
    _run_aegis_media(
        "meta-extract",
        params,
        dry_run,
        Path(".eva/artifacts"),
        ["terminal", "json"],
        carrier,
    )


@media_app.command("split")
def media_split_cmd(
    payload: Annotated[Path, typer.Argument(help="Payload file to split")],
    output_dir: Annotated[Path, typer.Argument(help="Output directory for generated shares")],
    k: Annotated[int, typer.Option("-k", help="Threshold shares required")] = 2,
    n: Annotated[int, typer.Option("-n", help="Total shares to generate")] = 3,
    password: Annotated[str | None, typer.Option("--password", help="Encryption password")] = None,
    dry_run: bool = False,
):
    """Split a secret payload across multiple secret shares."""
    params: dict[str, Any] = {
        "payload": str(payload),
        "output_dir": str(output_dir),
        "k": k,
        "n": n,
    }
    if password:
        params["password"] = password
    _run_aegis_media(
        "split",
        params,
        dry_run,
        Path(".eva/artifacts"),
        ["terminal", "json"],
        payload,
    )


@media_app.command("reconstruct")
def media_reconstruct_cmd(
    output: Annotated[Path, typer.Argument(help="Output path for reconstructed payload")],
    shares: Annotated[list[Path], typer.Argument(help="Share binary files")],
    password: Annotated[str | None, typer.Option("--password", help="Decryption password")] = None,
    dry_run: bool = False,
):
    """Reconstruct a secret payload from shares."""
    params: dict[str, Any] = {
        "output_path": str(output),
        "shares": [str(s) for s in shares],
    }
    if password:
        params["password"] = password
    _run_aegis_media(
        "reconstruct",
        params,
        dry_run,
        Path(".eva/artifacts"),
        ["terminal", "json"],
        shares[0] if shares else None,
    )


@media_app.command("fs-embed")
def media_fs_embed_cmd(
    target: Annotated[Path, typer.Argument(help="File to attach extended attribute payload to")],
    payload: Annotated[Path, typer.Argument(help="Secret payload file")],
    password: Annotated[str | None, typer.Option("--password", help="Encryption password")] = None,
    dry_run: bool = False,
):
    """Store hidden data in filesystem extended attributes (xattr)."""
    params: dict[str, Any] = {"target": str(target), "payload": str(payload)}
    if password:
        params["password"] = password
    _run_aegis_media(
        "fs-embed",
        params,
        dry_run,
        Path(".eva/artifacts"),
        ["terminal", "json"],
        target,
    )


@media_app.command("fs-extract")
def media_fs_extract_cmd(
    target: Annotated[Path, typer.Argument(help="File containing extended attribute payload")],
    output: Annotated[Path, typer.Argument(help="Output file for extracted payload")],
    password: Annotated[str | None, typer.Option("--password", help="Decryption password")] = None,
    dry_run: bool = False,
):
    """Extract hidden data from filesystem extended attributes (xattr)."""
    params: dict[str, Any] = {"target": str(target), "output_path": str(output)}
    if password:
        params["password"] = password
    _run_aegis_media(
        "fs-extract",
        params,
        dry_run,
        Path(".eva/artifacts"),
        ["terminal", "json"],
        target,
    )


@media_app.command("timestomp")
def media_timestomp_cmd(
    target: Annotated[Path, typer.Argument(help="Target file to modify timestamps on")],
    clone_from: Annotated[Path, typer.Option("--clone-from", help="Reference file to clone timestamps from")],
    dry_run: bool = False,
):
    """Clone MAC timestamps from a reference file."""
    _run_aegis_media(
        "timestomp",
        {"target": str(target), "clone_from": str(clone_from)},
        dry_run,
        Path(".eva/artifacts"),
        ["terminal", "json"],
        target,
    )


@media_app.command("shred")
def media_shred_cmd(
    file: Annotated[Path, typer.Argument(help="File to securely overwrite and delete")],
    passes: Annotated[int, typer.Option("--passes", help="Number of overwrite passes")] = 3,
    dry_run: bool = False,
):
    """Securely overwrite and shred a file to prevent recovery."""
    _run_aegis_media(
        "shred",
        {"file_path": str(file), "passes": passes},
        dry_run,
        Path(".eva/artifacts"),
        ["terminal", "json"],
        file,
    )


@sec_app.command("ingest")
def ingest_cmd(
    report: Annotated[Path, typer.Argument(help="SARIF, JSON, or Aegis JSON report")],
    artifacts_dir: Annotated[Path, typer.Option("--artifacts-dir", help="Artifact root directory")] = Path(
        ".eva/artifacts"
    ),
    formats: Annotated[
        list[str] | None, typer.Option("--format", "-f", help="Report format: terminal, json, markdown, sarif")
    ] = None,
):
    """Normalize an existing report into Eva's finding schema."""
    findings, context = ingest_report(report, artifacts_dir=artifacts_dir)
    _render_and_write(findings, context.run_dir, _formats(formats))
    print_success(f"Ingested {len(findings)} findings into {context.run_dir}")


@sec_app.command("report")
def report_cmd(
    report: Annotated[Path | None, typer.Argument(help="Normalized findings JSON or scanner report")] = None,
    artifacts_dir: Annotated[Path, typer.Option("--artifacts-dir", help="Artifact root directory")] = Path(
        ".eva/artifacts"
    ),
    formats: Annotated[
        list[str] | None, typer.Option("--format", "-f", help="Report format: terminal, json, markdown, sarif")
    ] = None,
):
    """Render terminal, JSON, Markdown, or SARIF reports from normalized findings."""
    target = report
    if target is None:
        candidates = sorted(artifacts_dir.glob("*/findings.json"))
        if not candidates:
            print_error("No report supplied and no .eva/artifacts/*/findings.json found.")
            raise typer.Exit(1)
        target = candidates[-1]
    findings = normalize_report(target)
    context = _new_context(artifacts_dir)
    _render_and_write(findings, context.run_dir, _formats(formats))
    print_success(f"Rendered {len(findings)} findings into {context.run_dir}")


@sec_app.command("run")
def run_cmd(
    plan: Annotated[Path, typer.Argument(help="Declarative eva sec workflow YAML")],
    dry_run: Annotated[bool, typer.Option("--dry-run", help="Validate and show commands without executing")] = False,
    yes: Annotated[bool, typer.Option("--yes", "-y", help="Confirm approved active operations")] = False,
):
    """Execute a declarative security workflow."""
    try:
        findings, context = run_security_workflow(plan, dry_run=dry_run, yes=yes)
    except Exception as exc:
        print_error(str(exc))
        raise typer.Exit(1) from exc
    render_terminal(findings, console)
    print_success(f"Workflow run {context.run_id} complete. Artifacts: {context.run_dir}")


@sec_app.command("zap")
def zap_cmd(
    target: Annotated[str, typer.Argument(help="Approved web target URL")],
    scope_file: Annotated[Path, typer.Option("--scope", help="Required ZAP authorization scope YAML")],
    active: Annotated[bool, typer.Option("--active", help="Enable active scanning after scope approval")] = False,
    yes: Annotated[bool, typer.Option("--yes", "-y", help="Confirm active scan after scope review")] = False,
    dry_run: Annotated[bool, typer.Option("--dry-run", help="Generate argv and plan without executing")] = False,
    generate_plan: Annotated[
        Path | None, typer.Option("--generate-plan", help="Write a ZAP automation YAML plan")
    ] = None,
    import_plan: Annotated[
        Path | None, typer.Option("--import-plan", help="Use an existing ZAP automation YAML plan")
    ] = None,
    artifacts_dir: Annotated[Path, typer.Option("--artifacts-dir", help="Artifact root directory")] = Path(
        ".eva/artifacts"
    ),
):
    """Run an authorized passive ZAP baseline, or explicit active scan with scope approval."""
    try:
        scope = load_scope_file(scope_file)
        assert_zap_authorized(target, scope, active=active)
    except ScopeError as exc:
        print_error(str(exc))
        raise typer.Exit(1) from exc
    if active:
        console.print(scope.summary())
        if not yes and not typer.confirm("Run active ZAP scan within this approved scope?", default=False):
            raise typer.Exit(1)
    context = _new_context(artifacts_dir, dry_run=dry_run, scope_id=scope.engagement_id)
    adapter = get_adapter("zap.active" if active else "zap.baseline")
    output_path = adapter.output_path(context.run_dir, "active" if active else "baseline")
    plan_path = import_plan or context.run_dir / "zap-automation.yaml"
    if not import_plan:
        plan = adapter.build_plan(target=target, scope=scope, output_path=output_path, active=active)
        adapter.write_plan(generate_plan or plan_path, plan)
        if generate_plan:
            plan_path = generate_plan
    result = adapter.execute(
        "active" if active else "baseline",
        {"target": target, "plan_path": str(plan_path), "active": active},
        cwd=Path.cwd(),
        run_dir=context.run_dir,
        run_id=context.run_id,
        dry_run=dry_run,
        scope_id=scope.engagement_id,
    )
    findings = []
    if result.output_path and Path(result.output_path).exists():
        context.artifacts.append(artifact_record(result.output_path, "zap-output"))
        findings = adapter.parse_output(Path(result.output_path), result.stdout)
    _render_and_write(findings, context.run_dir, ["terminal", "json", "sarif"])
    print_success(f"ZAP run {context.run_id} complete. Artifacts: {context.run_dir}")


# ---------------------------------------------------------------------------
# YARA Scanning & Compilation (eva sec yara)
# ---------------------------------------------------------------------------


@yara_app.command("scan")
def yara_scan_cmd(
    path: Annotated[Path, typer.Argument(help="Target file or directory to scan")],
    rules: Annotated[
        Path | None,
        typer.Option(
            "--rules",
            "-r",
            help="Path to YARA rule file (.yar), directory of rules, or compiled rules. Defaults to curated baseline.",
        ),
    ] = None,
    recursive: Annotated[bool, typer.Option("--recursive/--no-recursive", help="Scan directories recursively")] = True,
    dry_run: Annotated[bool, typer.Option("--dry-run", help="Show scan plan without executing")] = False,
    artifacts_dir: Annotated[Path, typer.Option("--artifacts-dir", help="Artifact root directory")] = Path(
        ".eva/artifacts"
    ),
    formats: Annotated[
        list[str] | None, typer.Option("--format", "-f", help="Report format: terminal, json, markdown, sarif")
    ] = None,
):
    """Scan files or directories using curated defensive YARA rules or custom rule files."""
    rules_path = rules or get_default_rules_path()
    context = _new_context(artifacts_dir, dry_run=dry_run)

    if dry_run:
        print_info(f"[Dry-Run] Planned YARA scan on: {path}")
        print_info(f"[Dry-Run] Rules source: {rules_path} (recursive={recursive})")
        print_info(f"[Dry-Run] Output formats: {_formats(formats)}")
        return

    if not path.exists():
        print_error(f"Scan target not found: {path}")
        raise typer.Exit(1)

    try:
        findings = scan_with_yara(path, rules=rules_path, recursive=recursive, artifact_path=str(context.run_dir))
    except Exception as exc:
        print_error(f"YARA scan failed: {exc}")
        raise typer.Exit(1) from exc

    write_json_artifact(
        context.run_dir / "yara-scan-manifest.json",
        {"target": str(path), "rules": str(rules_path), "recursive": recursive, "matches_count": len(findings)},
        "yara-scan",
    )
    report_paths = _render_and_write(findings, context.run_dir, _formats(formats))
    write_json_artifact(
        context.run_dir / "run-summary.json",
        {"run_id": context.run_id, "findings_count": len(findings), "reports": report_paths},
        "run-summary",
    )
    print_success(f"YARA scan complete: {len(findings)} finding(s). Artifacts: {context.run_dir}")


@yara_app.command("compile")
def yara_compile_cmd(
    rules_dir: Annotated[Path, typer.Argument(help="Directory of .yar rule files or single rule file to compile")],
    output: Annotated[Path, typer.Option("-o", "--output", help="Output path for compiled binary rules file")],
    dry_run: Annotated[
        bool, typer.Option("--dry-run", help="Validate rule syntax without writing output file")
    ] = False,
):
    """Compile YARA rules into a high-performance compiled binary rules file."""
    if dry_run:
        print_info(f"[Dry-Run] Planned compilation of YARA rules from {rules_dir} -> {output}")
        return

    try:
        compile_yara_rules(rules_dir, output_path=output)
        print_success(f"Successfully compiled YARA rules to {output}")
    except Exception as exc:
        print_error(f"Compilation failed: {exc}")
        raise typer.Exit(1) from exc


# ---------------------------------------------------------------------------
# Malware & Binary Static Analysis (eva sec binary)
# ---------------------------------------------------------------------------


@binary_app.command("pe")
def binary_pe_cmd(
    file: Annotated[Path, typer.Argument(help="Windows PE executable file to analyze (.exe, .dll, .sys)")],
    dry_run: Annotated[bool, typer.Option("--dry-run", help="Show analysis plan without executing")] = False,
    artifacts_dir: Annotated[Path, typer.Option("--artifacts-dir", help="Artifact root directory")] = Path(
        ".eva/artifacts"
    ),
    formats: Annotated[
        list[str] | None, typer.Option("--format", "-f", help="Report format: terminal, json, markdown, sarif")
    ] = None,
):
    """Extract PE headers, compile timestamp, entry point, imports/exports, and security flags."""
    context = _new_context(artifacts_dir, dry_run=dry_run)
    if dry_run:
        print_info(f"[Dry-Run] Planned PE static analysis for: {file}")
        print_info(f"[Dry-Run] Output formats: {_formats(formats)}")
        return

    if not file.exists():
        print_error(f"File not found: {file}")
        raise typer.Exit(1)

    try:
        metadata, findings = analyze_pe(file, artifact_path=str(context.run_dir))
    except Exception as exc:
        print_error(f"PE analysis error: {exc}")
        raise typer.Exit(1) from exc

    if metadata.get("is_valid_pe"):
        table = Table(title=f"PE Analysis: {file.name}")
        table.add_column("Property", style="cyan")
        table.add_column("Value")
        table.add_row("Architecture", str(metadata.get("optional_header", {}).get("architecture", "Unknown")))
        table.add_row("Entry Point", str(metadata.get("optional_header", {}).get("entry_point", "Unknown")))
        table.add_row("Compilation Time", str(metadata.get("file_header", {}).get("timedatestamp_iso", "Unknown")))
        table.add_row("Sections Count", str(metadata.get("file_header", {}).get("number_of_sections", 0)))
        table.add_row("Imported DLLs", str(metadata.get("imported_dlls_count", 0)))
        table.add_row("Exported Functions", str(metadata.get("exports_count", 0)))

        flags = metadata.get("security_flags", {})
        flag_summary = ", ".join([f"{k}={'yes' if v else 'no'}" for k, v in flags.items()])
        table.add_row("Mitigations / Flags", flag_summary)
        console.print(table)

    write_json_artifact(context.run_dir / "pe-analysis.json", metadata, "pe-analysis")
    report_paths = _render_and_write(findings, context.run_dir, _formats(formats))
    write_json_artifact(
        context.run_dir / "run-summary.json",
        {"run_id": context.run_id, "findings_count": len(findings), "reports": report_paths},
        "run-summary",
    )
    print_success(f"PE analysis complete: {len(findings)} finding(s). Artifacts: {context.run_dir}")


@binary_app.command("elf")
def binary_elf_cmd(
    file: Annotated[Path, typer.Argument(help="Linux ELF executable or shared object to analyze")],
    dry_run: Annotated[bool, typer.Option("--dry-run", help="Show analysis plan without executing")] = False,
    artifacts_dir: Annotated[Path, typer.Option("--artifacts-dir", help="Artifact root directory")] = Path(
        ".eva/artifacts"
    ),
    formats: Annotated[
        list[str] | None, typer.Option("--format", "-f", help="Report format: terminal, json, markdown, sarif")
    ] = None,
):
    """Extract ELF headers, architecture, entry point, shared libraries, symbols, and mitigations."""
    context = _new_context(artifacts_dir, dry_run=dry_run)
    if dry_run:
        print_info(f"[Dry-Run] Planned ELF static analysis for: {file}")
        print_info(f"[Dry-Run] Output formats: {_formats(formats)}")
        return

    if not file.exists():
        print_error(f"File not found: {file}")
        raise typer.Exit(1)

    try:
        metadata, findings = analyze_elf(file, artifact_path=str(context.run_dir))
    except Exception as exc:
        print_error(f"ELF analysis error: {exc}")
        raise typer.Exit(1) from exc

    if metadata.get("is_valid_elf"):
        table = Table(title=f"ELF Analysis: {file.name}")
        table.add_column("Property", style="cyan")
        table.add_column("Value")
        hdr = metadata.get("header", {})
        table.add_row("Class / Machine", f"{hdr.get('class', '')} / {hdr.get('machine', '')}")
        table.add_row("Entry Point", str(hdr.get("entry_point", "")))
        table.add_row("Shared Libraries", ", ".join(metadata.get("shared_libraries", [])) or "None")
        table.add_row("Dynamic Symbols", str(metadata.get("dynamic_symbols_count", 0)))

        mits = metadata.get("mitigations", {})
        mit_summary = f"RELRO: {mits.get('relro')}, Stack Canary: {mits.get('stack_canary')}, NX: {mits.get('nx')}, PIE: {mits.get('pie')}"
        table.add_row("Mitigations", mit_summary)
        console.print(table)

    write_json_artifact(context.run_dir / "elf-analysis.json", metadata, "elf-analysis")
    report_paths = _render_and_write(findings, context.run_dir, _formats(formats))
    write_json_artifact(
        context.run_dir / "run-summary.json",
        {"run_id": context.run_id, "findings_count": len(findings), "reports": report_paths},
        "run-summary",
    )
    print_success(f"ELF analysis complete: {len(findings)} finding(s). Artifacts: {context.run_dir}")


@binary_app.command("entropy")
def binary_entropy_cmd(
    file: Annotated[Path, typer.Argument(help="Binary or file to analyze for Shannon entropy")],
    block_size: Annotated[
        int, typer.Option("--block-size", "-b", help="Block size in bytes for chunked entropy calculation")
    ] = 1024,
    dry_run: Annotated[bool, typer.Option("--dry-run", help="Show analysis plan without executing")] = False,
    artifacts_dir: Annotated[Path, typer.Option("--artifacts-dir", help="Artifact root directory")] = Path(
        ".eva/artifacts"
    ),
    formats: Annotated[
        list[str] | None, typer.Option("--format", "-f", help="Report format: terminal, json, markdown, sarif")
    ] = None,
):
    """Compute Shannon entropy per block and sliding window to detect packed/encrypted code."""
    context = _new_context(artifacts_dir, dry_run=dry_run)
    if dry_run:
        print_info(f"[Dry-Run] Planned entropy analysis on {file} (block-size={block_size})")
        print_info(f"[Dry-Run] Output formats: {_formats(formats)}")
        return

    if not file.exists():
        print_error(f"File not found: {file}")
        raise typer.Exit(1)

    try:
        metadata, findings = analyze_file_entropy(file, block_size=block_size, artifact_path=str(context.run_dir))
    except Exception as exc:
        print_error(f"Entropy analysis error: {exc}")
        raise typer.Exit(1) from exc

    table = Table(title=f"Shannon Entropy: {file.name}")
    table.add_column("Metric", style="cyan")
    table.add_column("Value")
    table.add_row("File Size", f"{metadata['file_size']} bytes")
    table.add_row("Overall Entropy", f"{metadata['overall_entropy']:.4f} / 8.0 bits per byte")
    summ = metadata.get("summary", {})
    table.add_row("Block Min / Max / Mean", f"{summ.get('min'):.2f} / {summ.get('max'):.2f} / {summ.get('mean'):.2f}")
    table.add_row("Standard Deviation", f"{summ.get('stddev'):.4f}")
    table.add_row("Total Blocks", str(metadata.get("blocks_count", 0)))
    table.add_row("High-Entropy Regions", str(metadata.get("high_entropy_regions_count", 0)))
    console.print(table)

    write_json_artifact(context.run_dir / "entropy-analysis.json", metadata, "entropy-analysis")
    report_paths = _render_and_write(findings, context.run_dir, _formats(formats))
    write_json_artifact(
        context.run_dir / "run-summary.json",
        {"run_id": context.run_id, "findings_count": len(findings), "reports": report_paths},
        "run-summary",
    )
    print_success(f"Entropy analysis complete: {len(findings)} finding(s). Artifacts: {context.run_dir}")


@binary_app.command("strings")
def binary_strings_cmd(
    file: Annotated[Path, typer.Argument(help="Binary file to extract strings and IOCs from")],
    min_len: Annotated[int, typer.Option("--min-len", "-m", help="Minimum string length")] = 4,
    encoding: Annotated[
        str, typer.Option("--encoding", "-e", help="Comma-separated encodings: ascii,utf16")
    ] = "ascii,utf16",
    dry_run: Annotated[bool, typer.Option("--dry-run", help="Show analysis plan without executing")] = False,
    artifacts_dir: Annotated[Path, typer.Option("--artifacts-dir", help="Artifact root directory")] = Path(
        ".eva/artifacts"
    ),
    formats: Annotated[
        list[str] | None, typer.Option("--format", "-f", help="Report format: terminal, json, markdown, sarif")
    ] = None,
):
    """Extract strings with regex filtering for IOCs (IPs, URLs, registry paths, PowerShell)."""
    context = _new_context(artifacts_dir, dry_run=dry_run)
    enc_list = [enc.strip().lower() for enc in encoding.split(",") if enc.strip()]

    if dry_run:
        print_info(f"[Dry-Run] Planned strings extraction on {file} (min-len={min_len}, encodings={enc_list})")
        print_info(f"[Dry-Run] Output formats: {_formats(formats)}")
        return

    if not file.exists():
        print_error(f"File not found: {file}")
        raise typer.Exit(1)

    try:
        metadata, findings = extract_and_analyze_strings(
            file, min_len=min_len, encodings=enc_list, artifact_path=str(context.run_dir)
        )
    except Exception as exc:
        print_error(f"Strings extraction error: {exc}")
        raise typer.Exit(1) from exc

    table = Table(title=f"Strings & IOC Summary: {file.name}")
    table.add_column("Category", style="cyan")
    table.add_column("Count")
    table.add_row("Total Strings Extracted", str(metadata.get("total_strings_found", 0)))
    for cat, count in metadata.get("iocs_summary", {}).items():
        table.add_row(f"IOC: {cat}", str(count))
    console.print(table)

    write_json_artifact(context.run_dir / "strings-analysis.json", metadata, "strings-analysis")
    report_paths = _render_and_write(findings, context.run_dir, _formats(formats))
    write_json_artifact(
        context.run_dir / "run-summary.json",
        {"run_id": context.run_id, "findings_count": len(findings), "reports": report_paths},
        "run-summary",
    )
    print_success(f"Strings analysis complete: {len(findings)} finding(s). Artifacts: {context.run_dir}")


# ---------------------------------------------------------------------------
# Threat Intelligence & Enrichment (eva sec intel)
# ---------------------------------------------------------------------------


@intel_app.command("cve")
def intel_cve_cmd(
    cve_id: Annotated[str, typer.Argument(help="CVE identifier (e.g. CVE-2021-44228)")],
    dry_run: Annotated[bool, typer.Option("--dry-run", help="Show query plan without calling NIST NVD API")] = False,
    artifacts_dir: Annotated[Path, typer.Option("--artifacts-dir", help="Artifact root directory")] = Path(
        ".eva/artifacts"
    ),
    formats: Annotated[
        list[str] | None, typer.Option("--format", "-f", help="Report format: terminal, json, markdown, sarif")
    ] = None,
):
    """Fetch vulnerability description, CVSS v3.1 score, affected CPEs, and CWE details from NIST NVD API v2."""
    context = _new_context(artifacts_dir, dry_run=dry_run)
    if dry_run:
        print_info(f"[Dry-Run] Planned NIST NVD API v2 query for: {cve_id}")
        print_info(f"[Dry-Run] Output formats: {_formats(formats)}")
        return

    import asyncio

    client = IntelClient()
    try:
        metadata, findings = asyncio.run(client.fetch_cve(cve_id, artifact_path=str(context.run_dir)))
    except Exception as exc:
        print_error(f"CVE lookup error: {exc}")
        raise typer.Exit(1) from exc

    if metadata.get("found"):
        cvss = metadata.get("cvss", {})
        table = Table(title=f"NVD Vulnerability Intel: {cve_id.upper()}")
        table.add_column("Field", style="cyan")
        table.add_column("Detail")
        table.add_row(
            "Description",
            (metadata.get("description") or "")[:200] + ("..." if len(metadata.get("description", "")) > 200 else ""),
        )
        table.add_row("CVSS Score / Severity", f"{cvss.get('score', 'N/A')} ({cvss.get('severity', 'UNKNOWN')})")
        table.add_row("CVSS Vector", str(cvss.get("vector", "N/A")))
        table.add_row("Weaknesses (CWE)", ", ".join(metadata.get("cwes", [])) or "None specified")
        table.add_row("Affected Configurations", f"{len(metadata.get('affected_cpes', []))} CPE criteria")
        console.print(table)
    elif metadata.get("error"):
        print_info(f"NVD Response: {metadata.get('error')}")

    write_json_artifact(context.run_dir / "cve-intel.json", metadata, "cve-intel")
    report_paths = _render_and_write(findings, context.run_dir, _formats(formats))
    write_json_artifact(
        context.run_dir / "run-summary.json",
        {"run_id": context.run_id, "findings_count": len(findings), "reports": report_paths},
        "run-summary",
    )
    print_success(f"CVE lookup complete: {len(findings)} finding(s). Artifacts: {context.run_dir}")


@intel_app.command("ioc")
def intel_ioc_cmd(
    ioc_value: Annotated[str, typer.Argument(help="IOC value (IPv4, IPv6, Domain, URL, MD5, SHA-256)")],
    dry_run: Annotated[bool, typer.Option("--dry-run", help="Show query plan without calling external feeds")] = False,
    artifacts_dir: Annotated[Path, typer.Option("--artifacts-dir", help="Artifact root directory")] = Path(
        ".eva/artifacts"
    ),
    formats: Annotated[
        list[str] | None, typer.Option("--format", "-f", help="Report format: terminal, json, markdown, sarif")
    ] = None,
):
    """Automatically detect IOC type and query free/open intelligence feeds (AlienVault OTX, URLhaus, AbuseIPDB)."""
    context = _new_context(artifacts_dir, dry_run=dry_run)
    if dry_run:
        print_info(f"[Dry-Run] Planned Threat Intel query for IOC: {ioc_value}")
        print_info(f"[Dry-Run] Output formats: {_formats(formats)}")
        return

    import asyncio

    client = IntelClient()
    try:
        metadata, findings = asyncio.run(client.query_ioc(ioc_value, artifact_path=str(context.run_dir)))
    except Exception as exc:
        print_error(f"IOC query error: {exc}")
        raise typer.Exit(1) from exc

    table = Table(title=f"Threat Intel Enrichment: {ioc_value}")
    table.add_column("Feed / Attribute", style="cyan")
    table.add_column("Result")
    table.add_row("Detected Type", metadata.get("type", "unknown"))
    if metadata.get("internal"):
        table.add_row("Network Status", "RFC 1918 / Private Internal IP (External feeds skipped)")
    for src_name, src_info in metadata.get("sources", {}).items():
        if isinstance(src_info, dict):
            summary_str = ", ".join([f"{k}={v}" for k, v in src_info.items()])
            table.add_row(src_name, summary_str)
        else:
            table.add_row(src_name, str(src_info))
    console.print(table)

    write_json_artifact(context.run_dir / "ioc-intel.json", metadata, "ioc-intel")
    report_paths = _render_and_write(findings, context.run_dir, _formats(formats))
    write_json_artifact(
        context.run_dir / "run-summary.json",
        {"run_id": context.run_id, "findings_count": len(findings), "reports": report_paths},
        "run-summary",
    )
    print_success(f"IOC query complete: {len(findings)} finding(s). Artifacts: {context.run_dir}")


@intel_app.command("extract")
def intel_extract_cmd(
    target: Annotated[str, typer.Argument(help="File path or text string to extract IOCs from")],
    dry_run: Annotated[bool, typer.Option("--dry-run", help="Show extraction plan without parsing")] = False,
    artifacts_dir: Annotated[Path, typer.Option("--artifacts-dir", help="Artifact root directory")] = Path(
        ".eva/artifacts"
    ),
    formats: Annotated[
        list[str] | None, typer.Option("--format", "-f", help="Report format: terminal, json, markdown, sarif")
    ] = None,
):
    """Parse unstructured logs, reports, or text to extract and deduplicate all IOCs."""
    context = _new_context(artifacts_dir, dry_run=dry_run)
    if dry_run:
        print_info(f"[Dry-Run] Planned IOC extraction from input: {target[:80]}")
        print_info(f"[Dry-Run] Output formats: {_formats(formats)}")
        return

    try:
        extracted, findings = extract_iocs(target, artifact_path=str(context.run_dir))
    except Exception as exc:
        print_error(f"IOC extraction error: {exc}")
        raise typer.Exit(1) from exc

    table = Table(title="Extracted IOC Inventory")
    table.add_column("Type", style="cyan")
    table.add_column("Count")
    table.add_column("Sample Values")
    for ioc_type, vals in extracted.items():
        sample_str = ", ".join(vals[:3])
        if len(vals) > 3:
            sample_str += f" (+{len(vals) - 3} more)"
        table.add_row(ioc_type, str(len(vals)), sample_str or "-")
    console.print(table)

    write_json_artifact(context.run_dir / "extracted-iocs.json", extracted, "extracted-iocs")
    report_paths = _render_and_write(findings, context.run_dir, _formats(formats))
    write_json_artifact(
        context.run_dir / "run-summary.json",
        {"run_id": context.run_id, "findings_count": len(findings), "reports": report_paths},
        "run-summary",
    )
    print_success(f"IOC extraction complete: {len(findings)} finding(s). Artifacts: {context.run_dir}")
