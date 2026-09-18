from __future__ import annotations

import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from eva.security.audit import append_command_audit
from eva.security.redaction import redact_secrets
from eva.security_tools.base import SecurityAdapter
from eva.security_tools.models import AdapterMetadata, Finding, ToolExecutionResult, ToolStatus
from eva.security_tools.normalizers import make_finding, normalize_aegis
from eva.security_tools.runner import run_tool_argv
from eva.security_tools.utils import read_json_file

ALL_AEGIS_OPERATIONS = {
    "analyze",
    "detect-stego",
    "scan-structure",
    "extract-hidden",
    "sanitize",
    "slice-bitplanes",
    "sign",
    "verify",
    "keygen",
    "sign-asymmetric",
    "verify-asymmetric",
    "embed",
    "extract",
    "palette-embed",
    "palette-extract",
    "meta-embed",
    "meta-extract",
    "split",
    "reconstruct",
    "fs-embed",
    "fs-extract",
    "timestomp",
    "shred",
}

SAFE_AEGIS_OPERATIONS = ALL_AEGIS_OPERATIONS
BLOCKED_AEGIS_OPERATIONS: set[str] = set()


class AegisAdapter(SecurityAdapter):
    metadata = AdapterMetadata(
        name="aegis",
        executable="aegis",
        version_check=["aegis", "--help"],
        argv_schema={"path": "str", "operation": "aegis-operation"},
        output_schema="aegis-json-or-stdout",
        timeout=180,
        required_capabilities=[
            "metadata",
            "steganography-detection",
            "image-structure-validation",
            "hidden-data-detection",
            "integrity-verification",
            "evidence-hashing",
            "bitplane-slicing",
            "sanitization",
            "payload-embedding",
            "payload-extraction",
            "multi-carrier",
            "file-security",
        ],
        risk_level="local",
        supported_output_formats=["json", "text"],
    )
    install_hint = "Aegis engine is integrated directly into Eva."

    def status(self) -> ToolStatus:
        return ToolStatus(
            name=self.metadata.name,
            executable=self.metadata.executable,
            installed=True,
            version="0.1.0 (integrated)",
            supported_features=sorted(ALL_AEGIS_OPERATIONS),
            install_hint=self.install_hint,
        )

    def build_argv(self, operation: str, params: dict[str, Any], output_path: Path) -> list[str]:
        if operation not in ALL_AEGIS_OPERATIONS:
            raise ValueError(f"Unknown Aegis operation: {operation}")

        base = [self.metadata.executable, "--no-banner", operation]

        if operation == "analyze":
            path = str(params.get("path") or params.get("image") or "")
            if not path:
                raise ValueError("aegis analyze requires a path")
            return [*base, "--json-out", str(output_path), path]

        if operation == "detect-stego":
            path = str(params.get("path") or params.get("image") or "")
            if not path:
                raise ValueError("aegis detect-stego requires a path")
            return [*base, path]

        if operation == "scan-structure":
            path = str(params.get("path") or params.get("image") or "")
            if not path:
                raise ValueError("aegis scan-structure requires a path")
            return [*base, path]

        if operation == "extract-hidden":
            path = str(params.get("path") or params.get("image") or "")
            if not path:
                raise ValueError("aegis extract-hidden requires a path")
            extracted = Path(params.get("output_path") or output_path.with_suffix(".hidden.bin"))
            return [*base, path, str(extracted)]

        if operation == "sanitize":
            path = str(params.get("path") or params.get("image") or "")
            if not path:
                raise ValueError("aegis sanitize requires a path")
            sanitized = Path(params.get("output_path") or output_path.with_suffix(".sanitized.png"))
            return [*base, path, str(sanitized)]

        if operation == "slice-bitplanes":
            path = str(params.get("path") or params.get("image") or "")
            if not path:
                raise ValueError("aegis slice-bitplanes requires a path")
            bitplanes = Path(params.get("output_dir") or output_path.with_suffix(""))
            return [*base, path, str(bitplanes)]

        if operation == "sign":
            path = str(params.get("path") or params.get("image") or "")
            key = str(params.get("key", ""))
            if not path or not key:
                raise ValueError("aegis sign requires path and key")
            return [*base, "--key", key, path]

        if operation == "verify":
            path = str(params.get("path") or params.get("image") or "")
            key = str(params.get("key", ""))
            signature = str(params.get("signature", ""))
            if not path or not key or not signature:
                raise ValueError("aegis verify requires path, key, and signature")
            return [*base, "--key", key, path, signature]

        if operation == "keygen":
            output_dir = str(params.get("output_dir", "."))
            return [*base, output_dir]

        if operation == "sign-asymmetric":
            path = str(params.get("path") or params.get("image") or "")
            priv_key = str(params.get("priv_key", ""))
            if not path or not priv_key:
                raise ValueError("aegis sign-asymmetric requires path and priv_key")
            return [*base, "--priv-key", priv_key, path]

        if operation == "verify-asymmetric":
            path = str(params.get("path") or params.get("image") or "")
            pub_key = str(params.get("pub_key", ""))
            signature = str(params.get("signature", ""))
            if not path or not pub_key or not signature:
                raise ValueError("aegis verify-asymmetric requires path, pub_key, and signature")
            return [*base, "--pub-key", pub_key, path, signature]

        if operation == "embed":
            carrier = str(params.get("carrier") or params.get("carrier_path") or "")
            payload = str(params.get("payload") or params.get("payload_path") or "")
            dest = str(params.get("output_path") or params.get("output") or output_path)
            algo = str(params.get("algo", "adaptive"))
            if not carrier or not payload:
                raise ValueError("aegis embed requires carrier and payload")
            cmd = [*base, "--algo", algo]
            if params.get("password"):
                cmd.extend(["--password", str(params["password"])])
            return [*cmd, carrier, payload, dest]

        if operation == "extract":
            carrier = str(params.get("carrier") or params.get("carrier_path") or "")
            dest = str(params.get("output_path") or params.get("output") or output_path)
            algo = str(params.get("algo", "adaptive"))
            if not carrier:
                raise ValueError("aegis extract requires carrier")
            cmd = [*base, "--algo", algo]
            if params.get("password"):
                cmd.extend(["--password", str(params["password"])])
            return [*cmd, carrier, dest]

        if operation == "palette-embed":
            carrier = str(params.get("carrier") or params.get("carrier_path") or "")
            payload = str(params.get("payload") or params.get("payload_path") or "")
            dest = str(params.get("output_path") or params.get("output") or output_path)
            password = params.get("password")
            args = [*base]
            if password:
                args.extend(["--password", str(password)])
            return [*args, carrier, payload, dest]

        if operation == "palette-extract":
            carrier = str(params.get("carrier") or params.get("carrier_path") or "")
            dest = str(params.get("output_path") or params.get("output") or output_path)
            password = params.get("password")
            args = [*base]
            if password:
                args.extend(["--password", str(password)])
            return [*args, carrier, dest]

        if operation == "meta-embed":
            carrier = str(params.get("carrier") or params.get("carrier_path") or "")
            payload = str(params.get("payload") or params.get("payload_path") or "")
            dest = str(params.get("output_path") or params.get("output") or output_path)
            channel = str(params.get("channel", "gps"))
            password = params.get("password")
            args = [*base, "--channel", channel]
            if password:
                args.extend(["--password", str(password)])
            return [*args, carrier, payload, dest]

        if operation == "meta-extract":
            carrier = str(params.get("carrier") or params.get("carrier_path") or "")
            dest = str(params.get("output_path") or params.get("output") or output_path)
            channel = str(params.get("channel", "gps"))
            password = params.get("password")
            args = [*base, "--channel", channel]
            if password:
                args.extend(["--password", str(password)])
            return [*args, carrier, dest]

        if operation == "split":
            payload = str(params.get("payload") or "")
            dest = str(params.get("output_dir") or params.get("output") or output_path.parent / "shares")
            k = int(params.get("k", 2))
            n = int(params.get("n", 3))
            password = params.get("password")
            args = [*base, "-k", str(k), "-n", str(n)]
            if password:
                args.extend(["--password", str(password)])
            return [*args, payload, dest]

        if operation == "reconstruct":
            dest = str(params.get("output_path") or params.get("output") or output_path)
            shares = params.get("shares") or params.get("carriers", [])
            password = params.get("password")
            args = [*base]
            if password:
                args.extend(["--password", str(password)])
            return [*args, *[str(s) for s in shares], dest]

        if operation == "fs-embed":
            target = str(params.get("target") or params.get("path") or "")
            payload = str(params.get("payload") or "")
            password = params.get("password")
            args = [*base]
            if password:
                args.extend(["--password", str(password)])
            return [*args, target, payload]

        if operation == "fs-extract":
            target = str(params.get("target") or params.get("path") or "")
            dest = str(params.get("output_path") or params.get("output") or output_path)
            password = params.get("password")
            args = [*base]
            if password:
                args.extend(["--password", str(password)])
            return [*args, target, dest]

        if operation == "timestomp":
            target = str(params.get("target") or params.get("target_file") or "")
            clone_from = str(params.get("clone_from") or "")
            return [*base, "--clone-from", clone_from, target]

        if operation == "shred":
            file_path = str(params.get("path") or params.get("file_path") or "")
            passes = int(params.get("passes", 3))
            return [*base, "--passes", str(passes), file_path]

        path = str(params.get("path") or "")
        return [*base, path]

    def execute(
        self,
        operation: str,
        params: dict[str, Any],
        *,
        cwd: Path,
        run_dir: Path,
        run_id: str,
        dry_run: bool,
        scope_id: str | None = None,
    ) -> ToolExecutionResult:
        output_path = self.output_path(run_dir, operation)
        argv = self.build_argv(operation, params, output_path)

        if dry_run:
            return run_tool_argv(
                adapter=self.metadata.name,
                operation=operation,
                argv=argv,
                cwd=cwd,
                timeout=self.metadata.timeout,
                output_path=output_path,
                dry_run=True,
                run_id=run_id,
                scope_id=scope_id,
            )

        started = datetime.now(timezone.utc)
        start = time.time()
        try:
            from click.testing import CliRunner

            from eva.security_tools.aegis_engine.main import cli

            runner = CliRunner()
            # argv is ['aegis', '--no-banner', operation, ...]
            # pass args after 'aegis'
            res = runner.invoke(cli, argv[1:], catch_exceptions=False)
            finished = datetime.now(timezone.utc)
            result = ToolExecutionResult(
                adapter=self.metadata.name,
                operation=operation,
                argv=argv,
                dry_run=False,
                output_path=str(output_path) if output_path.exists() else None,
                return_code=res.exit_code,
                stdout=redact_secrets(res.output or ""),
                stderr="",
                started_at=started,
                finished_at=finished,
                duration_s=round(time.time() - start, 3),
            )
        except Exception as exc:  # noqa: BLE001
            finished = datetime.now(timezone.utc)
            result = ToolExecutionResult(
                adapter=self.metadata.name,
                operation=operation,
                argv=argv,
                dry_run=False,
                output_path=str(output_path) if output_path.exists() else None,
                return_code=1,
                stdout="",
                stderr=str(exc),
                started_at=started,
                finished_at=finished,
                duration_s=round(time.time() - start, 3),
            )

        append_command_audit(
            {
                "command": "eva sec",
                "run_id": run_id,
                "scope_id": scope_id,
                "adapter": self.metadata.name,
                "operation": operation,
                "argv": argv,
                "executed": True,
                "exit_status": result.return_code,
                "timed_out": False,
                "missing": False,
                "started_at": result.started_at.isoformat(),
                "finished_at": result.finished_at.isoformat(),
                "duration_s": result.duration_s,
                "artifact_path": result.output_path,
            }
        )
        return result

    def parse_output(self, output_path: Path, stdout: str = "") -> list[Finding]:
        if output_path.exists():
            try:
                return normalize_aegis(read_json_file(output_path), str(output_path))
            except Exception:  # noqa: BLE001, S110
                pass
        if stdout:
            return [
                make_finding(
                    tool="aegis",
                    rule_id="aegis.stdout",
                    title="Aegis output captured",
                    severity="info",
                    category="forensics",
                    evidence=stdout,
                    artifact_path=str(output_path),
                )
            ]
        return []
