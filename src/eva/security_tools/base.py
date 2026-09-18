from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Any

from eva.security.redaction import redact_secrets
from eva.security_tools.models import AdapterMetadata, Finding, ToolStatus
from eva.security_tools.runner import run_tool_argv


class SecurityAdapter:
    metadata: AdapterMetadata
    install_hint: str = ""

    def build_argv(self, operation: str, params: dict[str, Any], output_path: Path) -> list[str]:
        raise NotImplementedError

    def parse_output(self, output_path: Path, stdout: str = "") -> list[Finding]:
        return []

    def output_suffix(self, operation: str) -> str:
        return "json"

    def output_path(self, run_dir: Path, operation: str) -> Path:
        return run_dir / f"{self.metadata.name}-{operation}.{self.output_suffix(operation)}"

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
    ):
        output_path = self.output_path(run_dir, operation)
        argv = self.build_argv(operation, params, output_path)
        return run_tool_argv(
            adapter=self.metadata.name,
            operation=operation,
            argv=argv,
            cwd=cwd,
            timeout=self.metadata.timeout,
            output_path=output_path,
            dry_run=dry_run,
            run_id=run_id,
            scope_id=scope_id,
        )

    def status(self) -> ToolStatus:
        exe = shutil.which(self.metadata.executable)
        if not exe:
            return ToolStatus(
                name=self.metadata.name,
                executable=self.metadata.executable,
                installed=False,
                supported_features=self.metadata.required_capabilities,
                install_hint=self.install_hint,
                error="not found on PATH",
            )
        try:
            completed = subprocess.run(
                self.metadata.version_check,
                shell=False,
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            version = redact_secrets((completed.stdout or completed.stderr or "").strip().splitlines()[0:1][0])
        except (OSError, subprocess.TimeoutExpired, IndexError) as exc:
            return ToolStatus(
                name=self.metadata.name,
                executable=self.metadata.executable,
                installed=True,
                supported_features=self.metadata.required_capabilities,
                install_hint=self.install_hint,
                error=str(exc),
            )
        return ToolStatus(
            name=self.metadata.name,
            executable=self.metadata.executable,
            installed=True,
            version=version,
            supported_features=self.metadata.required_capabilities,
            install_hint=self.install_hint,
        )
