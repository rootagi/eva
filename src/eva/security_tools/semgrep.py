from __future__ import annotations

from pathlib import Path
from typing import Any

from eva.security_tools.base import SecurityAdapter
from eva.security_tools.models import AdapterMetadata, Finding
from eva.security_tools.normalizers import normalize_semgrep
from eva.security_tools.utils import read_json_file


class SemgrepAdapter(SecurityAdapter):
    metadata = AdapterMetadata(
        name="semgrep",
        executable="semgrep",
        version_check=["semgrep", "--version"],
        argv_schema={"path": "str", "config": "str"},
        output_schema="semgrep-json",
        timeout=300,
        required_capabilities=["sast"],
        risk_level="local",
        supported_output_formats=["json", "sarif"],
    )
    install_hint = "Install Semgrep with: python -m pip install semgrep"

    def build_argv(self, operation: str, params: dict[str, Any], output_path: Path) -> list[str]:
        path = str(params.get("path", "."))
        config = str(params.get("config", "auto"))
        return [
            self.metadata.executable,
            "scan",
            "--json",
            "--config",
            config,
            "--output",
            str(output_path),
            path,
        ]

    def parse_output(self, output_path: Path, stdout: str = "") -> list[Finding]:
        if not output_path.exists():
            return []
        return normalize_semgrep(read_json_file(output_path), str(output_path))
