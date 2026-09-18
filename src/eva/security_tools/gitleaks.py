from __future__ import annotations

from pathlib import Path
from typing import Any

from eva.security_tools.base import SecurityAdapter
from eva.security_tools.models import AdapterMetadata, Finding
from eva.security_tools.normalizers import normalize_gitleaks
from eva.security_tools.utils import read_json_file


class GitleaksAdapter(SecurityAdapter):
    metadata = AdapterMetadata(
        name="gitleaks",
        executable="gitleaks",
        version_check=["gitleaks", "version"],
        argv_schema={"path": "str"},
        output_schema="gitleaks-json",
        timeout=180,
        required_capabilities=["secret-detection"],
        risk_level="local",
        supported_output_formats=["json", "sarif"],
    )
    install_hint = "Install Gitleaks from https://github.com/gitleaks/gitleaks#installing"

    def build_argv(self, operation: str, params: dict[str, Any], output_path: Path) -> list[str]:
        path = str(params.get("path", "."))
        return [
            self.metadata.executable,
            "detect",
            "--source",
            path,
            "--report-format",
            "json",
            "--report-path",
            str(output_path),
            "--no-banner",
        ]

    def parse_output(self, output_path: Path, stdout: str = "") -> list[Finding]:
        if not output_path.exists():
            return []
        return normalize_gitleaks(read_json_file(output_path), str(output_path))
