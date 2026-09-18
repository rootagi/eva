from __future__ import annotations

from pathlib import Path
from typing import Any

from eva.security_tools.base import SecurityAdapter
from eva.security_tools.models import AdapterMetadata, Finding
from eva.security_tools.normalizers import normalize_osv
from eva.security_tools.utils import read_json_file


class OSVScannerAdapter(SecurityAdapter):
    metadata = AdapterMetadata(
        name="osv-scanner",
        executable="osv-scanner",
        version_check=["osv-scanner", "--version"],
        argv_schema={"path": "str"},
        output_schema="osv-json",
        timeout=300,
        required_capabilities=["dependency-vulnerabilities"],
        risk_level="local",
        supported_output_formats=["json"],
    )
    install_hint = "Install OSV-Scanner from https://google.github.io/osv-scanner/installation/"

    def build_argv(self, operation: str, params: dict[str, Any], output_path: Path) -> list[str]:
        path = str(params.get("path", "."))
        return [self.metadata.executable, "scan", "--format", "json", "--output", str(output_path), path]

    def parse_output(self, output_path: Path, stdout: str = "") -> list[Finding]:
        if not output_path.exists():
            return []
        return normalize_osv(read_json_file(output_path), str(output_path))
