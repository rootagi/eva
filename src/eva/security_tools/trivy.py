from __future__ import annotations

from pathlib import Path
from typing import Any

from eva.security_tools.base import SecurityAdapter
from eva.security_tools.models import AdapterMetadata, Finding
from eva.security_tools.normalizers import normalize_trivy
from eva.security_tools.utils import read_json_file


class TrivyAdapter(SecurityAdapter):
    metadata = AdapterMetadata(
        name="trivy",
        executable="trivy",
        version_check=["trivy", "--version"],
        argv_schema={"path": "str", "scanners": "list[str]"},
        output_schema="trivy-json",
        timeout=300,
        required_capabilities=["vulnerabilities", "secrets", "misconfigurations", "licenses", "sbom"],
        risk_level="local",
        supported_output_formats=["json", "sarif", "cyclonedx"],
    )
    install_hint = "Install Trivy from https://aquasecurity.github.io/trivy/latest/getting-started/installation/"

    def build_argv(self, operation: str, params: dict[str, Any], output_path: Path) -> list[str]:
        path = str(params.get("path", "."))
        scanners = params.get("scanners") or ["vuln", "secret", "misconfig", "license"]
        if not isinstance(scanners, list) or not all(isinstance(item, str) for item in scanners):
            raise ValueError("trivy scanners must be a list of strings")
        return [
            self.metadata.executable,
            "fs",
            "--format",
            "json",
            "--scanners",
            ",".join(scanners),
            "--output",
            str(output_path),
            path,
        ]

    def parse_output(self, output_path: Path, stdout: str = "") -> list[Finding]:
        if not output_path.exists():
            return []
        return normalize_trivy(read_json_file(output_path), str(output_path))
