from __future__ import annotations

from pathlib import Path
from typing import Any

from eva.security_tools.base import SecurityAdapter
from eva.security_tools.models import AdapterMetadata, Finding
from eva.security_tools.normalizers import normalize_syft
from eva.security_tools.utils import read_json_file


class SyftAdapter(SecurityAdapter):
    metadata = AdapterMetadata(
        name="syft",
        executable="syft",
        version_check=["syft", "version"],
        argv_schema={"path": "str"},
        output_schema="cyclonedx-json",
        timeout=180,
        required_capabilities=["sbom"],
        risk_level="local",
        supported_output_formats=["cyclonedx-json", "spdx-json"],
    )
    install_hint = "Install Syft from https://github.com/anchore/syft#installation"

    def output_suffix(self, operation: str) -> str:
        return "cdx.json"

    def build_argv(self, operation: str, params: dict[str, Any], output_path: Path) -> list[str]:
        path = str(params.get("path", "."))
        return [self.metadata.executable, path, "-o", f"cyclonedx-json={output_path}"]

    def parse_output(self, output_path: Path, stdout: str = "") -> list[Finding]:
        if not output_path.exists():
            return []
        try:
            return normalize_syft(read_json_file(output_path), str(output_path))
        except Exception:  # noqa: BLE001
            return []
