from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from typing import Any

from eva.security_tools.models import Finding
from eva.security_tools.normalizers import make_finding

RE_IPV4 = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
RE_URL = re.compile(r"\bhttps?://[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+\b", re.IGNORECASE)
RE_REGISTRY = re.compile(
    r"\b(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKLM|HKCU)\\[A-Za-z0-9_\\\-.]+|Software\\Microsoft\\Windows\\CurrentVersion\\[A-Za-z0-9_\\\-.]+",
    re.IGNORECASE,
)
RE_POWERSHELL = re.compile(
    r"\b(?:powershell(?:\.exe)?\s+-[A-Za-z0-9_\-\s]*|-(?:enc|encodedcommand|nop|noprofile|w\s+hidden|ep\s+bypass)\b|DownloadString|Invoke-Expression|IEX\b|\[System\.Convert\]::FromBase64String)",
    re.IGNORECASE,
)
RE_SUSPICIOUS_CMD = re.compile(
    r"\b(?:cmd\.exe\s+/[ck]|certutil(?:\.exe)?\s+-(?:urlcache|decode)|bitsadmin(?:\.exe)?\s+/transfer|vssadmin(?:\.exe)?\s+delete\s+shadows|schtasks(?:\.exe)?\s+/create|net\s+(?:user|localgroup)\s+[^/\r\n]+)\b",
    re.IGNORECASE,
)


def _is_valid_ipv4(ip_str: str) -> bool:
    try:
        ip = ipaddress.IPv4Address(ip_str)
        return not ip.is_multicast and not ip.is_unspecified
    except ValueError:
        return False


def extract_ascii_strings(data: bytes, min_len: int = 4) -> list[tuple[int, str]]:
    """Extract ASCII printable strings and their byte offsets."""
    pattern = re.compile(rb"[\x20-\x7E]{" + str(min_len).encode() + rb",}")
    matches = []
    for match in pattern.finditer(data):
        try:
            matches.append((match.start(), match.group(0).decode("ascii")))
        except UnicodeDecodeError:
            continue
    return matches


def extract_utf16_strings(data: bytes, min_len: int = 4) -> list[tuple[int, str]]:
    """Extract UTF-16LE and UTF-16BE printable strings and their byte offsets."""
    pattern = re.compile(rb"(?:[\x20-\x7E]\x00){" + str(min_len).encode() + rb",}")
    matches = []
    for match in pattern.finditer(data):
        try:
            matches.append((match.start(), match.group(0).decode("utf-16le")))
        except UnicodeDecodeError:
            continue
    return matches


def extract_and_analyze_strings(
    file_path: Path | str,
    min_len: int = 4,
    encodings: list[str] | None = None,
    artifact_path: str | None = None,
) -> tuple[dict[str, Any], list[Finding]]:
    """Extract strings from a binary file, classify IOCs, and generate normalized Findings."""
    path = Path(file_path).resolve()
    if not path.exists() or not path.is_file():
        raise FileNotFoundError(f"File not found: {path}")

    selected_encodings = encodings or ["ascii", "utf16"]
    data = path.read_bytes()

    raw_strings: list[tuple[int, str, str]] = []  # (offset, string, encoding)
    if "ascii" in selected_encodings:
        for offset, s in extract_ascii_strings(data, min_len=min_len):
            raw_strings.append((offset, s, "ascii"))
    if "utf16" in selected_encodings or "utf-16" in selected_encodings:
        for offset, s in extract_utf16_strings(data, min_len=min_len):
            raw_strings.append((offset, s, "utf-16le"))

    # Sort strings by offset
    raw_strings.sort(key=lambda x: x[0])

    findings: list[Finding] = []
    iocs: dict[str, list[dict[str, Any]]] = {
        "ipv4": [],
        "urls": [],
        "registry": [],
        "powershell": [],
        "commands": [],
    }

    seen_iocs: set[str] = set()

    for offset, string_val, encoding in raw_strings:
        # IPv4 Check
        for ip_match in RE_IPV4.findall(string_val):
            if _is_valid_ipv4(ip_match) and ip_match not in seen_iocs:
                seen_iocs.add(ip_match)
                try:
                    ip_obj = ipaddress.IPv4Address(ip_match)
                    is_private = ip_obj.is_private or ip_obj.is_loopback
                except ValueError:
                    is_private = False

                iocs["ipv4"].append({"value": ip_match, "offset": offset, "private": is_private})
                if not is_private:
                    findings.append(
                        make_finding(
                            tool="binary-strings",
                            rule_id="strings.ioc.public_ip",
                            title=f"Hardcoded public IPv4 address: {ip_match}",
                            severity="medium",
                            confidence="high",
                            category="ioc",
                            file=str(path),
                            line_start=offset,
                            evidence=f"String at offset 0x{offset:x} contains public IP {ip_match}",
                            artifact_path=artifact_path,
                        )
                    )

        # URLs Check
        for url_match in RE_URL.findall(string_val):
            if url_match not in seen_iocs:
                seen_iocs.add(url_match)
                iocs["urls"].append({"value": url_match, "offset": offset})
                findings.append(
                    make_finding(
                        tool="binary-strings",
                        rule_id="strings.ioc.url",
                        title=f"Hardcoded URL: {url_match}",
                        severity="medium",
                        confidence="high",
                        category="ioc",
                        file=str(path),
                        line_start=offset,
                        evidence=f"String at offset 0x{offset:x}: {url_match}",
                        artifact_path=artifact_path,
                    )
                )

        # Registry Keys Check
        for reg_match in RE_REGISTRY.findall(string_val):
            if reg_match not in seen_iocs:
                seen_iocs.add(reg_match)
                iocs["registry"].append({"value": reg_match, "offset": offset})
                findings.append(
                    make_finding(
                        tool="binary-strings",
                        rule_id="strings.ioc.registry_path",
                        title=f"Windows Registry path referenced: {reg_match}",
                        severity="low",
                        category="system_config",
                        file=str(path),
                        line_start=offset,
                        evidence=f"String at offset 0x{offset:x}: {reg_match}",
                        artifact_path=artifact_path,
                    )
                )

        # PowerShell Patterns Check
        for ps_match in RE_POWERSHELL.findall(string_val):
            if ps_match not in seen_iocs:
                seen_iocs.add(ps_match)
                iocs["powershell"].append({"value": ps_match, "offset": offset})
                findings.append(
                    make_finding(
                        tool="binary-strings",
                        rule_id="strings.ioc.powershell_pattern",
                        title=f"PowerShell invocation / cradle pattern: {ps_match}",
                        severity="high",
                        confidence="high",
                        category="execution_pattern",
                        file=str(path),
                        line_start=offset,
                        evidence=f"String at offset 0x{offset:x}: {ps_match}",
                        remediation="Inspect process parentage and monitor event log 4104 for script blocks.",
                        artifact_path=artifact_path,
                    )
                )

        # Suspicious Commands Check
        for cmd_match in RE_SUSPICIOUS_CMD.findall(string_val):
            if cmd_match not in seen_iocs:
                seen_iocs.add(cmd_match)
                iocs["commands"].append({"value": cmd_match, "offset": offset})
                findings.append(
                    make_finding(
                        tool="binary-strings",
                        rule_id="strings.ioc.suspicious_command",
                        title=f"Suspicious command execution artifact: {cmd_match}",
                        severity="high",
                        confidence="high",
                        category="execution_pattern",
                        file=str(path),
                        line_start=offset,
                        evidence=f"String at offset 0x{offset:x}: {cmd_match}",
                        artifact_path=artifact_path,
                    )
                )

    metadata = {
        "file": str(path),
        "file_size": len(data),
        "total_strings_found": len(raw_strings),
        "encodings": selected_encodings,
        "min_len": min_len,
        "iocs_summary": {k: len(v) for k, v in iocs.items()},
        "iocs": iocs,
        "strings_sample": [{"offset": off, "string": s[:80], "encoding": enc} for off, s, enc in raw_strings[:100]],
    }

    return metadata, findings
