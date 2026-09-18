from __future__ import annotations

import datetime
import math
from collections import Counter
from pathlib import Path
from typing import Any

import pefile

from eva.security_tools.models import Finding
from eva.security_tools.normalizers import make_finding

SUSPICIOUS_SECTION_NAMES = {
    "upx0",
    "upx1",
    "upx2",
    ".aspack",
    ".adata",
    ".themida",
    ".vmp0",
    ".vmp1",
    ".mpress1",
    ".mpress2",
    ".pec",
    ".pecompact",
    ".petite",
    ".fsg",
    ".nsp",
}

SUSPICIOUS_IMPORT_COMBINATIONS = {
    "process_injection": {
        "virtualalloc",
        "virtualallocex",
        "writeprocessmemory",
        "createremotethread",
        "queueuserapc",
        "setthreadcontext",
    },
    "keylogging": {"setwindowshookex", "getasynckeystate", "getkeystate"},
    "anti_debugging": {"isdebuggerpresent", "checkremotedebuggerpresent", "ntqueryinformationprocess"},
}


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    length = len(data)
    counts = Counter(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def analyze_pe(file_path: Path | str, artifact_path: str | None = None) -> tuple[dict[str, Any], list[Finding]]:
    """Analyze a Windows PE binary safely, extracting headers, sections, imports, exports,

    security mitigations, and suspicious indicators as normalized Findings.
    """
    path = Path(file_path).resolve()
    if not path.exists() or not path.is_file():
        raise FileNotFoundError(f"PE file not found: {path}")

    findings: list[Finding] = []
    metadata: dict[str, Any] = {
        "file": str(path),
        "file_size": path.stat().st_size,
        "is_valid_pe": False,
    }

    try:
        pe = pefile.PE(str(path), fast_load=False)
    except pefile.PEFormatError as exc:
        metadata["error"] = f"Invalid PE binary: {exc}"
        findings.append(
            make_finding(
                tool="binary-pe",
                rule_id="pe.malformed",
                title=f"Malformed or invalid PE file: {exc}",
                severity="low",
                category="binary_analysis",
                file=str(path),
                evidence=str(exc),
                artifact_path=artifact_path,
            )
        )
        return metadata, findings
    except Exception as exc:  # noqa: BLE001
        metadata["error"] = f"Error reading PE binary: {exc}"
        return metadata, findings

    try:
        metadata["is_valid_pe"] = True

        # DOS & NT Headers
        metadata["dos_header"] = {
            "e_magic": hex(pe.DOS_HEADER.e_magic),
            "e_lfanew": hex(pe.DOS_HEADER.e_lfanew),
        }

        # Timestamp
        timestamp_raw = pe.FILE_HEADER.TimeDateStamp
        dt = (
            datetime.datetime.fromtimestamp(timestamp_raw, tz=datetime.timezone.utc)
            if 0 < timestamp_raw < 2147483647
            else None
        )
        dt_str = dt.isoformat() if dt else "invalid"

        now = datetime.datetime.now(tz=datetime.timezone.utc)
        if dt and dt > now + datetime.timedelta(days=1):
            findings.append(
                make_finding(
                    tool="binary-pe",
                    rule_id="pe.timestamp.future",
                    title="Suspicious compilation timestamp in the future",
                    severity="medium",
                    category="tampering",
                    file=str(path),
                    evidence=f"TimeDateStamp is {dt_str} (future timestamp, often timestomped)",
                    artifact_path=artifact_path,
                )
            )

        metadata["file_header"] = {
            "machine": hex(pe.FILE_HEADER.Machine),
            "machine_desc": pefile.MACHINE_TYPE.get(pe.FILE_HEADER.Machine, "Unknown"),
            "number_of_sections": pe.FILE_HEADER.NumberOfSections,
            "timedatestamp": timestamp_raw,
            "timedatestamp_iso": dt_str,
            "characteristics": hex(pe.FILE_HEADER.Characteristics),
        }

        # Optional Header & Entry Point
        entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        image_base = pe.OPTIONAL_HEADER.ImageBase
        is_64bit = pe.OPTIONAL_HEADER.Magic == 0x20B

        metadata["optional_header"] = {
            "magic": hex(pe.OPTIONAL_HEADER.Magic),
            "architecture": "PE32+ (64-bit)" if is_64bit else "PE32 (32-bit)",
            "entry_point": hex(entry_point),
            "image_base": hex(image_base),
            "subsystem": pe.OPTIONAL_HEADER.Subsystem,
            "dll_characteristics": hex(pe.OPTIONAL_HEADER.DllCharacteristics),
        }

        # Security flags & Mitigations
        dll_chars = pe.OPTIONAL_HEADER.DllCharacteristics
        has_aslr = bool(dll_chars & pefile.DLL_CHARACTERISTICS["IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE"])
        has_dep = bool(dll_chars & pefile.DLL_CHARACTERISTICS["IMAGE_DLLCHARACTERISTICS_NX_COMPAT"])
        has_cfg = bool(dll_chars & pefile.DLL_CHARACTERISTICS.get("IMAGE_DLLCHARACTERISTICS_GUARD_CF", 0x4000))
        has_high_entropy_va = bool(
            dll_chars & pefile.DLL_CHARACTERISTICS.get("IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA", 0x0020)
        )
        has_no_seh = bool(dll_chars & pefile.DLL_CHARACTERISTICS.get("IMAGE_DLLCHARACTERISTICS_NO_SEH", 0x0400))

        # Check Authenticode signature
        sec_dir_idx = pefile.DIRECTORY_ENTRY.get("IMAGE_DIRECTORY_ENTRY_SECURITY", 4)
        has_signature = False
        if len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) > sec_dir_idx:
            sec_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[sec_dir_idx]
            has_signature = sec_dir.VirtualAddress > 0 and sec_dir.Size > 0

        metadata["security_flags"] = {
            "aslr": has_aslr,
            "dep_nx": has_dep,
            "control_flow_guard": has_cfg,
            "high_entropy_va": has_high_entropy_va,
            "no_seh": has_no_seh,
            "authenticode_signed": has_signature,
        }

        if not has_aslr:
            findings.append(
                make_finding(
                    tool="binary-pe",
                    rule_id="pe.mitigation.no_aslr",
                    title="PE binary lacks ASLR (Address Space Layout Randomization)",
                    severity="medium",
                    category="mitigation_missing",
                    file=str(path),
                    evidence="IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE flag is missing",
                    remediation="Recompile with /DYNAMICBASE linker flag",
                    artifact_path=artifact_path,
                )
            )

        if not has_dep:
            findings.append(
                make_finding(
                    tool="binary-pe",
                    rule_id="pe.mitigation.no_dep",
                    title="PE binary lacks DEP/NX (Data Execution Prevention)",
                    severity="high",
                    category="mitigation_missing",
                    file=str(path),
                    evidence="IMAGE_DLLCHARACTERISTICS_NX_COMPAT flag is missing",
                    remediation="Recompile with /NXCOMPAT linker flag",
                    artifact_path=artifact_path,
                )
            )

        if not has_signature:
            findings.append(
                make_finding(
                    tool="binary-pe",
                    rule_id="pe.signature.missing",
                    title="PE binary is unsigned (no Authenticode signature)",
                    severity="info",
                    category="integrity",
                    file=str(path),
                    evidence="IMAGE_DIRECTORY_ENTRY_SECURITY data directory is empty",
                    artifact_path=artifact_path,
                )
            )

        # Section Analysis
        sections_info: list[dict[str, Any]] = []
        entry_point_found_in_section = False

        for idx, sec in enumerate(pe.sections):
            name = sec.Name.decode("utf-8", errors="replace").strip("\x00")
            raw_size = sec.SizeOfRawData
            virt_size = sec.Misc_VirtualSize
            virt_addr = sec.VirtualAddress
            chars = sec.Characteristics
            sec_data = sec.get_data()
            sec_entropy = round(_shannon_entropy(sec_data), 3)

            is_readable = bool(chars & pefile.SECTION_CHARACTERISTICS["IMAGE_SCN_MEM_READ"])
            is_writable = bool(chars & pefile.SECTION_CHARACTERISTICS["IMAGE_SCN_MEM_WRITE"])
            is_executable = bool(chars & pefile.SECTION_CHARACTERISTICS["IMAGE_SCN_MEM_EXECUTE"])

            sec_info = {
                "name": name,
                "virtual_address": hex(virt_addr),
                "virtual_size": virt_size,
                "raw_size": raw_size,
                "entropy": sec_entropy,
                "readable": is_readable,
                "writable": is_writable,
                "executable": is_executable,
                "characteristics": hex(chars),
            }
            sections_info.append(sec_info)

            # Check if entry point falls in this section
            if virt_addr <= entry_point < virt_addr + max(virt_size, raw_size):
                entry_point_found_in_section = True
                if idx == len(pe.sections) - 1 and len(pe.sections) > 1:
                    findings.append(
                        make_finding(
                            tool="binary-pe",
                            rule_id="pe.entry_point.last_section",
                            title="Entry point located in last section (packer indicator)",
                            severity="high",
                            category="packer",
                            file=str(path),
                            evidence=f"Entry point 0x{entry_point:x} is in last section '{name}'",
                            artifact_path=artifact_path,
                        )
                    )

            # W^X violation
            if is_writable and is_executable:
                findings.append(
                    make_finding(
                        tool="binary-pe",
                        rule_id="pe.section.writable_executable",
                        title=f"Writable and executable section detected: '{name}' (W^X violation)",
                        severity="high",
                        confidence="high",
                        category="exploit_mitigation",
                        file=str(path),
                        evidence=f"Section '{name}' has both IMAGE_SCN_MEM_WRITE and IMAGE_SCN_MEM_EXECUTE",
                        remediation="Ensure code sections are not writable to prevent code injection and self-modifying payloads.",
                        artifact_path=artifact_path,
                    )
                )

            # High entropy section
            if sec_entropy > 7.2 and raw_size > 4096:
                findings.append(
                    make_finding(
                        tool="binary-pe",
                        rule_id="pe.section.high_entropy",
                        title=f"High entropy section '{name}' ({sec_entropy:.2f} bits/byte)",
                        severity="medium",
                        category="packer",
                        file=str(path),
                        evidence=f"Section '{name}' entropy={sec_entropy} indicates encrypted or compressed payload",
                        artifact_path=artifact_path,
                    )
                )

            # Suspicious section name
            clean_name = name.lower()
            if clean_name in SUSPICIOUS_SECTION_NAMES or any(
                clean_name.startswith(p) for p in SUSPICIOUS_SECTION_NAMES
            ):
                findings.append(
                    make_finding(
                        tool="binary-pe",
                        rule_id="pe.section.suspicious_name",
                        title=f"Suspicious section name '{name}' associated with packers/protectors",
                        severity="medium",
                        category="packer",
                        file=str(path),
                        evidence=f"Section name '{name}' matches known packer/protector signature",
                        artifact_path=artifact_path,
                    )
                )

        metadata["sections"] = sections_info

        if pe.sections and not entry_point_found_in_section and entry_point != 0:
            findings.append(
                make_finding(
                    tool="binary-pe",
                    rule_id="pe.entry_point.outside_sections",
                    title="Abnormal entry point outside known section boundaries",
                    severity="high",
                    category="anomaly",
                    file=str(path),
                    evidence=f"Entry point 0x{entry_point:x} does not fall within any declared section",
                    artifact_path=artifact_path,
                )
            )

        # Imports Analysis
        imports_dict: dict[str, list[str]] = {}
        all_imported_funcs_lower: set[str] = set()

        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode("utf-8", errors="replace").lower()
                funcs: list[str] = []
                for imp in entry.imports:
                    if imp.name:
                        func_name = imp.name.decode("utf-8", errors="replace")
                        funcs.append(func_name)
                        all_imported_funcs_lower.add(func_name.lower())
                    elif imp.ordinal is not None:
                        funcs.append(f"Ordinal#{imp.ordinal}")
                imports_dict[dll_name] = funcs

        metadata["imports"] = imports_dict
        metadata["imported_dlls_count"] = len(imports_dict)

        # Check suspicious API import sets
        for threat_type, api_set in SUSPICIOUS_IMPORT_COMBINATIONS.items():
            matched = all_imported_funcs_lower.intersection(api_set)
            if len(matched) >= 2:
                findings.append(
                    make_finding(
                        tool="binary-pe",
                        rule_id=f"pe.imports.{threat_type}",
                        title=f"Suspicious API import combination: {threat_type.replace('_', ' ')}",
                        severity="medium",
                        category="capabilities",
                        file=str(path),
                        evidence=f"Imported APIs: {', '.join(sorted(matched))}",
                        artifact_path=artifact_path,
                    )
                )

        # Exports Analysis
        exports_list: list[str] = []
        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                exp_name = exp.name.decode("utf-8", errors="replace") if exp.name else f"Ordinal#{exp.ordinal}"
                exports_list.append(exp_name)

        metadata["exports"] = exports_list
        metadata["exports_count"] = len(exports_list)

    finally:
        pe.close()

    return metadata, findings
