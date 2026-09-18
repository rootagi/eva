from __future__ import annotations

from pathlib import Path
from typing import Any

from elftools.common.exceptions import ELFError
from elftools.elf.dynamic import DynamicSection
from elftools.elf.elffile import ELFFile

from eva.security_tools.models import Finding
from eva.security_tools.normalizers import make_finding


def analyze_elf(file_path: Path | str, artifact_path: str | None = None) -> tuple[dict[str, Any], list[Finding]]:
    """Analyze a Linux ELF binary safely, extracting headers, architecture, entry point,

    shared libraries, dynamic symbols, exploit mitigations, and suspicious indicators.
    """
    path = Path(file_path).resolve()
    if not path.exists() or not path.is_file():
        raise FileNotFoundError(f"ELF file not found: {path}")

    findings: list[Finding] = []
    metadata: dict[str, Any] = {
        "file": str(path),
        "file_size": path.stat().st_size,
        "is_valid_elf": False,
    }

    try:
        with open(path, "rb") as f:
            elffile = ELFFile(f)
            metadata["is_valid_elf"] = True

            header = elffile.header
            e_type = header.get("e_type", "")
            e_machine = header.get("e_machine", "")
            e_entry = header.get("e_entry", 0)

            metadata["header"] = {
                "class": f"ELF{elffile.elfclass}",
                "data": "little-endian" if elffile.little_endian else "big-endian",
                "os_abi": header.get("e_ident", {}).get("EI_OSABI", "UNIX - System V"),
                "abi_version": header.get("e_ident", {}).get("EI_ABIVERSION", 0),
                "type": e_type,
                "machine": e_machine,
                "entry_point": hex(e_entry),
                "entry_point_int": e_entry,
            }

            # Exploit mitigations tracking
            has_gnu_stack = False
            stack_executable = False
            has_gnu_relro = False
            has_bind_now = False
            has_stack_canary = False
            has_pie = False

            # Segments & Mitigations
            segments_info = []
            for seg in elffile.iter_segments():
                seg_type = seg.header.p_type
                flags = seg.header.p_flags
                readable = bool(flags & 4)
                writable = bool(flags & 2)
                executable = bool(flags & 1)

                seg_info = {
                    "type": seg_type if isinstance(seg_type, str) else str(seg_type),
                    "offset": hex(seg.header.p_offset),
                    "vaddr": hex(seg.header.p_vaddr),
                    "memsz": seg.header.p_memsz,
                    "readable": readable,
                    "writable": writable,
                    "executable": executable,
                }
                segments_info.append(seg_info)

                # PT_GNU_STACK check for NX
                if seg_type == "PT_GNU_STACK" or seg_type == 0x6474E551:
                    has_gnu_stack = True
                    if executable:
                        stack_executable = True

                # PT_GNU_RELRO check for RELRO
                if seg_type == "PT_GNU_RELRO" or seg_type == 0x6474E552:
                    has_gnu_relro = True

                # W^X segment violation
                if writable and executable and seg_type == "PT_LOAD":
                    findings.append(
                        make_finding(
                            tool="binary-elf",
                            rule_id="elf.segment.writable_executable",
                            title=f"Writable and executable PT_LOAD segment at {seg_info['vaddr']} (W^X violation)",
                            severity="high",
                            confidence="high",
                            category="exploit_mitigation",
                            file=str(path),
                            evidence=f"Segment flags: r={readable}, w={writable}, x={executable}",
                            remediation="Ensure program segments do not have both write and execute permissions.",
                            artifact_path=artifact_path,
                        )
                    )

            metadata["segments_count"] = len(segments_info)

            # Shared Libraries & Dynamic Tags
            shared_libs: list[str] = []
            for sec in elffile.iter_sections():
                if isinstance(sec, DynamicSection):
                    for tag in sec.iter_tags():
                        if tag.entry.d_tag == "DT_NEEDED":
                            shared_libs.append(str(tag.needed))
                        elif tag.entry.d_tag == "DT_BIND_NOW":
                            has_bind_now = True
                        elif tag.entry.d_tag == "DT_FLAGS":
                            if tag.entry.d_val & 0x08:  # DF_BIND_NOW
                                has_bind_now = True
                        elif tag.entry.d_tag == "DT_FLAGS_1" and (tag.entry.d_val & 0x08000000):  # DF_1_PIE
                            has_pie = True

            metadata["shared_libraries"] = shared_libs

            # Dynamic Symbols for Stack Canary
            symbols_list: list[str] = []
            dynsym_sec = elffile.get_section_by_name(".dynsym")
            if dynsym_sec:
                for sym in dynsym_sec.iter_symbols():
                    sym_name = sym.name
                    if sym_name:
                        symbols_list.append(sym_name)
                        if sym_name in {"__stack_chk_fail", "__stack_chk_guard", "__intel_security_cookie"}:
                            has_stack_canary = True

            metadata["dynamic_symbols_count"] = len(symbols_list)
            metadata["dynamic_symbols_sample"] = symbols_list[:50]

            # PIE evaluation
            if e_type == "ET_DYN":
                has_pie = True
            elif e_type == "ET_EXEC":
                has_pie = False

            # RELRO evaluation
            relro_status = "none"
            if has_gnu_relro:
                relro_status = "full" if has_bind_now else "partial"

            nx_status = not stack_executable if has_gnu_stack else False

            mitigations = {
                "relro": relro_status,
                "stack_canary": has_stack_canary,
                "nx": nx_status,
                "pie": has_pie,
            }
            metadata["mitigations"] = mitigations

            # Generate findings for missing mitigations
            if not nx_status:
                findings.append(
                    make_finding(
                        tool="binary-elf",
                        rule_id="elf.mitigation.no_nx",
                        title="ELF executable stack detected (NX mitigation disabled)",
                        severity="high",
                        confidence="high",
                        category="exploit_mitigation",
                        file=str(path),
                        evidence="PT_GNU_STACK segment has executable flag enabled or missing",
                        remediation="Recompile with -z noexecstack to enforce Non-Executable stack.",
                        artifact_path=artifact_path,
                    )
                )

            if relro_status == "none":
                findings.append(
                    make_finding(
                        tool="binary-elf",
                        rule_id="elf.mitigation.no_relro",
                        title="ELF binary lacks RELRO protection (No RELRO)",
                        severity="medium",
                        category="exploit_mitigation",
                        file=str(path),
                        evidence="No PT_GNU_RELRO segment found; Global Offset Table (GOT) is writable",
                        remediation="Recompile with -Wl,-z,relro,-z,now",
                        artifact_path=artifact_path,
                    )
                )
            elif relro_status == "partial":
                findings.append(
                    make_finding(
                        tool="binary-elf",
                        rule_id="elf.mitigation.partial_relro",
                        title="ELF binary has only Partial RELRO (GOT overwrite possible)",
                        severity="low",
                        category="exploit_mitigation",
                        file=str(path),
                        evidence="PT_GNU_RELRO present but BIND_NOW is disabled",
                        remediation="Recompile with -Wl,-z,now for Full RELRO",
                        artifact_path=artifact_path,
                    )
                )

            if not has_stack_canary and len(symbols_list) > 0:
                findings.append(
                    make_finding(
                        tool="binary-elf",
                        rule_id="elf.mitigation.no_canary",
                        title="ELF binary lacks Stack Canary protection",
                        severity="medium",
                        category="exploit_mitigation",
                        file=str(path),
                        evidence="No __stack_chk_fail symbol found in dynamic symbol table",
                        remediation="Recompile with -fstack-protector-strong",
                        artifact_path=artifact_path,
                    )
                )

            if not has_pie:
                findings.append(
                    make_finding(
                        tool="binary-elf",
                        rule_id="elf.mitigation.no_pie",
                        title="ELF binary is not Position Independent (No PIE)",
                        severity="low",
                        category="exploit_mitigation",
                        file=str(path),
                        evidence=f"ELF type is {e_type} rather than ET_DYN",
                        remediation="Recompile with -fPIE -pie",
                        artifact_path=artifact_path,
                    )
                )

            # Sections list
            sections_list = []
            for sec in elffile.iter_sections():
                sections_list.append(
                    {
                        "name": sec.name,
                        "size": sec.data_size,
                        "addr": hex(sec.header.sh_addr),
                        "flags": hex(sec.header.sh_flags),
                    }
                )
            metadata["sections"] = sections_list

    except (ELFError, ValueError, OSError) as exc:
        metadata["error"] = f"Error analyzing ELF binary: {exc}"
        findings.append(
            make_finding(
                tool="binary-elf",
                rule_id="elf.malformed",
                title=f"Malformed or truncated ELF binary: {exc}",
                severity="low",
                category="binary_analysis",
                file=str(path),
                evidence=str(exc),
                artifact_path=artifact_path,
            )
        )
    except Exception as exc:  # noqa: BLE001
        metadata["error"] = f"Unexpected error analyzing ELF binary: {exc}"

    return metadata, findings
