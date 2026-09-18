import struct
from pathlib import Path

import pytest
from typer.testing import CliRunner

from eva.cli.app import app
from eva.security_tools.elf_analyzer import analyze_elf
from eva.security_tools.entropy import analyze_file_entropy
from eva.security_tools.pe_analyzer import analyze_pe
from eva.security_tools.strings_analyzer import extract_and_analyze_strings

runner = CliRunner()


def make_test_pe(file_path: Path, writable_code: bool = True, aslr: bool = False, dep: bool = False):
    """Generate a minimal valid PE32 binary with customizable characteristics."""
    dos_header = b"MZ" + b"\x00" * 58 + struct.pack("<I", 0x80) + b"\x00" * 64
    pe_sig = b"PE\x00\x00"
    file_hdr = struct.pack("<HHIIIHH", 0x014C, 1, 0x60000000, 0, 0, 224, 0x0102)
    opt_std = struct.pack("<HBBIIIIII", 0x010B, 1, 0, 512, 0, 0, 0x1000, 0x1000, 0x2000)

    dll_chars = 0
    if aslr:
        dll_chars |= 0x0040  # DYNAMIC_BASE
    if dep:
        dll_chars |= 0x0100  # NX_COMPAT

    opt_win = struct.pack(
        "<IIIHHHHHHIIIIHHIIIIII",
        0x400000,
        0x1000,
        0x200,
        4,
        0,
        0,
        0,
        4,
        0,
        0,
        0x3000,
        0x200,
        0,
        2,
        dll_chars,
        0x100000,
        0x1000,
        0x100000,
        0x1000,
        0,
        16,
    )
    data_dirs = b"\x00" * (16 * 8)

    chars = 0x60000020  # CODE | EXECUTE | READ
    if writable_code:
        chars |= 0x80000000  # WRITE -> W^X violation

    sec_hdr = struct.pack("<8sIIIIIIHHI", b".text\x00\x00\x00", 512, 0x1000, 512, 0x200, 0, 0, 0, 0, chars)

    pe_data = dos_header + pe_sig + file_hdr + opt_std + opt_win + data_dirs + sec_hdr
    pe_data += b"\x00" * (0x200 - len(pe_data))
    pe_data += b"\x90" * 512

    file_path.write_bytes(pe_data)
    return file_path


# --- PE Analyzer Tests ---


def test_pe_analysis_mitigations_and_wx_violation(tmp_path):
    pe_file = make_test_pe(tmp_path / "test.exe", writable_code=True, aslr=False, dep=False)
    meta, findings = analyze_pe(pe_file)

    assert meta["is_valid_pe"] is True
    assert meta["optional_header"]["architecture"] == "PE32 (32-bit)"
    assert meta["security_flags"]["aslr"] is False
    assert meta["security_flags"]["dep_nx"] is False

    rule_ids = {f.rule_id for f in findings}
    assert "pe.section.writable_executable" in rule_ids
    assert "pe.mitigation.no_aslr" in rule_ids
    assert "pe.mitigation.no_dep" in rule_ids
    assert "pe.signature.missing" in rule_ids


def test_pe_analysis_safe_mitigations(tmp_path):
    pe_file = make_test_pe(tmp_path / "safe.exe", writable_code=False, aslr=True, dep=True)
    meta, findings = analyze_pe(pe_file)

    assert meta["security_flags"]["aslr"] is True
    assert meta["security_flags"]["dep_nx"] is True

    rule_ids = {f.rule_id for f in findings}
    assert "pe.section.writable_executable" not in rule_ids
    assert "pe.mitigation.no_aslr" not in rule_ids
    assert "pe.mitigation.no_dep" not in rule_ids


def test_pe_analysis_corrupted_binary(tmp_path):
    corrupted = tmp_path / "corrupted.exe"
    corrupted.write_bytes(b"MZ\x00\x00INVALID_HEADER_DATA_NOT_A_PE")
    meta, findings = analyze_pe(corrupted)

    assert meta["is_valid_pe"] is False
    assert "error" in meta
    assert len(findings) >= 1
    assert findings[0].rule_id == "pe.malformed"


def test_pe_analysis_nonexistent_file():
    with pytest.raises(FileNotFoundError):
        analyze_pe("/tmp/nonexistent_pe_file.exe")


# --- ELF Analyzer Tests ---


def test_elf_analysis_system_binary():
    meta, findings = analyze_elf("/usr/bin/ls")
    assert meta["is_valid_elf"] is True
    assert isinstance(findings, list)
    assert "header" in meta
    assert meta["header"]["class"] in {"ELF64", "ELF32"}
    assert "mitigations" in meta
    assert "relro" in meta["mitigations"]
    assert "nx" in meta["mitigations"]
    assert "pie" in meta["mitigations"]


def test_elf_analysis_corrupted_binary(tmp_path):
    corrupted = tmp_path / "corrupted.elf"
    corrupted.write_bytes(b"\x7fELF\x02\x01\x01\x00" + b"\xff" * 20)
    meta, findings = analyze_elf(corrupted)

    assert "error" in meta or len(findings) >= 1


def test_elf_analysis_nonexistent_file():
    with pytest.raises(FileNotFoundError):
        analyze_elf("/tmp/nonexistent_elf_file.bin")


# --- Entropy Analyzer Tests ---


def test_entropy_zero_bytes(tmp_path):
    zero_file = tmp_path / "zeros.bin"
    zero_file.write_bytes(b"\x00" * 4096)
    meta, findings = analyze_file_entropy(zero_file, block_size=1024)

    assert meta["overall_entropy"] == 0.0
    assert meta["summary"]["mean"] == 0.0
    assert len(findings) == 0


def test_entropy_high_density(tmp_path):
    import os

    high_file = tmp_path / "random.bin"
    high_file.write_bytes(os.urandom(8192))
    meta, findings = analyze_file_entropy(high_file, block_size=1024)

    assert meta["overall_entropy"] > 7.5
    rule_ids = {f.rule_id for f in findings}
    assert "entropy.high_density_payload" in rule_ids or "entropy.file.overall_packed" in rule_ids


def test_entropy_empty_file(tmp_path):
    empty = tmp_path / "empty.bin"
    empty.write_bytes(b"")
    meta, findings = analyze_file_entropy(empty)
    assert meta["overall_entropy"] == 0.0
    assert findings == []


# --- Strings Analyzer Tests ---


def test_strings_analyzer_ioc_detection(tmp_path):
    sample = tmp_path / "suspicious.bin"
    data = (
        b"\x90" * 50
        + b"http://malware-drop.example.com/payload.exe\x00"
        + b"93.184.216.34\x00"
        + b"10.0.0.1\x00"  # private IP
        + b"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\x00"
        + b"powershell.exe -nop -w hidden -enc JABhID0A\x00"
        + b"cmd.exe /c whoami\x00"
    )
    sample.write_bytes(data)

    meta, findings = extract_and_analyze_strings(sample, min_len=4)
    assert meta["total_strings_found"] > 0
    assert meta["iocs_summary"]["urls"] >= 1
    assert meta["iocs_summary"]["ipv4"] >= 2
    assert meta["iocs_summary"]["registry"] >= 1
    assert meta["iocs_summary"]["powershell"] >= 1
    assert meta["iocs_summary"]["commands"] >= 1

    rule_ids = {f.rule_id for f in findings}
    assert "strings.ioc.url" in rule_ids
    assert "strings.ioc.public_ip" in rule_ids
    assert "strings.ioc.registry_path" in rule_ids
    assert "strings.ioc.powershell_pattern" in rule_ids


# --- CLI Integration Tests ---


def test_cli_binary_pe_dry_run(tmp_path):
    f = tmp_path / "test.exe"
    f.write_bytes(b"dummy")
    result = runner.invoke(app, ["sec", "binary", "pe", str(f), "--dry-run"])
    assert result.exit_code == 0
    assert "[Dry-Run]" in result.output


def test_cli_binary_pe_live(tmp_path):
    pe_file = make_test_pe(tmp_path / "cli_test.exe")
    result = runner.invoke(app, ["sec", "binary", "pe", str(pe_file), "--format", "json,markdown"])
    assert result.exit_code == 0
    assert "PE analysis complete" in result.output


def test_cli_binary_elf_dry_run():
    result = runner.invoke(app, ["sec", "binary", "elf", "/usr/bin/ls", "--dry-run"])
    assert result.exit_code == 0
    assert "[Dry-Run]" in result.output


def test_cli_binary_elf_live():
    result = runner.invoke(app, ["sec", "binary", "elf", "/usr/bin/ls", "--format", "json"])
    assert result.exit_code == 0
    assert "ELF analysis complete" in result.output


def test_cli_binary_entropy_dry_run(tmp_path):
    f = tmp_path / "data.bin"
    f.write_bytes(b"test data" * 100)
    result = runner.invoke(app, ["sec", "binary", "entropy", str(f), "--dry-run"])
    assert result.exit_code == 0
    assert "[Dry-Run]" in result.output


def test_cli_binary_entropy_live(tmp_path):
    f = tmp_path / "data.bin"
    f.write_bytes(b"test data" * 100)
    result = runner.invoke(app, ["sec", "binary", "entropy", str(f), "--format", "json"])
    assert result.exit_code == 0
    assert "Entropy analysis complete" in result.output


def test_cli_binary_strings_dry_run(tmp_path):
    f = tmp_path / "data.bin"
    f.write_bytes(b"test data" * 100)
    result = runner.invoke(app, ["sec", "binary", "strings", str(f), "--dry-run"])
    assert result.exit_code == 0
    assert "[Dry-Run]" in result.output


def test_cli_binary_strings_live(tmp_path):
    f = tmp_path / "data.bin"
    f.write_bytes(b"powershell.exe -enc JABhID0A\x00http://example.com/test\x00")
    result = runner.invoke(app, ["sec", "binary", "strings", str(f), "--format", "json"])
    assert result.exit_code == 0
    assert "Strings analysis complete" in result.output
