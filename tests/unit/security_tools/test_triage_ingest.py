import json

from typer.testing import CliRunner

from eva.cli.app import app
from eva.security_tools.normalizers import normalize_report

runner = CliRunner()


def test_normalize_windows_triage_json(tmp_path):
    report_file = tmp_path / "win_triage.json"
    data = {
        "schema": "eva.triage.v1",
        "tool": "triage-windows",
        "collected_at": "2026-09-18T00:00:00Z",
        "host": {"hostname": "WIN-SRV-01"},
        "findings": [
            {
                "id": "triage-win-startup-calc",
                "tool": "triage-windows",
                "rule_id": "persistence.startup.script_interpreter",
                "title": "Suspicious script interpreter in startup run key: calc",
                "severity": "high",
                "confidence": "high",
                "category": "persistence",
                "file": "HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                "evidence": "Run Key: calc -> powershell.exe -enc ...",
                "remediation": "Remove unauthorized autorun entries.",
                "fingerprint": "a1b2c3d4e5f60718293a4b5c6d7e8f90",
            }
        ],
    }
    report_file.write_text(json.dumps(data), encoding="utf-8")

    findings = normalize_report(report_file)
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "persistence.startup.script_interpreter"
    assert f.severity == "high"
    assert f.category == "persistence"
    assert "powershell.exe" in f.evidence


def test_normalize_linux_hardening_audit_json(tmp_path):
    report_file = tmp_path / "linux_audit.json"
    data = {
        "schema": "eva.triage.v1",
        "tool": "triage-linux-hardening",
        "collected_at": "2026-09-18T00:00:00Z",
        "host": {"hostname": "arch-linux-vm"},
        "audits": [
            {
                "control_id": "ssh.permit_root_login",
                "title": "SSH PermitRootLogin is enabled",
                "status": "FAIL",
                "severity": "high",
                "evidence": "PermitRootLogin yes in /etc/ssh/sshd_config",
                "remediation": "Set PermitRootLogin no",
            },
            {
                "control_id": "sysctl.aslr",
                "title": "Address Space Layout Randomization fully enabled",
                "status": "PASS",
                "severity": "info",
                "evidence": "kernel.randomize_va_space = 2",
                "remediation": "",
            },
        ],
        "findings": [
            {
                "id": "triage-linux-ssh.permit_root_login",
                "tool": "triage-linux-hardening",
                "rule_id": "hardening.ssh.permit_root_login",
                "title": "SSH PermitRootLogin is enabled",
                "severity": "high",
                "confidence": "high",
                "category": "hardening_audit",
                "file": "/etc/ssh/sshd_config",
                "evidence": "PermitRootLogin yes",
                "remediation": "Set PermitRootLogin no",
                "fingerprint": "b2c3d4e5f60718293a4b5c6d7e8f90a1",
            }
        ],
    }
    report_file.write_text(json.dumps(data), encoding="utf-8")

    findings = normalize_report(report_file)
    assert len(findings) >= 1
    rule_ids = {f.rule_id for f in findings}
    assert "hardening.ssh.permit_root_login" in rule_ids or "ssh.permit_root_login" in rule_ids


def test_cli_ingest_triage_report(tmp_path):
    report_file = tmp_path / "triage.json"
    data = {
        "schema": "eva.triage.v1",
        "tool": "triage-linux",
        "collected_at": "2026-09-18T00:00:00Z",
        "host": {"hostname": "localhost"},
        "findings": [
            {
                "id": "triage-linux-telnet",
                "tool": "triage-linux",
                "rule_id": "network.listener.insecure_protocol",
                "title": "Insecure Telnet service listening on port 23",
                "severity": "high",
                "confidence": "high",
                "category": "network_anomaly",
                "evidence": "Port 23 listening",
                "remediation": "Disable telnet",
                "fingerprint": "c3d4e5f60718293a4b5c6d7e8f90a1b2",
            }
        ],
    }
    report_file.write_text(json.dumps(data), encoding="utf-8")

    result = runner.invoke(app, ["sec", "ingest", str(report_file), "--format", "terminal,json,sarif,markdown"])
    assert result.exit_code == 0
    assert "Ingested 1 findings" in result.output
