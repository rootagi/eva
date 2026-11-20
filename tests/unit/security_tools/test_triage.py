import json
from unittest.mock import patch

from eva.security_tools.triage import (
    SCHEMA,
    detect_platform,
    discover_collectors,
    run_triage,
    select_collectors,
    validate_triage_document,
    validate_triage_files,
)


def test_detect_platform():
    with patch("platform.system", return_value="Linux"):
        assert detect_platform() == "linux"
    with patch("platform.system", return_value="Windows"):
        assert detect_platform() == "windows"
    with patch("platform.system", return_value="Darwin"):
        assert detect_platform() == "linux"


def test_discover_collectors_and_select(tmp_path):
    scripts_dir = tmp_path / "custom_scripts"
    scripts_dir.mkdir()
    linux_dir = scripts_dir / "linux"
    linux_dir.mkdir()
    s1 = linux_dir / "network_conn.sh"
    s1.write_text("#!/bin/bash\necho hi", encoding="utf-8")
    s2 = linux_dir / "detect_rootkits.sh"
    s2.write_text("#!/bin/bash\necho rootkit", encoding="utf-8")

    discovered = discover_collectors("linux", scripts_dir=scripts_dir)
    names = [s["name"] for s in discovered]
    assert "network_conn.sh" in names
    assert "detect_rootkits.sh" in names

    # Exclude slow
    mock_scripts = [
        {"name": "network_conn.sh", "relpath": "linux/network_conn.sh", "is_slow": False},
        {"name": "detect_rootkits.sh", "relpath": "linux/detect_rootkits.sh", "is_slow": True},
    ]
    fast_only = select_collectors(mock_scripts, exclude_slow=True)
    assert len(fast_only) == 1
    assert fast_only[0]["name"] == "network_conn.sh"

    # Include pattern
    network_only = select_collectors(mock_scripts, include=["*network*"])
    assert len(network_only) == 1
    assert network_only[0]["name"] == "network_conn.sh"

    # Exclude pattern
    no_network = select_collectors(mock_scripts, exclude=["*network*"])
    assert "network_conn.sh" not in [s["name"] for s in no_network]


def test_validate_triage_document_valid():
    valid_doc = {
        "schema": SCHEMA,
        "tool": "eva-triage-network",
        "collected_at": "2026-11-20T01:00:00Z",
        "host": {"hostname": "prod-web-01"},
        "findings": [
            {
                "id": "F-001",
                "rule_id": "NET-001",
                "title": "Suspicious outbound connection",
                "category": "network",
                "severity": "high",
                "confidence": "high",
                "evidence": "Outbound TCP connection to 198.51.100.5:4444",
                "remediation": "Block IP at perimeter firewall",
            }
        ],
    }

    result = validate_triage_document(valid_doc, path="report.json")
    assert result.valid is True
    assert result.findings == 1
    assert result.severity_counts["high"] == 1
    assert len(result.errors) == 0


def test_validate_triage_document_invalid():
    # Not a dict
    res1 = validate_triage_document(["not a dict"])
    assert res1.valid is False
    assert any("report root must be a JSON object" in err for err in res1.errors)

    # Missing schema & tool
    res2 = validate_triage_document({})
    assert res2.valid is False
    assert any("schema must be" in err for err in res2.errors)
    assert any("top-level 'tool'" in err for err in res2.errors)

    # Missing required finding fields
    bad_finding_doc = {
        "schema": SCHEMA,
        "tool": "eva-triage",
        "collected_at": "2026-11-20T01:00:00Z",
        "host": {"hostname": "box"},
        "findings": [{"id": "F1"}],  # missing rule_id, title, category, evidence, remediation
    }
    res3 = validate_triage_document(bad_finding_doc)
    assert res3.valid is False
    assert any("missing 'title'" in err for err in res3.errors)


def test_validate_triage_files(tmp_path):
    f_valid = tmp_path / "valid.json"
    valid_doc = {
        "schema": SCHEMA,
        "tool": "test-tool",
        "collected_at": "2026-11-20T01:00:00Z",
        "host": {"hostname": "localhost"},
        "findings": [],
    }
    f_valid.write_text(json.dumps(valid_doc), encoding="utf-8")

    summary = validate_triage_files([f_valid])
    assert summary["all_valid"] is True
    assert summary["files_checked"] == 1
    assert summary["files_valid"] == 1


def test_run_triage_mock(tmp_path):
    out_dir = tmp_path / "triage_out"
    scripts_dir = tmp_path / "scripts"
    linux_dir = scripts_dir / "linux"
    linux_dir.mkdir(parents=True)
    collector = linux_dir / "custom_collector.sh"
    collector.write_text(
        '#!/bin/bash\necho \'{"schema": "eva.triage.v1", "tool": "test", "collected_at": "2026-11-20T01:00:00Z", "host": {"hostname": "h"}, "findings": []}\'',
        encoding="utf-8",
    )
    collector.chmod(0o755)

    result = run_triage(
        output_dir=out_dir,
        platform_name="linux",
        scripts_dir=scripts_dir,
        scripts=["custom_collector.sh"],
        timeout=10,
    )
    assert result["schema"] == "eva.triage.orchestrator.v1"
    assert result["scripts_total"] == 1
    assert result["scripts_ok"] == 1
    assert out_dir.is_dir()
    assert (out_dir / "summary.json").is_file()
