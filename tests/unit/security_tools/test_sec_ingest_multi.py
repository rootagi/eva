import json
from pathlib import Path

from typer.testing import CliRunner

from eva.cli.app import app
from eva.security_tools.workflow import expand_report_paths, ingest_reports

runner = CliRunner()


def test_expand_report_paths_globs_and_dirs(tmp_path: Path):
    sub = tmp_path / "sub"
    sub.mkdir()
    f1 = sub / "report1.json"
    f1.write_text('{"tool": "trivy", "findings": []}')

    f2 = sub / "report2.jsonl"
    f2.write_text('{"title": "x", "severity": "low"}\n')

    # Ignored directory
    git_dir = tmp_path / ".git"
    git_dir.mkdir()
    ignored = git_dir / "hidden.json"
    ignored.write_text('{"tool": "trivy"}')

    # Non-report extension
    txt_file = sub / "notes.txt"
    txt_file.write_text("not a report")

    # Expand directory
    found = expand_report_paths([str(tmp_path)])
    assert f1.resolve() in found
    assert f2.resolve() in found
    assert ignored.resolve() not in found
    assert txt_file.resolve() not in found

    # Expand glob
    glob_found = expand_report_paths([str(sub / "*.json")])
    assert f1.resolve() in glob_found
    assert len(glob_found) == 1


def test_ingest_reports_deduplication_and_summary(tmp_path: Path):
    # Two reports with the same finding
    f1 = tmp_path / "r1.json"
    f1.write_text(
        json.dumps(
            {
                "tool": "semgrep",
                "findings": [
                    {
                        "title": "SQL Injection",
                        "severity": "high",
                        "file": "app/db.py",
                        "line_start": 42,
                        "references": ["https://owasp.org/sql-injection"],
                    }
                ],
            }
        )
    )

    f2 = tmp_path / "r2.json"
    f2.write_text(
        json.dumps(
            {
                "tool": "semgrep",
                "findings": [
                    {
                        "title": "SQL Injection",
                        "severity": "high",
                        "file": "app/db.py",
                        "line_start": 42,
                        "references": ["https://cwe.mitre.org/data/definitions/89.html"],
                    },
                    {
                        "title": "Hardcoded Secret",
                        "severity": "critical",
                        "file": "app/auth.py",
                        "line_start": 10,
                    },
                ],
            }
        )
    )

    out_dir = tmp_path / "ingest_out"
    findings, context, _stats = ingest_reports([str(f1), str(f2)], artifacts_dir=out_dir)

    assert len(findings) == 2  # Deduplicated from 3 raw findings

    # Check ingest summary was written
    summary_file = context.run_dir / "ingest-summary.json"
    assert summary_file.exists()
    summary = json.loads(summary_file.read_text(encoding="utf-8"))

    assert len(summary["input_files"]) == 2
    assert summary["total_raw_findings"] == 3
    assert summary["total_unique_findings"] == 2
    assert summary["total_duplicates"] == 1


def test_ingest_cli_keep_going_and_variadic(tmp_path: Path):
    valid_report = tmp_path / "valid.json"
    valid_report.write_text(
        json.dumps(
            {
                "tool": "bandit",
                "findings": [
                    {"title": "Weak Hash", "severity": "medium", "file": "crypto.py", "line_start": 5},
                ],
            }
        )
    )

    corrupt_report = tmp_path / "corrupt.json"
    corrupt_report.write_text("{corrupt json...")

    # Without --keep-going, corrupt report should fail
    res_fail = runner.invoke(app, ["sec", "ingest", str(valid_report), str(corrupt_report)])
    assert res_fail.exit_code != 0

    # With --keep-going, valid report should be ingested while corrupt is skipped
    res_ok = runner.invoke(app, ["sec", "ingest", str(valid_report), str(corrupt_report), "--keep-going"])
    assert res_ok.exit_code == 0
    assert "valid.json: 1 findings" in res_ok.output
    assert "Ingested 1 findings" in res_ok.output
