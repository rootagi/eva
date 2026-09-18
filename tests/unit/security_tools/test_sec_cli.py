import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml
from typer.testing import CliRunner

from eva.cli.app import app

runner = CliRunner()


def make_scope_file(path: Path, **overrides):
    data = {
        "version": 1,
        "engagement_id": "test-cli-001",
        "expires_at": (datetime.now(timezone.utc) + timedelta(days=2)).isoformat(),
        "paths": ["."],
        "web_targets": ["https://staging.example.internal/api"],
        "allowed_ports": [443],
        "max_requests_per_second": 2.0,
        "max_concurrency": 2,
        "max_duration_seconds": 600,
        "allow_active_scanning": False,
    }
    data.update(overrides)
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    return path


def test_cli_doctor():
    result = runner.invoke(app, ["sec", "doctor"])
    assert result.exit_code == 0
    assert "aegis.analyze" in result.output
    assert "trivy.filesystem" in result.output


def test_cli_assess_dry_run(tmp_path):
    result = runner.invoke(app, ["sec", "assess", str(tmp_path), "--dry-run", "--include-osv", "--include-syft"])
    assert result.exit_code == 0
    assert "complete" in result.output.lower() or "eva security findings" in result.output.lower()


def test_cli_media_analyze_dry_run(tmp_path):
    img = tmp_path / "test.png"
    img.write_bytes(b"dummy")
    result = runner.invoke(app, ["sec", "media", "analyze", str(img), "--dry-run"])
    assert result.exit_code == 0
    assert "complete" in result.output.lower()


def test_cli_media_detect_stego_dry_run(tmp_path):
    img = tmp_path / "test.png"
    img.write_bytes(b"dummy")
    result = runner.invoke(app, ["sec", "media", "detect-stego", str(img), "--dry-run"])
    assert result.exit_code == 0


def test_cli_media_scan_structure_dry_run(tmp_path):
    img = tmp_path / "test.png"
    img.write_bytes(b"dummy")
    result = runner.invoke(app, ["sec", "media", "scan-structure", str(img), "--dry-run"])
    assert result.exit_code == 0


def test_cli_media_extract_hidden_dry_run(tmp_path):
    img = tmp_path / "test.png"
    img.write_bytes(b"dummy")
    result = runner.invoke(app, ["sec", "media", "extract-hidden", str(img), "--dry-run"])
    assert result.exit_code == 0


def test_cli_media_sanitize_dry_run(tmp_path):
    img = tmp_path / "test.png"
    img.write_bytes(b"dummy")
    out = tmp_path / "clean.png"
    result = runner.invoke(app, ["sec", "media", "sanitize", str(img), str(out), "--dry-run"])
    assert result.exit_code == 0


def test_cli_media_slice_bitplanes_dry_run(tmp_path):
    img = tmp_path / "test.png"
    img.write_bytes(b"dummy")
    out_dir = tmp_path / "bitplanes"
    result = runner.invoke(app, ["sec", "media", "slice-bitplanes", str(img), str(out_dir), "--dry-run"])
    assert result.exit_code == 0


def test_cli_media_sign_and_verify_dry_run(tmp_path):
    img = tmp_path / "test.png"
    img.write_bytes(b"dummy")
    res_sign = runner.invoke(app, ["sec", "media", "sign", str(img), "--key", "mysecret", "--dry-run"])
    assert res_sign.exit_code == 0

    res_verify = runner.invoke(app, ["sec", "media", "verify", str(img), "mysig", "--key", "mysecret", "--dry-run"])
    assert res_verify.exit_code == 0


def test_cli_media_asymmetric_dry_run(tmp_path):
    img = tmp_path / "test.png"
    img.write_bytes(b"dummy")
    res_keygen = runner.invoke(app, ["sec", "media", "keygen", str(tmp_path), "--dry-run"])
    assert res_keygen.exit_code == 0

    priv = tmp_path / "priv.pem"
    pub = tmp_path / "pub.pem"
    priv.write_text("priv", encoding="utf-8")
    pub.write_text("pub", encoding="utf-8")

    res_sign = runner.invoke(app, ["sec", "media", "sign-asymmetric", str(img), "--priv-key", str(priv), "--dry-run"])
    assert res_sign.exit_code == 0

    res_ver = runner.invoke(
        app, ["sec", "media", "verify-asymmetric", str(img), "sig", "--pub-key", str(pub), "--dry-run"]
    )
    assert res_ver.exit_code == 0


def test_cli_media_embed_and_extract_dry_run(tmp_path):
    carrier = tmp_path / "carrier.png"
    carrier.write_bytes(b"carrier")
    payload = tmp_path / "secret.txt"
    payload.write_text("topsecret", encoding="utf-8")
    stego = tmp_path / "stego.png"
    extracted = tmp_path / "recovered.txt"

    res_embed = runner.invoke(app, ["sec", "media", "embed", str(carrier), str(payload), str(stego), "--dry-run"])
    assert res_embed.exit_code == 0

    res_extract = runner.invoke(app, ["sec", "media", "extract", str(carrier), str(extracted), "--dry-run"])
    assert res_extract.exit_code == 0


def test_cli_media_shred_dry_run(tmp_path):
    target = tmp_path / "to_delete.txt"
    target.write_text("delete me", encoding="utf-8")
    result = runner.invoke(app, ["sec", "media", "shred", str(target), "--passes", "3", "--dry-run"])
    assert result.exit_code == 0


def test_cli_media_palette_dry_run(tmp_path):
    carrier = tmp_path / "carrier.png"
    carrier.write_bytes(b"carrier")
    payload = tmp_path / "secret.txt"
    payload.write_text("secret", encoding="utf-8")
    out = tmp_path / "stego.png"
    res_embed = runner.invoke(
        app, ["sec", "media", "palette-embed", str(carrier), str(payload), str(out), "--password", "pw", "--dry-run"]
    )
    assert res_embed.exit_code == 0

    res_extract = runner.invoke(
        app, ["sec", "media", "palette-extract", str(carrier), str(out), "--password", "pw", "--dry-run"]
    )
    assert res_extract.exit_code == 0


def test_cli_media_meta_dry_run(tmp_path):
    carrier = tmp_path / "carrier.jpg"
    carrier.write_bytes(b"carrier")
    payload = tmp_path / "secret.txt"
    payload.write_text("secret", encoding="utf-8")
    out = tmp_path / "stego.jpg"
    res_embed = runner.invoke(
        app,
        [
            "sec",
            "media",
            "meta-embed",
            str(carrier),
            str(payload),
            str(out),
            "--channel",
            "xmp",
            "--password",
            "pw",
            "--dry-run",
        ],
    )
    assert res_embed.exit_code == 0

    res_extract = runner.invoke(
        app,
        ["sec", "media", "meta-extract", str(carrier), str(out), "--channel", "xmp", "--password", "pw", "--dry-run"],
    )
    assert res_extract.exit_code == 0


def test_cli_media_split_and_reconstruct_dry_run(tmp_path):
    payload = tmp_path / "secret.txt"
    payload.write_text("secret", encoding="utf-8")
    shares_dir = tmp_path / "shares"
    res_split = runner.invoke(
        app,
        ["sec", "media", "split", str(payload), str(shares_dir), "-k", "2", "-n", "3", "--password", "pw", "--dry-run"],
    )
    assert res_split.exit_code == 0

    share1 = tmp_path / "share_1.bin"
    share2 = tmp_path / "share_2.bin"
    share1.write_bytes(b"s1")
    share2.write_bytes(b"s2")
    out = tmp_path / "reconstructed.txt"
    res_recon = runner.invoke(
        app, ["sec", "media", "reconstruct", str(out), str(share1), str(share2), "--password", "pw", "--dry-run"]
    )
    assert res_recon.exit_code == 0


def test_cli_media_fs_dry_run(tmp_path):
    target = tmp_path / "target.txt"
    target.write_text("carrier", encoding="utf-8")
    payload = tmp_path / "secret.txt"
    payload.write_text("secret", encoding="utf-8")
    res_embed = runner.invoke(
        app, ["sec", "media", "fs-embed", str(target), str(payload), "--password", "pw", "--dry-run"]
    )
    assert res_embed.exit_code == 0

    out = tmp_path / "recovered.txt"
    res_extract = runner.invoke(
        app, ["sec", "media", "fs-extract", str(target), str(out), "--password", "pw", "--dry-run"]
    )
    assert res_extract.exit_code == 0


def test_cli_media_timestomp_dry_run(tmp_path):
    target = tmp_path / "target.txt"
    target.write_text("target", encoding="utf-8")
    clone_from = tmp_path / "source.txt"
    clone_from.write_text("source", encoding="utf-8")
    res = runner.invoke(app, ["sec", "media", "timestomp", str(target), "--clone-from", str(clone_from), "--dry-run"])
    assert res.exit_code == 0


def test_cli_ingest_and_report(tmp_path):
    report_file = tmp_path / "gitleaks.json"
    report_file.write_text(
        json.dumps(
            [
                {
                    "RuleID": "generic-api-key",
                    "Description": "Generic API Key",
                    "File": "config.py",
                    "StartLine": 5,
                    "EndLine": 5,
                    "Secret": "secret12345",
                }
            ]
        ),
        encoding="utf-8",
    )

    ingest_res = runner.invoke(app, ["sec", "ingest", str(report_file), "--artifacts-dir", str(tmp_path / "art")])
    assert ingest_res.exit_code == 0
    assert "Ingested 1 findings" in ingest_res.output

    report_res = runner.invoke(app, ["sec", "report", "--artifacts-dir", str(tmp_path / "art")])
    assert report_res.exit_code == 0
    assert "generic-api-key" in report_res.output


def test_cli_run_workflow_dry_run(tmp_path):
    plan_file = tmp_path / "workflow.yaml"
    plan_file.write_text(
        """
version: 1
name: test-wf
artifacts_dir: """
        + str(tmp_path / "art")
        + """
steps:
  - uses: trivy.filesystem
    with:
      path: .
  - uses: report.merge
    with:
      format: [json, markdown]
""",
        encoding="utf-8",
    )
    res = runner.invoke(app, ["sec", "run", str(plan_file), "--dry-run"])
    assert res.exit_code == 0
    assert "Workflow run" in res.output


def test_cli_zap_dry_run(tmp_path):
    scope = make_scope_file(tmp_path / "scope.yaml")
    target = "https://staging.example.internal/api/v1"

    # Passive baseline
    res = runner.invoke(app, ["sec", "zap", target, "--scope", str(scope), "--dry-run"])
    assert res.exit_code == 0
    assert "ZAP run" in res.output

    # Active scanning without allow_active_scanning in scope -> fails
    res_active_fail = runner.invoke(app, ["sec", "zap", target, "--scope", str(scope), "--active", "--dry-run"])
    assert res_active_fail.exit_code != 0

    # Active scanning with allow_active_scanning: true, confirmed with --yes
    active_scope = make_scope_file(tmp_path / "active_scope.yaml", allow_active_scanning=True)
    res_active = runner.invoke(
        app,
        ["sec", "zap", target, "--scope", str(active_scope), "--active", "--yes", "--dry-run"],
    )
    assert res_active.exit_code == 0
