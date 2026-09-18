from pathlib import Path

import pytest
from PIL import Image

from eva.security_tools.aegis import ALL_AEGIS_OPERATIONS, AegisAdapter


def test_aegis_status():
    adapter = AegisAdapter()
    status = adapter.status()
    assert status.installed is True
    assert "integrated" in status.version
    assert set(status.supported_features) == ALL_AEGIS_OPERATIONS


def test_aegis_build_argv_validation(tmp_path):
    adapter = AegisAdapter()
    out = tmp_path / "out.json"

    # Unknown operation
    with pytest.raises(ValueError, match="Unknown Aegis operation"):
        adapter.build_argv("invalid_op", {}, out)

    # Missing path in analyze
    with pytest.raises(ValueError, match="requires a path"):
        adapter.build_argv("analyze", {}, out)

    # Missing key in sign
    with pytest.raises(ValueError, match="requires path and key"):
        adapter.build_argv("sign", {"path": "test.png"}, out)

    # Valid analyze argv
    argv = adapter.build_argv("analyze", {"path": "test.png"}, out)
    assert argv == ["aegis", "--no-banner", "analyze", "--json-out", str(out), "test.png"]

    # Valid embed argv
    argv_embed = adapter.build_argv(
        "embed",
        {"carrier": "c.png", "payload": "p.txt", "output_path": "out.png", "algo": "adaptive"},
        out,
    )
    assert argv_embed == ["aegis", "--no-banner", "embed", "--algo", "adaptive", "c.png", "p.txt", "out.png"]


def test_aegis_build_argv_all_operations(tmp_path):
    adapter = AegisAdapter()
    out = tmp_path / "out.json"

    # palette-embed / palette-extract
    argv = adapter.build_argv(
        "palette-embed", {"carrier": "c.png", "payload": "p.txt", "output_path": "out.png", "password": "pw"}, out
    )
    assert "--password" in argv
    assert argv[-3:] == ["c.png", "p.txt", "out.png"]

    argv = adapter.build_argv("palette-extract", {"carrier": "c.png", "output_path": "p.txt", "password": "pw"}, out)
    assert "--password" in argv
    assert argv[-2:] == ["c.png", "p.txt"]

    # meta-embed / meta-extract
    argv = adapter.build_argv(
        "meta-embed",
        {"carrier": "c.png", "payload": "p.txt", "output_path": "out.png", "channel": "xmp", "password": "pw"},
        out,
    )
    assert "--channel" in argv
    assert "xmp" in argv
    assert "--password" in argv

    argv = adapter.build_argv(
        "meta-extract", {"carrier": "c.png", "output_path": "p.txt", "channel": "gps", "password": "pw"}, out
    )
    assert "--channel" in argv
    assert "gps" in argv
    assert "--password" in argv

    # split / reconstruct
    argv = adapter.build_argv(
        "split", {"payload": "p.txt", "output_dir": "shares", "k": 2, "n": 3, "password": "pw"}, out
    )
    assert "-k" in argv and "-n" in argv and "--password" in argv

    argv = adapter.build_argv(
        "reconstruct", {"shares": ["s1.bin", "s2.bin"], "output_path": "out.txt", "password": "pw"}, out
    )
    assert "s1.bin" in argv and "s2.bin" in argv and "out.txt" in argv

    # fs-embed / fs-extract
    argv = adapter.build_argv("fs-embed", {"target": "t.txt", "payload": "p.txt", "password": "pw"}, out)
    assert "--password" in argv and "t.txt" in argv and "p.txt" in argv

    argv = adapter.build_argv("fs-extract", {"target": "t.txt", "output_path": "p.txt", "password": "pw"}, out)
    assert "--password" in argv and "t.txt" in argv and "p.txt" in argv

    # timestomp
    argv = adapter.build_argv("timestomp", {"target": "t.txt", "clone_from": "c.txt"}, out)
    assert "--clone-from" in argv and "c.txt" in argv

    # shred
    argv = adapter.build_argv("shred", {"path": "t.txt", "passes": 5}, out)
    assert "--passes" in argv and "5" in argv and "t.txt" in argv

    # slice-bitplanes / scan-structure / extract-hidden
    argv = adapter.build_argv("slice-bitplanes", {"path": "img.png", "output_dir": "bp"}, out)
    assert "img.png" in argv and "bp" in argv

    argv = adapter.build_argv("scan-structure", {"path": "img.png"}, out)
    assert "img.png" in argv

    argv = adapter.build_argv("extract-hidden", {"path": "img.png", "output_path": "h.bin"}, out)
    assert "img.png" in argv and "h.bin" in argv

    # keygen / sign-asymmetric / verify-asymmetric
    argv = adapter.build_argv("keygen", {"output_dir": "keys"}, out)
    assert "keys" in argv

    argv = adapter.build_argv("sign-asymmetric", {"path": "img.png", "priv_key": "k.pem"}, out)
    assert "--priv-key" in argv

    argv = adapter.build_argv("verify-asymmetric", {"path": "img.png", "signature": "sig", "pub_key": "k.pub"}, out)
    assert "--pub-key" in argv and "sig" in argv


def test_aegis_dry_run(tmp_path):
    adapter = AegisAdapter()
    result = adapter.execute(
        "analyze",
        {"path": "test.png"},
        cwd=tmp_path,
        run_dir=tmp_path,
        run_id="dry-1",
        dry_run=True,
    )
    assert result.dry_run is True
    assert result.return_code is None
    assert "analyze" in result.argv


def test_aegis_in_process_signing_and_verification(tmp_path):
    adapter = AegisAdapter()
    img_path = tmp_path / "sample.png"
    Image.new("RGB", (40, 40), color="blue").save(img_path)

    # 1. Sign
    sign_result = adapter.execute(
        "sign",
        {"path": str(img_path), "key": "supersecretkey"},
        cwd=tmp_path,
        run_dir=tmp_path,
        run_id="sign-1",
        dry_run=False,
    )
    assert sign_result.return_code == 0
    assert "Signature:" in sign_result.stdout
    # Extract signature from stdout
    sig_line = next(line for line in sign_result.stdout.splitlines() if "Signature:" in line)
    signature = sig_line.split("Signature:")[1].strip()

    # 2. Verify with correct key & signature
    verify_result = adapter.execute(
        "verify",
        {"path": str(img_path), "key": "supersecretkey", "signature": signature},
        cwd=tmp_path,
        run_dir=tmp_path,
        run_id="verify-1",
        dry_run=False,
    )
    assert verify_result.return_code == 0
    assert "VALID" in verify_result.stdout

    # 3. Verify with wrong key
    verify_bad = adapter.execute(
        "verify",
        {"path": str(img_path), "key": "wrongkey", "signature": signature},
        cwd=tmp_path,
        run_dir=tmp_path,
        run_id="verify-2",
        dry_run=False,
    )
    assert verify_bad.return_code == 0
    assert "INVALID" in verify_bad.stdout


def test_aegis_in_process_analyze_and_parse(tmp_path):
    adapter = AegisAdapter()
    img_path = tmp_path / "sample.png"
    Image.new("RGB", (50, 50), color="green").save(img_path)

    # Append trailing data to create anomaly
    with open(img_path, "ab") as f:
        f.write(b"EXTRANEOUS_TRAILING_DATA_12345")

    result = adapter.execute(
        "analyze",
        {"path": str(img_path)},
        cwd=tmp_path,
        run_dir=tmp_path,
        run_id="ana-1",
        dry_run=False,
    )
    assert result.return_code == 0
    assert result.output_path is not None
    assert Path(result.output_path).exists()

    findings = adapter.parse_output(Path(result.output_path), result.stdout)
    assert len(findings) > 0
    assert any("trailing" in f.title.lower() or "structural anomaly" in f.title.lower() for f in findings)


def test_aegis_in_process_sanitize(tmp_path):
    adapter = AegisAdapter()
    img_path = tmp_path / "dirty.png"
    sanitized_path = tmp_path / "clean.png"
    Image.new("RGB", (30, 30), color="yellow").save(img_path)

    result = adapter.execute(
        "sanitize",
        {"path": str(img_path), "output_path": str(sanitized_path)},
        cwd=tmp_path,
        run_dir=tmp_path,
        run_id="san-1",
        dry_run=False,
    )
    assert result.return_code == 0
    assert sanitized_path.exists()
