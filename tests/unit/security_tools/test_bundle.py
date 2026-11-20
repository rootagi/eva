import pytest

from eva.security_tools.bundle import (
    CONTAINER_MAGIC,
    BundleError,
    create_bundle,
    decrypt_container,
    encrypt_container,
    is_encrypted_bundle,
    list_bundle,
    sanitize_relative_path,
    verify_bundle,
)


def test_sanitize_relative_path():
    assert sanitize_relative_path("foo/bar/baz.txt") == "foo/bar/baz.txt"
    assert sanitize_relative_path("./foo//bar/") == "foo/bar"
    with pytest.raises(BundleError, match="Directory traversal prohibited"):
        sanitize_relative_path("foo/../../bar")


def test_container_encryption_decryption_roundtrip():
    secret_data = b"confidential incident response data 12345"
    passphrase = "correct-horse-battery-staple"

    encrypted = encrypt_container(secret_data, passphrase, iterations=1000)
    assert encrypted.startswith(CONTAINER_MAGIC)
    assert len(encrypted) >= 40 + len(secret_data)

    decrypted = decrypt_container(encrypted, passphrase)
    assert decrypted == secret_data

    # Bad passphrase
    with pytest.raises(BundleError, match="Decryption failed"):
        decrypt_container(encrypted, "wrong-passphrase")

    # Corrupt magic
    corrupted_magic = b"WRONGMAG" + encrypted[8:]
    with pytest.raises(BundleError, match="Invalid container magic header"):
        decrypt_container(corrupted_magic, passphrase)

    # Truncated container
    with pytest.raises(BundleError, match="Corrupt bundle: file size is smaller than header minimum"):
        decrypt_container(b"EVABUND1short", passphrase)


def test_create_and_verify_encrypted_bundle(tmp_path):
    target_dir = tmp_path / "evidence_src"
    target_dir.mkdir()
    f1 = target_dir / "log.txt"
    f1.write_text("system compromised at 12:00", encoding="utf-8")
    f2 = target_dir / "dump.bin"
    f2.write_bytes(b"\x00\x01\x02\x03\x04")

    out_bundle = tmp_path / "case01.eva.tar.gz"
    res = create_bundle(
        targets=[target_dir],
        output=out_bundle,
        case_id="INC-2026-001",
        examiner="analyst_alice",
        encrypt=True,
        passphrase="bundle-test-pass",
        iterations=1000,
    )
    assert res["status"] == "created"
    assert out_bundle.is_file()
    assert is_encrypted_bundle(out_bundle)

    # Verify sidecar created
    sidecar = tmp_path / "case01.eva.tar.gz.sha256"
    assert sidecar.is_file()

    # Verify bundle
    v_res = verify_bundle(out_bundle, passphrase="bundle-test-pass")
    assert v_res["valid"] is True
    assert v_res["sidecar_verified"] is True
    assert v_res["files_verified"] == 2
    assert len(v_res["errors"]) == 0

    # List bundle contents
    l_res = list_bundle(out_bundle, passphrase="bundle-test-pass")
    assert l_res["encrypted"] is True
    assert l_res["case_id"] == "INC-2026-001"
    assert len(l_res["files"]) == 2

    # Verification failure on bad passphrase
    bad_v = verify_bundle(out_bundle, passphrase="wrong-passphrase")
    assert bad_v["valid"] is False
    assert any("Decryption failed" in err for err in bad_v["errors"])

    # Tampered sidecar
    sidecar.write_text("0000000000000000000000000000000000000000000000000000000000000000  case01.eva.tar.gz\n")
    tampered_v = verify_bundle(out_bundle, passphrase="bundle-test-pass")
    assert tampered_v["valid"] is False
    assert any("Sidecar SHA-256 mismatch" in err for err in tampered_v["errors"])


def test_create_unencrypted_bundle(tmp_path):
    target_file = tmp_path / "sample.log"
    target_file.write_text("plain evidence", encoding="utf-8")

    out_bundle = tmp_path / "plain_case.tar.gz"
    res = create_bundle(
        targets=[target_file],
        output=out_bundle,
        encrypt=False,
    )
    assert res["status"] == "created"
    assert not is_encrypted_bundle(out_bundle)

    v_res = verify_bundle(out_bundle)
    assert v_res["valid"] is True
    assert v_res["files_verified"] == 1


def test_create_bundle_errors(tmp_path):
    # Non-existent target
    with pytest.raises(BundleError, match="Target does not exist"):
        create_bundle(targets=[tmp_path / "non_existent"], output=tmp_path / "out.tar.gz", encrypt=False)

    # Already existing output without force
    existing = tmp_path / "exists.tar.gz"
    existing.write_text("data")
    src = tmp_path / "src.txt"
    src.write_text("src")
    with pytest.raises(BundleError, match="Output file already exists"):
        create_bundle(targets=[src], output=existing, force=False, encrypt=False)

    # Encrypted without passphrase
    with pytest.raises(BundleError, match="Passphrase required for encrypted bundle"):
        create_bundle(targets=[src], output=tmp_path / "out2.tar.gz", encrypt=True, passphrase=None)
