"""Adversarial stress test suite for Milestone 3 (WI-14, WI-15, WI-16, WI-17, WI-18).

Empirical validation by Challenger M3-2:
1. WI-14: Model discovery cache TTL, negative caching, set-model validation, --force override.
2. WI-15: Cryptographic audit log tampering (command, timestamp, hash, deletion) and tamper pinpointing.
3. WI-16: Evidence bundle security (ciphertext tamper, header corrupt, wrong passphrase, path traversal, CLI wiring).
4. WI-17: Optional extras factoring, simulated missing modules, exit code 1, actionable hints, zero traceback.
5. WI-18: Bounded YARA scanner (15 MiB skip, .git pruning, symlink skip, deadline enforcement, structured stats).
"""

from __future__ import annotations

import io
import json
import os
import tarfile
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from eva.cli.app import app
from eva.cli.commands.config_cmd import (
    _fetch_provider_models,
)
from eva.security.audit import (
    append_command_audit,
    verify_audit_chain,
)
from eva.security_tools.bundle import (
    BundleError,
    create_bundle,
    decrypt_container,
    encrypt_container,
    sanitize_relative_path,
    verify_bundle,
)
from eva.security_tools.deps import check_extra_available
from eva.security_tools.yara_scanner import (
    YaraScanResult,
    collect_scan_files,
    scan_with_yara,
)

runner = CliRunner()


# ============================================================================
# 1. ADVERSARIAL STRESS TEST: WI-14 (Model Discovery Cache TTL & Validation)
# ============================================================================


class TestWI14ModelDiscoveryCacheAndValidation:
    """Stress-test model cache TTL, negative caching resilience, and set-model validation."""

    def test_cache_hit_before_3600s_does_not_call_provider(self, tmp_path: Path):
        """Assert cache hits return cached models without live network/provider invocation before 3600s."""
        fake_cache_file = tmp_path / "models_cache.json"
        now = time.time()
        initial_models = [{"id": "openrouter/mock-model-v1", "name": "Mock Model V1"}]
        cache_data = {
            "version": 1,
            "providers": {
                "openrouter": {
                    "fetched_at": now - 1800,  # 30 minutes ago (< 3600s)
                    "models": initial_models,
                }
            },
        }
        fake_cache_file.write_text(json.dumps(cache_data), encoding="utf-8")

        mock_get_models = MagicMock(return_value=[{"id": "live/should-not-be-called"}])

        with (
            patch("eva.cli.commands.config_cmd._get_models_cache_file", return_value=fake_cache_file),
            patch("eva.providers.openrouter_provider.get_models", mock_get_models),
        ):
            models, from_cache = _fetch_provider_models("openrouter", refresh=False)

        assert from_cache is True
        assert models == initial_models
        assert mock_get_models.call_count == 0

    def test_cache_refresh_after_3600s_invokes_provider_and_updates_cache(self, tmp_path: Path):
        """Assert cache entries older than 3600s trigger a fresh provider query and refresh disk cache."""
        fake_cache_file = tmp_path / "models_cache.json"
        now = time.time()
        stale_models = [{"id": "openrouter/stale-model", "name": "Stale Model"}]
        cache_data = {
            "version": 1,
            "providers": {
                "openrouter": {
                    "fetched_at": now - 3601,  # Expired (> 3600s)
                    "models": stale_models,
                }
            },
        }
        fake_cache_file.write_text(json.dumps(cache_data), encoding="utf-8")

        fresh_models = [{"id": "openrouter/fresh-model-v2", "name": "Fresh Model V2"}]
        mock_get_models = MagicMock(return_value=fresh_models)

        with (
            patch("eva.cli.commands.config_cmd._get_models_cache_file", return_value=fake_cache_file),
            patch("eva.providers.openrouter_provider.get_models", mock_get_models),
        ):
            models, from_cache = _fetch_provider_models("openrouter", refresh=False)

        assert from_cache is False
        assert models == fresh_models
        assert mock_get_models.call_count == 1

        # Check that disk cache was updated
        updated_cache = json.loads(fake_cache_file.read_text(encoding="utf-8"))
        entry = updated_cache["providers"]["openrouter"]
        assert entry["models"] == fresh_models
        assert entry["fetched_at"] >= now

    def test_explicit_refresh_flag_bypasses_valid_fresh_cache(self, tmp_path: Path):
        """Assert --refresh bypasses cache even when fetched_at was 1 second ago."""
        fake_cache_file = tmp_path / "models_cache.json"
        now = time.time()
        cache_data = {
            "version": 1,
            "providers": {
                "openrouter": {
                    "fetched_at": now - 5,
                    "models": [{"id": "openrouter/cached"}],
                }
            },
        }
        fake_cache_file.write_text(json.dumps(cache_data), encoding="utf-8")

        new_models = [{"id": "openrouter/forced-fresh"}]
        mock_get_models = MagicMock(return_value=new_models)

        with (
            patch("eva.cli.commands.config_cmd._get_models_cache_file", return_value=fake_cache_file),
            patch("eva.providers.openrouter_provider.get_models", mock_get_models),
        ):
            models, from_cache = _fetch_provider_models("openrouter", refresh=True)

        assert from_cache is False
        assert models == new_models
        assert mock_get_models.call_count == 1

    def test_negative_caching_failed_requests_never_overwrite_or_poison_cache(self, tmp_path: Path):
        """Assert failed/errored provider calls NEVER poison valid cache with empty models or update TTL."""
        fake_cache_file = tmp_path / "models_cache.json"
        orig_fetched_at = time.time() - 4000  # Stale, so a refresh will be attempted
        valid_models = [{"id": "openrouter/reliable-model"}]
        cache_data = {
            "version": 1,
            "providers": {
                "openrouter": {
                    "fetched_at": orig_fetched_at,
                    "models": valid_models,
                }
            },
        }
        fake_cache_file.write_text(json.dumps(cache_data), encoding="utf-8")

        # Provider completely fails with an exception across both get_models and get_free_models
        mock_fail = MagicMock(side_effect=RuntimeError("Provider network down"))

        with (
            patch("eva.cli.commands.config_cmd._get_models_cache_file", return_value=fake_cache_file),
            patch("eva.providers.openrouter_provider.get_models", mock_fail),
            patch("eva.providers.openrouter_provider.get_free_models", mock_fail),
        ):
            models, from_cache = _fetch_provider_models("openrouter", refresh=False)

        # Fallback to existing valid cached models without crashing
        assert models == valid_models
        assert from_cache is True

        # Ensure disk cache was NOT overwritten with empty list or new timestamp
        disk_cache = json.loads(fake_cache_file.read_text(encoding="utf-8"))
        assert disk_cache["providers"]["openrouter"]["models"] == valid_models
        assert disk_cache["providers"]["openrouter"]["fetched_at"] == orig_fetched_at

    def test_set_model_validation_rejects_unknown_and_force_overrides(self, tmp_path: Path):
        """Assert eva config set-model rejects unknown models with code 1, but --force accepts."""
        # 1. Unknown model rejection
        with patch(
            "eva.cli.commands.config_cmd._get_known_models_for_provider",
            return_value=[{"id": "openrouter/auto"}, {"id": "google/gemini-2.5-pro"}],
        ):
            result = runner.invoke(app, ["config", "set-model", "openrouter", "unsupported/malicious-model-xyz"])
            assert result.exit_code == 1
            assert "is not a recognized model" in result.output
            assert "--force" in result.output

        # 2. --force override succeeds
        with patch(
            "eva.cli.commands.config_cmd._get_known_models_for_provider",
            return_value=[{"id": "openrouter/auto"}],
        ):
            result_force = runner.invoke(
                app, ["config", "set-model", "openrouter", "unsupported/custom-finetune", "--force"]
            )
            assert result_force.exit_code == 0
            assert "set to 'unsupported/custom-finetune'" in result_force.output

        # 3. Model prefix handling: 'models/xyz' and 'xyz' are both recognized
        with patch(
            "eva.cli.commands.config_cmd._get_known_models_for_provider",
            return_value=[{"id": "models/gemini-pro"}],
        ):
            result_prefix = runner.invoke(app, ["config", "set-model", "gemini", "gemini-pro"])
            assert result_prefix.exit_code == 0


# ============================================================================
# 2. ADVERSARIAL STRESS TEST: WI-15 (Cryptographic Audit Log Tampering)
# ============================================================================


class TestWI15AuditLogTampering:
    """Stress-test tamper detection in hash-chained audit logging."""

    @pytest.fixture
    def populated_audit_log(self, tmp_path: Path) -> Path:
        """Create a valid hash-chained audit log with 5 distinct entries."""
        log_file = tmp_path / "command_audit.jsonl"
        for i in range(1, 6):
            entry = {
                "command": f"echo 'test step {i}'",
                "step": i,
                "user": "adversary",
            }
            append_command_audit(entry, log_file=log_file)
        # Verify initial valid state
        initial_check = verify_audit_chain(log_file)
        assert initial_check.is_valid is True
        assert initial_check.count == 5
        return log_file

    def test_tamper_modified_command_in_payload_detected(self, populated_audit_log: Path):
        """Tamper with command text in sequence 3; assert detection and failure pinpoint."""
        lines = populated_audit_log.read_text(encoding="utf-8").splitlines()
        rec3 = json.loads(lines[2])
        rec3["command"] = "rm -rf / --no-preserve-root"  # INJECT TAMPER
        lines[2] = json.dumps(rec3)
        populated_audit_log.write_text("\n".join(lines) + "\n", encoding="utf-8")

        result = verify_audit_chain(populated_audit_log)
        assert result.is_valid is False
        assert result.broken_index == 3
        assert "Hash signature mismatch at sequence 3" in result.message

        # Verify CLI verify exits 1
        with patch("eva.security.audit.get_command_audit_log", return_value=populated_audit_log):
            cli_res = runner.invoke(app, ["config", "audit", "verify"])
            assert cli_res.exit_code == 1
            assert "COMPROMISED / BROKEN" in cli_res.output
            assert "3" in cli_res.output

    def test_tamper_altered_timestamp_detected(self, populated_audit_log: Path):
        """Tamper with timestamp in sequence 2; assert detection and broken line 2."""
        lines = populated_audit_log.read_text(encoding="utf-8").splitlines()
        rec2 = json.loads(lines[1])
        rec2["timestamp"] = "1970-01-01T00:00:00+00:00"  # BACKDATE
        lines[1] = json.dumps(rec2)
        populated_audit_log.write_text("\n".join(lines) + "\n", encoding="utf-8")

        result = verify_audit_chain(populated_audit_log)
        assert result.is_valid is False
        assert result.broken_index == 2
        assert "Hash signature mismatch at sequence 2" in result.message

        with patch("eva.security.audit.get_command_audit_log", return_value=populated_audit_log):
            cli_res = runner.invoke(app, ["config", "audit", "verify"])
            assert cli_res.exit_code == 1
            assert "Broken Sequence / Line" in cli_res.output
            assert "2" in cli_res.output

    def test_tamper_altered_stored_hash_detected(self, populated_audit_log: Path):
        """Tamper with stored hash in sequence 2; assert hash signature mismatch."""
        lines = populated_audit_log.read_text(encoding="utf-8").splitlines()
        rec2 = json.loads(lines[1])
        # Invert the last hex character
        orig_hash = rec2["hash"]
        flipped = orig_hash[:-1] + ("0" if orig_hash[-1] != "0" else "1")
        rec2["hash"] = flipped
        lines[1] = json.dumps(rec2)
        populated_audit_log.write_text("\n".join(lines) + "\n", encoding="utf-8")

        result = verify_audit_chain(populated_audit_log)
        assert result.is_valid is False
        assert result.broken_index == 2
        assert "Hash signature mismatch at sequence 2" in result.message

    def test_tamper_deleted_middle_record_detected(self, populated_audit_log: Path):
        """Delete sequence 3; assert previous hash mismatch at following record."""
        lines = populated_audit_log.read_text(encoding="utf-8").splitlines()
        # Remove line 3 (index 2)
        deleted_lines = [lines[0], lines[1], lines[3], lines[4]]
        populated_audit_log.write_text("\n".join(deleted_lines) + "\n", encoding="utf-8")

        result = verify_audit_chain(populated_audit_log)
        assert result.is_valid is False
        assert result.broken_index == 3  # Line 3 in the new file (which was sequence 4)
        assert "Previous hash mismatch at sequence 4" in result.message


# ============================================================================
# 3. ADVERSARIAL STRESS TEST: WI-16 (Evidence Bundle Security & Traversal)
# ============================================================================


class TestWI16EvidenceBundleSecurityAndAdversarial:
    """Stress-test evidence bundles against ciphertext tamper, corrupt headers, wrong passphrase, and traversal."""

    @pytest.fixture
    def test_bundle(self, tmp_path: Path) -> tuple[Path, str]:
        """Create an encrypted test bundle."""
        src_dir = tmp_path / "incident_src"
        src_dir.mkdir()
        (src_dir / "auth.log").write_text("Failed password for root from 192.168.1.100 port 22", encoding="utf-8")
        (src_dir / "memdump.raw").write_bytes(os.urandom(2048))

        out_bundle = tmp_path / "forensics.evabnd"
        passphrase = "adversarial-crypto-passphrase-2026"
        res = create_bundle(
            targets=[src_dir],
            output=out_bundle,
            case_id="IR-ADV-001",
            examiner="challenger_m3_2",
            encrypt=True,
            passphrase=passphrase,
            iterations=1000,
        )
        assert res["status"] == "created"
        assert out_bundle.exists()
        return out_bundle, passphrase

    def test_tamper_ciphertext_byte_fails_closed(self, test_bundle: tuple[Path, str]):
        """Tamper with a single ciphertext byte; assert decryption fails closed without traceback."""
        bundle_path, passphrase = test_bundle
        raw = bytearray(bundle_path.read_bytes())

        # Ciphertext starts after 40-byte header (8 magic + 16 salt + 12 nonce + 4 iter)
        tamper_offset = 45
        raw[tamper_offset] ^= 0xFF
        bundle_path.write_bytes(bytes(raw))

        # Verification must fail
        v_res = verify_bundle(bundle_path, passphrase=passphrase)
        assert v_res["valid"] is False
        assert any(
            "Decryption failed" in err or "Sidecar SHA-256 mismatch" in err or "Archive extraction error" in err
            for err in v_res["errors"]
        )

    def test_decrypt_container_corrupt_magic_fails_closed(self):
        """Assert decrypt_container strictly rejects invalid container magic header."""
        secret_data = b"secret incident log"
        passphrase = "test-passphrase"
        encrypted = bytearray(encrypt_container(secret_data, passphrase, iterations=1000))
        encrypted[0:8] = b"CORRUPT!"

        with pytest.raises(BundleError, match="Invalid container magic header"):
            decrypt_container(bytes(encrypted), passphrase)

    def test_verify_bundle_corrupted_magic_unhandled_crash_vulnerability(self, test_bundle: tuple[Path, str]):
        """Document vulnerability: verify_bundle crashes with unhandled tarfile.ReadError when container magic is corrupt.

        Because open_bundle_tar falls back to tarfile.open on non-EVABUND1 magic, and verify_bundle only
        catches BundleError at the outer call site, corrupted containers throw an unhandled tarfile.ReadError
        rather than returning valid=False.
        """
        bundle_path, passphrase = test_bundle
        raw = bytearray(bundle_path.read_bytes())
        raw[0:8] = b"CORRUPT!"
        bundle_path.write_bytes(bytes(raw))

        v_res = verify_bundle(bundle_path, passphrase=passphrase)
        assert v_res["valid"] is False
        assert len(v_res["errors"]) > 0

    def test_wrong_passphrase_fails_closed_zero_leak(self, test_bundle: tuple[Path, str]):
        """Assert incorrect passphrase fails closed without exposing plaintext or unhandled crash."""
        bundle_path, _ = test_bundle
        v_res = verify_bundle(bundle_path, passphrase="completely-wrong-passphrase")
        assert v_res["valid"] is False
        assert any("Decryption failed" in err for err in v_res["errors"])

    def test_path_traversal_in_archive_strictly_rejected(self, tmp_path: Path):
        """Create a malicious tar archive containing directory traversal paths; assert verify rejects."""
        malicious_tar = tmp_path / "traversal.tar"
        with tarfile.open(malicious_tar, "w") as tar:
            # 1. Manifest
            manifest = {
                "schema": "eva.evidence.v1",
                "case_id": "TRAVERSAL-TEST",
                "files": [{"path": "bundle/evidence/../../etc/passwd", "sha256": "abc", "size": 10}],
            }
            m_bytes = json.dumps(manifest).encode("utf-8")
            t_info = tarfile.TarInfo("bundle/manifest.json")
            t_info.size = len(m_bytes)
            tar.addfile(t_info, io.BytesIO(m_bytes))

            # 2. Traversal file
            f_bytes = b"root:x:0:0:root:/root:/bin/bash"
            traversal_info = tarfile.TarInfo("bundle/evidence/../../etc/passwd")
            traversal_info.size = len(f_bytes)
            tar.addfile(traversal_info, io.BytesIO(f_bytes))

        # Test verify_bundle on malicious archive
        v_res = verify_bundle(malicious_tar)
        assert v_res["valid"] is False
        assert any("Illegal path in archive member" in err for err in v_res["errors"])

    def test_sanitize_relative_path_traversal_boundaries(self):
        """Assert sanitize_relative_path catches varied traversal patterns."""
        with pytest.raises(BundleError, match="Directory traversal prohibited"):
            sanitize_relative_path("../etc/passwd")

        with pytest.raises(BundleError, match="Directory traversal prohibited"):
            sanitize_relative_path("foo/bar/../../../root/.ssh/id_rsa")

        with pytest.raises(BundleError, match="Directory traversal prohibited"):
            sanitize_relative_path("..")


# ============================================================================
# 4. ADVERSARIAL STRESS TEST: WI-16 CLI Subcommands (Defect Demonstration)
# ============================================================================


class TestWI16CLIInterfaceContracts:
    """Empirically exercise CLI commands for sec bundle and sec triage.

    These tests assert that user invocations of CLI commands execute properly.
    """

    def test_bundle_create_cli_wiring_defect(self, tmp_path: Path):
        """eva sec bundle create passes targets and output, successfully creating bundle."""
        sample_file = tmp_path / "sample.txt"
        sample_file.write_text("forensic sample", encoding="utf-8")
        out_bnd = tmp_path / "test.evabnd"

        res = runner.invoke(app, ["sec", "bundle", "create", str(sample_file), "-o", str(out_bnd), "--no-encrypt"])
        assert res.exit_code == 0
        assert out_bnd.exists()

    def test_bundle_verify_cli_wiring_defect(self, tmp_path: Path):
        """eva sec bundle verify passes archive_path, successfully verifying bundle."""
        sample_file = tmp_path / "sample.txt"
        sample_file.write_text("forensic sample", encoding="utf-8")
        out_bnd = tmp_path / "test.evabnd"
        create_bundle(targets=[sample_file], output=out_bnd, encrypt=False)

        res = runner.invoke(app, ["sec", "bundle", "verify", str(out_bnd)])
        assert res.exit_code == 0
        assert "verified successfully" in res.output

    def test_bundle_list_cli_wiring_defect(self, tmp_path: Path):
        """eva sec bundle list passes archive_path, successfully listing bundle contents."""
        sample_file = tmp_path / "sample.txt"
        sample_file.write_text("forensic sample", encoding="utf-8")
        out_bnd = tmp_path / "test.evabnd"
        create_bundle(targets=[sample_file], output=out_bnd, encrypt=False)

        res = runner.invoke(app, ["sec", "bundle", "list", str(out_bnd)])
        assert res.exit_code == 0
        assert "sample.txt" in res.output

    def test_triage_run_cli_wiring_defect(self, tmp_path: Path):
        """eva sec triage run passes platform_name, successfully planning or running triage."""
        triage_out = tmp_path / "triage_out"
        res = runner.invoke(app, ["sec", "triage", "run", "--output-dir", str(triage_out), "--dry-run"])
        assert res.exit_code == 0
        assert "Planned triage run" in res.output


# ============================================================================
# 5. ADVERSARIAL STRESS TEST: WI-17 (Optional Extras Factoring & Error Ergonomics)
# ============================================================================


class TestWI17OptionalExtrasFactoring:
    """Stress-test optional extras dependency checking, actionable hints, and traceback prevention."""

    def test_check_extra_available_detects_simulated_missing_packages(self):
        """Simulate missing optional modules and assert correct actionable pip install hint returned."""
        with patch("importlib.import_module", side_effect=ImportError("No module named 'pefile'")):
            hint = check_extra_available("sec")
            assert hint == 'pip install "eva-cli[sec]"'

        with patch("importlib.import_module", side_effect=ImportError("No module named 'cv2'")):
            hint_media = check_extra_available("sec-media")
            assert hint_media == 'pip install "eva-cli[sec-media]"'

    def test_missing_extra_cli_exit_code_and_zero_traceback(self):
        """Assert invoking security command with missing extra yields exit code 1 with zero tracebacks."""
        # 1. YARA scan command when yara extra missing
        with (
            patch("eva.security_tools.cli.check_extra_available", return_value='pip install "eva-cli[sec]"'),
            patch("eva.security_tools.yara_scanner.yara", None),
        ):
            res_yara = runner.invoke(app, ["sec", "yara", "scan", "pyproject.toml"])
            assert res_yara.exit_code == 1
            assert 'pip install "eva-cli[sec]"' in res_yara.output
            assert "Traceback (most recent call last)" not in res_yara.output

        # 2. PE binary command when sec extra missing
        with patch("eva.security_tools.cli.check_extra_available", return_value='pip install "eva-cli[sec]"'):
            res_pe = runner.invoke(app, ["sec", "binary", "pe", "pyproject.toml"])
            assert res_pe.exit_code == 1
            assert 'pip install "eva-cli[sec]"' in res_pe.output
            assert "Traceback (most recent call last)" not in res_pe.output

        # 3. ELF binary command when sec extra missing
        with patch("eva.security_tools.cli.check_extra_available", return_value='pip install "eva-cli[sec]"'):
            res_elf = runner.invoke(app, ["sec", "binary", "elf", "pyproject.toml"])
            assert res_elf.exit_code == 1
            assert 'pip install "eva-cli[sec]"' in res_elf.output
            assert "Traceback (most recent call last)" not in res_elf.output


# ============================================================================
# 6. ADVERSARIAL STRESS TEST: WI-18 (Bounded YARA Scanner Limits & Deadlines)
# ============================================================================


class TestWI18BoundedYaraScanner:
    """Stress-test 10 MiB limit, .git/ pruning without descent, symlink skipping, and scan deadlines."""

    @pytest.fixture
    def mock_yara_tree(self, tmp_path: Path) -> tuple[Path, Path, Path, Path]:
        """Construct directory tree containing:
        - Small regular file (1 KB)
        - Oversized file (15 MiB)
        - Ignored directory .git/ with hidden files
        - Symlink pointing to regular file
        """
        scan_root = tmp_path / "yara_scan_root"
        scan_root.mkdir()

        # 1. Small regular file
        small_file = scan_root / "payload.bin"
        small_file.write_bytes(b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")

        # 2. Oversized 15 MiB file (exceeds 10 MiB limit)
        oversized_file = scan_root / "oversized_15mb.iso"
        # Create large file
        with open(oversized_file, "wb") as f:
            f.seek(15 * 1024 * 1024 - 1)
            f.write(b"\0")
        assert oversized_file.stat().st_size == 15 * 1024 * 1024

        # 3. Ignored .git directory containing files
        git_dir = scan_root / ".git"
        git_dir.mkdir()
        git_file = git_dir / "index_blob.dat"
        git_file.write_bytes(b"git internal object")

        # 4. Ignored node_modules directory
        nm_dir = scan_root / "node_modules"
        nm_dir.mkdir()
        (nm_dir / "package.js").write_text("console.log('vendor');", encoding="utf-8")

        # 5. Symlink
        symlink_file = scan_root / "symlink_to_payload.bin"
        try:
            symlink_file.symlink_to(small_file)
        except OSError:
            pass  # Windows unprivileged symlink fallback

        return scan_root, small_file, oversized_file, git_file

    def test_collect_scan_files_skips_15mb_prunes_git_and_skips_symlinks(
        self, mock_yara_tree: tuple[Path, Path, Path, Path]
    ):
        """Empirically assert collect_scan_files skips oversized file, prunes .git, and skips symlinks."""
        scan_root, small_file, oversized_file, git_file = mock_yara_tree

        files, skip_counts = collect_scan_files(scan_root, recursive=True)

        # Assert only the eligible small regular file was collected
        assert small_file in files
        assert oversized_file not in files
        assert git_file not in files

        # Assert structured skip counts
        assert skip_counts["oversized"] >= 1
        if hasattr(os, "symlink"):
            assert skip_counts["symlink"] >= 1

    def test_scan_with_yara_produces_structured_stats_and_skips_correctly(
        self, mock_yara_tree: tuple[Path, Path, Path, Path]
    ):
        """Empirically test scan_with_yara execution with dummy compiled rule."""
        scan_root, _small_file, _, _ = mock_yara_tree

        # Mock compiled YARA rules
        mock_rule = MagicMock()
        mock_rule.match.return_value = []

        result: YaraScanResult = scan_with_yara(scan_root, rules=mock_rule)

        assert isinstance(result, YaraScanResult)
        stats = result.stats
        assert stats["files_scanned"] == 1
        assert stats["files_skipped"] >= 1
        assert stats["skipped_reasons"]["oversized"] >= 1
        assert stats["timed_out"] is False
        assert stats["findings_count"] == 0

    def test_scan_deadline_enforcement_halts_gracefully(self, mock_yara_tree: tuple[Path, Path, Path, Path]):
        """Empirically assert scan deadline stops scan and marks timed_out = True."""
        scan_root, _, _, _ = mock_yara_tree

        mock_rule = MagicMock()
        mock_rule.match.return_value = []

        # Zero/negative deadline to trigger instant timeout
        result: YaraScanResult = scan_with_yara(scan_root, rules=mock_rule, scan_deadline_seconds=0.0)

        assert result.timed_out is True
        assert result.stats["timed_out"] is True
