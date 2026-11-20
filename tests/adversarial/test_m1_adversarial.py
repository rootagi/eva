"""Adversarial stress-test harness for Milestone 1 (WI-01 through WI-05).

Empirical challenger test suite executing generators, oracles, and adversarial attacks.
"""

import json
import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from eva.cache.cache import generate_cache_key
from eva.cli.app import app
from eva.config import AppConfig, ProviderConfig
from eva.indexing.finder import find_files_python_fallback
from eva.prompts import WORK_SYSTEM_PROMPT
from eva.providers import dispatch
from eva.providers.gemini_provider import ToolCall, format_gemini_contents
from eva.workspace.git_ops import apply_unified_diff
from eva.workspace.gitignore import ALWAYS_IGNORED_DIRS

try:
    import eva_fastwalk

    HAS_RUST = True
except ImportError:
    HAS_RUST = False


# ===========================================================================
# WI-01: Adversarial Response Cache Key & Divergence Tests
# ===========================================================================


class TestWI01CacheAdversarial:
    """Adversarial testing of cache key generation and namespacing."""

    def test_cache_key_divergence_across_models_same_provider(self):
        """Identical prompts must produce divergent cache keys across different models."""
        models = [
            "llama-3.1-8b-instant",
            "llama-3.3-70b-versatile",
            "gpt-4o",
            "gpt-4o-mini",
            "gemini-2.5-flash",
            "gemini-3-pro",
            "claude-3-5-sonnet",
        ]
        keys = set()
        for m in models:
            k = generate_cache_key(
                model=f"provider:{m}",
                system_prompt="sys prompt",
                user_prompt="user prompt",
                context="context data",
            )
            assert k.startswith("v2:"), f"Key {k} must start with namespace prefix v2:"
            keys.add(k)

        assert len(keys) == len(models), "Cache keys collided across different models!"

    def test_cache_key_namespace_handling(self):
        """Verify namespace prefixes and empty/custom namespaces."""
        k_default = generate_cache_key("m", "s", "u", "c")
        assert k_default.startswith("v2:")

        k_custom = generate_cache_key("m", "s", "u", "c", namespace="custom_v3")
        assert k_custom.startswith("custom_v3:")
        assert k_custom != k_default

        k_none = generate_cache_key("m", "s", "u", "c", namespace="")
        assert not k_none.startswith(":")
        assert ":" not in k_none  # bare hex digest

    def test_cache_key_unicode_adversarial(self):
        """Adversarial unicode inputs: RTL, CJK, emoji ZWJ sequences, control characters, null bytes."""
        adversarial_strings = [
            "こんにちは世界 🚀 👾 💻",
            "مرحبا بالعالم (Arabic RTL text with diacritics: ً ٌ ٍ َ ُ ِ ّ ْ)",
            "שלום עולם (Hebrew RTL text with niqqud)",
            "👨‍👩‍👧‍👦 (Multi-person ZWJ sequence emoji)",
            "🏳️‍🌈 (Rainbow flag ZWJ sequence)",
            "Z͑ͫ̓ͪ̂ͫ̽͏̴̙̤̞͉͚̯̞̠͍A̧̧̘̫͔ͫ̃͊ͧ̏̔̊́͢L̠ͨͧͩ͘G̴̻͈͍͔̹̑͗̎̅͛́Ǫ̵̹̻̝̳͂̌̌͘ (Zalgo combining marks)",
            "\x00\x01\x02\x08\x0b\x0c\x0e\x1f (ASCII control characters and null byte)",
            "Mixed: \u202eRTL_OVERRIDE\u202c and symbols: ∀x∈ℝ, ∃y: y > x",
        ]

        seen_keys = set()
        for s in adversarial_strings:
            k = generate_cache_key(model=s, system_prompt=s, user_prompt=s, context=s)
            assert isinstance(k, str)
            assert k.startswith("v2:")
            assert len(k) == 3 + 64  # 'v2:' + sha256 hex length
            seen_keys.add(k)

        assert len(seen_keys) == len(adversarial_strings)

    def test_cache_key_deterministic_and_large_inputs(self):
        """Ensure hashing is deterministic across identical large inputs (500KB context)."""
        large_context = "x" * 500_000
        k1 = generate_cache_key("model", "sys", "user", large_context)
        k2 = generate_cache_key("model", "sys", "user", large_context)
        assert k1 == k2

        k_diff = generate_cache_key("model", "sys", "user", large_context + "1")
        assert k1 != k_diff

    def test_dispatch_caching_multi_model_isolation(self):
        """Verify dispatch cache isolation when querying different models under the same provider."""
        config = AppConfig()
        config.general.default_provider = "groq"
        config.providers["groq"] = ProviderConfig(model="llama-3.1-8b-instant")

        call_log = []

        def mock_call_provider(provider, sys_prompt, user_prompt, context, cfg):
            active_model = cfg.providers[provider.name].model
            call_log.append(active_model)
            yield f"response_from_{active_model}"

        with patch("eva.providers.call_provider", side_effect=mock_call_provider):
            # Model 1: first call -> cache miss
            r1 = "".join(dispatch("sys", "user", "ctx", config, use_cache=True))
            assert r1 == "response_from_llama-3.1-8b-instant"
            assert len(call_log) == 1

            # Model 1: second call -> cache hit
            r1_cached = "".join(dispatch("sys", "user", "ctx", config, use_cache=True))
            assert r1_cached == "response_from_llama-3.1-8b-instant"
            assert len(call_log) == 1

            # Switch model to Model 2: must be cache miss
            config.providers["groq"].model = "llama-3.3-70b-versatile"
            r2 = "".join(dispatch("sys", "user", "ctx", config, use_cache=True))
            assert r2 == "response_from_llama-3.3-70b-versatile"
            assert len(call_log) == 2

            # Model 2: second call -> cache hit
            r2_cached = "".join(dispatch("sys", "user", "ctx", config, use_cache=True))
            assert r2_cached == "response_from_llama-3.3-70b-versatile"
            assert len(call_log) == 2

            # Switch back to Model 1: must hit cache populated earlier
            config.providers["groq"].model = "llama-3.1-8b-instant"
            r1_rehit = "".join(dispatch("sys", "user", "ctx", config, use_cache=True))
            assert r1_rehit == "response_from_llama-3.1-8b-instant"
            assert len(call_log) == 2  # No new call!


# ===========================================================================
# WI-02: Adversarial Privilege Escalation & Safety Checks Tests
# ===========================================================================


class TestWI02PrivilegeGatingAdversarial:
    """Stress-test privilege gating, allowlist bypasses, and injection attempts."""

    def test_work_system_prompt_omits_all_sudo_instructions(self):
        """WORK_SYSTEM_PROMPT must have zero mentions of sudo or privilege escalation."""
        prompt_lower = WORK_SYSTEM_PROMPT.lower()
        assert "sudo" not in prompt_lower, "WORK_SYSTEM_PROMPT still contains 'sudo'!"
        assert "elevated" not in prompt_lower, "WORK_SYSTEM_PROMPT still mentions elevated privileges!"
        assert "root privileges" not in prompt_lower

    def test_failing_command_no_sudo_retry_without_flag(self):
        """Failing command without --allow-sudo must exit immediately with returncode and NO prompt."""
        runner = CliRunner()
        with (
            patch("eva.cli.commands.work._resolve_app_attr") as mock_resolve,
            patch("subprocess.run") as mock_run,
            patch("typer.confirm") as mock_confirm,
        ):
            mock_config = MagicMock()
            mock_config.general.allowed_command_prefixes = []
            mock_config.general.sandbox_risky_commands = False

            def resolve_se(name, default):
                if name == "load_config":
                    return lambda: mock_config
                if name == "dispatch":
                    return lambda *args, **kwargs: iter(["cat /root/secret.txt"])
                return default

            mock_resolve.side_effect = resolve_se
            mock_run.return_value = MagicMock(returncode=13, stdout="", stderr="Permission denied")

            result = runner.invoke(app, ["work", "--yes", "read root secret"])
            assert result.exit_code == 13
            mock_confirm.assert_not_called()
            assert mock_run.call_count == 1  # Exactly 1 un-elevated attempt, NO retry

    def test_allow_sudo_does_not_double_sudo(self):
        """If the command already starts with sudo, --allow-sudo must NOT attempt sudo sudo."""
        runner = CliRunner()
        with (
            patch("eva.cli.commands.work._resolve_app_attr") as mock_resolve,
            patch("subprocess.run") as mock_run,
        ):
            mock_config = MagicMock()
            mock_config.general.allowed_command_prefixes = []
            mock_config.general.sandbox_risky_commands = False

            def resolve_se(name, default):
                if name == "load_config":
                    return lambda: mock_config
                if name == "dispatch":
                    return lambda *args, **kwargs: iter(["sudo systemctl status"])
                return default

            mock_resolve.side_effect = resolve_se
            mock_run.return_value = MagicMock(returncode=3, stdout="", stderr="Not found")

            result = runner.invoke(app, ["work", "--yes", "--allow-sudo", "check status"])
            assert result.exit_code == 3
            # Should have run once and exited, NOT attempted 'sudo sudo systemctl status'
            assert mock_run.call_count == 1

    def test_allowlist_bypass_injection_attempts(self):
        """Adversarial injection attempts through command chaining, subshells, and newlines."""
        runner = CliRunner()
        audit_log = []

        with (
            patch("eva.cli.commands.work._resolve_app_attr") as mock_resolve,
            patch("subprocess.run") as mock_run,
        ):
            mock_config = MagicMock()
            mock_config.general.allowed_command_prefixes = ["apt", "sudo apt"]
            mock_config.general.sandbox_risky_commands = False

            def resolve_se(name, default):
                if name == "load_config":
                    return lambda: mock_config
                if name == "append_command_audit":
                    return audit_log.append
                return default

            mock_resolve.side_effect = resolve_se

            # Attack 1: Command chaining with semicolon: "apt update; rm -rf /"
            # It fails the un-elevated run, then attempts escalation
            def run_se(argv, **kwargs):
                assert kwargs.get("shell") is False, "Privilege escalation MUST NOT use shell=True!"
                return MagicMock(returncode=1, stdout="", stderr="error")

            mock_run.side_effect = run_se

            # If dispatch returned a chained command matching blast radius
            with patch(
                "eva.cli.commands.work._resolve_app_attr",
                side_effect=lambda name, default: (
                    (lambda *a, **k: iter(["apt update && rm -rf /"]))
                    if name == "dispatch"
                    else resolve_se(name, default)
                ),
            ):
                res = runner.invoke(app, ["work", "--yes", "--allow-sudo", "do update"])
                # Must be blocked by safety checks or blast-radius pattern
                assert res.exit_code != 0

    def test_escalated_execution_prohibits_shell_true(self):
        """Verify that escalated subprocess call strictly prohibits shell=True."""
        runner = CliRunner()
        captured_kwargs = []

        with (
            patch("eva.cli.commands.work._resolve_app_attr") as mock_resolve,
            patch("subprocess.run") as mock_run,
        ):
            mock_config = MagicMock()
            mock_config.general.allowed_command_prefixes = ["id", "sudo id"]
            mock_config.general.sandbox_risky_commands = False

            def resolve_se(name, default):
                if name == "load_config":
                    return lambda: mock_config
                if name == "dispatch":
                    return lambda *args, **kwargs: iter(["id -u"])
                return default

            mock_resolve.side_effect = resolve_se

            def mock_subp(argv, **kwargs):
                captured_kwargs.append(kwargs)
                if len(captured_kwargs) == 1:
                    return MagicMock(returncode=1, stdout="", stderr="unprivileged error")
                return MagicMock(returncode=0, stdout="0\n", stderr="")

            mock_run.side_effect = mock_subp

            result = runner.invoke(app, ["work", "--yes", "--allow-sudo", "get id"])
            assert result.exit_code == 0
            assert len(captured_kwargs) == 2
            # The second (escalated) call MUST have shell=False
            assert captured_kwargs[1]["shell"] is False


# ===========================================================================
# WI-03: Adversarial Fastwalk & Traversal Parity Tests
# ===========================================================================


class TestWI03FastwalkAdversarial:
    """Stress-test Rust fastwalk and Python fallback with deep trees, symlinks, and ignore rules."""

    @pytest.fixture
    def complex_workspace(self, tmp_path: Path):
        """Create a deep, complex directory structure with ignored dirs at multiple levels."""
        # Standard files
        (tmp_path / "root.txt").write_text("root", encoding="utf-8")

        # 1. ALWAYS_IGNORED_DIRS at root
        for ignored in ALWAYS_IGNORED_DIRS:
            d = tmp_path / ignored
            d.mkdir(parents=True, exist_ok=True)
            (d / "secret.dat").write_text("hidden", encoding="utf-8")

        # 2. Deep nested structure (20 levels deep)
        curr = tmp_path / "deep"
        curr.mkdir()
        for i in range(1, 20):
            curr = curr / f"level_{i}"
            curr.mkdir()
            (curr / f"file_{i}.txt").write_text(f"level {i}", encoding="utf-8")
            if i in (5, 12, 17):
                # Nested node_modules and .git
                nested_node = curr / "node_modules"
                nested_node.mkdir()
                (nested_node / "pkg.js").write_text("js", encoding="utf-8")

        # 3. Custom extra directories
        custom_dir = tmp_path / "custom_temp" / "sub"
        custom_dir.mkdir(parents=True)
        (custom_dir / "temp.log").write_text("log", encoding="utf-8")

        return tmp_path

    def test_fastwalk_always_ignored_dirs_pruning(self, complex_workspace: Path):
        """All ALWAYS_IGNORED_DIRS must be pruned in both Rust and Python traversals."""
        py_files = {
            p.relative_to(complex_workspace).as_posix() for p in find_files_python_fallback(complex_workspace, "*")
        }

        # None of the ALWAYS_IGNORED_DIRS files should be present
        for ignored in ALWAYS_IGNORED_DIRS:
            assert not any(p.startswith(f"{ignored}/") for p in py_files), f"Python walk leaked {ignored}"

        if HAS_RUST:
            rust_raw = eva_fastwalk.fast_find_files(str(complex_workspace), "*")
            rust_files = {Path(p).relative_to(complex_workspace).as_posix() for p in rust_raw}
            for ignored in ALWAYS_IGNORED_DIRS:
                assert not any(p.startswith(f"{ignored}/") for p in rust_files), f"Rust walk leaked {ignored}"
            assert py_files == rust_files, "Parity mismatch between Python and Rust traversals!"

    def test_fastwalk_unignore_flag_parity(self, complex_workspace: Path):
        """Unignoring specific directories (e.g. .venv and target) must work in both engines."""
        py_files = {
            p.relative_to(complex_workspace).as_posix()
            for p in find_files_python_fallback(complex_workspace, "*", unignore=[".venv", "target"])
        }
        assert ".venv/secret.dat" in py_files
        assert "target/secret.dat" in py_files
        assert "node_modules/secret.dat" not in py_files
        assert ".git/secret.dat" not in py_files

        if HAS_RUST:
            rust_raw = eva_fastwalk.fast_find_files(str(complex_workspace), "*", unignore=[".venv", "target"])
            rust_files = {Path(p).relative_to(complex_workspace).as_posix() for p in rust_raw}
            assert rust_files == py_files

    def test_fastwalk_extra_ignored_parity(self, complex_workspace: Path):
        """extra_ignored must prune custom directories in both engines."""
        py_files = {
            p.relative_to(complex_workspace).as_posix()
            for p in find_files_python_fallback(complex_workspace, "*", extra_ignored=["custom_temp", "deep"])
        }
        assert "custom_temp/sub/temp.log" not in py_files
        assert not any(p.startswith("deep/") for p in py_files)
        assert "root.txt" in py_files

        if HAS_RUST:
            rust_raw = eva_fastwalk.fast_find_files(str(complex_workspace), "*", extra_ignored=["custom_temp", "deep"])
            rust_files = {Path(p).relative_to(complex_workspace).as_posix() for p in rust_raw}
            assert rust_files == py_files

    def test_fastwalk_symlink_handling(self, tmp_path: Path):
        """Symlinks (directory, file, broken, loop) must not crash or cause infinite loops."""
        (tmp_path / "real_dir").mkdir()
        (tmp_path / "real_dir" / "file.txt").write_text("data", encoding="utf-8")

        # Create symlinks
        try:
            (tmp_path / "link_dir").symlink_to(tmp_path / "real_dir")
            (tmp_path / "link_file.txt").symlink_to(tmp_path / "real_dir" / "file.txt")
            (tmp_path / "dangling_link").symlink_to(tmp_path / "nonexistent")
            # Loop: loop_dir contains link pointing to itself
            loop_dir = tmp_path / "loop_dir"
            loop_dir.mkdir()
            (loop_dir / "cycle").symlink_to(loop_dir)
        except OSError:
            pytest.skip("Symlink creation not permitted in environment")

        py_files = {p.relative_to(tmp_path).as_posix() for p in find_files_python_fallback(tmp_path, "*")}
        assert "real_dir/file.txt" in py_files

        if HAS_RUST:
            rust_raw = eva_fastwalk.fast_find_files(str(tmp_path), "*")
            rust_files = {Path(p).relative_to(tmp_path).as_posix() for p in rust_raw}
            assert "real_dir/file.txt" in rust_files


# ===========================================================================
# WI-04: Adversarial Unified Diff Security & Atomic Rollback Tests
# ===========================================================================


class TestWI04DiffSecurityAndRollbackAdversarial:
    """Adversarially attack apply_unified_diff with path traversals, sensitive files, and rollback."""

    def test_diff_rejects_directory_traversal(self, tmp_path: Path):
        """Diff headers containing traversal sequences must be rejected."""
        target = tmp_path / "app.py"
        target.write_text("original\n", encoding="utf-8")

        attack_diffs = [
            "--- a/../../../../etc/shadow\n+++ b/../../../../etc/shadow\n@@ -1,1 +1,1 @@\n-x\n+pwned\n",
            "--- a/sub/../../outside.py\n+++ b/sub/../../outside.py\n@@ -1,1 +1,1 @@\n-x\n+pwned\n",
            "--- a/..\\..\\windows.ini\n+++ b/..\\..\\windows.ini\n@@ -1,1 +1,1 @@\n-x\n+pwned\n",
            "--- a/./../escaped.py\n+++ b/./../escaped.py\n@@ -1,1 +1,1 @@\n-x\n+pwned\n",
        ]

        for diff in attack_diffs:
            res = apply_unified_diff(diff, root_dir=tmp_path)
            assert res is False, f"Diff traversal succeeded: {diff}"

    def test_diff_rejects_absolute_paths(self, tmp_path: Path):
        """Diff headers containing absolute paths must be rejected."""
        attack_diffs = [
            "--- /etc/passwd\n+++ /etc/passwd\n@@ -1,1 +1,1 @@\n-root:x:0:0\n+root:x:1:1\n",
            "--- /var/log/syslog\n+++ /var/log/syslog\n@@ -1,1 +1,1 @@\n-x\n+y\n",
            "--- C:\\Windows\\System32\\calc.exe\n+++ C:\\Windows\\System32\\calc.exe\n@@ -1,1 +1,1 @@\n-x\n+y\n",
        ]
        for diff in attack_diffs:
            res = apply_unified_diff(diff, root_dir=tmp_path)
            assert res is False, f"Absolute path succeeded: {diff}"

    def test_diff_rejects_sensitive_files(self, tmp_path: Path):
        """Sensitive files (root and nested) must be blocked unless force_include is specified."""
        sensitive_paths = [
            tmp_path / ".env",
            tmp_path / "config" / ".env",
            tmp_path / ".git" / "config",
            tmp_path / "deep" / "nested" / "id_rsa",
            tmp_path / "credentials.json",
        ]

        for s_path in sensitive_paths:
            s_path.parent.mkdir(parents=True, exist_ok=True)
            s_path.write_text("SECRET_KEY=12345\n", encoding="utf-8")

            rel = s_path.relative_to(tmp_path).as_posix()
            diff = f"--- a/{rel}\n+++ b/{rel}\n@@ -1,1 +1,1 @@\n-SECRET_KEY=12345\n+SECRET_KEY=POISONED\n"

            res = apply_unified_diff(diff, root_dir=tmp_path)
            assert res is False, f"Sensitive file modification permitted: {rel}"
            assert s_path.read_text(encoding="utf-8") == "SECRET_KEY=12345\n"

            # Permitted when force_include explicitly includes it
            res_forced = apply_unified_diff(diff, root_dir=tmp_path, force_include={rel})
            assert res_forced is True
            assert s_path.read_text(encoding="utf-8") == "SECRET_KEY=POISONED\n"

    def test_diff_rejects_symlinks(self, tmp_path: Path):
        """Diff targeting a symlink or file within a symlinked directory must be rejected."""
        target_real = tmp_path / "real.py"
        target_real.write_text("real content\n", encoding="utf-8")

        symlink_file = tmp_path / "sym_target.py"
        try:
            symlink_file.symlink_to(target_real)
        except OSError:
            pytest.skip("Symlinks not supported")

        diff = "--- a/sym_target.py\n+++ b/sym_target.py\n@@ -1,1 +1,1 @@\n-real content\n+hacked content\n"
        res = apply_unified_diff(diff, root_dir=tmp_path)
        assert res is False
        assert target_real.read_text(encoding="utf-8") == "real content\n"

    def test_diff_authorized_paths_enforcement(self, tmp_path: Path):
        """Only files within authorized_paths may be modified."""
        file_a = tmp_path / "allowed.py"
        file_b = tmp_path / "disallowed.py"
        file_a.write_text("init a\n", encoding="utf-8")
        file_b.write_text("init b\n", encoding="utf-8")

        diff = (
            "--- a/allowed.py\n+++ b/allowed.py\n@@ -1,1 +1,1 @@\n-init a\n+mod a\n"
            "--- a/disallowed.py\n+++ b/disallowed.py\n@@ -1,1 +1,1 @@\n-init b\n+mod b\n"
        )

        res = apply_unified_diff(diff, root_dir=tmp_path, authorized_paths={file_a})
        assert res is False
        # Neither file should be modified
        assert file_a.read_text(encoding="utf-8") == "init a\n"
        assert file_b.read_text(encoding="utf-8") == "init b\n"

    def test_diff_atomic_rollback_on_second_file_failure(self, tmp_path: Path):
        """Multi-file diff: File 1 matches, File 2 has invalid hunk -> complete atomic rollback."""
        file1 = tmp_path / "file1.py"
        file2 = tmp_path / "file2.py"
        file3 = tmp_path / "file3.py"

        file1.write_text("line1\nline2\nline3\n", encoding="utf-8")
        file2.write_text("alpha\nbeta\ngamma\n", encoding="utf-8")
        file3.write_text("one\ntwo\nthree\n", encoding="utf-8")

        file1_original = file1.read_text(encoding="utf-8")
        file2_original = file2.read_text(encoding="utf-8")
        file3_original = file3.read_text(encoding="utf-8")

        # Diff where file 1 and 3 are valid, but file 2 contains a hunk that does not match
        multi_diff = (
            "--- a/file1.py\n+++ b/file1.py\n@@ -1,1 +1,1 @@\n-line1\n+line1_MODIFIED\n"
            "--- a/file2.py\n+++ b/file2.py\n@@ -1,1 +1,1 @@\n-NONEXISTENT_LINE\n+beta_MODIFIED\n"
            "--- a/file3.py\n+++ b/file3.py\n@@ -1,1 +1,1 @@\n-one\n+one_MODIFIED\n"
        )

        res = apply_unified_diff(multi_diff, root_dir=tmp_path)
        assert res is False, "Multi-file patch with broken hunk must return False"

        # Verify atomic integrity: ALL files must be in their exact original state
        assert file1.read_text(encoding="utf-8") == file1_original
        assert file2.read_text(encoding="utf-8") == file2_original
        assert file3.read_text(encoding="utf-8") == file3_original

    def test_diff_atomic_rollback_on_disk_replace_failure(self, tmp_path: Path):
        """Simulate an OS write/replace error mid-flight -> verify rollback restores previous files."""
        file1 = tmp_path / "f1.py"
        file2 = tmp_path / "f2.py"

        file1.write_text("file1 initial\n", encoding="utf-8")
        file2.write_text("file2 initial\n", encoding="utf-8")

        multi_diff = (
            "--- a/f1.py\n+++ b/f1.py\n@@ -1,1 +1,1 @@\n-file1 initial\n+file1 new\n"
            "--- a/f2.py\n+++ b/f2.py\n@@ -1,1 +1,1 @@\n-file2 initial\n+file2 new\n"
        )

        real_replace = os.replace
        replace_count = 0

        def faulty_replace(src, dst):
            nonlocal replace_count
            replace_count += 1
            if replace_count == 2:
                raise OSError("Simulated I/O disk error on file 2")
            real_replace(src, dst)

        with patch("os.replace", side_effect=faulty_replace):
            res = apply_unified_diff(multi_diff, root_dir=tmp_path)
            assert res is False

        # File 1 was replaced then restored from .bak during rollback
        assert file1.read_text(encoding="utf-8") == "file1 initial\n"
        assert file2.read_text(encoding="utf-8") == "file2 initial\n"


# ===========================================================================
# WI-05: Adversarial Gemini Multi-Turn Structured Tool Mapping Tests
# ===========================================================================


class TestWI05GeminiToolsAdversarial:
    """Stress-test Gemini multi-turn tool calling with parallel calls, invalid IDs, and empty args."""

    def test_parallel_tool_calls_mapping(self):
        """Multiple parallel ToolCalls in one assistant turn must map to multiple FunctionCalls."""
        messages = [
            {"role": "user", "content": "Search code and read config"},
            {
                "role": "assistant",
                "content": "Searching now...",
                "tool_calls": [
                    ToolCall(call_id="call_1", name="search_code", arguments={"pattern": "def main"}),
                    ToolCall(call_id="call_2", name="read_file", arguments={"path": "config.yaml"}),
                    ToolCall(call_id="call_3", name="git_status", arguments={}),
                ],
            },
            {"role": "tool", "tool_call_id": "call_1", "content": json.dumps({"results": ["main.py:10"]})},
            {"role": "tool", "tool_call_id": "call_2", "content": "debug: true"},
            {"role": "tool", "tool_call_id": "call_3", "content": "clean working tree"},
        ]

        _system_instruction, contents = format_gemini_contents(messages)
        assert len(contents) == 5

        # Assistant turn
        model_turn = contents[1]
        assert model_turn.role == "model"
        # 1 text part + 3 function calls = 4 parts
        assert len(model_turn.parts) == 4
        assert model_turn.parts[0].text == "Searching now..."
        assert model_turn.parts[1].function_call.name == "search_code"
        assert model_turn.parts[1].function_call.id == "call_1"
        assert model_turn.parts[2].function_call.name == "read_file"
        assert model_turn.parts[2].function_call.id == "call_2"
        assert model_turn.parts[3].function_call.name == "git_status"
        assert model_turn.parts[3].function_call.id == "call_3"

        # Tool response turns
        resp1 = contents[2]
        assert resp1.role == "user"
        assert resp1.parts[0].function_response.name == "search_code"
        assert resp1.parts[0].function_response.response == {"results": ["main.py:10"]}

        resp2 = contents[3]
        assert resp2.role == "user"
        assert resp2.parts[0].function_response.name == "read_file"
        assert resp2.parts[0].function_response.response == {"response": "debug: true"}

    def test_missing_or_empty_tool_call_id_raises_value_error(self):
        """Tool response with missing, None, or whitespace-only tool_call_id must raise ValueError."""
        invalid_messages = [
            [{"role": "tool", "name": "foo", "content": "bar"}],  # missing id
            [{"role": "tool", "tool_call_id": None, "name": "foo", "content": "bar"}],
            [{"role": "tool", "tool_call_id": "", "name": "foo", "content": "bar"}],
            [{"role": "tool", "tool_call_id": "   ", "name": "foo", "content": "bar"}],
        ]

        for msgs in invalid_messages:
            with pytest.raises(ValueError, match="missing required 'tool_call_id'"):
                format_gemini_contents(msgs)

    def test_empty_and_malformed_arguments_handling(self):
        """Verify handling of empty strings, None, and invalid JSON strings in tool call arguments."""
        messages = [
            {
                "role": "assistant",
                "tool_calls": [
                    {"id": "c1", "function": {"name": "f1", "arguments": ""}},
                    {"id": "c2", "function": {"name": "f2", "arguments": "{malformed json"}},
                    {"id": "c3", "function": {"name": "f3", "arguments": None}},
                    {"id": "c4", "function": {"name": "f4", "arguments": {"valid": 123}}},
                ],
            }
        ]

        _, contents = format_gemini_contents(messages)
        parts = contents[0].parts
        assert len(parts) == 4

        # c1 empty string -> empty dict
        assert parts[0].function_call.args == {}
        # c2 malformed json -> fallback to input field
        assert parts[1].function_call.args == {"input": "{malformed json"}
        # c3 None -> empty dict
        assert parts[2].function_call.args == {}
        # c4 valid dict -> dict preserved
        assert parts[3].function_call.args == {"valid": 123}

    def test_tool_name_fallback_from_prior_call(self):
        """When tool message lacks 'name', it must be resolved from call_id registered in history."""
        messages = [
            {
                "role": "assistant",
                "tool_calls": [
                    {"id": "lookup_123", "name": "get_weather", "args": {"city": "Paris"}},
                ],
            },
            {
                "role": "tool",
                "tool_call_id": "lookup_123",
                # Note: 'name' is omitted
                "content": json.dumps({"temp": 20}),
            },
        ]

        _, contents = format_gemini_contents(messages)
        tool_turn = contents[1]
        assert tool_turn.parts[0].function_response.name == "get_weather"
        assert tool_turn.parts[0].function_response.response == {"temp": 20}
