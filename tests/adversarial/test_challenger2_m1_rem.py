"""Empirical challenger stress-test harness for Milestone 1 Remediation (Iteration 2).

Verifies:
1. Symlink rejection across broken, circular, and intermediate path symlinks.
2. Non-symlink patch application with atomic rollback on invalid hunks.
3. Invariant integrity for WI-01, WI-02, WI-03, and WI-05.
"""

import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from eva.cache.cache import generate_cache_key
from eva.cli.app import app
from eva.indexing.finder import find_files_python_fallback
from eva.prompts import WORK_SYSTEM_PROMPT
from eva.providers.gemini_provider import ToolCall, format_gemini_contents
from eva.workspace.git_ops import apply_unified_diff

try:
    import eva_fastwalk

    HAS_RUST = True
except ImportError:
    HAS_RUST = False


# ==============================================================================
# 1. Empirical Testing of Symlink Rejection in git_ops.py
# ==============================================================================


class TestEmpiricalSymlinkRejection:
    """Empirical verification of symlink rejection under adversarial conditions."""

    def test_broken_symlink_direct(self, tmp_path: Path):
        """Direct broken symlink in diff target must be rejected."""
        broken = tmp_path / "broken.py"
        try:
            broken.symlink_to(tmp_path / "does_not_exist.py")
        except OSError:
            pytest.skip("Symlink creation not supported")

        diff = "--- a/broken.py\n+++ b/broken.py\n@@ -1,1 +1,1 @@\n-old\n+new\n"
        res = apply_unified_diff(diff, root_dir=tmp_path)
        assert res is False, "Broken symlink target was not rejected"

    def test_broken_symlink_intermediate(self, tmp_path: Path):
        """Intermediate directory that is a broken symlink must be rejected."""
        broken_dir = tmp_path / "broken_dir"
        try:
            broken_dir.symlink_to(tmp_path / "nonexistent_dir")
        except OSError:
            pytest.skip("Symlink creation not supported")

        diff = "--- a/broken_dir/file.py\n+++ b/broken_dir/file.py\n@@ -1,1 +1,1 @@\n-old\n+new\n"
        res = apply_unified_diff(diff, root_dir=tmp_path)
        assert res is False, "Intermediate broken directory symlink was not rejected"

    def test_circular_symlink_self(self, tmp_path: Path):
        """Self-referencing symlink must be rejected."""
        cycle = tmp_path / "cycle.py"
        try:
            cycle.symlink_to(cycle)
        except OSError:
            pytest.skip("Symlink creation not supported")

        diff = "--- a/cycle.py\n+++ b/cycle.py\n@@ -1,1 +1,1 @@\n-old\n+new\n"
        res = apply_unified_diff(diff, root_dir=tmp_path)
        assert res is False, "Self-circular symlink was not rejected"

    def test_circular_symlink_two_node(self, tmp_path: Path):
        """Two-node circular symlink chain (a -> b, b -> a) must be rejected."""
        link_a = tmp_path / "link_a.py"
        link_b = tmp_path / "link_b.py"
        try:
            link_a.symlink_to(link_b)
            link_b.symlink_to(link_a)
        except OSError:
            pytest.skip("Symlink creation not supported")

        diff = "--- a/link_a.py\n+++ b/link_a.py\n@@ -1,1 +1,1 @@\n-old\n+new\n"
        res = apply_unified_diff(diff, root_dir=tmp_path)
        assert res is False, "Two-node circular symlink was not rejected"

    def test_circular_symlink_directory_root(self, tmp_path: Path):
        """Directory symlink pointing to repo root must be rejected and underlying file unchanged."""
        dir_cycle = tmp_path / "cycle_dir"
        real_file = tmp_path / "target.py"
        real_file.write_text("safe_content\n", encoding="utf-8")
        try:
            dir_cycle.symlink_to(tmp_path)
        except OSError:
            pytest.skip("Symlink creation not supported")

        diff = "--- a/cycle_dir/target.py\n+++ b/cycle_dir/target.py\n@@ -1,1 +1,1 @@\n-safe_content\n+pwned_content\n"
        res = apply_unified_diff(diff, root_dir=tmp_path)
        assert res is False, "Circular directory symlink was not rejected"
        assert real_file.read_text(encoding="utf-8") == "safe_content\n"

    def test_intermediate_path_symlink(self, tmp_path: Path):
        """Intermediate directory symlink (root / 'dir_symlink' / 'file.py') must be rejected."""
        real_dir = tmp_path / "real_dir"
        real_dir.mkdir()
        real_file = real_dir / "file.py"
        real_file.write_text("initial_code\n", encoding="utf-8")

        dir_sym = tmp_path / "dir_symlink"
        try:
            dir_sym.symlink_to(real_dir)
        except OSError:
            pytest.skip("Symlink creation not supported")

        diff = "--- a/dir_symlink/file.py\n+++ b/dir_symlink/file.py\n@@ -1,1 +1,1 @@\n-initial_code\n+tampered_code\n"
        res = apply_unified_diff(diff, root_dir=tmp_path)
        assert res is False, "Intermediate directory symlink was not rejected"
        assert real_file.read_text(encoding="utf-8") == "initial_code\n"

    def test_deep_nested_intermediate_symlink(self, tmp_path: Path):
        """Deep intermediate symlink component (root / 'a' / 'sym_b' / 'c' / 'file.py') must be rejected."""
        real_target_dir = tmp_path / "real_sub"
        real_target_dir.mkdir()
        nested_c = real_target_dir / "c"
        nested_c.mkdir()
        file_c = nested_c / "file.py"
        file_c.write_text("c_clean\n", encoding="utf-8")

        dir_a = tmp_path / "a"
        dir_a.mkdir()
        sym_b = dir_a / "sym_b"
        try:
            sym_b.symlink_to(real_target_dir)
        except OSError:
            pytest.skip("Symlink creation not supported")

        diff = "--- a/a/sym_b/c/file.py\n+++ b/a/sym_b/c/file.py\n@@ -1,1 +1,1 @@\n-c_clean\n+c_poisoned\n"
        res = apply_unified_diff(diff, root_dir=tmp_path)
        assert res is False, "Deep nested intermediate symlink was not rejected"
        assert file_c.read_text(encoding="utf-8") == "c_clean\n"

    def test_external_symlink_file_and_directory(self, tmp_path: Path):
        """Symlinks pointing outside repository root must be rejected."""
        ext_dir = tmp_path.parent / f"ext_workspace_{tmp_path.name}"
        ext_dir.mkdir(exist_ok=True)
        try:
            ext_file = ext_dir / "external.py"
            ext_file.write_text("ext_data\n", encoding="utf-8")

            link_file = tmp_path / "link_ext.py"
            link_dir = tmp_path / "link_dir_ext"
            link_file.symlink_to(ext_file)
            link_dir.symlink_to(ext_dir)

            diff_f = "--- a/link_ext.py\n+++ b/link_ext.py\n@@ -1,1 +1,1 @@\n-ext_data\n+ext_hacked\n"
            assert apply_unified_diff(diff_f, root_dir=tmp_path) is False
            assert ext_file.read_text(encoding="utf-8") == "ext_data\n"

            diff_d = "--- a/link_dir_ext/external.py\n+++ b/link_dir_ext/external.py\n@@ -1,1 +1,1 @@\n-ext_data\n+ext_hacked\n"
            assert apply_unified_diff(diff_d, root_dir=tmp_path) is False
            assert ext_file.read_text(encoding="utf-8") == "ext_data\n"
        finally:
            import shutil

            shutil.rmtree(ext_dir, ignore_errors=True)

    def test_symlink_in_multifile_patch_atomic_rejection(self, tmp_path: Path):
        """Multi-file patch containing a regular valid file and a symlink file must reject atomically."""
        f1 = tmp_path / "valid.py"
        f1.write_text("valid_orig\n", encoding="utf-8")

        real_target = tmp_path / "real.py"
        real_target.write_text("real_orig\n", encoding="utf-8")
        sym_f2 = tmp_path / "sym.py"
        try:
            sym_f2.symlink_to(real_target)
        except OSError:
            pytest.skip("Symlink creation not supported")

        multi_diff = (
            "--- a/valid.py\n+++ b/valid.py\n@@ -1,1 +1,1 @@\n-valid_orig\n+valid_mod\n"
            "--- a/sym.py\n+++ b/sym.py\n@@ -1,1 +1,1 @@\n-real_orig\n+real_mod\n"
        )
        res = apply_unified_diff(multi_diff, root_dir=tmp_path)
        assert res is False, "Multi-file patch with symlink was not rejected"
        assert f1.read_text(encoding="utf-8") == "valid_orig\n"
        assert real_target.read_text(encoding="utf-8") == "real_orig\n"

    def test_windows_backslash_intermediate_symlink(self, tmp_path: Path):
        """Windows backslash path target must normalize and reject symlinks."""
        real_sub = tmp_path / "win_sub"
        real_sub.mkdir()
        real_file = real_sub / "app.py"
        real_file.write_text("win_clean\n", encoding="utf-8")

        sym_sub = tmp_path / "win_sym"
        try:
            sym_sub.symlink_to(real_sub)
        except OSError:
            pytest.skip("Symlink creation not supported")

        diff = "--- a/win_sym\\app.py\n+++ b/win_sym\\app.py\n@@ -1,1 +1,1 @@\n-win_clean\n+win_tampered\n"
        res = apply_unified_diff(diff, root_dir=tmp_path)
        assert res is False, "Windows backslash symlink was not rejected"
        assert real_file.read_text(encoding="utf-8") == "win_clean\n"


# ==============================================================================
# 2. Non-Symlink Patches and Atomic Rollback on Invalid Hunks
# ==============================================================================


class TestEmpiricalPatchAndAtomicRollback:
    """Empirical verification of atomic rollback and clean patch application."""

    def test_clean_single_file_patch(self, tmp_path: Path):
        """Valid single-file patch applies cleanly and leaves no temporary artifacts."""
        f = tmp_path / "mod.py"
        f.write_text("alpha = 1\nbeta = 2\n", encoding="utf-8")

        diff = "--- a/mod.py\n+++ b/mod.py\n@@ -1,2 +1,2 @@\n alpha = 1\n-beta = 2\n+beta = 20\n"
        res = apply_unified_diff(diff, root_dir=tmp_path)
        assert res is True
        assert f.read_text(encoding="utf-8") == "alpha = 1\nbeta = 20\n"

        # Check no .tmp files left
        tmp_files = list(tmp_path.glob(".*.tmp.*"))
        assert len(tmp_files) == 0

    def test_clean_multi_file_patch(self, tmp_path: Path):
        """Valid multi-file patch applies all files correctly."""
        f1 = tmp_path / "m1.py"
        f2 = tmp_path / "m2.py"
        f1.write_text("x = 10\n", encoding="utf-8")
        f2.write_text("y = 20\n", encoding="utf-8")

        diff = (
            "--- a/m1.py\n+++ b/m1.py\n@@ -1,1 +1,1 @@\n-x = 10\n+x = 100\n"
            "--- a/m2.py\n+++ b/m2.py\n@@ -1,1 +1,1 @@\n-y = 20\n+y = 200\n"
        )
        res = apply_unified_diff(diff, root_dir=tmp_path)
        assert res is True
        assert f1.read_text(encoding="utf-8") == "x = 100\n"
        assert f2.read_text(encoding="utf-8") == "y = 200\n"

    def test_atomic_rollback_on_invalid_hunk_context(self, tmp_path: Path):
        """If file 2 has an unmatchable hunk, file 1 is never modified on disk."""
        f1 = tmp_path / "f1.py"
        f2 = tmp_path / "f2.py"
        f1.write_text("step1 = True\n", encoding="utf-8")
        f2.write_text("step2 = True\n", encoding="utf-8")

        # file 2 attempts to replace non-existent context
        diff = (
            "--- a/f1.py\n+++ b/f1.py\n@@ -1,1 +1,1 @@\n-step1 = True\n+step1 = False\n"
            "--- a/f2.py\n+++ b/f2.py\n@@ -1,1 +1,1 @@\n-nonexistent_code\n+step2 = False\n"
        )
        res = apply_unified_diff(diff, root_dir=tmp_path)
        assert res is False
        assert f1.read_text(encoding="utf-8") == "step1 = True\n"
        assert f2.read_text(encoding="utf-8") == "step2 = True\n"

    def test_atomic_rollback_on_three_files(self, tmp_path: Path):
        """3-file diff where 3rd file has invalid hunk leaves all 3 files untouched."""
        f1 = tmp_path / "f1.py"
        f2 = tmp_path / "f2.py"
        f3 = tmp_path / "f3.py"
        f1.write_text("f1 = 1\n", encoding="utf-8")
        f2.write_text("f2 = 2\n", encoding="utf-8")
        f3.write_text("f3 = 3\n", encoding="utf-8")

        diff = (
            "--- a/f1.py\n+++ b/f1.py\n@@ -1,1 +1,1 @@\n-f1 = 1\n+f1 = 11\n"
            "--- a/f2.py\n+++ b/f2.py\n@@ -1,1 +1,1 @@\n-f2 = 2\n+f2 = 22\n"
            "--- a/f3.py\n+++ b/f3.py\n@@ -1,1 +1,1 @@\n-f3 = MISMATCH\n+f3 = 33\n"
        )
        res = apply_unified_diff(diff, root_dir=tmp_path)
        assert res is False
        assert f1.read_text(encoding="utf-8") == "f1 = 1\n"
        assert f2.read_text(encoding="utf-8") == "f2 = 2\n"
        assert f3.read_text(encoding="utf-8") == "f3 = 3\n"

    def test_atomic_rollback_on_partial_hunk_failure(self, tmp_path: Path):
        """Single file with 2 hunks: 1st matches, 2nd fails -> file remains completely untouched."""
        f = tmp_path / "multi_hunk.py"
        f.write_text("def a():\n    return 1\n\ndef b():\n    return 2\n", encoding="utf-8")

        diff = (
            "--- a/multi_hunk.py\n+++ b/multi_hunk.py\n"
            "@@ -1,2 +1,2 @@\n def a():\n-    return 1\n+    return 100\n"
            "@@ -4,2 +4,2 @@\n def b():\n-    return WRONG\n+    return 200\n"
        )
        res = apply_unified_diff(diff, root_dir=tmp_path)
        assert res is False
        assert f.read_text(encoding="utf-8") == "def a():\n    return 1\n\ndef b():\n    return 2\n"

    def test_atomic_rollback_on_simulated_disk_failure(self, tmp_path: Path):
        """Simulated OS write/replace error mid-flight triggers backup restoration."""
        f1 = tmp_path / "disk1.py"
        f2 = tmp_path / "disk2.py"
        f1.write_text("init1\n", encoding="utf-8")
        f2.write_text("init2\n", encoding="utf-8")

        diff = (
            "--- a/disk1.py\n+++ b/disk1.py\n@@ -1,1 +1,1 @@\n-init1\n+new1\n"
            "--- a/disk2.py\n+++ b/disk2.py\n@@ -1,1 +1,1 @@\n-init2\n+new2\n"
        )

        real_replace = os.replace

        def faulty_replace(src, dst):
            if "disk2.py" in str(dst):
                raise OSError("Simulated I/O disk failure on disk2")
            real_replace(src, dst)

        with patch("os.replace", side_effect=faulty_replace):
            res = apply_unified_diff(diff, root_dir=tmp_path)
            assert res is False

        assert f1.read_text(encoding="utf-8") == "init1\n"
        assert f2.read_text(encoding="utf-8") == "init2\n"


# ==============================================================================
# 3. WI-01, WI-02, WI-03, WI-05 Behavioral Integrity Verification
# ==============================================================================


class TestEmpiricalWIIntegrity:
    """Verify that WI-01, WI-02, WI-03, and WI-05 remain fully intact."""

    def test_wi01_cache_key_v2_model_namespacing(self):
        """WI-01: Cache keys include v2: prefix and diverge across resolved models."""
        k1 = generate_cache_key(model="provider:model-a", system_prompt="s", user_prompt="u", context="c")
        k2 = generate_cache_key(model="provider:model-b", system_prompt="s", user_prompt="u", context="c")
        assert k1.startswith("v2:")
        assert k2.startswith("v2:")
        assert k1 != k2

    def test_wi02_work_prompt_and_sudo_gating(self):
        """WI-02: WORK_SYSTEM_PROMPT has no sudo; failing command exits without sudo prompt."""
        assert "sudo" not in WORK_SYSTEM_PROMPT.lower()

        runner = CliRunner()
        with (
            patch("eva.cli.commands.work._resolve_app_attr") as mock_resolve,
            patch("subprocess.run") as mock_run,
            patch("typer.confirm") as mock_confirm,
        ):
            mock_cfg = MagicMock()
            mock_cfg.general.allowed_command_prefixes = []
            mock_cfg.general.sandbox_risky_commands = False

            def resolve_se(name, default):
                if name == "load_config":
                    return lambda: mock_cfg
                if name == "dispatch":
                    return lambda *a, **k: iter(["false"])
                return default

            mock_resolve.side_effect = resolve_se
            mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="error")

            result = runner.invoke(app, ["work", "--yes", "test command"])
            assert result.exit_code == 1
            mock_confirm.assert_not_called()
            assert "sudo" not in result.output.lower()

    @pytest.mark.skipif(not HAS_RUST, reason="Rust eva_fastwalk not installed")
    def test_wi03_fastwalk_rust_python_traversal_parity(self, tmp_path: Path):
        """WI-03: Parity between Rust fastwalk and Python fallback."""
        (tmp_path / "a.py").write_text("a", encoding="utf-8")
        (tmp_path / "b.txt").write_text("b", encoding="utf-8")
        (tmp_path / "node_modules").mkdir()
        (tmp_path / "node_modules" / "sub.js").write_text("js", encoding="utf-8")
        (tmp_path / ".git").mkdir()
        (tmp_path / ".git" / "HEAD").write_text("head", encoding="utf-8")

        rust_files = {Path(p).name for p in eva_fastwalk.fast_find_files(str(tmp_path), "*")}
        py_files = {p.name for p in find_files_python_fallback(tmp_path, "*")}

        assert rust_files == py_files
        assert "sub.js" not in rust_files
        assert "HEAD" not in rust_files
        assert "a.py" in rust_files
        assert "b.txt" in rust_files

    def test_wi05_gemini_multiturn_tool_mapping(self):
        """WI-05: Multi-turn tool calling mapped correctly with FunctionCall and FunctionResponse."""
        messages = [
            {"role": "system", "content": "You are a test agent."},
            {"role": "user", "content": "Run tool"},
            {
                "role": "assistant",
                "tool_calls": [
                    ToolCall(call_id="call_x", name="my_tool", arguments={"arg1": "val1"}),
                ],
            },
            {
                "role": "tool",
                "tool_call_id": "call_x",
                "name": "my_tool",
                "content": {"result": "success"},
            },
        ]

        sys_inst, contents = format_gemini_contents(messages)
        assert sys_inst == "You are a test agent."
        assert len(contents) == 3

        # Model turn
        assert contents[1].role == "model"
        fc = contents[1].parts[0].function_call
        assert fc.id == "call_x"
        assert fc.name == "my_tool"
        assert fc.args == {"arg1": "val1"}

        # Tool response turn
        assert contents[2].role == "user"
        fr = contents[2].parts[0].function_response
        assert fr.id == "call_x"
        assert fr.name == "my_tool"
        assert fr.response == {"result": "success"}
