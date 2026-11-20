import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from eva.cache import generate_cache_key
from eva.cli.app import app
from eva.config import AppConfig, ProviderConfig
from eva.indexing.finder import find_files_python_fallback
from eva.prompts import WORK_SYSTEM_PROMPT
from eva.providers import ToolCall, dispatch, resolve_effective_model
from eva.providers.gemini_provider import format_gemini_contents
from eva.workspace.git_ops import apply_unified_diff

try:
    import eva_fastwalk

    HAS_RUST = True
except ImportError:
    HAS_RUST = False


# ==============================================================================
# WI-01: Cache Key Behavior Across Providers (gemini, groq, openrouter)
# ==============================================================================


def test_wi01_model_resolution_and_cache_key_divergence():
    """Verify cache keys diverge across providers and across models for the same provider."""
    config = AppConfig()

    # 1. Gemini
    gemini_default_model = resolve_effective_model("gemini", config)
    assert gemini_default_model == "gemini-3-flash"
    key_gemini_default = generate_cache_key(
        f"gemini:{gemini_default_model}", "sys_p", "user_p", "context_str", namespace="v2"
    )
    assert key_gemini_default.startswith("v2:")

    # Gemini with custom model
    cfg_gemini_custom = AppConfig(providers={"gemini": ProviderConfig(model="gemini-2.5-pro")})
    gemini_custom_model = resolve_effective_model("gemini", cfg_gemini_custom)
    assert gemini_custom_model == "gemini-2.5-pro"
    key_gemini_custom = generate_cache_key(
        f"gemini:{gemini_custom_model}", "sys_p", "user_p", "context_str", namespace="v2"
    )
    assert key_gemini_default != key_gemini_custom

    # 2. Groq
    groq_default_model = resolve_effective_model("groq", config)
    assert groq_default_model == "llama-3.1-8b-instant"
    key_groq_default = generate_cache_key(
        f"groq:{groq_default_model}", "sys_p", "user_p", "context_str", namespace="v2"
    )
    assert key_groq_default.startswith("v2:")
    assert key_gemini_default != key_groq_default

    cfg_groq_custom = AppConfig(providers={"groq": ProviderConfig(model="llama-3.3-70b-versatile")})
    groq_custom_model = resolve_effective_model("groq", cfg_groq_custom)
    assert groq_custom_model == "llama-3.3-70b-versatile"
    key_groq_custom = generate_cache_key(f"groq:{groq_custom_model}", "sys_p", "user_p", "context_str", namespace="v2")
    assert key_groq_default != key_groq_custom

    # 3. OpenRouter
    openrouter_default_model = resolve_effective_model("openrouter", config)
    # openrouter defaults to openrouter/free or resolves to first free model/openrouter/auto
    assert openrouter_default_model in ("openrouter/free", "openrouter/auto") or "/" in openrouter_default_model
    key_openrouter_default = generate_cache_key(
        f"openrouter:{openrouter_default_model}", "sys_p", "user_p", "context_str", namespace="v2"
    )
    assert key_openrouter_default.startswith("v2:")
    assert key_openrouter_default != key_gemini_default
    assert key_openrouter_default != key_groq_default

    cfg_openrouter_custom = AppConfig(providers={"openrouter": ProviderConfig(model="anthropic/claude-3-haiku")})
    openrouter_custom_model = resolve_effective_model("openrouter", cfg_openrouter_custom)
    assert openrouter_custom_model == "anthropic/claude-3-haiku"
    key_openrouter_custom = generate_cache_key(
        f"openrouter:{openrouter_custom_model}", "sys_p", "user_p", "context_str", namespace="v2"
    )
    assert key_openrouter_default != key_openrouter_custom


def test_wi01_dispatch_caching_across_providers(tmp_path, monkeypatch):
    """Verify dispatch caches per provider:model identity and prevents cross-provider poison."""
    monkeypatch.setattr("eva.cache.cache.get_cache_dir", lambda: tmp_path / "cache")
    config = AppConfig()

    call_counts = {"gemini": 0, "groq": 0}

    def mock_call_provider(provider, sys_p, user_p, ctx, cfg):
        call_counts[provider.name] = call_counts.get(provider.name, 0) + 1
        yield f"Response from {provider.name}"

    monkeypatch.setattr("eva.providers.call_provider", mock_call_provider)

    # 1. Call gemini
    out1 = list(dispatch("sys", "user", "ctx", config, pinned_provider="gemini", use_cache=True))
    assert "".join(out1) == "Response from gemini"
    assert call_counts["gemini"] == 1

    # 2. Call gemini again -> Cache hit
    out2 = list(dispatch("sys", "user", "ctx", config, pinned_provider="gemini", use_cache=True))
    assert "".join(out2) == "Response from gemini"
    assert call_counts["gemini"] == 1  # Unchanged!

    # 3. Call groq with EXACT SAME prompt -> Cache MISS (different provider)
    out3 = list(dispatch("sys", "user", "ctx", config, pinned_provider="groq", use_cache=True))
    assert "".join(out3) == "Response from groq"
    assert call_counts["groq"] == 1

    # 4. Call groq again -> Cache hit for groq
    out4 = list(dispatch("sys", "user", "ctx", config, pinned_provider="groq", use_cache=True))
    assert "".join(out4) == "Response from groq"
    assert call_counts["groq"] == 1


def test_wi01_cache_key_adversarial_inputs():
    """Verify cache keys with unicode, emoji, empty prompts, and large context."""
    # Unicode and emoji
    k_unicode = generate_cache_key("m", "시스템", "用户提示 🚀", "контекст")
    assert k_unicode.startswith("v2:")

    # Empty vs Non-empty context
    k_empty_ctx = generate_cache_key("m", "sys", "usr", "")
    k_none_like_ctx = generate_cache_key("m", "sys", "usr", "")
    assert k_empty_ctx == k_none_like_ctx

    k_with_ctx = generate_cache_key("m", "sys", "usr", "some context")
    assert k_empty_ctx != k_with_ctx

    # Large context (200KB)
    large_context = "x" * 200_000
    k_large = generate_cache_key("m", "sys", "usr", large_context)
    assert k_large.startswith("v2:")


# ==============================================================================
# WI-02: WORK_SYSTEM_PROMPT & Sudo Escalation Gating
# ==============================================================================


def test_wi02_work_system_prompt_adherence():
    """Verify WORK_SYSTEM_PROMPT does not contain any mention of sudo."""
    assert "sudo" not in WORK_SYSTEM_PROMPT.lower()

    # Verify golden file matches
    golden_path = Path("tests/fixtures/golden/prompts/work_system_prompt.txt")
    if golden_path.exists():
        golden_content = golden_path.read_text(encoding="utf-8").strip()
        assert "sudo" not in golden_content.lower()
        assert golden_content == WORK_SYSTEM_PROMPT.strip()


def test_wi02_work_cli_exits_nonzero_without_sudo_prompt():
    """Empirically test that when a command fails (e.g. false), CLI exits non-zero without asking to retry with sudo."""
    runner = CliRunner()

    with (
        patch("eva.cli.commands.work._resolve_app_attr") as mock_resolve,
        patch("typer.confirm") as mock_confirm,
    ):
        mock_config = MagicMock()
        mock_config.general.allowed_command_prefixes = []
        mock_config.general.sandbox_risky_commands = False

        def resolve_side_effect(name, default):
            if name == "load_config":
                return lambda: mock_config
            if name == "dispatch":
                return lambda *args, **kwargs: iter(["false"])
            if name == "append_command_audit":
                return MagicMock()
            return default

        mock_resolve.side_effect = resolve_side_effect

        # Run command with --yes and --no-project-context
        result = runner.invoke(app, ["work", "fail-intentionally", "-y", "--no-project-context"])

        # Must exit non-zero (returncode 1 from 'false')
        assert result.exit_code != 0
        # Must NOT prompt for confirmation
        mock_confirm.assert_not_called()
        assert "Retry with sudo?" not in result.output
        assert "sudo" not in result.output.lower()


def test_wi02_work_cli_with_allow_sudo_enforces_allowlist():
    """Empirically test that even with --allow-sudo, disallowed command prefixes (like sudo cat) are blocked."""
    runner = CliRunner()

    with (
        patch("eva.cli.commands.work._resolve_app_attr") as mock_resolve,
        patch("subprocess.run") as mock_run,
    ):
        mock_config = MagicMock()
        mock_config.general.allowed_command_prefixes = ["cat"]  # 'cat' is allowed initially, but 'sudo cat' is NOT
        mock_config.general.sandbox_risky_commands = False

        def resolve_side_effect(name, default):
            if name == "load_config":
                return lambda: mock_config
            if name == "dispatch":
                return lambda *args, **kwargs: iter(["cat /etc/shadow"])
            if name == "append_command_audit":
                return MagicMock()
            return default

        mock_resolve.side_effect = resolve_side_effect

        # Initial run of cat /etc/shadow fails with returncode 1
        proc_fail = MagicMock(returncode=1, stdout="", stderr="Permission denied")
        mock_run.return_value = proc_fail

        result = runner.invoke(app, ["work", "read-shadow", "-y", "--no-project-context", "--allow-sudo"])

        assert result.exit_code != 0
        # Refusal of escalated command must be printed
        assert "Refusing to execute escalated command" in result.output


# ==============================================================================
# WI-03: Parity Comparison Between fast_find_files (Rust) & Python Fallback
# ==============================================================================


@pytest.mark.skipif(not HAS_RUST, reason="Rust extension eva_fastwalk not installed")
def test_wi03_rust_python_parity_across_workspace_directories():
    """Run parity comparison between fast_find_files (Rust) and Python fallback across workspace subdirs."""
    dirs_to_test = [
        Path("src/eva/cache").resolve(),
        Path("src/eva/cli").resolve(),
        Path("src/eva/indexing").resolve(),
        Path("src/eva/workspace").resolve(),
        Path("tests/unit/cache").resolve(),
        Path("src").resolve(),
        Path("tests").resolve(),
    ]

    for d in dirs_to_test:
        if not d.exists():
            continue

        rust_files = set(eva_fastwalk.fast_find_files(str(d), "*"))
        python_files = {str(p) for p in find_files_python_fallback(d, "*")}

        assert rust_files == python_files, f"Parity mismatch in directory: {d}. Diff: {rust_files ^ python_files}"


@pytest.mark.skipif(not HAS_RUST, reason="Rust extension eva_fastwalk not installed")
def test_wi03_rust_python_parity_with_patterns_and_ignores(tmp_path):
    """Stress-test pattern matching, extra_ignored, and unignore parity."""
    # Create test tree
    (tmp_path / "a.py").write_text("print('a')")
    (tmp_path / "b.txt").write_text("text")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "c.py").write_text("print('c')")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "lib.js").write_text("console.log('node')")
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "HEAD").write_text("ref")
    (tmp_path / "custom_ignored").mkdir()
    (tmp_path / "custom_ignored" / "d.py").write_text("print('d')")

    # 1. Default ignored dirs (node_modules, .git pruned)
    rust_all = {Path(p).name for p in eva_fastwalk.fast_find_files(str(tmp_path), "*")}
    py_all = {p.name for p in find_files_python_fallback(tmp_path, "*")}
    assert rust_all == py_all
    assert "lib.js" not in rust_all
    assert "HEAD" not in rust_all
    assert "d.py" in rust_all

    # 2. Pattern filter (*.py)
    rust_py = {Path(p).name for p in eva_fastwalk.fast_find_files(str(tmp_path), "*.py")}
    py_py = {p.name for p in find_files_python_fallback(tmp_path, "*.py")}
    assert rust_py == py_py
    assert "b.txt" not in rust_py

    # 3. extra_ignored
    rust_extra = {
        Path(p).name for p in eva_fastwalk.fast_find_files(str(tmp_path), "*", extra_ignored=["custom_ignored"])
    }
    py_extra = {p.name for p in find_files_python_fallback(tmp_path, "*", extra_ignored=["custom_ignored"])}
    assert rust_extra == py_extra
    assert "d.py" not in rust_extra

    # 4. unignore
    rust_unign = {Path(p).name for p in eva_fastwalk.fast_find_files(str(tmp_path), "*", unignore=["node_modules"])}
    py_unign = {p.name for p in find_files_python_fallback(tmp_path, "*", unignore=["node_modules"])}
    assert rust_unign == py_unign
    assert "lib.js" in rust_unign


# ==============================================================================
# WI-04: Atomic Rollback on Read-Only Files, Write Failures, or Schema Errors
# ==============================================================================


def test_wi04_atomic_rollback_on_write_failure(tmp_path):
    """Test atomic rollback when write to the second file fails mid-patch (e.g. disk/permission failure)."""
    file1 = tmp_path / "module1.py"
    file2 = tmp_path / "module2.py"
    file1.write_text("def fn1():\n    return 1\n")
    file2.write_text("def fn2():\n    return 2\n")

    diff = """--- a/module1.py
+++ b/module1.py
@@ -1,2 +1,2 @@
 def fn1():
-    return 1
+    return 100
--- a/module2.py
+++ b/module2.py
@@ -1,2 +1,2 @@
 def fn2():
-    return 2
+    return 200
"""

    real_replace = os.replace

    def faulty_replace(src, dst):
        # Simulate failure when applying replacement to module2.py
        if "module2" in str(dst):
            raise OSError("Simulated I/O write failure / read-only device")
        real_replace(src, dst)

    with patch("os.replace", side_effect=faulty_replace):
        success = apply_unified_diff(diff, root_dir=tmp_path)

    # Must return False indicating failure
    assert success is False

    # file1 MUST be rolled back to its original content
    assert file1.read_text() == "def fn1():\n    return 1\n"
    # file2 MUST be untouched
    assert file2.read_text() == "def fn2():\n    return 2\n"


@pytest.mark.skipif(sys.platform == "win32", reason="Directory chmod read-only is not supported on Windows")
def test_wi04_atomic_rollback_on_readonly_target_directory(tmp_path):
    """Test atomic rollback when the directory of the second file is read-only (PermissionError)."""
    sub_ro = tmp_path / "readonly_sub"
    sub_ro.mkdir()
    file1 = tmp_path / "valid1.py"
    file2 = sub_ro / "valid2.py"
    file1.write_text("val1 = 1\n")
    file2.write_text("val2 = 2\n")

    diff = """--- a/valid1.py
+++ b/valid1.py
@@ -1,1 +1,1 @@
-val1 = 1
+val1 = 10
--- a/readonly_sub/valid2.py
+++ b/readonly_sub/valid2.py
@@ -1,1 +1,1 @@
-val2 = 2
+val2 = 20
"""
    # Make directory read-only
    sub_ro.chmod(0o555)
    try:
        success = apply_unified_diff(diff, root_dir=tmp_path)
        assert success is False
        # file1 must be restored to original
        assert file1.read_text() == "val1 = 1\n"
    finally:
        # Restore permissions for tmp cleanup
        sub_ro.chmod(0o777)


def test_wi04_atomic_rollback_on_schema_or_hunk_error(tmp_path):
    """Test that if second file has an unmatchable hunk (schema/patch error), file 1 is never modified."""
    file1 = tmp_path / "f1.py"
    file2 = tmp_path / "f2.py"
    file1.write_text("alpha\nbeta\n")
    file2.write_text("gamma\ndelta\n")

    # Second hunk attempts to replace non-existent content 'non_existent_text'
    diff = """--- a/f1.py
+++ b/f1.py
@@ -1,2 +1,2 @@
 alpha
-beta
+beta_modified
--- a/f2.py
+++ b/f2.py
@@ -1,2 +1,2 @@
-non_existent_text
+replaced
 delta
"""

    success = apply_unified_diff(diff, root_dir=tmp_path)
    assert success is False

    # file 1 was never touched
    assert file1.read_text() == "alpha\nbeta\n"
    assert file2.read_text() == "gamma\ndelta\n"


def test_wi04_atomic_rollback_on_sensitive_target_in_multifile(tmp_path):
    """Test that if second file in a multi-file diff is sensitive (.env), file 1 is never modified."""
    file1 = tmp_path / "f1.py"
    file2 = tmp_path / ".env"
    file1.write_text("app_code = True\n")
    file2.write_text("SECRET=123\n")

    diff = """--- a/f1.py
+++ b/f1.py
@@ -1,1 +1,1 @@
-app_code = True
+app_code = False
--- a/.env
+++ b/.env
@@ -1,1 +1,1 @@
-SECRET=123
+SECRET=hacked
"""

    success = apply_unified_diff(diff, root_dir=tmp_path)
    assert success is False

    # Neither file should have been modified
    assert file1.read_text() == "app_code = True\n"
    assert file2.read_text() == "SECRET=123\n"


# ==============================================================================
# WI-05: Gemini Multi-Turn Structured Tool Calls
# ==============================================================================


def test_wi05_gemini_multiturn_tool_calls_complex_conversation():
    """Test format_gemini_contents with complex ToolCall instances and dictionaries across 4+ turns."""

    messages = [
        # Turn 0: System prompt
        {"role": "system", "content": "You are a specialized code analysis agent."},
        # Turn 1: User prompt
        {"role": "user", "content": "Analyze repository and check dependencies."},
        # Turn 2: Assistant with mixed text and 2 ToolCalls (one dict, one ToolCall object)
        {
            "role": "assistant",
            "content": "I will inspect files and query dependencies.",
            "tool_calls": [
                {
                    "id": "call_find_1",
                    "type": "function",
                    "function": {"name": "find_files", "arguments": '{"pattern": "*.py"}'},
                },
                ToolCall(name="check_deps", arguments={"manifest": "pyproject.toml"}, call_id="call_deps_2"),
            ],
        },
        # Turn 3: Tool responses (one string JSON, one dict)
        {
            "role": "tool",
            "tool_call_id": "call_find_1",
            "name": "find_files",
            "content": '["main.py", "utils.py"]',
        },
        {
            "role": "tool",
            "tool_call_id": "call_deps_2",
            "content": {"dependencies": ["rich", "typer"], "valid": True},
        },
        # Turn 4: Assistant next step with ToolCall
        {
            "role": "assistant",
            "content": "Dependencies valid. Running security audit.",
            "tool_calls": [ToolCall(name="sec_audit", arguments={"level": "high"}, call_id="call_sec_3")],
        },
        # Turn 5: Tool response
        {
            "role": "tool",
            "tool_call_id": "call_sec_3",
            "content": {"vulnerabilities_found": 0, "status": "clean"},
        },
        # Turn 6: Assistant final summary
        {"role": "assistant", "content": "Audit complete. Zero vulnerabilities found."},
    ]

    sys_instruction, contents = format_gemini_contents(messages)

    # 1. Verify system instruction extracted
    assert sys_instruction == "You are a specialized code analysis agent."

    # 2. Verify turn structure
    # Expected contents:
    # 0: user (Turn 1)
    # 1: model (Turn 2, 3 parts: text, fc1, fc2)
    # 2: user (Turn 3, tool response 1)
    # 3: user (Turn 3, tool response 2)
    # 4: model (Turn 4, 2 parts: text, fc3)
    # 5: user (Turn 5, tool response 3)
    # 6: model (Turn 6, text part)
    assert len(contents) == 7

    # Turn 1: User
    assert contents[0].role == "user"
    assert contents[0].parts[0].text == "Analyze repository and check dependencies."

    # Turn 2: Model (mixed text + 2 tool calls)
    assert contents[1].role == "model"
    assert len(contents[1].parts) == 3
    assert contents[1].parts[0].text == "I will inspect files and query dependencies."
    fc1 = contents[1].parts[1].function_call
    assert fc1.name == "find_files"
    assert fc1.args == {"pattern": "*.py"}
    assert fc1.id == "call_find_1"

    fc2 = contents[1].parts[2].function_call
    assert fc2.name == "check_deps"
    assert fc2.args == {"manifest": "pyproject.toml"}
    assert fc2.id == "call_deps_2"

    # Turn 3: Tool Responses (role user, FunctionResponse)
    assert contents[2].role == "user"
    fr1 = contents[2].parts[0].function_response
    assert fr1.name == "find_files"
    assert fr1.id == "call_find_1"
    assert fr1.response == {"response": '["main.py", "utils.py"]'}

    assert contents[3].role == "user"
    fr2 = contents[3].parts[0].function_response
    assert fr2.name == "check_deps"
    assert fr2.id == "call_deps_2"
    assert fr2.response == {"dependencies": ["rich", "typer"], "valid": True}

    # Turn 4: Model
    assert contents[4].role == "model"
    assert contents[4].parts[0].text == "Dependencies valid. Running security audit."
    fc3 = contents[4].parts[1].function_call
    assert fc3.name == "sec_audit"
    assert fc3.args == {"level": "high"}
    assert fc3.id == "call_sec_3"

    # Turn 5: Tool response
    assert contents[5].role == "user"
    fr3 = contents[5].parts[0].function_response
    assert fr3.name == "sec_audit"
    assert fr3.id == "call_sec_3"
    assert fr3.response == {"vulnerabilities_found": 0, "status": "clean"}

    # Turn 6: Model final
    assert contents[6].role == "model"
    assert contents[6].parts[0].text == "Audit complete. Zero vulnerabilities found."


def test_wi05_gemini_tool_call_validation_and_edge_cases():
    """Verify error on missing/empty tool_call_id and resilient arg parsing."""
    # 1. Missing tool_call_id in role='tool' must raise ValueError
    with pytest.raises(ValueError, match="missing required 'tool_call_id'"):
        format_gemini_contents([{"role": "tool", "content": "result without id"}])

    # 2. Empty tool_call_id in role='tool' must raise ValueError
    with pytest.raises(ValueError, match="missing required 'tool_call_id'"):
        format_gemini_contents([{"role": "tool", "tool_call_id": "   ", "content": "result"}])

    # 3. Malformed JSON arguments in assistant tool call falls back to {'input': raw_args}
    _, contents = format_gemini_contents(
        [
            {
                "role": "assistant",
                "tool_calls": [{"id": "c1", "function": {"name": "run", "arguments": "not-valid-json {"}}],
            }
        ]
    )
    fc = contents[0].parts[0].function_call
    assert fc.name == "run"
    assert fc.args == {"input": "not-valid-json {"}


def test_wi01_delimiter_collision_resistance():
    """Verify delimiter collision resistance across model, system_prompt, and user_prompt."""
    # If concatenated simply without structured serialization, 'model'='foo', 'sys'='bar' might collide with 'model'='foob', 'sys'='ar'
    k1 = generate_cache_key("foo", "bar", "user", "ctx")
    k2 = generate_cache_key("foob", "ar", "user", "ctx")
    assert k1 != k2

    k3 = generate_cache_key("provider:model", "", "user", "")
    k4 = generate_cache_key("provider", ":model", "user", "")
    assert k3 != k4


def test_wi03_real_workspace_gitignore_parity(tmp_path):
    """Verify Rust fastwalk and Python fallback respect gitignore rules identically within a git repo."""
    (tmp_path / ".git").mkdir()
    (tmp_path / ".gitignore").write_text("*.log\nignored_subdir/\n!important.log\n")
    (tmp_path / "app.py").write_text("print('app')")
    (tmp_path / "debug.log").write_text("debug")
    (tmp_path / "important.log").write_text("important")
    (tmp_path / "ignored_subdir").mkdir()
    (tmp_path / "ignored_subdir" / "data.txt").write_text("data")

    # In both walkers within a git repo, app.py and important.log should be included; debug.log and data.txt ignored
    if HAS_RUST:
        rust_files = {Path(p).name for p in eva_fastwalk.fast_find_files(str(tmp_path), "*")}
        py_files = {p.name for p in find_files_python_fallback(tmp_path, "*")}
        assert "app.py" in rust_files
        assert "important.log" in rust_files
        assert "debug.log" not in rust_files
        assert "data.txt" not in rust_files
        # Check exact parity
        assert rust_files == py_files


def test_wi04_three_file_rollback(tmp_path):
    """Verify that in a 3-file diff, failure on the 3rd file rolls back files 1 and 2."""
    f1 = tmp_path / "f1.py"
    f2 = tmp_path / "f2.py"
    f3 = tmp_path / "f3.py"
    f1.write_text("f1_orig\n")
    f2.write_text("f2_orig\n")
    f3.write_text("f3_orig\n")

    diff = """--- a/f1.py
+++ b/f1.py
@@ -1,1 +1,1 @@
-f1_orig
+f1_new
--- a/f2.py
+++ b/f2.py
@@ -1,1 +1,1 @@
-f2_orig
+f2_new
--- a/f3.py
+++ b/f3.py
@@ -1,1 +1,1 @@
-f3_orig
+f3_new
"""

    real_replace = os.replace

    def replace_fail_on_f3(src, dst):
        if "f3" in str(dst):
            raise OSError("I/O error during f3 write")
        real_replace(src, dst)

    with patch("os.replace", side_effect=replace_fail_on_f3):
        success = apply_unified_diff(diff, root_dir=tmp_path)

    assert success is False
    # All three files must have original contents
    assert f1.read_text() == "f1_orig\n"
    assert f2.read_text() == "f2_orig\n"
    assert f3.read_text() == "f3_orig\n"


def test_wi04_target_file_does_not_exist(tmp_path):
    """Verify that a diff referencing a non-existent file is rejected before disk writes."""
    f1 = tmp_path / "exists.py"
    f1.write_text("orig_content\n")

    diff = """--- a/exists.py
+++ b/exists.py
@@ -1,1 +1,1 @@
-orig_content
+new_content
--- a/does_not_exist.py
+++ b/does_not_exist.py
@@ -1,1 +1,1 @@
-ghost
+phantom
"""

    success = apply_unified_diff(diff, root_dir=tmp_path)
    assert success is False
    # exists.py must be untouched
    assert f1.read_text() == "orig_content\n"


def test_wi05_nested_args_and_parallel_calls():
    """Verify tool calls with deeply nested JSON arguments and duplicate tool names with unique IDs."""
    messages = [
        {"role": "user", "content": "Fetch metrics and configuration."},
        {
            "role": "assistant",
            "tool_calls": [
                {
                    "id": "query_1",
                    "function": {
                        "name": "query_db",
                        "arguments": {"filter": {"tags": ["prod", "us-east"], "metrics": {"cpu": True}}},
                    },
                },
                {
                    "id": "query_2",
                    "function": {
                        "name": "query_db",
                        "arguments": {"filter": {"tags": ["staging", "eu-west"], "metrics": {"mem": True}}},
                    },
                },
            ],
        },
        {"role": "tool", "tool_call_id": "query_1", "content": {"cpu_util": 0.45}},
        {"role": "tool", "tool_call_id": "query_2", "content": {"mem_free_mb": 1024}},
    ]

    _, contents = format_gemini_contents(messages)
    assert len(contents) == 4

    # Assistant turn has 2 FunctionCall parts, both with name 'query_db' but different IDs and args
    m_content = contents[1]
    assert m_content.role == "model"
    assert len(m_content.parts) == 2
    fc1 = m_content.parts[0].function_call
    fc2 = m_content.parts[1].function_call
    assert fc1.name == "query_db" and fc1.id == "query_1"
    assert fc1.args["filter"]["tags"] == ["prod", "us-east"]
    assert fc2.name == "query_db" and fc2.id == "query_2"
    assert fc2.args["filter"]["tags"] == ["staging", "eu-west"]

    # Tool responses mapped correctly to user FunctionResponses
    fr1 = contents[2].parts[0].function_response
    assert fr1.name == "query_db" and fr1.id == "query_1"
    assert fr1.response == {"cpu_util": 0.45}

    fr2 = contents[3].parts[0].function_response
    assert fr2.name == "query_db" and fr2.id == "query_2"
    assert fr2.response == {"mem_free_mb": 1024}


# ==============================================================================
# Adversarial Challenge Tests: Uncovered Flaws & Vulnerability Reproduction
# ==============================================================================


def test_challenge_symlink_internal_bypass(tmp_path):
    """VULNERABILITY REPRODUCTION: An in-repository symlink bypasses symlink checks because .resolve() is called before checking is_symlink."""
    real_file = tmp_path / "real.py"
    real_file.write_text("original_real\n")

    sym_file = tmp_path / "sym.py"
    sym_file.symlink_to(real_file)

    diff = """--- a/sym.py
+++ b/sym.py
@@ -1,1 +1,1 @@
-original_real
+poisoned_real
"""
    # Contract: diff targeting a symlink MUST be rejected (return False)
    res = apply_unified_diff(diff, root_dir=tmp_path)
    # If vulnerable, res is True and real_file was overwritten!
    assert res is False, "VULNERABILITY CONFIRMED: In-repo symlink was resolved and allowed to modify real file!"


@pytest.mark.xfail(
    reason="WI-04 Vulnerability: .git/ directory files (.git/config, .git/hooks) are not in DENYLIST_PATTERNS and thus permitted by apply_unified_diff",
    strict=False,
)
def test_challenge_git_config_modification(tmp_path):
    """VULNERABILITY REPRODUCTION: .git/config and .git/hooks are not blocked by sensitive file denylist in apply_unified_diff."""
    git_dir = tmp_path / ".git"
    git_dir.mkdir()
    config_file = git_dir / "config"
    config_file.write_text("[core]\n\trepositoryformatversion = 0\n")

    diff = """--- a/.git/config
+++ b/.git/config
@@ -1,2 +1,2 @@
 [core]
-\trepositoryformatversion = 0
+\trepositoryformatversion = 999
"""
    # Contract: Sensitive files like .git/config must be blocked
    res = apply_unified_diff(diff, root_dir=tmp_path)
    assert res is False, "VULNERABILITY CONFIRMED: Modification to .git/config was permitted!"


@pytest.mark.xfail(
    reason="WI-05 Defect: Empty string tool arguments produce {'input': ''} instead of empty dict {}",
    strict=False,
)
def test_challenge_gemini_empty_string_arguments():
    """DEFECT REPRODUCTION: ToolCall with arguments='' produces args={'input': ''} instead of empty dict {}."""
    messages = [
        {
            "role": "assistant",
            "tool_calls": [{"id": "call_empty", "function": {"name": "test_fn", "arguments": ""}}],
        }
    ]
    _, contents = format_gemini_contents(messages)
    fc = contents[0].parts[0].function_call
    assert fc.args == {}, f"DEFECT CONFIRMED: arguments='' parsed as {fc.args} instead of {{}}"
