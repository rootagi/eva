from unittest.mock import patch

import pytest
import typer

from eva.workspace.git_ops import (
    _fix_diff_headers,
    apply_unified_diff,
    run_git,
)


def test_fix_diff_headers_bare_at_at(tmp_path):
    f = tmp_path / "foo.py"
    f.write_text("line1\nline2\nline3\n", encoding="utf-8")

    raw_diff = f"--- a/{f}\n+++ b/{f}\n@@\n-line2\n+line2_modified\n"
    fixed = _fix_diff_headers(raw_diff)
    assert "@@ -2,1 +2,1 @@" in fixed


def test_apply_unified_diff_success(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    target = tmp_path / "bar.py"
    target.write_text("a\nb\nc\n", encoding="utf-8")
    diff_text = "--- a/bar.py\n+++ b/bar.py\n@@ -1,3 +1,3 @@\n a\n-b\n+B\n c\n"

    result = apply_unified_diff(diff_text)
    assert result is True
    assert target.read_text(encoding="utf-8") == "a\nB\nc\n"


def test_apply_unified_diff_fallback_fails(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    diff_text = "--- a/nonexistent.py\n+++ b/nonexistent.py\n@@ -1,1 +1,1 @@\n-old\n+new\n"

    assert apply_unified_diff(diff_text) is False


def test_apply_unified_diff_rejects_path_traversal(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    target = tmp_path / "app.py"
    target.write_text("orig\n", encoding="utf-8")

    diff_text = "--- a/../escaped.txt\n+++ b/../escaped.txt\n@@ -1,1 +1,1 @@\n-old\n+new\n"
    assert apply_unified_diff(diff_text) is False
    assert not (tmp_path.parent / "escaped.txt").exists()


def test_apply_unified_diff_rejects_absolute_path(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    diff_text = "--- /etc/shadow\n+++ /etc/shadow\n@@ -1,1 +1,1 @@\n-root:*\n+root:hacked\n"
    assert apply_unified_diff(diff_text) is False


def test_apply_unified_diff_rejects_sensitive_file(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    env_file = tmp_path / ".env"
    env_file.write_text("SECRET=1\n", encoding="utf-8")

    diff_text = "--- a/.env\n+++ b/.env\n@@ -1,1 +1,1 @@\n-SECRET=1\n+SECRET=2\n"
    assert apply_unified_diff(diff_text) is False
    assert env_file.read_text(encoding="utf-8") == "SECRET=1\n"


def test_apply_unified_diff_force_include_sensitive_file(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    env_file = tmp_path / ".env"
    env_file.write_text("SECRET=1\n", encoding="utf-8")

    diff_text = "--- a/.env\n+++ b/.env\n@@ -1,1 +1,1 @@\n-SECRET=1\n+SECRET=2\n"
    assert apply_unified_diff(diff_text, force_include={".env"}) is True
    assert env_file.read_text(encoding="utf-8") == "SECRET=2\n"


def test_apply_unified_diff_rejects_unauthorized_scope(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    f1 = tmp_path / "allowed.py"
    f2 = tmp_path / "forbidden.py"
    f1.write_text("v=1\n", encoding="utf-8")
    f2.write_text("v=1\n", encoding="utf-8")

    diff_text = "--- a/forbidden.py\n+++ b/forbidden.py\n@@ -1,1 +1,1 @@\n-v=1\n+v=2\n"
    assert apply_unified_diff(diff_text, authorized_paths={f1}) is False
    assert f2.read_text(encoding="utf-8") == "v=1\n"


def test_apply_unified_diff_atomic_multi_file_rollback(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    f1 = tmp_path / "file1.py"
    f1.write_text("initial1\n", encoding="utf-8")

    # Multi-file diff where file 2 hunk fails to match
    diff_text = (
        "--- a/file1.py\n"
        "+++ b/file1.py\n"
        "@@ -1,1 +1,1 @@\n"
        "-initial1\n"
        "+modified1\n"
        "--- a/file2.py\n"
        "+++ b/file2.py\n"
        "@@ -1,1 +1,1 @@\n"
        "-unmatched_pattern\n"
        "+modified2\n"
    )

    f2 = tmp_path / "file2.py"
    f2.write_text("actual_content2\n", encoding="utf-8")

    assert apply_unified_diff(diff_text) is False
    # Verify file 1 was NOT modified (atomic rollback / dry-run)
    assert f1.read_text(encoding="utf-8") == "initial1\n"
    assert f2.read_text(encoding="utf-8") == "actual_content2\n"


def test_apply_unified_diff_rejects_in_repo_symlink_file(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    real_file = tmp_path / "real.py"
    real_file.write_text("val = 1\n", encoding="utf-8")
    link_file = tmp_path / "link.py"
    try:
        link_file.symlink_to(real_file)
    except OSError:
        pytest.skip("Symlink creation not supported in current environment")

    diff_text = "--- a/link.py\n+++ b/link.py\n@@ -1,1 +1,1 @@\n-val = 1\n+val = 2\n"
    assert apply_unified_diff(diff_text) is False
    assert real_file.read_text(encoding="utf-8") == "val = 1\n"


def test_apply_unified_diff_rejects_symlink_directory(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    real_dir = tmp_path / "real_dir"
    real_dir.mkdir()
    child_file = real_dir / "child.py"
    child_file.write_text("orig = 1\n", encoding="utf-8")

    link_dir = tmp_path / "link_dir"
    try:
        link_dir.symlink_to(real_dir)
    except OSError:
        pytest.skip("Symlink creation not supported in current environment")

    diff_text = "--- a/link_dir/child.py\n+++ b/link_dir/child.py\n@@ -1,1 +1,1 @@\n-orig = 1\n+orig = 2\n"
    assert apply_unified_diff(diff_text) is False
    assert child_file.read_text(encoding="utf-8") == "orig = 1\n"


def test_apply_unified_diff_rejects_nested_symlink_directory(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    real_dir = tmp_path / "real_dir"
    real_dir.mkdir()
    sub_dir = real_dir / "sub"
    sub_dir.mkdir()
    target_file = sub_dir / "nested.py"
    target_file.write_text("depth = 1\n", encoding="utf-8")

    parent_dir = tmp_path / "parent_dir"
    parent_dir.mkdir()
    link_dir = parent_dir / "sym_dir"
    try:
        link_dir.symlink_to(real_dir)
    except OSError:
        pytest.skip("Symlink creation not supported in current environment")

    diff_text = "--- a/parent_dir/sym_dir/sub/nested.py\n+++ b/parent_dir/sym_dir/sub/nested.py\n@@ -1,1 +1,1 @@\n-depth = 1\n+depth = 2\n"
    assert apply_unified_diff(diff_text) is False
    assert target_file.read_text(encoding="utf-8") == "depth = 1\n"


def test_apply_unified_diff_rejects_multi_file_with_symlink(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    real_valid = tmp_path / "valid.py"
    real_valid.write_text("valid = 1\n", encoding="utf-8")

    real_target = tmp_path / "target.py"
    real_target.write_text("target = 1\n", encoding="utf-8")
    link_file = tmp_path / "link.py"
    try:
        link_file.symlink_to(real_target)
    except OSError:
        pytest.skip("Symlink creation not supported in current environment")

    diff_text = (
        "--- a/valid.py\n"
        "+++ b/valid.py\n"
        "@@ -1,1 +1,1 @@\n"
        "-valid = 1\n"
        "+valid = 2\n"
        "--- a/link.py\n"
        "+++ b/link.py\n"
        "@@ -1,1 +1,1 @@\n"
        "-target = 1\n"
        "+target = 2\n"
    )
    assert apply_unified_diff(diff_text) is False
    assert real_valid.read_text(encoding="utf-8") == "valid = 1\n"
    assert real_target.read_text(encoding="utf-8") == "target = 1\n"


def test_run_git_file_not_found():
    with patch("subprocess.run", side_effect=FileNotFoundError), pytest.raises(typer.Exit):
        run_git(["status"])
