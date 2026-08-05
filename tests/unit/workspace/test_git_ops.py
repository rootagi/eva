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


def test_apply_unified_diff_git_apply_success(tmp_path):
    target = tmp_path / "bar.py"
    target.write_text("a\nb\nc\n", encoding="utf-8")
    diff_text = f"--- a/{target}\n+++ b/{target}\n@@ -1,3 +1,3 @@\n a\n-b\n+B\n c\n"

    apply_unified_diff(diff_text)
    assert target.read_text(encoding="utf-8") == "a\nB\nc\n"


def test_apply_unified_diff_fallback_fails(tmp_path):
    target = tmp_path / "nonexistent.py"
    diff_text = f"--- a/{target}\n+++ b/{target}\n@@ -1,1 +1,1 @@\n-old\n+new\n"

    with pytest.raises(typer.Exit):
        apply_unified_diff(diff_text)


def test_run_git_file_not_found():
    with patch("subprocess.run", side_effect=FileNotFoundError), pytest.raises(typer.Exit):
        run_git(["status"])
