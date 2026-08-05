from pathlib import Path

import pytest

from eva.workspace.git_ops import apply_diff_python_fallback, extract_unified_diff

GOLDEN_DIR = Path(__file__).parents[2] / "fixtures" / "golden" / "patches"


def test_golden_patch_extraction():
    fenced_raw = (GOLDEN_DIR / "sample1_fenced.txt").read_text(encoding="utf-8")
    expected_diff = (GOLDEN_DIR / "sample1_expected.diff").read_text(encoding="utf-8")

    extracted = extract_unified_diff(fenced_raw)
    assert extracted.strip() == expected_diff.strip()


def test_golden_patch_application(tmp_path):
    target_file = tmp_path / "example.py"
    target_file.write_text('def hello():\n    print("hello")\n', encoding="utf-8")

    diff_text = f'--- a/{target_file}\n+++ b/{target_file}\n@@ -1,3 +1,3 @@\n def hello():\n-    print("hello")\n+    print("hello world")\n'

    applied = apply_diff_python_fallback(diff_text)
    assert applied is True
    assert target_file.read_text(encoding="utf-8") == 'def hello():\n    print("hello world")\n'


def test_invalid_diff_raises_error():
    with pytest.raises(ValueError, match="model did not return a unified diff"):
        extract_unified_diff("Here is the updated code without a diff.")
