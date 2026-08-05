"""Compatibility re-exports for git_ops."""

from eva.workspace.git_ops import (
    apply_diff_python_fallback,
    apply_unified_diff,
    extract_unified_diff,
    run_git,
)

__all__ = [
    "apply_diff_python_fallback",
    "apply_unified_diff",
    "extract_unified_diff",
    "run_git",
]
