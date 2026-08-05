"""Compatibility re-exports for context.gitignore."""

from eva.workspace.gitignore import ALWAYS_IGNORED_DIRS, get_gitignore_spec, is_ignored

__all__ = ["ALWAYS_IGNORED_DIRS", "get_gitignore_spec", "is_ignored"]
