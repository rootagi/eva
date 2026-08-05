"""Compatibility re-exports for eva.context."""

from eva.indexing.finder import find_files
from eva.indexing.io import ContextReadError, read_text_file_for_context
from eva.indexing.tokenizer import count_tokens, trim_context
from eva.indexing.tree import generate_tree
from eva.workspace.gitignore import ALWAYS_IGNORED_DIRS, get_gitignore_spec, is_ignored

__all__ = [
    "ALWAYS_IGNORED_DIRS",
    "ContextReadError",
    "count_tokens",
    "find_files",
    "generate_tree",
    "get_gitignore_spec",
    "is_ignored",
    "read_text_file_for_context",
    "trim_context",
]
