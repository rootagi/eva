"""Compatibility re-exports for context.finder."""

from eva.indexing.finder import HAS_RUST, find_files

__all__ = ["HAS_RUST", "find_files"]
