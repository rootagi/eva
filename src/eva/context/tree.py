"""Compatibility re-exports for context.tree."""

from eva.indexing.tree import HAS_RUST, generate_tree

__all__ = ["HAS_RUST", "generate_tree"]
