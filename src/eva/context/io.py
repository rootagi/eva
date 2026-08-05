"""Compatibility re-exports for context.io."""

from eva.indexing.io import MAX_CONTEXT_FILE_BYTES, ContextReadError, read_text_file_for_context

__all__ = ["MAX_CONTEXT_FILE_BYTES", "ContextReadError", "read_text_file_for_context"]
