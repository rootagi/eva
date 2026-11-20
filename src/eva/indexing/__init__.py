from typing import Any

__all__ = [
    "ContextReadError",
    "DepGraph",
    "DependencyGraph",
    "PackResult",
    "ProjectStack",
    "build_dep_graph",
    "count_tokens",
    "detect_stack",
    "extract_polyglot_imports",
    "find_files",
    "find_files_python_fallback",
    "generate_tree",
    "init_context_md",
    "normalize_repo_imports",
    "pack_repository",
    "read_text_file_for_context",
    "trim_context",
]

_LAZY_IMPORTS: dict[str, tuple[str, str]] = {
    "find_files": ("eva.indexing.finder", "find_files"),
    "find_files_python_fallback": ("eva.indexing.finder", "find_files_python_fallback"),
    "_find_files_python": ("eva.indexing.finder", "_find_files_python"),
    "ContextReadError": ("eva.indexing.io", "ContextReadError"),
    "read_text_file_for_context": ("eva.indexing.io", "read_text_file_for_context"),
    "PackResult": ("eva.indexing.packer", "PackResult"),
    "pack_repository": ("eva.indexing.packer", "pack_repository"),
    "DepGraph": ("eva.indexing.repo_index", "DepGraph"),
    "DependencyGraph": ("eva.indexing.repo_index", "DependencyGraph"),
    "ProjectStack": ("eva.indexing.repo_index", "ProjectStack"),
    "build_dep_graph": ("eva.indexing.repo_index", "build_dep_graph"),
    "detect_stack": ("eva.indexing.repo_index", "detect_stack"),
    "extract_polyglot_imports": ("eva.indexing.repo_index", "extract_polyglot_imports"),
    "normalize_repo_imports": ("eva.indexing.repo_index", "normalize_repo_imports"),
    "init_context_md": ("eva.indexing.repo_index", "init_context_md"),
    "count_tokens": ("eva.indexing.tokenizer", "count_tokens"),
    "trim_context": ("eva.indexing.tokenizer", "trim_context"),
    "generate_tree": ("eva.indexing.tree", "generate_tree"),
}


def __getattr__(name: str) -> Any:
    if name in _LAZY_IMPORTS:
        import importlib

        mod_name, attr_name = _LAZY_IMPORTS[name]
        mod = importlib.import_module(mod_name)
        return getattr(mod, attr_name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
