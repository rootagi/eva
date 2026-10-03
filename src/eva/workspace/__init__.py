from typing import Any

__all__ = [
    "ALWAYS_IGNORED_DIRS",
    "PROJECT_CONTEXT_PATH",
    "WorkspaceSession",
    "add_bookmark",
    "add_history",
    "add_note",
    "apply_diff_python_fallback",
    "apply_unified_diff",
    "configure_ignored_dirs",
    "create_workspace",
    "extract_unified_diff",
    "get_active_workspace",
    "get_gitignore_spec",
    "get_workspace",
    "is_ignored",
    "list_workspaces",
    "load_project_context",
    "redact_secrets",
    "run_git",
    "set_active_workspace",
]

_LAZY_IMPORTS: dict[str, tuple[str, str]] = {
    "apply_diff_python_fallback": ("eva.workspace.git_ops", "apply_diff_python_fallback"),
    "apply_unified_diff": ("eva.workspace.git_ops", "apply_unified_diff"),
    "extract_unified_diff": ("eva.workspace.git_ops", "extract_unified_diff"),
    "run_git": ("eva.workspace.git_ops", "run_git"),
    "ALWAYS_IGNORED_DIRS": ("eva.workspace.gitignore", "ALWAYS_IGNORED_DIRS"),
    "configure_ignored_dirs": ("eva.workspace.gitignore", "configure_ignored_dirs"),
    "get_gitignore_spec": ("eva.workspace.gitignore", "get_gitignore_spec"),
    "is_ignored": ("eva.workspace.gitignore", "is_ignored"),
    "PROJECT_CONTEXT_PATH": ("eva.workspace.project_context", "PROJECT_CONTEXT_PATH"),
    "load_project_context": ("eva.workspace.project_context", "load_project_context"),
    "WorkspaceSession": ("eva.workspace.session", "WorkspaceSession"),
    "add_bookmark": ("eva.workspace.session", "add_bookmark"),
    "add_history": ("eva.workspace.session", "add_history"),
    "add_note": ("eva.workspace.session", "add_note"),
    "create_workspace": ("eva.workspace.session", "create_workspace"),
    "get_active_workspace": ("eva.workspace.session", "get_active_workspace"),
    "get_workspace": ("eva.workspace.session", "get_workspace"),
    "list_workspaces": ("eva.workspace.session", "list_workspaces"),
    "redact_secrets": ("eva.workspace.session", "redact_secrets"),
    "set_active_workspace": ("eva.workspace.session", "set_active_workspace"),
}


def __getattr__(name: str) -> Any:
    if name in _LAZY_IMPORTS:
        import importlib

        mod_name, attr_name = _LAZY_IMPORTS[name]
        mod = importlib.import_module(mod_name)
        return getattr(mod, attr_name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
