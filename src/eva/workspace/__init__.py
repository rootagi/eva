from eva.workspace.git_ops import (
    apply_diff_python_fallback,
    apply_unified_diff,
    extract_unified_diff,
    run_git,
)
from eva.workspace.gitignore import ALWAYS_IGNORED_DIRS, get_gitignore_spec, is_ignored
from eva.workspace.session import (
    WorkspaceSession,
    add_bookmark,
    add_history,
    add_note,
    create_workspace,
    get_active_workspace,
    get_workspace,
    list_workspaces,
    redact_secrets,
    set_active_workspace,
)

__all__ = [
    "ALWAYS_IGNORED_DIRS",
    "WorkspaceSession",
    "add_bookmark",
    "add_history",
    "add_note",
    "apply_diff_python_fallback",
    "apply_unified_diff",
    "create_workspace",
    "extract_unified_diff",
    "get_active_workspace",
    "get_gitignore_spec",
    "get_workspace",
    "is_ignored",
    "list_workspaces",
    "redact_secrets",
    "run_git",
    "set_active_workspace",
]
