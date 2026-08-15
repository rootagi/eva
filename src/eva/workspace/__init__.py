from eva.workspace.git_ops import (
    apply_diff_python_fallback,
    apply_unified_diff,
    extract_unified_diff,
    run_git,
)
from eva.workspace.gitignore import (
    ALWAYS_IGNORED_DIRS,
    configure_ignored_dirs,
    get_gitignore_spec,
    is_ignored,
)
from eva.workspace.project_context import PROJECT_CONTEXT_PATH, load_project_context
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
