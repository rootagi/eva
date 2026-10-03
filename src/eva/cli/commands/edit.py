from pathlib import Path

import typer

from eva.cli.helpers import _read_context_file, _resolve_app_attr, console


def commit(
    provider: str | None = typer.Option(None, "--provider", "-p", help="Pin to a specific provider"),
):
    """Generate a conventional commit message for staged changes."""
    from eva.config import load_config as _load_config
    from eva.indexing.tokenizer import trim_context
    from eva.prompts import COMMIT_SYSTEM_PROMPT
    from eva.providers import _resolve_provider_name, get_context_budget
    from eva.providers import dispatch as _dispatch
    from eva.ui.formatter import is_ai_error, print_error
    from eva.ui.streaming import stream_response
    from eva.workspace.git_ops import run_git as _run_git

    run_git = _resolve_app_attr("run_git", _run_git)
    load_config = _resolve_app_attr("load_config", _load_config)
    dispatch = _resolve_app_attr("dispatch", _dispatch)

    diff_res = run_git(["diff", "--staged"])
    if diff_res.returncode != 0:
        print_error("Failed to run git diff.")
        raise typer.Exit(1)

    diff_text = diff_res.stdout.strip()
    if not diff_text:
        print_error("No staged changes found. Use 'git add' first.")
        raise typer.Exit(1)

    config = load_config()
    provider_name = _resolve_provider_name(config, provider)
    max_tokens = config.general.context_token_limit or get_context_budget(provider_name, config)
    trimmed_diff = trim_context(diff_text, max_tokens=max_tokens)
    stream = dispatch(COMMIT_SYSTEM_PROMPT, "Generate commit message", trimmed_diff, config, pinned_provider=provider)
    result = stream_response(stream)
    if is_ai_error(result):
        print_error(result.strip())
        raise typer.Exit(1)
    print(result.strip())


def changes(
    staged: bool = typer.Option(False, "--staged", help="Explain staged changes instead of unstaged changes"),
    provider: str | None = typer.Option(None, "--provider", "-p", help="Pin to a specific provider"),
):
    """Explain unstaged or staged git changes."""
    from eva.config import load_config as _load_config
    from eva.indexing.tokenizer import trim_context
    from eva.prompts import CHANGES_SYSTEM_PROMPT
    from eva.providers import _resolve_provider_name, get_context_budget
    from eva.providers import dispatch as _dispatch
    from eva.ui.formatter import is_ai_error, print_error, print_markdown
    from eva.ui.streaming import stream_response
    from eva.workspace.git_ops import run_git as _run_git

    run_git = _resolve_app_attr("run_git", _run_git)
    load_config = _resolve_app_attr("load_config", _load_config)
    dispatch = _resolve_app_attr("dispatch", _dispatch)

    args = ["diff", "--staged"] if staged else ["diff"]
    diff_res = run_git(args)
    if diff_res.returncode != 0:
        print_error("Failed to run git diff.")
        raise typer.Exit(1)

    diff_text = diff_res.stdout.strip()
    if not diff_text:
        print_error("No changes found.")
        raise typer.Exit(1)

    config = load_config()
    provider_name = _resolve_provider_name(config, provider)
    max_tokens = config.general.context_token_limit or get_context_budget(provider_name, config)
    trimmed_diff = trim_context(diff_text, max_tokens=max_tokens)
    stream = dispatch(
        CHANGES_SYSTEM_PROMPT,
        "Explain the changes in this git diff.",
        trimmed_diff,
        config,
        pinned_provider=provider,
    )
    result = stream_response(stream)
    if is_ai_error(result):
        print_error(result.strip())
        raise typer.Exit(1)
    print_markdown(result)


def edit(
    query: list[str] = typer.Argument(..., help="Requested code change"),
    files: list[Path] = typer.Option(..., "--file", "-f", help="File to include and allow in the generated diff"),
    provider: str | None = typer.Option(None, "--provider", "-p", help="Pin to a specific provider"),
    apply_changes: bool = typer.Option(False, "--apply", help="Apply the generated patch after review confirmation"),
):
    """Generate a reviewable unified diff for file edits."""
    from eva.config import load_config as _load_config
    from eva.prompts import EDIT_SYSTEM_PROMPT
    from eva.providers import dispatch as _dispatch
    from eva.ui.formatter import is_ai_error, print_error, print_info, print_success
    from eva.ui.streaming import stream_response
    from eva.workspace.git_ops import apply_unified_diff, extract_unified_diff

    load_config = _resolve_app_attr("load_config", _load_config)
    dispatch = _resolve_app_attr("dispatch", _dispatch)

    config = load_config()
    context = ""
    for path in files:
        context += _read_context_file(path, header=f"File: {path}")

    query_str = " ".join(query)
    stream = dispatch(EDIT_SYSTEM_PROMPT, query_str, context, config, pinned_provider=provider)
    result = stream_response(stream)
    if is_ai_error(result):
        print_error(result.strip())
        raise typer.Exit(1)

    try:
        diff_text = extract_unified_diff(result)
    except ValueError as exc:
        print_error(f"Refusing to apply non-diff model output: {exc}")
        console.print(result)
        raise typer.Exit(1) from exc

    console.print(diff_text)
    if not apply_changes and not typer.confirm("Apply this patch?"):
        print_info("Patch not applied.")
        return

    apply_unified_diff(diff_text)
    print_success("Patch applied.")
