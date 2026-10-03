import sys
from pathlib import Path

import typer

from eva.cli.helpers import _read_context_file, _resolve_app_attr, console, err_console


def ask(
    query: list[str] = typer.Argument(..., help="The prompt or question to ask Eva"),
    files: list[Path] = typer.Option(None, "--file", "-f", help="Include file content as context"),
    dirs: list[Path] = typer.Option(None, "--dir", "-d", help="Include a directory tree as context"),
    repo: Path | None = typer.Option(
        None,
        "--repo",
        help="Pack the entire repository (respecting .gitignore and sensitive-file exclusions) as context, up to the active provider's context budget",
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Show what would be packed and sent, without sending it"),
    yes: bool = typer.Option(
        False, "--yes", "-y", help="Skip the confirmation prompt before sending repo-wide context"
    ),
    provider: str | None = typer.Option(None, "--provider", "-p", help="Pin to a specific provider"),
    no_cache: bool = typer.Option(False, "--no-cache", help="Bypass the response cache"),
    output_format: str = typer.Option(
        "text", "--format", help="Output format: 'text' (default, rendered markdown) or 'json'"
    ),
    no_project_context: bool = typer.Option(
        False, "--no-project-context", help="Skip auto-loading .eva/context.md for this run"
    ),
    force_include: list[Path] = typer.Option(
        None, "--force-include", help="Force inclusion of specific denylisted files for this repo packing run"
    ),
):
    """Ask a question, optionally including local file context or repo-wide packed context."""
    from eva.config import load_config as _load_config
    from eva.indexing.packer import pack_repository
    from eva.indexing.tokenizer import trim_context
    from eva.indexing.tree import generate_tree
    from eva.prompts import ASK_SYSTEM_PROMPT
    from eva.providers import _resolve_provider_name, get_context_budget
    from eva.providers import dispatch as _dispatch
    from eva.security.work_safety import append_command_audit as _append_command_audit
    from eva.ui.formatter import print_error, print_info
    from eva.ui.output import emit_result
    from eva.ui.streaming import stream_response
    from eva.workspace.project_context import load_project_context

    load_config = _resolve_app_attr("load_config", _load_config)
    dispatch = _resolve_app_attr("dispatch", _dispatch)
    append_command_audit = _resolve_app_attr("append_command_audit", _append_command_audit)

    if output_format not in ("text", "json"):
        print_error(f"Invalid --format '{output_format}'. Use 'text' or 'json'.")
        raise typer.Exit(1)

    config = load_config()
    context = "" if no_project_context else load_project_context(Path.cwd())
    pack_res = None
    provider_name = _resolve_provider_name(config, provider)

    if repo:
        if not repo.is_dir():
            print_error(f"Not a directory: {repo}")
            raise typer.Exit(1)
        max_tokens = get_context_budget(provider_name, config)
        force_include_set = (
            {p.as_posix() for p in force_include} | {p.name for p in force_include} if force_include else frozenset()
        )
        if force_include:
            for fi in force_include:
                append_command_audit(
                    {
                        "action": "sensitive_file_override",
                        "command": "ask",
                        "path": str(fi),
                        "query": " ".join(query),
                    }
                )
        pack_res = pack_repository(repo, max_tokens=max_tokens, force_include=force_include_set)

        from rich.table import Table

        table = Table(title="Repository Context Packing Summary")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="magenta")

        table.add_row("Repository Root", str(repo))
        table.add_row("Target Provider", provider_name)
        table.add_row("Context Budget", f"{max_tokens} tokens")
        table.add_row("Files Scanned", str(pack_res.total_files_scanned))
        table.add_row("Files Included", str(len(pack_res.included_files)))
        table.add_row("Files Excluded", str(len(pack_res.excluded_files)))
        table.add_row("Tokens Included", str(pack_res.total_tokens_included))

        if pack_res.excluded_files:
            reasons_count: dict[str, int] = {}
            for _path, reason in pack_res.excluded_files:
                reasons_count[reason] = reasons_count.get(reason, 0) + 1
            reason_str = ", ".join(f"{count} {reason}" for reason, count in reasons_count.items())
            table.add_row("Exclusion Reasons", reason_str)

        console.print(table)

        if dry_run:
            print_info("Dry run only. Context packed but not sent.")
            raise typer.Exit(0)

        if not yes:
            confirmed = typer.confirm("Send repo-packed context to model?")
            if not confirmed:
                print_info("Cancelled sending repo-packed context.")
                raise typer.Exit(0)

        context += pack_res.packed_context

    if files:
        for path in files:
            context += _read_context_file(path, header=f"File: {path}")

    if dirs:
        for path in dirs:
            if not path.is_dir():
                print_error(f"Not a directory: {path}")
                raise typer.Exit(1)
            tree_text = generate_tree(path)
            context += f"\n=== Directory tree: {path} ===\n{tree_text}\n"

    if context and not repo:
        max_tokens = config.general.context_token_limit or get_context_budget(provider_name, config)
        context = trim_context(context, max_tokens=max_tokens)

    query_str = " ".join(query)
    stream = dispatch(ASK_SYSTEM_PROMPT, query_str, context, config, pinned_provider=provider, use_cache=not no_cache)
    result = stream_response(stream)

    if repo and pack_res:
        append_command_audit(
            {
                "action": "repo_pack",
                "provider": provider_name,
                "repo_path": str(repo),
                "included_files": pack_res.included_files,
                "total_tokens": pack_res.total_tokens_included,
                "excluded_files": [{"path": path, "reason": reason} for path, reason in pack_res.excluded_files],
            }
        )

    had_error = emit_result(result, output_format, meta={"provider": provider_name})
    if had_error:
        raise typer.Exit(1)


def explain(
    target: str = typer.Argument(None, help="File path, concept, or pipe input to explain"),
    provider: str | None = typer.Option(None, "--provider", "-p", help="Pin to a specific provider"),
    output_format: str = typer.Option(
        "text", "--format", help="Output format: 'text' (default, rendered markdown) or 'json'"
    ),
):
    """Explain a file, error log, or piped stdout."""
    from eva.config import load_config as _load_config
    from eva.indexing.repo_index import build_dep_graph, detect_stack
    from eva.prompts import EXPLAIN_SYSTEM_PROMPT
    from eva.providers import _resolve_provider_name
    from eva.providers import dispatch as _dispatch
    from eva.ui.formatter import print_error
    from eva.ui.output import emit_result
    from eva.ui.streaming import stream_response

    load_config = _resolve_app_attr("load_config", _load_config)
    dispatch = _resolve_app_attr("dispatch", _dispatch)

    if output_format not in ("text", "json"):
        print_error(f"Invalid --format '{output_format}'. Use 'text' or 'json'.")
        raise typer.Exit(1)

    config = load_config()
    context = ""
    query = "Explain this content."

    if not sys.stdin.isatty():
        piped_input = sys.stdin.read()
        if piped_input.strip():
            context = f"\n=== Piped Input ===\n{piped_input}\n"
            if target:
                query = target

    if not context and target:
        path = Path(target)
        if path.exists() and path.is_file():
            context = _read_context_file(path, header=f"File: {path}")
            query = f"Explain the file {target}."
        elif path.exists() and path.is_dir():
            stack = detect_stack(path)
            dep_graph = build_dep_graph(path)
            context = f"\n=== Project Stack ===\n{stack.to_summary_string()}\n\n=== Dependency Graph ===\n{dep_graph.to_summary_string()}\n"
            query = f"Explain the repository structure and architecture at {target}."
        else:
            query = f"Explain: {target}"

    if not context and not target:
        path = Path(".")
        stack = detect_stack(path)
        dep_graph = build_dep_graph(path)
        context = f"\n=== Project Stack ===\n{stack.to_summary_string()}\n\n=== Dependency Graph ===\n{dep_graph.to_summary_string()}\n"
        query = "Explain the project structure, stack, and architecture of this repository."

    provider_name = _resolve_provider_name(config, provider)
    stream = dispatch(EXPLAIN_SYSTEM_PROMPT, query, context, config, pinned_provider=provider)
    result = stream_response(stream)
    had_error = emit_result(result, output_format, meta={"provider": provider_name})
    if had_error:
        raise typer.Exit(1)


def investigate(
    query: str = typer.Argument(..., help="Question or objective for repository investigation"),
    path: str = typer.Argument(".", help="Target repository directory path (defaults to '.')"),
    provider: str | None = typer.Option(
        None,
        "--provider",
        "-p",
        help="Pin to a specific provider (e.g. groq, openrouter, opencode_zen, gemini)",
    ),
    max_turns: int = typer.Option(
        8,
        "--max-turns",
        help="Maximum turn limit for the investigation loop (defaults to 8)",
    ),
    yes: bool = typer.Option(
        False,
        "--yes",
        "-y",
        help="Skip upfront confirmation prompt",
    ),
    force_include: list[Path] = typer.Option(
        None,
        "--force-include",
        help="Force inclusion of specific denylisted files for this run",
    ),
):
    """Agentic, multi-turn, query-driven repo exploration."""
    from eva.agent import StoppedReason
    from eva.agent import run_investigation as _run_investigation
    from eva.config import load_config as _load_config
    from eva.providers import _resolve_provider_name
    from eva.providers import is_tool_capable as _is_tool_capable
    from eva.security.audit import append_investigation_audit as _append_investigation_audit
    from eva.security.work_safety import append_command_audit as _append_command_audit
    from eva.ui.formatter import print_error, print_info, print_markdown

    load_config = _resolve_app_attr("load_config", _load_config)
    is_tool_capable = _resolve_app_attr("is_tool_capable", _is_tool_capable)
    run_investigation = _resolve_app_attr("run_investigation", _run_investigation)
    append_investigation_audit = _resolve_app_attr("append_investigation_audit", _append_investigation_audit)
    append_command_audit = _resolve_app_attr("append_command_audit", _append_command_audit)

    config = load_config()
    resolved_provider = _resolve_provider_name(config, provider)

    if not is_tool_capable(resolved_provider):
        print_error(
            f"The current provider ({resolved_provider}) does not support agentic exploration. "
            "Use --provider groq/openrouter/opencode_zen/gemini, or set one of those as your default with `eva use <provider>`."
        )
        raise typer.Exit(1)

    target_root = Path(path).resolve()
    if not target_root.exists() or not target_root.is_dir():
        print_error(f"Target path '{path}' does not exist or is not a directory.")
        raise typer.Exit(1)

    if not yes:
        err_console.print(
            f"[yellow]Notice:[/yellow] Agentic investigation will read repository files as needed "
            f"and send their contents to provider '{resolved_provider}'."
        )
        confirm = typer.confirm("Do you want to proceed?", default=True)
        if not confirm:
            print_info("Investigation cancelled.")
            raise typer.Exit(0)

    def on_tool_start(tool_name: str, args: dict):
        if tool_name == "read_file":
            p = args.get("path", "")
            err_console.print(f"[dim]Reading {p}...[/dim]")
        elif tool_name == "list_directory":
            p = args.get("path", ".")
            err_console.print(f"[dim]Listing {p}...[/dim]")
        elif tool_name == "search_code":
            pat = args.get("pattern", "")
            err_console.print(f"[dim]Searching code for '{pat}'...[/dim]")

    force_include_set = (
        {p.as_posix() for p in force_include} | {p.name for p in force_include} if force_include else frozenset()
    )
    if force_include:
        for fi in force_include:
            append_command_audit(
                {
                    "action": "sensitive_file_override",
                    "command": "investigate",
                    "path": str(fi),
                    "query": query,
                }
            )

    result = run_investigation(
        query=query,
        root=target_root,
        config=config,
        provider_name=resolved_provider,
        max_turns=max_turns,
        on_tool_start=on_tool_start,
        force_include=force_include_set,
    )

    append_investigation_audit(
        provider=resolved_provider,
        query=query,
        files_read=result.files_read,
        turns_used=result.turns_used,
        stopped_reason=result.stopped_reason.value,
    )

    if result.final_answer:
        print_markdown(result.final_answer)

    if result.stopped_reason != StoppedReason.COMPLETED:
        print_info(f"Session ended: {result.stopped_reason.value}")


def analyze(
    prompt: list[str] = typer.Argument(None, help="Custom prompt or focus instructions for analysis"),
    files: list[Path] = typer.Option(None, "--file", "-f", help="Files to analyze"),
    provider: str | None = typer.Option(None, "--provider", "-p", help="Pin to a specific provider"),
):
    """Analyze logs, errors, or file output."""
    from eva.config import load_config as _load_config
    from eva.prompts import ANALYZE_SYSTEM_PROMPT
    from eva.providers import dispatch as _dispatch
    from eva.ui.formatter import is_ai_error, print_error, print_markdown
    from eva.ui.streaming import stream_response

    load_config = _resolve_app_attr("load_config", _load_config)
    dispatch = _resolve_app_attr("dispatch", _dispatch)

    config = load_config()
    context = ""

    if not sys.stdin.isatty():
        piped_input = sys.stdin.read()
        if piped_input.strip():
            context += f"\n=== Piped Input ===\n{piped_input}\n"

    if files:
        for path in files:
            context += _read_context_file(path, header=f"File: {path}")

    if not context.strip():
        print_error("Provide files with -f or pipe stdout into 'eva analyze'.")
        raise typer.Exit(1)

    query = " ".join(prompt) if prompt else "Analyze the provided content, identify issues, and suggest solutions."
    stream = dispatch(ANALYZE_SYSTEM_PROMPT, query, context, config, pinned_provider=provider)
    result = stream_response(stream)
    if is_ai_error(result):
        print_error(result.strip())
        raise typer.Exit(1)
    print_markdown(result)
