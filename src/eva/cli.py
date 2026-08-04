import shutil
import subprocess
import sys
from pathlib import Path

import typer

from eva import __version__
from eva.budget import get_live_budget
from eva.cache import clear_cache as do_clear_cache
from eva.cache import generate_cache_key, get_cached_response, set_cached_response
from eva.chat_session import run_chat_session
from eva.config import (
    KeyringUnavailableError,
    clear_api_key,
    get_api_key,
    get_api_key_env_var,
    get_config_dir,
    keyring_backend_available,
    load_config,
    save_config,
    set_api_key,
)
from eva.context.finder import find_files
from eva.context.io import ContextReadError, read_text_file_for_context
from eva.context.tree import generate_tree
from eva.diagnostics import get_log_file, setup_logging
from eva.git_ops import apply_unified_diff, extract_unified_diff, run_git
from eva.prompts import (
    ANALYZE_SYSTEM_PROMPT,
    ASK_SYSTEM_PROMPT,
    COMMIT_SYSTEM_PROMPT,
    EDIT_SYSTEM_PROMPT,
    EXPLAIN_SYSTEM_PROMPT,
    WORK_SYSTEM_PROMPT,
)
from eva.router import dispatch, get_provider
from eva.ui.formatter import (
    console,
    err_console,
    is_ai_error,
    print_error,
    print_info,
    print_markdown,
    print_success,
    print_warning,
)
from eva.ui.streaming import stream_response
from eva.work_safety import (
    CommandExtractionError,
    append_command_audit,
    get_command_audit_log,
    parse_safe_command,
)

app = typer.Typer(help="Eva - Command Line Intelligence")
config_app = typer.Typer(help="Manage configuration")
cache_app = typer.Typer(help="Manage cache")

app.add_typer(config_app, name="config")
app.add_typer(cache_app, name="cache")


def _version_callback(value: bool):
    if value:
        typer.echo(f"Eva {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Write debug diagnostics to stderr and eva.log."),
    version: bool | None = typer.Option(
        None,
        "--version",
        callback=_version_callback,
        is_eager=True,
        help="Show Eva version and exit.",
    ),
):
    setup_logging(verbose=verbose)


def _read_stdin_if_available() -> str:
    if sys.stdin.isatty():
        return ""
    try:
        return sys.stdin.read()
    except (OSError, ValueError):
        return ""


def _render_or_exit(result: str):
    if is_ai_error(result):
        print_error(result.strip())
        raise typer.Exit(1)
    print_markdown(result)


def _get_model_for_cache(provider_name: str, config) -> str:
    """Return 'provider:model' string for use in cache keys."""
    p_config = config.providers.get(provider_name)
    model = p_config.model if p_config else "unknown"
    return f"{provider_name}:{model}"


def _read_context_file(path: Path, header: str | None = None) -> str:
    try:
        text, warnings = read_text_file_for_context(path)
    except ContextReadError as exc:
        print_error(str(exc))
        raise typer.Exit(1) from exc

    for warning in warnings:
        print_warning(warning)

    label = header or f"File: {path}"
    return f"\n{label}\n{text}"


@app.command()
def ask(
    query: str,
    provider: str | None = typer.Option(None, "--provider", "-p", help="Pin to a specific provider"),
    file: list[Path] | None = typer.Option(None, "--file", "-f", help="Include file context (repeatable)"),
    dir: Path | None = typer.Option(None, "--dir", "-d", help="Include directory context (tree)"),
    no_cache: bool = typer.Option(False, "--no-cache", help="Bypass the response cache"),
):
    """Ask a one-shot question."""
    config = load_config()

    context = _read_stdin_if_available()

    if file:
        for f in file:
            context += _read_context_file(f, header=f"File: {f}")

    if dir:
        if not dir.is_dir():
            print_error(f"Directory {dir} does not exist or is not a directory.")
            raise typer.Exit(1)
        context += f"\nDirectory structure of {dir.name}:\n" + generate_tree(dir)

    active_provider = provider if provider else config.general.default_provider
    cache_model = _get_model_for_cache(active_provider, config)
    cache_key = generate_cache_key(cache_model, ASK_SYSTEM_PROMPT, query, context)

    if not no_cache:
        cached = get_cached_response(cache_key)
        if cached:
            print_info("Result found in cache.")
            print_markdown(cached)
            return

    stream = dispatch(ASK_SYSTEM_PROMPT, query, context, config, pinned_provider=provider)
    result = stream_response(stream)

    _render_or_exit(result)
    if "[Eva Error]" not in result and "Error:" not in result:
        set_cached_response(cache_key, result)


@app.command()
def explain(
    path: Path, provider: str | None = typer.Option(None, "--provider", "-p", help="Pin to a specific provider")
):
    """Summarize or explain a file or directory."""
    if not path.exists():
        print_error(f"Path {path} does not exist.")
        raise typer.Exit(1)

    config = load_config()

    context = ""
    query = f"Please explain {path.name}"

    if path.is_dir():
        context = f"Directory structure:\n{generate_tree(path)}"
    else:
        context = _read_context_file(path, header=f"File content: {path}")

    active_provider = provider if provider else config.general.default_provider
    cache_model = _get_model_for_cache(active_provider, config)
    cache_key = generate_cache_key(cache_model, EXPLAIN_SYSTEM_PROMPT, query, context)

    cached = get_cached_response(cache_key)
    if cached:
        print_info("Result found in cache.")
        print_markdown(cached)
        return

    stream = dispatch(EXPLAIN_SYSTEM_PROMPT, query, context, config, pinned_provider=provider)
    result = stream_response(stream)

    _render_or_exit(result)
    if "[Eva Error]" not in result and "Error:" not in result:
        set_cached_response(cache_key, result)


@app.command()
def analyse(
    query: str | None = typer.Argument(None, help="Optional specific question about the output"),
    provider: str | None = typer.Option(None, "--provider", "-p", help="Pin to a specific provider"),
):
    """Analyze piped output from another command (e.g. ls -la | eva analyse)."""
    _analyse_impl(query, provider, command_name="analyse")


@app.command()
def analyze(
    query: str | None = typer.Argument(None, help="Optional specific question about the output"),
    provider: str | None = typer.Option(None, "--provider", "-p", help="Pin to a specific provider"),
):
    """Alias for analyse."""
    _analyse_impl(query, provider, command_name="analyze")


def _analyse_impl(query: str | None, provider: str | None, command_name: str):
    config = load_config()

    if sys.stdin.isatty():
        print_error(
            f"No input provided. Please pipe output to this command. Example: eva find '*.py' | eva {command_name}"
        )
        raise typer.Exit(1)

    context = sys.stdin.read()
    if not context.strip():
        print_error("Piped input was empty.")
        raise typer.Exit(1)

    q = query if query else "Please analyze the following output and summarize its contents or identify any issues."

    active_provider = provider if provider else config.general.default_provider
    cache_model = _get_model_for_cache(active_provider, config)
    cache_key = generate_cache_key(cache_model, ANALYZE_SYSTEM_PROMPT, q, context)

    cached = get_cached_response(cache_key)
    if cached:
        print_info("Result found in cache.")
        print_markdown(cached)
        return

    stream = dispatch(ANALYZE_SYSTEM_PROMPT, q, context, config, pinned_provider=provider)
    result = stream_response(stream)

    _render_or_exit(result)
    if not is_ai_error(result):
        set_cached_response(cache_key, result)


@app.command()
def chat(
    provider: str | None = typer.Option(None, "--provider", "-p", help="Pin to a specific provider"),
    session: str | None = typer.Option(None, "--session", "-s", help="Save chat transcript under this session name"),
    resume: bool = typer.Option(False, "--resume", help="Resume the named session"),
):
    """Interactive REPL."""
    config = load_config()
    run_chat_session(config=config, provider=provider, session=session, resume=resume)


@app.command()
def work(
    query: list[str] = typer.Argument(..., help="The natural language command description"),
    provider: str | None = typer.Option(None, "--provider", "-p", help="Pin to a specific provider"),
    auto_confirm: bool = typer.Option(
        False, "--yes", "-y", help="Auto-confirm only when EVA_WORK_ASSUME_YES=1 is also set"
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Generate and audit the command without executing it"),
):
    """Execute a command generated from natural language."""
    config = load_config()
    query_str = " ".join(query)

    from rich.live import Live
    from rich.spinner import Spinner

    stream = dispatch(WORK_SYSTEM_PROMPT, query_str, "", config, pinned_provider=provider)

    model_output = ""
    spinner = Spinner("dots", text="Generating command...")
    with Live(spinner, console=err_console, refresh_per_second=15, transient=True):
        for chunk in stream:
            model_output += chunk

    if is_ai_error(model_output):
        append_command_audit(
            {"query": query_str, "model_output": model_output, "executed": False, "blocked_reason": "provider_error"}
        )
        print_error(model_output.strip())
        raise typer.Exit(1)

    try:
        parsed = parse_safe_command(model_output)
    except CommandExtractionError as exc:
        append_command_audit(
            {"query": query_str, "model_output": model_output, "executed": False, "blocked_reason": str(exc)}
        )
        print_error(f"Refusing to execute ambiguous model output: {exc}")
        raise typer.Exit(1) from exc

    err_console.print(f"[info]ℹ Generated command:\n> {parsed.command}\n[/info]")

    if dry_run:
        append_command_audit(
            {"query": query_str, "command": parsed.command, "argv": parsed.argv, "executed": False, "dry_run": True}
        )
        print_info(f"Dry run only. Audit log: {get_command_audit_log()}")
        return

    execute = auto_confirm
    if not execute:
        execute = typer.confirm("Do you want to execute this command?")

    if execute:
        result = subprocess.run(parsed.command, shell=True, check=False)
        append_command_audit(
            {
                "query": query_str,
                "command": parsed.command,
                "argv": parsed.argv,
                "executed": True,
                "return_code": result.returncode,
            }
        )
        if result.returncode != 0:
            # Check if execution failed due to missing root/sudo privileges
            if not parsed.command.strip().startswith("sudo ") and typer.confirm(
                "Command failed due to missing privileges. Retry with sudo?", default=True
            ):
                sudo_cmd = f"sudo {parsed.command}"
                result = subprocess.run(sudo_cmd, shell=True, check=False)
                if result.returncode != 0:
                    raise typer.Exit(result.returncode)
                return
            raise typer.Exit(result.returncode)
    else:
        append_command_audit(
            {
                "query": query_str,
                "command": parsed.command,
                "argv": parsed.argv,
                "executed": False,
                "blocked_reason": "user_declined",
            }
        )


@app.command()
def find(
    pattern: str = typer.Argument(..., help="Glob pattern to match files"),
    path: str = typer.Argument(".", help="Root directory to search"),
):
    """Find files locally. Zero AI cost."""
    found = False
    for p in find_files(path, pattern):
        print(p)
        found = True
    if not found:
        print_info("No files found.")


@app.command()
def tree(path: str = typer.Argument(".", help="Root directory to display")):
    """Generate a directory tree. Zero AI cost."""
    print(generate_tree(path))


@app.command()
def grep(
    pattern: str = typer.Argument(..., help="Search pattern"),
    path: str = typer.Argument(".", help="Directory or file to search"),
):
    """Wrap ripgrep for fast searching. Zero AI cost."""
    try:
        subprocess.run(["rg", "--", pattern, path], check=False)
    except FileNotFoundError:
        print_error("ripgrep (rg) is not installed on this system.")


@app.command()
def usage():
    """Show remaining RPM/RPD per provider."""
    budget = get_live_budget()
    print_info("Current Usage:")
    for provider, stats in budget.usage_by_provider.items():
        print(f"  {provider}:")
        print(f"    Today: {stats.requests_today}")
        print(f"    This minute: {stats.requests_this_minute}")


@app.command()
def providers():
    """List configured providers and quotas."""
    config = load_config()
    budget = get_live_budget()

    print_info(f"Default Provider: {config.general.default_provider}")
    print_info(f"Fallback Enabled: {config.general.fallback_enabled}")
    if config.general.fallback_enabled:
        print_info(f"Fallback Order: {', '.join(config.general.fallback_order)}")

    print("\nProviders Configured:")
    for name, p_config in config.providers.items():
        prov = get_provider(name)
        max_rpm = prov.max_rpm if prov else "Unknown"
        max_rpd = prov.max_rpd if prov else "Unknown"

        usage_stats = budget.usage_by_provider.get(name)
        used_rpd = usage_stats.requests_today if usage_stats else 0
        used_rpm = usage_stats.requests_this_minute if usage_stats else 0

        print(f"  - {name}: model={p_config.model}")
        print(f"    Usage: {used_rpd}/{max_rpd} per day, {used_rpm}/{max_rpm} per min")


@app.command()
def doctor(
    network: bool = typer.Option(
        False, "--network", help="Also perform network-backed provider checks where supported"
    ),
):
    """Check local Eva health and common environment problems."""
    ok = True
    try:
        config = load_config()
    except Exception as exc:
        console.print(f"Eva {__version__}")
        console.print(f"Config: {get_config_dir() / 'config.toml'}")
        console.print(f"✖ config invalid: {exc}")
        raise typer.Exit(1) from exc

    console.print(f"Eva {__version__}")
    console.print(f"Config: {get_config_dir() / 'config.toml'}")
    console.print(f"Log file: {get_log_file()}")

    keyring_ok, keyring_detail = keyring_backend_available()
    if keyring_ok:
        console.print(f"✔ keyring backend: {keyring_detail}")
    else:
        ok = False
        console.print(f"✖ keyring backend unavailable: {keyring_detail}")

    rg_path = shutil.which("rg")
    if rg_path:
        console.print(f"✔ ripgrep: {rg_path}")
    else:
        ok = False
        console.print("✖ ripgrep (rg) not found; `eva grep` will not work")

    console.print(f"Default provider: {config.general.default_provider}")
    for name in config.providers:
        registered = get_provider(name) is not None
        key = get_api_key(name)
        env_var = get_api_key_env_var(name)
        key_status = "set" if key else f"missing ({env_var} or keyring)"
        if not registered:
            ok = False
            console.print(f"✖ provider {name}: not registered, api_key={key_status}")
        elif not key:
            console.print(f"⚠ provider {name}: registered=True, api_key={key_status}")
        else:
            console.print(f"✔ provider {name}: registered=True, api_key={key_status}")

    if network:
        console.print(
            "Network checks are provider-specific and may consume rate-limit budget; use config models for model-list checks."
        )

    if not ok:
        raise typer.Exit(1)


@app.command()
def changes(
    query: str | None = typer.Argument(None, help="Optional question about the git diff"),
    staged: bool = typer.Option(False, "--staged", help="Explain staged changes instead of unstaged changes"),
    provider: str | None = typer.Option(None, "--provider", "-p", help="Pin to a specific provider"),
):
    """Explain current git changes with diff-aware context."""
    args = ["diff", "--staged"] if staged else ["diff"]
    diff = run_git(args)
    if diff.returncode != 0:
        print_error(diff.stderr.strip() or "git diff failed")
        raise typer.Exit(1)
    if not diff.stdout.strip():
        print_info("No git diff to explain.")
        return

    config = load_config()
    q = query or "Explain these git changes, highlight risks, and suggest review points."
    stream = dispatch(ANALYZE_SYSTEM_PROMPT, q, diff.stdout, config, pinned_provider=provider)
    result = stream_response(stream)
    _render_or_exit(result)


@app.command("commit-message")
def commit_message(
    staged: bool = typer.Option(True, "--staged/--all", help="Use staged diff or all unstaged+staged changes"),
    provider: str | None = typer.Option(None, "--provider", "-p", help="Pin to a specific provider"),
):
    """Generate a commit message from the current git diff."""
    args = ["diff", "--staged"] if staged else ["diff", "HEAD"]
    diff = run_git(args)
    if diff.returncode != 0:
        print_error(diff.stderr.strip() or "git diff failed")
        raise typer.Exit(1)
    if not diff.stdout.strip():
        print_info("No git diff available for a commit message.")
        return

    config = load_config()
    stream = dispatch(
        COMMIT_SYSTEM_PROMPT, "Write a commit message for this diff.", diff.stdout, config, pinned_provider=provider
    )
    result = stream_response(stream)
    if is_ai_error(result):
        print_error(result.strip())
        raise typer.Exit(1)
    print(result.strip())


@app.command()
def edit(
    query: list[str] = typer.Argument(..., help="Requested code change"),
    files: list[Path] = typer.Option(..., "--file", "-f", help="File to include and allow in the generated diff"),
    provider: str | None = typer.Option(None, "--provider", "-p", help="Pin to a specific provider"),
    apply_changes: bool = typer.Option(False, "--apply", help="Apply the generated patch after review confirmation"),
):
    """Generate a reviewable unified diff for file edits."""
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


@app.command()
def use(provider: str):
    """Set the default AI provider."""
    config = load_config()
    if provider not in config.providers:
        print_error(f"Provider '{provider}' not found. Available providers: {', '.join(config.providers.keys())}")
        raise typer.Exit(1)
    config.general.default_provider = provider
    save_config(config)
    print_success(f"Default provider set to {provider}")


@config_app.command("set-provider")
def set_provider(name: str):
    """Change the persistent default provider."""
    use(name)


@config_app.command("set-key")
def set_key_cmd(
    provider: str = typer.Argument(..., help="The name of the provider (e.g. groq, openrouter)"),
    key: str | None = typer.Argument(None, help="The API key (if omitted, you will be prompted securely)"),
):
    """Store an API key via keyring."""
    config = load_config()
    if provider not in config.providers:
        print_error(f"Provider '{provider}' not found. Available providers: {', '.join(config.providers.keys())}")
        raise typer.Exit(1)

    if not key:
        import getpass

        key = getpass.getpass(f"Enter API key for {provider}: ")
        if not key.strip():
            print_error("API key cannot be empty.")
            return

    try:
        set_api_key(provider, key.strip())
    except KeyringUnavailableError as exc:
        print_error(str(exc))
        raise typer.Exit(1) from exc
    print_success(f"API key for {provider} stored successfully.")


@config_app.command("clear-key")
def clear_key_cmd(provider: str = typer.Argument(..., help="The name of the provider (e.g. groq, openrouter)")):
    """Clear the stored API key for a provider."""
    config = load_config()
    if provider not in config.providers:
        print_error(f"Provider '{provider}' not found. Available providers: {', '.join(config.providers.keys())}")
        raise typer.Exit(1)
    try:
        clear_api_key(provider)
    except KeyringUnavailableError as exc:
        print_error(str(exc))
        raise typer.Exit(1) from exc
    print_success(f"API key for {provider} cleared.")


@config_app.command("clear-keys")
def clear_keys_cmd():
    """Clear all stored API keys for all configured providers."""
    config = load_config()
    for provider in config.providers:
        try:
            clear_api_key(provider)
        except KeyringUnavailableError as exc:
            print_warning(f"Could not clear key for {provider}: {exc}")
    print_success("All provider API keys cleared.")


@config_app.command("status")
def status_cmd():
    """Check which providers have credentials configured."""
    config = load_config()
    print_info("Provider Credential Status:")
    for provider in config.providers:
        key = get_api_key(provider)
        if key:
            print_success(f"{provider}: Configured")
        else:
            print_warning(f"{provider}: Not configured")


@config_app.command("models")
def list_models():
    """List current model and fetch available models for the active provider."""
    config = load_config()
    provider_name = config.general.default_provider
    print_info(f"Current Default Provider: {provider_name}")

    current_model = config.providers.get(provider_name)
    if current_model:
        print_info(f"Current Model: {current_model.model}")

    try:
        models = []
        if provider_name == "openrouter":
            print_info("Fetching free models from OpenRouter...")
            from eva.router.openrouter_provider import get_free_models

            models = get_free_models()
        elif provider_name == "groq":
            print_info("Fetching models from Groq...")
            from eva.router.groq_provider import get_models

            models = get_models()
            if not models:
                print_error("Failed to fetch Groq models. Is your API key set? Run: eva config set-key groq")
                raise typer.Exit(1)
        elif provider_name == "gemini":
            print_info("Fetching models from Gemini...")
            from eva.router.gemini_provider import get_models

            models = get_models()
            if not models:
                print_error("Failed to fetch Gemini models. Is your API key set? Run: eva config set-key gemini")
                raise typer.Exit(1)
        elif provider_name == "opencode_zen":
            print_info("Fetching models from OpenCode Zen...")
            from eva.router.opencode_zen_provider import get_free_models

            models = get_free_models()
            if not models:
                print_error(
                    "Failed to fetch OpenCode Zen models. Is your API key set? Run: eva config set-key opencode_zen"
                )
                raise typer.Exit(1)
        else:
            print_error(f"Fetching models dynamically for '{provider_name}' is not currently supported via CLI.")
            raise typer.Exit(1)

        if not models:
            print_error("No models found or failed to fetch.")
            raise typer.Exit(1)

        print(f"\nAvailable Models for {provider_name}:")
        for m in models:
            # OpenRouter has 'name', Groq mostly just has 'id'
            name = m.get("name", "N/A")
            if name == "N/A" and "id" in m:
                name = m["id"]
            print(f"  - {m['id']} (Name: {name})")

        print(f"\nUse 'eva config set-model {provider_name} <model_id>' to configure a model.")
    except Exception as e:
        print_error(f"Error fetching models: {e!s}")
        raise typer.Exit(1) from e


@config_app.command("set-model")
def set_model_cmd(provider: str, model: str):
    """Set the model for a specific provider."""
    config = load_config()
    if provider not in config.providers:
        print_error(f"Provider '{provider}' not found. Available providers: {', '.join(config.providers.keys())}")
        raise typer.Exit(1)

    config.providers[provider].model = model
    save_config(config)
    print_success(f"Model for provider '{provider}' set to '{model}'")


@cache_app.command("clear")
def cache_clear():
    """Clear response cache."""
    do_clear_cache()
    print_success("Cache cleared.")


if __name__ == "__main__":
    app()
