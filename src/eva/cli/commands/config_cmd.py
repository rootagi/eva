import os
import re
from pathlib import Path

import typer

from eva.cli.helpers import _resolve_app_attr, console

config_app = typer.Typer(help="Manage Eva configuration and API keys.")


def _get_config_funcs():
    from eva.config import (
        KeyringUnavailableError,
        clear_api_key,
        get_api_key,
        get_api_key_env_var,
        get_config_file,
        keyring_backend_available,
        load_config,
        save_config,
        set_api_key,
    )

    return (
        KeyringUnavailableError,
        _resolve_app_attr("clear_api_key", clear_api_key),
        _resolve_app_attr("get_api_key", get_api_key),
        get_api_key_env_var,
        get_config_file,
        keyring_backend_available,
        _resolve_app_attr("load_config", load_config),
        _resolve_app_attr("save_config", save_config),
        _resolve_app_attr("set_api_key", set_api_key),
    )


def use(provider: str):
    """Set the default AI provider."""
    from eva.ui.formatter import print_error, print_success

    (_, _, _, _, _, _, load_config, save_config, _) = _get_config_funcs()
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


def _get_models_cache_file() -> Path:
    from eva.config import get_config_dir

    return get_config_dir() / "models_cache.json"


def _load_models_cache() -> dict:
    import json

    cache_file = _get_models_cache_file()
    if cache_file.exists():
        try:
            data = json.loads(cache_file.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                return {"version": 1, "providers": {}}
            if not isinstance(data.get("providers"), dict):
                data["providers"] = {}
            return data
        except (OSError, json.JSONDecodeError, ValueError):
            return {"version": 1, "providers": {}}
    return {"version": 1, "providers": {}}


def _save_models_cache(cache_data: dict) -> None:
    import json
    import tempfile

    cache_file = _get_models_cache_file()
    cache_file.parent.mkdir(parents=True, exist_ok=True)
    temp_dir = cache_file.parent
    try:
        with tempfile.NamedTemporaryFile("w", dir=temp_dir, delete=False, encoding="utf-8") as tf:
            json.dump(cache_data, tf, indent=2)
            tf.flush()
            os.fsync(tf.fileno())
            temp_name = tf.name
        os.replace(temp_name, cache_file)
    except (OSError, TypeError, ValueError):
        pass


def _fetch_provider_models(
    provider_name: str, free_only: bool = False, refresh: bool = False
) -> tuple[list[dict], bool]:
    """Fetch models for provider using disk cache (1h TTL). Returns (models, from_cache)."""
    import importlib
    import time

    from eva.providers import PROVIDER_MAP

    cache_data = _load_models_cache()
    providers = cache_data.get("providers") or {}
    cached_entry = providers.get(provider_name, {}) if isinstance(providers, dict) else {}
    fetched_at = cached_entry.get("fetched_at", 0)
    cached_models = cached_entry.get("free_models" if free_only else "models", [])

    if not refresh and cached_models and (time.time() - fetched_at < 3600):
        return cached_models, True

    mod_path = PROVIDER_MAP.get(provider_name)
    if not mod_path:
        return cached_models, False

    try:
        mod = importlib.import_module(mod_path)
    except (ImportError, AttributeError, ValueError):
        return cached_models, False

    live_models: list[dict] = []
    live_free: list[dict] = []

    if free_only:
        get_free_fn = getattr(mod, "get_free_models", None)
        if callable(get_free_fn):
            try:
                live_free = get_free_fn()
            except (RuntimeError, ValueError, OSError, KeyError, TypeError):
                live_free = []
        if not live_free:
            get_all_fn = getattr(mod, "get_models", None)
            if callable(get_all_fn):
                try:
                    all_m = get_all_fn()
                    live_free = [m for m in all_m if "free" in m.get("id", "").lower()]
                except (RuntimeError, ValueError, OSError, KeyError, TypeError):
                    live_free = []
        live_models = live_free
    else:
        get_all_fn = getattr(mod, "get_models", None)
        if callable(get_all_fn):
            try:
                live_models = get_all_fn()
            except (RuntimeError, ValueError, OSError, KeyError, TypeError):
                live_models = []

    if live_models:
        if not isinstance(cache_data.get("providers"), dict):
            cache_data["providers"] = {}
        if provider_name not in cache_data["providers"] or not isinstance(cache_data["providers"][provider_name], dict):
            cache_data["providers"][provider_name] = {}
        cache_data["providers"][provider_name]["fetched_at"] = time.time()
        if free_only:
            cache_data["providers"][provider_name]["free_models"] = live_models
        else:
            cache_data["providers"][provider_name]["models"] = live_models
        _save_models_cache(cache_data)
        return live_models, False

    if cached_models:
        return cached_models, True

    return [], False


def _get_known_models_for_provider(provider_name: str) -> list[dict]:
    models, _ = _fetch_provider_models(provider_name, free_only=False, refresh=False)
    return models


@config_app.command("set-model")
def set_model_cmd(
    provider: str = typer.Argument(..., help="The provider name (e.g. openrouter, groq, gemini, ollama, llamacpp)"),
    model: str = typer.Argument(..., help="The model identifier to use for this provider"),
    force: bool = typer.Option(
        False, "--force", "-f", help="Force setting model without validating against discovered models"
    ),
):
    """Set the active model for a specific provider."""
    from eva.ui.formatter import print_error, print_success

    (_, _, _, _, _, _, load_config, save_config, _) = _get_config_funcs()
    config = load_config()
    if provider not in config.providers:
        print_error(f"Provider '{provider}' not found. Available providers: {', '.join(config.providers.keys())}")
        raise typer.Exit(1)

    if not force:
        known = _get_known_models_for_provider(provider)
        if known:
            valid_ids = set()
            for m in known:
                mid = m.get("id", "")
                if mid:
                    valid_ids.add(mid)
                    if mid.startswith("models/"):
                        valid_ids.add(mid.removeprefix("models/"))
                    else:
                        valid_ids.add(f"models/{mid}")
            if model not in valid_ids:
                print_error(
                    f"Model '{model}' is not a recognized model for provider '{provider}'. Use --force to override."
                )
                raise typer.Exit(1)

    config.providers[provider].model = model
    save_config(config)
    print_success(f"Model for provider '{provider}' set to '{model}'.")


@config_app.command("models")
def models_cmd(
    provider: str | None = typer.Argument(None, help="Provider name (e.g. openrouter, groq, gemini, ollama, llamacpp)"),
    provider_opt: str | None = typer.Option(None, "--provider", "-p", help="Provider name"),
    json_output: bool = typer.Option(False, "--json", help="Output models in JSON format"),
    refresh: bool = typer.Option(False, "--refresh", help="Force re-fetch from provider, bypassing cache"),
    free_only: bool = typer.Option(False, "--free-only", help="Filter for free models where supported"),
):
    """List available models for configured or registered providers with 1-hour cache."""
    import json

    from rich.table import Table

    from eva.providers import PROVIDER_MAP
    from eva.ui.formatter import print_error, print_info

    (_, _, _, _, _, _, load_config, _, _) = _get_config_funcs()
    config = load_config()

    target_provider = provider or provider_opt
    available = sorted(set(PROVIDER_MAP.keys()) | set(config.providers.keys()))

    if target_provider:
        if target_provider not in available:
            print_error(f"Unknown provider '{target_provider}'. Available providers: {', '.join(available)}")
            raise typer.Exit(1)
        providers_to_query = [target_provider]
    else:
        providers_to_query = available

    results: dict[str, list[dict]] = {}
    total_count = 0

    for p in providers_to_query:
        model_list, _ = _fetch_provider_models(p, free_only=free_only, refresh=refresh)
        results[p] = model_list
        total_count += len(model_list)

    if json_output:
        console.print(json.dumps(results, indent=2), soft_wrap=True)
        return

    if total_count == 0:
        print_info("No models discovered. Ensure API keys or local servers are configured.")
        return

    table = Table(title=f"Discovered Models (Total: {total_count})")
    table.add_column("Provider", style="cyan")
    table.add_column("Model ID", style="yellow")
    table.add_column("Display Name", style="white")

    for p, model_list in results.items():
        for m in model_list:
            mid = m.get("id", "")
            mname = m.get("name", "")
            table.add_row(p, mid, mname)

    console.print(table)


@config_app.command("set-key")
def set_key_cmd(
    provider: str = typer.Argument(..., help="The name of the provider (e.g. groq, openrouter)"),
    key: str | None = typer.Argument(None, help="The API key (if omitted, you will be prompted securely)"),
):
    """Store an API key via keyring."""
    from eva.ui.formatter import print_error, print_info, print_success

    (KeyringUnavailableError, _, _, get_api_key_env_var, _, _, load_config, _, set_api_key) = _get_config_funcs()
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
        env_var = get_api_key_env_var(provider)
        print_info(f"You can also export {env_var} in your shell environment.")
        raise typer.Exit(1) from exc

    print_success(f"API key for '{provider}' saved successfully.")


@config_app.command("remove-key")
def remove_key_cmd(
    provider: str = typer.Argument(..., help="The name of the provider (e.g. groq, openrouter, gemini)"),
):
    """Remove a stored API key from the OS keyring."""
    from eva.ui.formatter import print_error, print_success

    (KeyringUnavailableError, clear_api_key, _, _, _, _, load_config, _, _) = _get_config_funcs()
    config = load_config()
    if provider not in config.providers:
        print_error(f"Provider '{provider}' not found. Available providers: {', '.join(config.providers.keys())}")
        raise typer.Exit(1)

    try:
        clear_api_key(provider)
    except KeyringUnavailableError as exc:
        print_error(str(exc))
        raise typer.Exit(1) from exc

    print_success(f"API key for '{provider}' removed successfully.")


@config_app.command("allow-command")
def allow_command_cmd(
    prefix: str = typer.Argument(..., help="Command prefix to allow (e.g. git, npm, ls)"),
):
    """Add a command prefix to the opt-in execution allowlist."""
    from eva.ui.formatter import print_error, print_info, print_success

    (_, _, _, _, _, _, load_config, save_config, _) = _get_config_funcs()
    config = load_config()
    p = prefix.strip()
    if not p:
        print_error("Command prefix cannot be empty.")
        raise typer.Exit(1)

    if p not in config.general.allowed_command_prefixes:
        config.general.allowed_command_prefixes.append(p)
        save_config(config)
        print_success(f"Added '{p}' to allowed command prefixes.")
    else:
        print_info(f"Prefix '{p}' is already in the allowlist.")


@config_app.command("disallow-command")
def disallow_command_cmd(
    prefix: str = typer.Argument(..., help="Command prefix to remove from allowlist"),
):
    """Remove a command prefix from the opt-in execution allowlist."""
    from eva.ui.formatter import print_error, print_success

    (_, _, _, _, _, _, load_config, save_config, _) = _get_config_funcs()
    config = load_config()
    p = prefix.strip()
    if p in config.general.allowed_command_prefixes:
        config.general.allowed_command_prefixes.remove(p)
        save_config(config)
        print_success(f"Removed '{p}' from allowed command prefixes.")
    else:
        print_error(f"Prefix '{p}' is not in the allowlist.")
        raise typer.Exit(1)


@config_app.command("import-allowlist")
def import_allowlist_cmd(
    path: Path = typer.Argument(..., help="Path to text file containing command prefixes (one per line)"),
):
    """Import command prefixes from a file into allowed_command_prefixes."""
    from eva.ui.formatter import print_error, print_success

    if not path.is_file():
        print_error(f"File not found: {path}")
        raise typer.Exit(1)

    try:
        content = path.read_text(encoding="utf-8")
    except OSError as exc:
        print_error(f"Failed to read file '{path}': {exc}")
        raise typer.Exit(1) from exc

    (_, _, _, _, _, _, load_config, save_config, _) = _get_config_funcs()
    config = load_config()
    added_count = 0
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line not in config.general.allowed_command_prefixes:
            config.general.allowed_command_prefixes.append(line)
            added_count += 1

    save_config(config)
    print_success(f"Imported {added_count} new allowed command prefix(es) from '{path}'.")


@config_app.command("set-redaction-threshold")
def set_redaction_threshold_cmd(
    threshold: float = typer.Argument(..., help="Entropy threshold (0 < value <= 8.0)"),
):
    """Set the process-wide Shannon entropy threshold for secret redaction."""
    from eva.ui.formatter import print_error, print_success

    if threshold <= 0 or threshold > 8.0:
        print_error("Entropy threshold must be between 0.0 and 8.0 (exclusive 0, inclusive 8).")
        raise typer.Exit(1)
    (_, _, _, _, _, _, load_config, save_config, _) = _get_config_funcs()
    config = load_config()
    config.general.redaction_entropy_threshold = threshold
    save_config(config)
    print_success(f"Redaction entropy threshold set to {threshold}.")


@config_app.command("allow-redaction-pattern")
def allow_redaction_pattern_cmd(
    pattern: str = typer.Argument(..., help="Regex pattern of tokens to exempt from entropy redaction"),
):
    """Add a regex pattern to exempt matching tokens from entropy redaction."""
    from eva.ui.formatter import print_error, print_info, print_success

    p = pattern.strip()
    if not p:
        print_error("Pattern cannot be empty.")
        raise typer.Exit(1)
    try:
        re.compile(p)
    except re.error as exc:
        print_error(f"Invalid regex pattern: {exc}")
        raise typer.Exit(1) from exc

    (_, _, _, _, _, _, load_config, save_config, _) = _get_config_funcs()
    config = load_config()
    if p not in config.general.redaction_ignore_patterns:
        config.general.redaction_ignore_patterns.append(p)
        save_config(config)
        print_success(f"Added '{p}' to redaction ignore patterns.")
    else:
        print_info(f"Pattern '{p}' is already in the ignore list.")


@config_app.command("disallow-redaction-pattern")
def disallow_redaction_pattern_cmd(
    pattern: str = typer.Argument(..., help="Regex pattern to remove from redaction ignore list"),
):
    """Remove a regex pattern from redaction ignore list."""
    from eva.ui.formatter import print_error, print_success

    p = pattern.strip()
    (_, _, _, _, _, _, load_config, save_config, _) = _get_config_funcs()
    config = load_config()
    if p in config.general.redaction_ignore_patterns:
        config.general.redaction_ignore_patterns.remove(p)
        save_config(config)
        print_success(f"Removed '{p}' from redaction ignore patterns.")
    else:
        print_error(f"Pattern '{p}' is not in the ignore list.")
        raise typer.Exit(1)


@config_app.command("ignore-dir")
def ignore_dir_cmd(
    name: str = typer.Argument(..., help="Directory name to add to always-ignored directories"),
):
    """Add a directory name to the process-wide ignored directories set."""
    from eva.ui.formatter import print_error, print_info, print_success

    d = name.strip()
    if not d:
        print_error("Directory name cannot be empty.")
        raise typer.Exit(1)
    (_, _, _, _, _, _, load_config, save_config, _) = _get_config_funcs()
    config = load_config()
    if d in config.general.unignore_dirs:
        config.general.unignore_dirs.remove(d)
    if d not in config.general.extra_ignored_dirs:
        config.general.extra_ignored_dirs.append(d)
        save_config(config)
        print_success(f"Added '{d}' to extra ignored directories.")
    else:
        print_info(f"Directory '{d}' is already in extra ignored directories.")


@config_app.command("unignore-dir")
def unignore_dir_cmd(
    name: str = typer.Argument(..., help="Directory name to remove from always-ignored directories"),
):
    """Unignore a directory name so it is scanned and indexed."""
    from eva.ui.formatter import print_error, print_info, print_success

    d = name.strip()
    if not d:
        print_error("Directory name cannot be empty.")
        raise typer.Exit(1)
    (_, _, _, _, _, _, load_config, save_config, _) = _get_config_funcs()
    config = load_config()
    if d in config.general.extra_ignored_dirs:
        config.general.extra_ignored_dirs.remove(d)
    if d not in config.general.unignore_dirs:
        config.general.unignore_dirs.append(d)
        save_config(config)
        print_success(f"Added '{d}' to unignored directories.")
    else:
        print_info(f"Directory '{d}' is already in unignored directories.")


@config_app.command("allow-sensitive-file")
def allow_sensitive_file_cmd(
    pattern: str = typer.Argument(..., help="Filename glob pattern to allowlist (e.g. *.example.env)"),
):
    """Add a glob pattern to the sensitive-file allowlist."""
    from eva.ui.formatter import print_error, print_info, print_success

    p = pattern.strip()
    if not p:
        print_error("Pattern cannot be empty.")
        raise typer.Exit(1)
    (_, _, _, _, _, _, load_config, save_config, _) = _get_config_funcs()
    config = load_config()
    if p not in config.general.sensitive_file_allowlist:
        config.general.sensitive_file_allowlist.append(p)
        save_config(config)
        print_success(f"Added '{p}' to sensitive file allowlist.")
    else:
        print_info(f"Pattern '{p}' is already in the sensitive file allowlist.")


@config_app.command("disallow-sensitive-file")
def disallow_sensitive_file_cmd(
    pattern: str = typer.Argument(..., help="Filename glob pattern to remove from allowlist"),
):
    """Remove a glob pattern from the sensitive-file allowlist."""
    from eva.ui.formatter import print_error, print_success

    p = pattern.strip()
    (_, _, _, _, _, _, load_config, save_config, _) = _get_config_funcs()
    config = load_config()
    if p in config.general.sensitive_file_allowlist:
        config.general.sensitive_file_allowlist.remove(p)
        save_config(config)
        print_success(f"Removed '{p}' from sensitive file allowlist.")
    else:
        print_error(f"Pattern '{p}' is not in the sensitive file allowlist.")
        raise typer.Exit(1)


@config_app.command("show")
def show_config():
    """Display current configuration, default provider, and key statuses."""
    from rich.table import Table

    (_, _, get_api_key, _, get_config_file, _, load_config, _, _) = _get_config_funcs()
    config = load_config()

    table = Table(title="Eva Configuration")
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="magenta")

    table.add_row("Config Path", str(get_config_file()))
    table.add_row("Default Provider", config.general.default_provider)
    table.add_row("Fallback Enabled", str(config.general.fallback_enabled))
    table.add_row("Fallback Order", ", ".join(config.general.fallback_order))
    allowlist_str = (
        ", ".join(config.general.allowed_command_prefixes)
        if config.general.allowed_command_prefixes
        else "Disabled (empty)"
    )
    table.add_row("Allowed Command Prefixes", allowlist_str)
    table.add_row("Redaction Entropy Threshold", str(config.general.redaction_entropy_threshold))
    redaction_ignore_str = (
        ", ".join(config.general.redaction_ignore_patterns) if config.general.redaction_ignore_patterns else "None"
    )
    table.add_row("Redaction Ignore Patterns", redaction_ignore_str)
    extra_ignored_str = ", ".join(config.general.extra_ignored_dirs) if config.general.extra_ignored_dirs else "None"
    table.add_row("Extra Ignored Dirs", extra_ignored_str)
    unignore_str = ", ".join(config.general.unignore_dirs) if config.general.unignore_dirs else "None"
    table.add_row("Unignore Dirs", unignore_str)
    sensitive_allow_str = (
        ", ".join(config.general.sensitive_file_allowlist) if config.general.sensitive_file_allowlist else "None"
    )
    table.add_row("Sensitive File Allowlist", sensitive_allow_str)
    context_limit_str = (
        str(config.general.context_token_limit)
        if config.general.context_token_limit is not None
        else "Provider Default"
    )
    table.add_row("Context Token Limit", context_limit_str)
    table.add_row("Encrypt Sessions", str(config.general.encrypt_sessions))

    console.print(table)
    console.print()

    prov_table = Table(title="Configured Providers & Key Status")
    prov_table.add_column("Provider", style="cyan")
    prov_table.add_column("Model", style="yellow")
    prov_table.add_column("API Key Status", style="green")

    for name, p_cfg in config.providers.items():
        key = get_api_key(name)
        status = "[green]Configured[/green]" if key else "[red]Missing[/red]"
        is_default = " (default)" if name == config.general.default_provider else ""
        prov_table.add_row(f"{name}{is_default}", p_cfg.model, status)

    console.print(prov_table)


@config_app.command("doctor")
def doctor():
    """Diagnose environment, keyring backend, and provider connectivity."""
    from eva.ui.formatter import print_error, print_info, print_success

    (_, _, get_api_key, get_api_key_env_var, _, keyring_backend_available, load_config, _, _) = _get_config_funcs()
    print_info("Running Eva Environment Doctor...\n")

    ok, info = keyring_backend_available()
    if ok:
        print_success(f"Keyring Backend: Available ({info})")
    else:
        print_error(f"Keyring Backend: Unavailable ({info})")

    config = load_config()
    print_info(f"Default Provider: {config.general.default_provider}")

    for name in config.providers:
        key = get_api_key(name)
        env_var = get_api_key_env_var(name)
        if key:
            source = f"env var {env_var}" if os.getenv(env_var) else "keyring"
            print_success(f"Provider '{name}': API key found ({source})")
        else:
            print_error(f"Provider '{name}': No API key set (keyring or {env_var})")


audit_app = typer.Typer(help="Inspect and verify the cryptographic command audit log.")
config_app.add_typer(audit_app, name="audit")


@audit_app.command("verify")
def audit_verify_cmd(
    json_output: bool = typer.Option(False, "--json", help="Output verification result in JSON format"),
):
    """Verify cryptographic hash chain integrity of the command audit log."""
    import json

    from rich.table import Table

    from eva.security.audit import verify_audit_chain
    from eva.ui.formatter import print_error, print_success

    result = verify_audit_chain()

    if json_output:
        data = {
            "valid": result.is_valid,
            "entries": result.count,
            "first_timestamp": result.first_timestamp,
            "last_timestamp": result.last_timestamp,
            "broken_index": result.broken_index,
            "message": result.message,
        }
        console.print(json.dumps(data, indent=2), soft_wrap=True)
    else:
        table = Table(title="Audit Log Hash Chain Verification")
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="magenta")
        status_str = "[green]VALID (Unbroken)[/green]" if result.is_valid else "[red]COMPROMISED / BROKEN[/red]"
        table.add_row("Status", status_str)
        table.add_row("Verified Records", str(result.count))
        table.add_row("First Timestamp", str(result.first_timestamp or "N/A"))
        table.add_row("Last Timestamp", str(result.last_timestamp or "N/A"))
        if not result.is_valid:
            table.add_row("Broken Sequence / Line", str(result.broken_index or "Unknown"))
        table.add_row("Details", result.message)
        console.print(table)
        if result.is_valid:
            print_success(result.message)
        else:
            print_error(result.message)

    if not result.is_valid:
        raise typer.Exit(1)


@audit_app.command("show")
def audit_show_cmd(
    tail: int = typer.Option(20, "--tail", "-n", "--limit", help="Number of recent records to display"),
    json_output: bool = typer.Option(False, "--json", help="Output records in JSON format"),
):
    """Show recent command audit log records with secret redaction."""
    import json

    from rich.table import Table

    from eva.security.audit import _sanitize_dict, get_command_audit_log
    from eva.ui.formatter import print_info

    log_file = get_command_audit_log()
    records = []
    if log_file.exists() and log_file.stat().st_size > 0:
        with open(log_file, "r", encoding="utf-8") as f:
            for line in f:
                line_str = line.strip()
                if line_str:
                    try:
                        record = json.loads(line_str)
                        records.append(_sanitize_dict(record))
                    except (json.JSONDecodeError, ValueError, TypeError):
                        pass

    if tail > 0:
        records = records[-tail:]

    if json_output:
        console.print(json.dumps(records, indent=2), soft_wrap=True)
        return

    if not records:
        print_info("Audit log is empty.")
        return

    table = Table(title=f"Command Audit Log (showing {len(records)} entries)")
    table.add_column("Seq", style="cyan", justify="right")
    table.add_column("Timestamp", style="dim")
    table.add_column("Action / Command", style="yellow")
    table.add_column("Hash Prefix", style="green")
    table.add_column("Details", style="white")

    for r in records:
        seq = str(r.get("seq", "?"))
        ts = str(r.get("timestamp", ""))
        action = str(r.get("action") or r.get("command") or "")
        h = str(r.get("hash", ""))[:12] + "..." if r.get("hash") else ""
        details = ", ".join(
            f"{k}={v}" for k, v in r.items() if k not in ("seq", "timestamp", "action", "command", "hash", "prev_hash")
        )
        table.add_row(seq, ts, action, h, details[:80])

    console.print(table)
