import typer

from eva.cli.helpers import _resolve_app_attr, console

budget_app = typer.Typer(help="Inspect rate limits and token budget usage.")


@budget_app.command("show")
def show_budget():
    """Show current request usage counts and rate limit budgets."""
    from rich.table import Table

    from eva.config import load_config as _load_config
    from eva.providers import get_provider
    from eva.workflows.budget import load_budget, normalize_usage_stats, remaining_budget

    load_config = _resolve_app_attr("load_config", _load_config)
    config = load_config()
    budget = load_budget()

    table = Table(title="Token Budget & Rate Limit Usage")
    table.add_column("Provider", style="cyan")
    table.add_column("RPM Limit", style="yellow")
    table.add_column("Used (Min)", style="magenta")
    table.add_column("RPD Limit", style="yellow")
    table.add_column("Used (Day)", style="magenta")

    for name in config.providers:
        provider = get_provider(name)
        if not provider:
            continue

        rpd_rem, rpm_rem = remaining_budget(name, provider.max_rpm, provider.max_rpd)
        stats = budget.usage_by_provider.get(name)
        stats_norm = normalize_usage_stats(stats) if stats else None

        used_min = stats_norm.requests_this_minute if stats_norm else 0
        used_day = stats_norm.requests_today if stats_norm else 0

        table.add_row(
            name,
            str(provider.max_rpm),
            f"{used_min} ({rpm_rem} left)",
            str(provider.max_rpd),
            f"{used_day} ({rpd_rem} left)",
        )

    console.print(table)


def usage():
    """Show normalized local provider usage counters."""
    show_budget()
