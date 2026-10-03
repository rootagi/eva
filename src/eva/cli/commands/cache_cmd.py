import typer

from eva.cli.helpers import _resolve_app_attr

cache_app = typer.Typer(help="Manage response cache.")


@cache_app.command("clear")
def cache_clear_cmd():
    """Clear cached AI responses."""
    from eva.cache import clear_cache as _clear_cache
    from eva.ui.formatter import print_success

    clear_cache = _resolve_app_attr("clear_cache", _clear_cache)
    clear_cache()
    print_success("Cache cleared.")
