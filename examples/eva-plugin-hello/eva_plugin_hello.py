"""Example plugin implementation for Eva CLI."""

import typer

from eva.plugins import EvaPlugin


class HelloPlugin(EvaPlugin):
    """Example plugin that registers a single harmless 'hello' CLI command."""

    name = "eva-hello"
    version = "0.1.0"

    def register_commands(self, app: typer.Typer) -> None:
        @app.command("hello")
        def hello(name: str = typer.Argument("World", help="Name to greet")):
            """Say hello — example command added by eva-hello plugin."""
            typer.echo(f"Hello, {name}! (from eva-hello plugin)")
