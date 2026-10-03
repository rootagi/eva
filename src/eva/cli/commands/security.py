import click
import typer
from typer.core import TyperGroup


class _LazySecGroup(TyperGroup):
    """Click group wrapper that lazily imports eva.security_tools.cli only when 'eva sec' is invoked."""

    _real_group: click.Group | None = None

    def _get_real_group(self) -> click.Group:
        if self._real_group is None:
            from eva.security_tools.cli import sec_app as real_sec_app

            self._real_group = typer.main.get_group(real_sec_app)
        return self._real_group

    def list_commands(self, ctx: click.Context) -> list[str]:
        return self._get_real_group().list_commands(ctx)

    def get_command(self, ctx: click.Context, cmd_name: str) -> click.Command | None:
        return self._get_real_group().get_command(ctx, cmd_name)


sec_app = typer.Typer(
    name="sec",
    cls=_LazySecGroup,
    help="Authorized security assessment and evidence analysis.",
)
