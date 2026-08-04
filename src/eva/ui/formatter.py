from rich.console import Console
from rich.markdown import Markdown
from rich.markup import escape
from rich.panel import Panel
from rich.theme import Theme

eva_theme = Theme(
    {
        "info": "cyan",
        "warning": "yellow",
        "error": "bold red",
        "success": "green",
    }
)

console = Console(theme=eva_theme)
err_console = Console(theme=eva_theme, stderr=True)


def print_error(msg: str):
    err_console.print(f"[error]✖ {escape(msg)}[/error]")


def print_success(msg: str):
    err_console.print(f"[success]✔ {escape(msg)}[/success]")


def print_info(msg: str):
    err_console.print(f"[info]ℹ {escape(msg)}[/info]")


def print_warning(msg: str):
    err_console.print(f"[warning]⚠ {escape(msg)}[/warning]")


def print_markdown(content: str, title: str | None = None):
    md = Markdown(content)
    if title:
        console.print(Panel(md, title=f"[info]{title}[/info]", border_style="cyan"))
    else:
        console.print(md)


def is_ai_error(result: str) -> bool:
    stripped = result.strip()
    return stripped.startswith(("[Eva Error]", "Error:")) or "\n[Eva Error]" in result
