"""Interactive Terminal Web Explorer with Non-TTY Detection and Link Navigation."""

from __future__ import annotations

import sys

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()


def is_interactive_tty() -> bool:
    """Check if the current process is connected to an interactive TTY."""
    return sys.stdin.isatty() and sys.stdout.isatty()


def explore_web(query: str | None = None) -> None:
    """Run interactive web SERP navigation and page reader."""
    if not is_interactive_tty():
        console.print("[yellow]Notice: Interactive terminal explorer requires an interactive TTY terminal.[/yellow]")
        sys.exit(1)

    from eva.web.fetcher import fetch_url
    from eva.web.searxng import search

    current_query = query or ""
    if not current_query:
        try:
            current_query = input("Enter search query: ").strip()
        except (EOFError, KeyboardInterrupt):
            return

    if not current_query:
        return

    results = search(current_query, limit=10)
    if not results:
        console.print(f"[red]No search results found for '{current_query}'.[/red]")
        return

    table = Table(title=f"Search Results: {current_query}", show_lines=True)
    table.add_column("#", style="cyan", width=4)
    table.add_column("Title", style="bold green")
    table.add_column("URL", style="blue")
    table.add_column("Snippet", style="dim")

    for i, r in enumerate(results, start=1):
        table.add_row(str(i), r.get("title", ""), r.get("url", ""), r.get("description", "")[:120])

    console.print(table)
    console.print("[yellow]Enter result number to open, or 'q' to quit:[/yellow]")

    try:
        choice = input("> ").strip().lower()
        if choice in ("q", "quit", "exit"):
            return
        if choice.isdigit() and 1 <= int(choice) <= len(results):
            selected = results[int(choice) - 1]
            target_url = selected["url"]
            console.print(f"[green]Fetching {target_url}...[/green]")
            doc = fetch_url(target_url)
            console.print(
                Panel(
                    doc.get("body_markdown", "")[:4000],
                    title=f"[bold]{doc.get('title', 'Page Content')}[/bold]",
                    subtitle=target_url,
                )
            )
    except (EOFError, KeyboardInterrupt):
        pass
