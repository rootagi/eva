"""Web search, browsing, indexing, and terminal imaging CLI commands."""

from __future__ import annotations

import json
import logging
from typing import Any

import typer

from eva.cli.helpers import console

logger = logging.getLogger(__name__)

web_app = typer.Typer(
    name="web",
    help="Terminal web search, offline FTS5 indexing, and rich image preview.",
    no_args_is_help=True,
)


@web_app.command("search")
def search_cmd(
    query: str = typer.Argument(..., help="Search query string"),
    offline: bool = typer.Option(False, "--offline", help="Search only local offline FTS5 cache"),
    category: str = typer.Option("general", "--category", "-c", help="SearXNG category"),
    limit: int = typer.Option(10, "--limit", "-n", help="Maximum search results to return"),
    output_format: str = typer.Option("text", "--format", "-f", help="Output format: text, json, or url"),
) -> None:
    """Search the web via SearXNG or query offline cached documents."""
    from eva.web.searxng import search

    results = search(query=query, category=category, limit=limit, offline=offline)

    if results:
        from eva.web.index import WebIndex

        try:
            WebIndex().save_last_search(results, query=query)
        except (OSError, RuntimeError, ValueError) as exc:
            logger.debug("Failed to save last search results: %s", exc)

    if output_format == "json":
        print(json.dumps(results, indent=2))
        return

    if output_format == "url":
        for i, r in enumerate(results, start=1):
            url = r.get("url", "")
            title = r.get("title", "")
            console.print(f"[cyan]#{i:2d}[/cyan] [blue]{url}[/blue] [dim]({title})[/dim]")
        return

    if not results:
        console.print(f"[yellow]No results found for '{query}'.[/yellow]")
        return

    from rich.markup import escape
    from rich.table import Table

    table = Table(title=f"Web Search Results ({len(results)})", show_lines=True)
    table.add_column("#", style="cyan", width=4)
    table.add_column("Title", style="bold green")
    table.add_column("URL", style="blue")
    table.add_column("Snippet", style="dim")

    for i, r in enumerate(results, start=1):
        url = r.get("url", "").strip()
        title = r.get("title", "")
        snippet = (r.get("description") or "")[:150]

        if url:
            title_cell = f"[link={url}]{escape(title)}[/link]"
            url_cell = f"[link={url}]{escape(url)}[/link]"
        else:
            title_cell = escape(title)
            url_cell = ""

        table.add_row(str(i), title_cell, url_cell, snippet)
    console.print(table)
    console.print("[dim]Tip: Ctrl+Click any Title or URL to open in browser, or run 'eva web open <#> -b'[/dim]")


@web_app.command("open")
def open_cmd(
    url_or_id: str = typer.Argument(..., help="URL to fetch, indexed document ID, or search result #"),
    show_images: bool = typer.Option(False, "--images", "-i", help="Render images found in document"),
    output_format: str = typer.Option("text", "--format", "-f", help="Output format: text or json"),
    browser: bool = typer.Option(False, "--browser", "-b", help="Open document directly in system web browser"),
) -> None:
    """Open and render a web page or indexed document in terminal reader mode."""
    from eva.web.fetcher import fetch_url
    from eva.web.index import WebIndex

    idx = WebIndex()
    clean_arg = url_or_id.strip()
    is_num = clean_arg.lstrip("#").isdigit()

    doc = None
    target_url: str | None = None

    if is_num:
        num_val = int(clean_arg.lstrip("#"))
        # Priority 1: Check most recent search result index (e.g. 1..10)
        last_item = idx.get_last_search_item(num_val)
        if last_item and last_item.get("url"):
            target_url = last_item["url"]
            doc = idx.get_document(target_url)
            if not doc:
                doc = {
                    "url": target_url,
                    "title": last_item.get("title", ""),
                    "description": last_item.get("description", ""),
                    "body_markdown": "",
                    "image_urls": [last_item["img_src"]] if last_item.get("img_src") else [],
                }
        else:
            # Priority 2: Fall back to database primary key ID
            doc = idx.get_document(num_val)
            if doc:
                target_url = doc.get("url")
    else:
        # Priority 3: Direct URL string
        target_url = clean_arg
        doc = idx.get_document(target_url)

    if not target_url:
        console.print(f"[red]Result or document '{url_or_id}' not found in recent search or index.[/red]")
        raise typer.Exit(code=1)

    if browser:
        import webbrowser

        console.print(f"[green]Opening in browser:[/green] {target_url}")
        webbrowser.open(target_url)
        return

    # Fetch live content if document is missing or was only passively indexed without markdown
    if not doc or not doc.get("body_markdown"):
        if not target_url.startswith(("http://", "https://")):
            console.print(f"[red]Document ID '{url_or_id}' not found in index.[/red]")
            raise typer.Exit(code=1)

        try:
            fetched = fetch_url(target_url)
            idx.index_document(
                url=fetched["url"],
                title=fetched.get("title") or (doc.get("title") if doc else ""),
                description=fetched.get("description") or (doc.get("description") if doc else ""),
                body_markdown=fetched.get("body_markdown", ""),
                image_urls=fetched.get("images", []),
            )
            doc = fetched
        except Exception as exc:
            if not doc:
                console.print(f"[red]Failed to fetch '{target_url}': {exc}[/red]")
                raise typer.Exit(code=1) from exc
            console.print(f"[dim]Could not fetch live content from '{target_url}': {exc}[/dim]")

    if output_format == "json":
        print(json.dumps(doc, indent=2))
        return

    from rich.markdown import Markdown
    from rich.panel import Panel

    body = (doc.get("body_markdown") or "").strip()
    content: Any = Markdown(body) if body else "[dim]No readable markdown content extracted.[/dim]"

    console.print(
        Panel(
            content,
            title=f"[bold green]{doc.get('title', 'Document')}[/bold green]",
            subtitle=doc.get("url", ""),
        )
    )

    if show_images and doc.get("image_urls"):
        from eva.web.imaging import render_image

        for img_url in doc["image_urls"][:3]:
            try:
                rendered = render_image(img_url)
                if rendered:
                    console.print(rendered)
            except (OSError, RuntimeError, ValueError) as exc:
                console.print(f"[dim]Failed to render image {img_url}: {exc}[/dim]")


@web_app.command("index")
def index_cmd(
    url: str = typer.Argument(..., help="Starting URL to crawl and index"),
    depth: int = typer.Option(1, "--depth", "-d", help="Crawl depth"),
    same_domain: bool = typer.Option(True, "--same-domain", help="Restrict crawling to the same domain"),
    max_pages: int = typer.Option(10, "--max-pages", help="Maximum pages to index"),
) -> None:
    """Crawl and index a web page and linked documents into SQLite FTS5 database."""
    import urllib.parse

    from eva.web.fetcher import fetch_url
    from eva.web.index import WebIndex

    idx = WebIndex()
    visited: set[str] = set()
    queue: list[tuple[str, int]] = [(url, 0)]
    initial_domain = urllib.parse.urlparse(url).netloc
    indexed_count = 0

    while queue and indexed_count < max_pages:
        current_url, current_depth = queue.pop(0)
        if current_url in visited:
            continue
        visited.add(current_url)

        try:
            console.print(f"[cyan]Indexing ({indexed_count + 1}/{max_pages}):[/cyan] {current_url}")
            doc = fetch_url(current_url)
            idx.index_document(
                url=doc["url"],
                title=doc.get("title", ""),
                description=doc.get("description", ""),
                body_markdown=doc.get("body_markdown", ""),
                image_urls=doc.get("images", []),
            )
            indexed_count += 1

            if current_depth < depth:
                for link in doc.get("links", []):
                    target = link.get("url", "")
                    if target.startswith(("http://", "https://")):
                        target_domain = urllib.parse.urlparse(target).netloc
                        if (not same_domain or target_domain == initial_domain) and target not in visited:
                            queue.append((target, current_depth + 1))
        except (OSError, RuntimeError, ValueError) as exc:
            console.print(f"[yellow]Skipping {current_url}: {exc}[/yellow]")

    console.print(f"[green]Successfully indexed {indexed_count} pages.[/green]")


@web_app.command("image")
def image_cmd(
    url_or_path: str = typer.Argument(..., help="Image URL, local file path, or search result #"),
    protocol: str = typer.Option(
        "auto", "--protocol", "-p", help="Terminal image protocol: auto, kitty, sixel, iterm2, halfblock"
    ),
    width: int = typer.Option(80, "--width", "-w", help="Output character width"),
    view: bool = typer.Option(False, "--view", "-v", help="Open in system HD image viewer (xdg-open)"),
    browser: bool = typer.Option(False, "--browser", "-b", help="Open image URL in web browser"),
) -> None:
    """Render an image in the terminal using Kitty, Sixel, iTerm2, or half-blocks, or open in HD viewer."""
    import subprocess
    import tempfile
    import webbrowser
    from pathlib import Path

    clean_target = url_or_path.strip()
    if clean_target.lstrip("#").isdigit():
        num_val = int(clean_target.lstrip("#"))
        from eva.web.index import WebIndex

        idx = WebIndex()
        last_item = idx.get_last_search_item(num_val)
        if last_item:
            resolved = last_item.get("img_src") or last_item.get("url")
            if resolved:
                url_or_path = resolved

    if browser:
        target = (
            url_or_path if url_or_path.startswith(("http://", "https://")) else f"file://{Path(url_or_path).resolve()}"
        )
        console.print(f"[green]Opening in browser:[/green] {target}")
        webbrowser.open(target)
        return

    if view:
        if url_or_path.startswith(("http://", "https://")):
            import httpx

            with httpx.Client(timeout=10.0) as client:
                resp = client.get(url_or_path)
                resp.raise_for_status()
                ext = ".jpg"
                ct = resp.headers.get("content-type", "")
                if "png" in ct:
                    ext = ".png"
                elif "webp" in ct:
                    ext = ".webp"
                elif "gif" in ct:
                    ext = ".gif"
                with tempfile.NamedTemporaryFile(delete=False, suffix=ext) as tmp:
                    tmp.write(resp.content)
                    target_file = tmp.name
        else:
            target_file = str(Path(url_or_path).resolve())

        console.print(f"[green]Opening in HD image viewer:[/green] {target_file}")
        try:
            subprocess.Popen(["xdg-open", target_file], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except OSError as exc:
            console.print(f"[yellow]Could not launch viewer: {exc}[/yellow]")
        return

    from eva.web.imaging import render_image

    rendered = render_image(url_or_path, protocol=protocol, width=width)
    if rendered:
        sys_stdout = console.file
        sys_stdout.write(rendered)
        sys_stdout.flush()


@web_app.command("images")
def images_cmd(
    query: str = typer.Argument(..., help="Search query for images"),
    cols: int = typer.Option(3, "--cols", "-c", help="Number of columns in the grid (e.g. 3 for 3x3)"),
    limit: int = typer.Option(9, "--limit", "-n", help="Total number of images to return (e.g. 9 for 3x3)"),
    width: int = typer.Option(80, "--width", "-w", help="Output terminal character width"),
    protocol: str = typer.Option(
        "auto", "--protocol", "-p", help="Terminal image protocol: auto, kitty, iterm2, halfblock"
    ),
    view: bool = typer.Option(False, "--view", "-v", help="Open composite gallery in HD system viewer (xdg-open)"),
) -> None:
    """Search for images via SearXNG and render directly in a 3x3 grid or terminal ratio."""
    import subprocess
    import tempfile

    from rich.markup import escape
    from rich.table import Table

    from eva.web.imaging import create_image_grid, render_image
    from eva.web.searxng import search

    console.print(f"[dim]Searching images for '{query}'...[/dim]")
    results = search(query=query, category="images", limit=limit)

    if results:
        from eva.web.index import WebIndex

        try:
            WebIndex().save_last_search(results, query=query)
        except (OSError, RuntimeError, ValueError) as exc:
            logger.debug("Failed to save last search results: %s", exc)

    if not results:
        console.print(f"[yellow]No image results found for '{query}'.[/yellow]")
        console.print("[dim]Ensure your SearXNG instance is running and has image search enabled.[/dim]")
        return

    console.print(f"[cyan]Rendering {len(results)} images in {cols}-column grid...[/cyan]")
    grid_bytes, loaded_items = create_image_grid(results, cols=cols)

    if not grid_bytes:
        console.print("[red]Failed to load or compile image results.[/red]")
        return

    if view:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".png") as tmp:
            tmp.write(grid_bytes)
            tmp_name = tmp.name
        console.print(f"[green]Opening gallery in HD image viewer:[/green] {tmp_name}")
        try:
            subprocess.Popen(["xdg-open", tmp_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except OSError as exc:
            console.print(f"[yellow]Could not launch viewer: {exc}[/yellow]")
        return

    rendered = render_image(grid_bytes, protocol=protocol, width=width)
    if rendered:
        sys_stdout = console.file
        sys_stdout.write(rendered)
        sys_stdout.flush()

    table = Table(title="Gallery Index", show_lines=False)
    table.add_column("#", style="cyan", width=4)
    table.add_column("Title", style="bold")
    table.add_column("Source / Image Link", style="blue")

    for i, item in enumerate(loaded_items, start=1):
        full_url = item.get("img_src") or item.get("url", "")
        title = item.get("title", f"Image {i}")
        link_cell = f"[link={full_url}]{escape(full_url)}[/link]" if full_url else "[dim]No URL[/dim]"
        title_cell = f"[link={full_url}]{escape(title)}[/link]" if full_url else escape(title)
        table.add_row(f"#{i}", title_cell, link_cell)

    console.print(table)
    console.print("[dim]Tip: Ctrl+Click any Title or Link to view full-res, or run 'eva web image <URL> -v'[/dim]")


@web_app.command("history")
def history_cmd(
    limit: int = typer.Option(20, "--limit", "-n", help="Maximum history records to display"),
    output_format: str = typer.Option("text", "--format", "-f", help="Output format: text or json"),
) -> None:
    """Show browsing and index history from local database."""
    from eva.web.index import WebIndex

    idx = WebIndex()
    records = idx.list_history(limit=limit)

    if output_format == "json":
        print(json.dumps(records, indent=2))
        return

    if not records:
        console.print("[dim]No browsing or indexing history found.[/dim]")
        return

    from rich.table import Table

    table = Table(title="Web History", show_lines=False)
    table.add_column("ID", style="cyan", width=5)
    table.add_column("Title", style="bold")
    table.add_column("Domain", style="blue")
    table.add_column("URL", style="dim")

    for rec in records:
        table.add_row(str(rec.get("id", "")), rec.get("title", ""), rec.get("domain", ""), rec.get("url", ""))
    console.print(table)


@web_app.command("explore")
def explore_cmd(
    query: str = typer.Argument(None, help="Initial search query to explore"),
) -> None:
    """Interactive SERP explorer and terminal web reader."""
    from eva.web.explorer import explore_web

    explore_web(query=query)
