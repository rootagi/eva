from collections.abc import Iterator

from rich.live import Live
from rich.spinner import Spinner

from eva.ui.formatter import err_console


def stream_response(stream: Iterator[str]) -> str:
    """Consume a streaming LLM response, showing progress on stderr."""
    full_text = ""
    got_first_chunk = False

    with Live(Spinner("dots", text="Thinking..."), console=err_console, refresh_per_second=10, transient=True) as live:
        for chunk in stream:
            full_text += chunk
            if not got_first_chunk:
                got_first_chunk = True
            live.update(Spinner("dots", text=f"Receiving... ({len(full_text)} chars)"))

    return full_text
