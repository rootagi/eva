import json
from typing import Any

from eva.ui.formatter import is_ai_error, print_error, print_markdown


def emit_result(content: str, output_format: str, meta: dict[str, Any] | None = None) -> bool:
    """Print a command result in the requested format.

    Returns True if `content` represents an error (so callers can set the
    process exit code consistently across both formats).
    """
    error = is_ai_error(content)
    if output_format == "json":
        payload = {"content": content.strip(), "is_error": error, **(meta or {})}
        print(json.dumps(payload, indent=2))
    else:
        if error:
            print_error(content.strip())
        else:
            print_markdown(content)
    return error
