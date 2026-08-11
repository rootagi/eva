from pathlib import Path

MAX_CONTEXT_FILE_BYTES = 1_000_000


class ContextReadError(RuntimeError):
    pass


def read_text_file_for_context(path: Path, max_bytes: int = MAX_CONTEXT_FILE_BYTES) -> tuple[str, list[str]]:
    """Read a file for model context without crashing on invalid UTF-8.

    Returns (text, warnings). Binary files are rejected because replacement text
    tends to waste context and mislead the model.
    """
    warnings: list[str] = []

    if not path.exists():
        raise ContextReadError(f"File {path} does not exist.")
    if not path.is_file():
        raise ContextReadError(f"{path} is not a regular file.")

    size = path.stat().st_size
    read_limit = min(size, max_bytes)
    with open(path, "rb") as f:
        data = f.read(read_limit)

    if b"\x00" in data:
        raise ContextReadError(f"{path} appears to be binary; refusing to send it as text context.")

    if size > max_bytes:
        warnings.append(f"{path} is {size} bytes; only the first {max_bytes} bytes were read.")

    return data.decode("utf-8", errors="replace"), warnings
