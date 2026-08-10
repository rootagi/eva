import hashlib
import logging
import os

import tiktoken

logger = logging.getLogger(__name__)

# Module-level encoding cache
_encoding: tiktoken.Encoding | None = None
_encoding_loaded: bool = False
_warning_emitted: bool = False


def _get_encoding() -> tiktoken.Encoding | None:
    """Return the cl100k_base encoding, or None if unavailable.

    Resolution order:
      1. EVA_TIKTOKEN_ENCODING_PATH env var  →  load from local file
      2. tiktoken.get_encoding()             →  may download on first use
      3. None (fallback to approximate counting)
    """
    global _encoding, _encoding_loaded, _warning_emitted

    if _encoding_loaded:
        return _encoding

    # 1. Try user-supplied local encoding file
    custom_path = os.environ.get("EVA_TIKTOKEN_ENCODING_PATH")
    if custom_path:
        try:
            with open(custom_path, "rb") as f:
                contents = f.read()
            data_hash = hashlib.sha256(contents).hexdigest()
            mergeable_ranks: dict[bytes, int] = {}
            import base64

            for line in contents.splitlines():
                line = line.strip()
                if not line:
                    continue
                parts = line.split()
                if len(parts) != 2:
                    continue
                token_bytes = base64.b64decode(parts[0])
                rank = int(parts[1])
                mergeable_ranks[token_bytes] = rank
            # cl100k_base uses these special tokens
            special_tokens = {
                "<|endoftext|>": 100257,
                "<|fim_prefix|>": 100258,
                "<|fim_middle|>": 100259,
                "<|fim_suffix|>": 100260,
                "<|endofprompt|>": 100276,
            }
            _encoding = tiktoken.Encoding(
                name=f"cl100k_base_local_{data_hash[:8]}",
                pat_str=r"""'(?i:[sdmt]|ll|ve|re)|[^\r\n\p{L}\p{N}]?\p{L}+|\p{N}{1,3}| ?[^\s\p{L}\p{N}]+[\r\n]*|\s*[\r\n]|\s+(?!\S)|\s+""",
                mergeable_ranks=mergeable_ranks,
                special_tokens=special_tokens,
            )
            _encoding_loaded = True
            logger.debug("Loaded tiktoken encoding from %s", custom_path)
            return _encoding
        except Exception as exc:  # noqa: BLE001 – intentionally catch all errors (network, SSL, IO)
            if not _warning_emitted:
                logger.warning(
                    "Failed to load tiktoken encoding from EVA_TIKTOKEN_ENCODING_PATH=%s: %s. Trying default download.",
                    custom_path,
                    exc,
                )
                _warning_emitted = True

    # 2. Try tiktoken's built-in download/cache
    try:
        _encoding = tiktoken.get_encoding("cl100k_base")
        _encoding_loaded = True
        return _encoding
    except Exception as exc:  # noqa: BLE001 – intentionally catch all errors (network, SSL, IO)
        if not _warning_emitted:
            logger.warning(
                "Could not load tiktoken cl100k_base encoding (network unavailable?): %s. "
                "Token counting will use an approximate character-based method.",
                exc,
            )
            _warning_emitted = True
        _encoding_loaded = True  # Don't retry on every call
        return None


def reset_encoding_cache() -> None:
    """Reset the module-level encoding cache. Intended for testing."""
    global _encoding, _encoding_loaded, _warning_emitted
    _encoding = None
    _encoding_loaded = False
    _warning_emitted = False


def count_tokens(text: str) -> int:
    encoding = _get_encoding()
    if encoding is not None:
        return len(encoding.encode(text))
    # Fallback approximation: 1 token ~= 4 chars
    return len(text) // 4


def trim_context(text: str, max_tokens: int, keep: str = "head") -> str:
    """Trim text to a token budget.

    keep="head" preserves the beginning of static context such as files.
    keep="tail" preserves the end of rolling context such as chat history.
    """
    if keep not in {"head", "tail"}:
        raise ValueError("keep must be 'head' or 'tail'")

    encoding = _get_encoding()
    if encoding is not None:
        tokens = encoding.encode(text)
        if len(tokens) <= max_tokens:
            return text
        if keep == "tail":
            return "...[Context Trimmed]...\n" + encoding.decode(tokens[-max_tokens:])
        return encoding.decode(tokens[:max_tokens]) + "\n...[Context Trimmed]..."

    # Fallback: approximate by characters
    max_chars = max_tokens * 4
    if len(text) <= max_chars:
        return text
    if keep == "tail":
        return "...[Context Trimmed]...\n" + text[-max_chars:]
    return text[:max_chars] + "\n...[Context Trimmed]..."
