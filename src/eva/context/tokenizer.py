import tiktoken


def count_tokens(text: str) -> int:
    try:
        encoding = tiktoken.get_encoding("cl100k_base")
        return len(encoding.encode(text))
    except (ValueError, KeyError, RuntimeError, TypeError):
        # Fallback approximation: 1 token ~= 4 chars
        return len(text) // 4


def trim_context(text: str, max_tokens: int, keep: str = "head") -> str:
    """Trim text to a token budget.

    keep="head" preserves the beginning of static context such as files.
    keep="tail" preserves the end of rolling context such as chat history.
    """
    if keep not in {"head", "tail"}:
        raise ValueError("keep must be 'head' or 'tail'")

    try:
        encoding = tiktoken.get_encoding("cl100k_base")
        tokens = encoding.encode(text)
        if len(tokens) <= max_tokens:
            return text
        if keep == "tail":
            return "...[Context Trimmed]...\n" + encoding.decode(tokens[-max_tokens:])
        return encoding.decode(tokens[:max_tokens]) + "\n...[Context Trimmed]..."
    except (ValueError, KeyError, RuntimeError, TypeError):
        # Fallback
        max_chars = max_tokens * 4
        if len(text) <= max_chars:
            return text
        if keep == "tail":
            return "...[Context Trimmed]...\n" + text[-max_chars:]
        return text[:max_chars] + "\n...[Context Trimmed]..."
