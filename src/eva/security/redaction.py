import math
import re
from collections import Counter

# Known secret key patterns
SECRET_PATTERNS = [
    # OpenAI, Anthropic, OpenRouter, etc. sk-* keys
    (r"\b(sk-[A-Za-z0-9_-]{20,})\b", "[REDACTED_SECRET_KEY]"),
    # GitHub Personal Access Tokens (ghp, gho, ghu, ghs, ghr, etc.)
    (r"\b(gh[pousr]_[A-Za-z0-9_]{36,})\b", "[REDACTED_GITHUB_TOKEN]"),
    # GitLab Personal Access Tokens (glpat-)
    (r"\b(glpat-[A-Za-z0-9_-]{20,})\b", "[REDACTED_GITLAB_TOKEN]"),
    # AWS Access Key ID
    (r"\b(AKIA[0-9A-Z]{16})\b", "[REDACTED_AWS_KEY_ID]"),
    # Slack Tokens
    (r"\b(xox[bpsra]-[0-9a-zA-Z-]{10,})\b", "[REDACTED_SLACK_TOKEN]"),
    # Eva specific API key env vars
    (r"\b(EVA_[A-Z0-9_]+_API_KEY=)[^\s]+\b", r"\1[REDACTED_API_KEY]"),
    # Bearer and Basic authentication headers
    (r"\b(Bearer\s+)[A-Za-z0-9._~+/-]+=*\b", r"\1[REDACTED_BEARER_TOKEN]"),
    (r"\b(Basic\s+)[A-Za-z0-9._~+/-]+=*\b", r"\1[REDACTED_BASIC_AUTH]"),
    # Generic key assignment patterns (api_key, secret, password, auth_token, etc.)
    (
        r"\b(api[_-]?key|secret|password|passwd|auth[_-]?token|access[_-]?token)\s*[:=]\s*['\"]?[A-Za-z0-9._~+/-]{10,}['\"]?",
        r"\1: [REDACTED]",
    ),
    # PEM Private key blocks
    (
        r"-----BEGIN\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE\s+KEY-----[\s\S]*?-----END\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE\s+KEY-----",
        "[REDACTED_PRIVATE_KEY]",
    ),
]

COMPILED_SECRET_PATTERNS = [(re.compile(p, re.IGNORECASE), repl) for p, repl in SECRET_PATTERNS]

# Token pattern for entropy checking (non-whitespace tokens >= 16 chars)
HIGH_ENTROPY_TOKEN_RE = re.compile(r"\b[A-Za-z0-9+/=_\-.~!@#$%^&*()]{16,}\b")


def shannon_entropy(s: str) -> float:
    """Calculate the Shannon entropy of a string (in bits per character)."""
    if not s:
        return 0.0
    length = len(s)
    counts = Counter(s)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


_current_entropy_threshold: float = 3.5
_current_ignore_patterns: list[re.Pattern] = []


def configure_redaction(entropy_threshold: float, ignore_patterns: list[str]) -> None:
    """Set process-wide redaction tuning from AppConfig. Call once at startup."""
    global _current_entropy_threshold, _current_ignore_patterns
    _current_entropy_threshold = entropy_threshold
    _current_ignore_patterns = [re.compile(p) for p in ignore_patterns]


def _is_ignored_token(token: str) -> bool:
    return any(p.search(token) for p in _current_ignore_patterns)


KNOWN_SAFE_TOKENS = frozenset({"sensitive_file_override"})


def redact_secrets(text: str, entropy_threshold: float | None = None) -> str:
    """Redact secrets, API keys, tokens, private keys, and high-entropy strings from text.

    Applied BEFORE writing data to disk (logs, replay, cache, memory) and BEFORE provider calls.

    entropy_threshold overrides the process-wide configured value for this call
    only; defaults to whatever configure_redaction() set (or 3.5 if never called,
    preserving current behavior for direct/test callers).
    """
    if not text:
        return text

    threshold = entropy_threshold if entropy_threshold is not None else _current_entropy_threshold
    redacted = text

    # Step 1: Regex pattern redaction
    for pattern, repl in COMPILED_SECRET_PATTERNS:
        redacted = pattern.sub(repl, redacted)

    # Step 2: High-entropy string redaction
    def replace_high_entropy(match: re.Match) -> str:
        token = match.group(0)
        # Skip tokens that look like already-redacted markers, standard web URLs, env keys, or known safe tokens
        if (
            "[REDACTED" in token
            or token.startswith(("http://", "https://", "EVA_", "REDACTED_"))
            or token in KNOWN_SAFE_TOKENS
            or _is_ignored_token(token)
        ):
            return token

        if "/" in token:
            segments = token.split("/")
            return "/".join(
                "[REDACTED_HIGH_ENTROPY]"
                if len(seg) >= 16
                and not _is_ignored_token(seg)
                and seg not in KNOWN_SAFE_TOKENS
                and shannon_entropy(seg) > threshold
                else seg
                for seg in segments
            )
        if not _is_ignored_token(token) and token not in KNOWN_SAFE_TOKENS and shannon_entropy(token) > threshold:
            return "[REDACTED_HIGH_ENTROPY]"
        return token

    redacted = HIGH_ENTROPY_TOKEN_RE.sub(replace_high_entropy, redacted)

    return redacted
