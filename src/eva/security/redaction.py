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


def redact_secrets(text: str, entropy_threshold: float = 3.5) -> str:
    """Redact secrets, API keys, tokens, private keys, and high-entropy strings from text.

    Applied BEFORE writing data to disk (logs, replay, cache, memory) and BEFORE provider calls.
    """
    if not text:
        return text

    redacted = text

    # Step 1: Regex pattern redaction
    for pattern, repl in COMPILED_SECRET_PATTERNS:
        redacted = pattern.sub(repl, redacted)

    # Step 2: High-entropy string redaction
    def replace_high_entropy(match: re.Match) -> str:
        token = match.group(0)
        # Skip tokens that look like already-redacted markers or standard web URLs
        if token.startswith(("[REDACTED", "http://", "https://")):
            return token
        # Skip standard UUIDs or hex strings with lower entropy
        if shannon_entropy(token) > entropy_threshold:
            return "[REDACTED_HIGH_ENTROPY]"
        return token

    redacted = HIGH_ENTROPY_TOKEN_RE.sub(replace_high_entropy, redacted)

    return redacted
