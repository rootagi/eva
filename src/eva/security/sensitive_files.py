import fnmatch
from pathlib import Path

DENYLIST_PATTERNS: tuple[str, ...] = (
    ".env",
    ".env.*",
    "*.env",
    "*.key",
    "*.pem",
    "*.p12",
    "*.pfx",
    "*.jks",
    "*.keystore",
    "*.tfvars",
    ".netrc",
    ".npmrc",
    ".pypirc",
    "credentials.json",
    "credentials.*",
    "secrets.*",
    "id_rsa*",
    "id_dsa*",
    "id_ecdsa*",
    "id_ed25519*",
)


_allowlist_patterns: tuple[str, ...] = ()


def configure_sensitive_file_allowlist(patterns: list[str]) -> None:
    """Filenames matching any of these glob patterns are never treated as
    sensitive, overriding DENYLIST_PATTERNS. Call once at startup."""
    global _allowlist_patterns
    _allowlist_patterns = tuple(patterns)


def is_sensitive_file(relative_path: str | Path) -> bool:
    """Check if a relative file path matches the sensitive file denylist."""
    rel_str = str(relative_path)
    filename = Path(relative_path).name.lower()
    if any(fnmatch.fnmatchcase(filename, p.lower()) or fnmatch.fnmatchcase(rel_str, p) for p in _allowlist_patterns):
        return False
    return any(
        fnmatch.fnmatchcase(filename, pattern) or fnmatch.fnmatchcase(rel_str, pattern) for pattern in DENYLIST_PATTERNS
    )
