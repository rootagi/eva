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


def is_sensitive_file(relative_path: str | Path) -> bool:
    """Check if a relative file path matches the sensitive file denylist."""
    filename = Path(relative_path).name.lower()
    return any(fnmatch.fnmatchcase(filename, pattern) for pattern in DENYLIST_PATTERNS)
