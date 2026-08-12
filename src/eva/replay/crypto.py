"""Encryption for replay session data at rest.

redact_secrets() strips known secret patterns from command/output text,
but terminal output can still carry sensitive data redaction won't
catch (PII, internal hostnames, proprietary data, secret formats we
don't recognize). Replay files are therefore encrypted at rest as a
second layer, independent of redaction.

Key storage mirrors eva.config.config's API-key handling: prefer the
OS keyring, and fall back to a mode-0600 file in the config dir when
no keyring backend is available (headless CI, some containers) so that
replay recording never hard-fails a command.
"""

import json
import logging
from pathlib import Path
from typing import Any

import keyring
from cryptography.fernet import Fernet, InvalidToken
from keyring.errors import KeyringError, NoKeyringError

from eva.config import APP_NAME, get_config_dir

logger = logging.getLogger(__name__)

_KEYRING_USERNAME = "replay-encryption-key"
_FALLBACK_KEY_FILENAME = ".replay.key"

# Broad on purpose: mirrors eva.config.config.keyring_backend_available,
# since misbehaving keyring backends raise more than just KeyringError.
_KEYRING_FAILURE_MODES = (NoKeyringError, KeyringError, RuntimeError, TypeError, AttributeError, ValueError)

_cached_fernet: Fernet | None = None


def restrict_permissions(path: Path) -> None:
    """Best-effort chmod 0600. Public: also used by recorder.py on data files."""
    try:
        path.chmod(0o600)
    except OSError:
        pass  # not all platforms support POSIX perms (e.g. Windows)


def _fallback_key_path() -> Path:
    return get_config_dir() / _FALLBACK_KEY_FILENAME


def _load_or_create_fallback_key() -> bytes:
    path = _fallback_key_path()
    if path.exists():
        return path.read_bytes()
    key = Fernet.generate_key()
    path.write_bytes(key)
    restrict_permissions(path)
    return key


def _get_or_create_key() -> bytes:
    try:
        existing = keyring.get_password(APP_NAME, _KEYRING_USERNAME)
        if existing:
            return existing.encode("utf-8")
        new_key = Fernet.generate_key()
        keyring.set_password(APP_NAME, _KEYRING_USERNAME, new_key.decode("utf-8"))
        return new_key
    except _KEYRING_FAILURE_MODES as exc:
        logger.debug("Keyring unavailable for replay encryption key, using fallback file: %s", exc)
        return _load_or_create_fallback_key()


def get_fernet() -> Fernet:
    """Return a cached Fernet instance, creating/loading the key on first use."""
    global _cached_fernet
    if _cached_fernet is None:
        _cached_fernet = Fernet(_get_or_create_key())
    return _cached_fernet


def reset_cached_fernet() -> None:
    """Clear the cached key/Fernet instance. Mainly useful for tests."""
    global _cached_fernet
    _cached_fernet = None


def encrypt_json(obj: Any) -> bytes:
    return get_fernet().encrypt(json.dumps(obj).encode("utf-8"))


def decrypt_json_line(raw: bytes) -> Any:
    """Decrypt one encrypted JSON record.

    Falls back to plain json.loads on InvalidToken so replay data
    written before encryption was introduced still loads.
    """
    try:
        return json.loads(get_fernet().decrypt(raw))
    except InvalidToken:
        return json.loads(raw)
