from unittest.mock import MagicMock, patch

import keyring
import pytest
from keyring.errors import KeyringError, NoKeyringError

from eva.config import (
    KeyringUnavailableError,
    clear_api_key,
    get_api_key,
    keyring_backend_available,
    set_api_key,
)


def test_get_api_key_keyring(monkeypatch):
    monkeypatch.delenv("EVA_GROQ_API_KEY", raising=False)
    with patch("keyring.get_password", return_value="secret_key"):
        assert get_api_key("groq") == "secret_key"


def test_get_api_key_no_keyring_error(monkeypatch):
    monkeypatch.delenv("EVA_GROQ_API_KEY", raising=False)
    with patch("keyring.get_password", side_effect=NoKeyringError()):
        assert get_api_key("groq") is None


def test_get_api_key_keyring_error(monkeypatch):
    monkeypatch.delenv("EVA_GROQ_API_KEY", raising=False)
    with patch("keyring.get_password", side_effect=KeyringError("backend failed")):
        assert get_api_key("groq") is None


def test_set_api_key_success():
    with patch("keyring.set_password") as mock_set:
        set_api_key("groq", "new_key")
        mock_set.assert_called_once_with("eva", "groq", "new_key")


def test_set_api_key_no_keyring_error():
    with patch("keyring.set_password", side_effect=NoKeyringError()), pytest.raises(KeyringUnavailableError):
        set_api_key("groq", "key")


def test_set_api_key_generic_keyring_error():
    with patch("keyring.set_password", side_effect=KeyringError("fail")), pytest.raises(KeyringUnavailableError):
        set_api_key("groq", "key")


def test_clear_api_key_success():
    with patch("keyring.delete_password") as mock_del:
        clear_api_key("groq")
        mock_del.assert_called_once_with("eva", "groq")


def test_clear_api_key_missing_password():
    with patch("keyring.delete_password", side_effect=keyring.errors.PasswordDeleteError()):
        clear_api_key("groq")  # Should not raise


def test_clear_api_key_no_keyring_error():
    with patch("keyring.delete_password", side_effect=NoKeyringError()), pytest.raises(KeyringUnavailableError):
        clear_api_key("groq")


def test_clear_api_key_generic_keyring_error():
    with patch("keyring.delete_password", side_effect=KeyringError("fail")), pytest.raises(KeyringUnavailableError):
        clear_api_key("groq")


def test_keyring_backend_available_success():
    with patch("keyring.get_keyring") as mock_get, patch("keyring.get_password"):
        mock_backend = MagicMock()
        mock_backend.priority = 10
        mock_get.return_value = mock_backend
        ok, info = keyring_backend_available()
        assert ok is True
        assert "priority=10" in info


def test_keyring_backend_available_failure():
    with patch("keyring.get_keyring", side_effect=NoKeyringError()):
        ok, _ = keyring_backend_available()
        assert ok is False


def test_keyring_backend_available_zero_priority():
    with patch("keyring.get_keyring") as mock_get:
        mock_backend = MagicMock()
        mock_backend.priority = 0
        mock_backend.__class__.__name__ = "FailKeyring"
        mock_get.return_value = mock_backend
        ok, info = keyring_backend_available()
        assert ok is False
        assert "priority=0" in info


def test_keyring_fallback_degradation_behavior(monkeypatch):
    """Explicitly verify that when keyring is unavailable, Eva degrades gracefully to documented fallback."""
    # 1. Environment variable fallback works when env var is present
    monkeypatch.setenv("EVA_GROQ_API_KEY", "env-secret-123")
    with patch("keyring.get_password", side_effect=NoKeyringError()):
        assert get_api_key("groq") == "env-secret-123"

    # 2. When env var is missing and keyring is unavailable, get_api_key returns None
    monkeypatch.delenv("EVA_GROQ_API_KEY", raising=False)
    with patch("keyring.get_password", side_effect=NoKeyringError()):
        assert get_api_key("groq") is None

    # 3. set_api_key raises KeyringUnavailableError instructing user to set env var
    with (
        patch("keyring.set_password", side_effect=NoKeyringError()),
        pytest.raises(KeyringUnavailableError) as exc_info,
    ):
        set_api_key("groq", "new-key")
    assert "EVA_GROQ_API_KEY" in str(exc_info.value)
