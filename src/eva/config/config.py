import logging
import os
from pathlib import Path

import keyring
from keyring.errors import KeyringError, NoKeyringError
from platformdirs import user_config_dir
from pydantic import BaseModel, Field

APP_NAME = "eva"
logger = logging.getLogger(__name__)


class KeyringUnavailableError(RuntimeError):
    """Raised when the host has no usable keyring backend."""


def get_config_dir() -> Path:
    d = Path(user_config_dir(APP_NAME))
    d.mkdir(parents=True, exist_ok=True)
    return d


def get_config_file() -> Path:
    return get_config_dir() / "config.toml"


class ProviderConfig(BaseModel):
    model: str


class GeneralConfig(BaseModel):
    default_provider: str = "openrouter"
    fallback_enabled: bool = True
    fallback_order: list[str] = Field(
        default_factory=lambda: ["openrouter", "groq", "gemini", "opencode_zen", "ollama", "llamacpp"]
    )
    sandbox_risky_commands: bool = False
    telemetry_enabled: bool = False
    telemetry_export_endpoint: str | None = None



class AppConfig(BaseModel):
    general: GeneralConfig = Field(default_factory=GeneralConfig)
    providers: dict[str, ProviderConfig] = Field(
        default_factory=lambda: {
            "openrouter": ProviderConfig(model="openrouter/free"),
            "groq": ProviderConfig(model="llama-3.1-8b-instant"),
            "gemini": ProviderConfig(model="gemini-3-flash"),
            "opencode_zen": ProviderConfig(model="big-pickle"),
            "ollama": ProviderConfig(model="gemma4:12b"),
            "llamacpp": ProviderConfig(model="default"),
        }
    )


def load_config() -> AppConfig:
    import tomli

    config_file = get_config_file()
    if not config_file.exists():
        return AppConfig()

    with open(config_file, "rb") as f:
        data = tomli.load(f)
    return AppConfig(**data)


def save_config(config: AppConfig):
    import tomli_w

    config_file = get_config_file()
    with open(config_file, "wb") as f:
        tomli_w.dump(config.model_dump(exclude_none=True), f)



def get_api_key_env_var(provider: str) -> str:
    normalized = provider.upper().replace("-", "_")
    return f"EVA_{normalized}_API_KEY"


def get_api_key(provider: str) -> str | None:
    env_key = os.getenv(get_api_key_env_var(provider))
    if env_key:
        return env_key
    try:
        return keyring.get_password(APP_NAME, provider)
    except NoKeyringError:
        logger.warning("No keyring backend is available for provider %s", provider)
        return None
    except KeyringError as exc:
        logger.warning("Keyring lookup failed for provider %s: %s", provider, exc)
        return None


def set_api_key(provider: str, key: str):
    try:
        keyring.set_password(APP_NAME, provider, key)
    except NoKeyringError as exc:
        env_var = get_api_key_env_var(provider)
        raise KeyringUnavailableError(
            "No OS keyring backend is available. Install/configure a keyring backend "
            f"or set {env_var} in the environment for this provider."
        ) from exc
    except KeyringError as exc:
        raise KeyringUnavailableError(f"Keyring failed while storing the API key: {exc}") from exc


def clear_api_key(provider: str):
    try:
        keyring.delete_password(APP_NAME, provider)
    except keyring.errors.PasswordDeleteError:
        pass  # Key doesn't exist, which is fine
    except NoKeyringError as exc:
        raise KeyringUnavailableError("No OS keyring backend is available.") from exc
    except KeyringError as exc:
        raise KeyringUnavailableError(f"Keyring failed while deleting the API key: {exc}") from exc


def keyring_backend_available() -> tuple[bool, str]:
    try:
        backend = keyring.get_keyring()
        keyring.get_password(APP_NAME, "__doctor_probe__")
        priority = getattr(backend, "priority", None)
        return True, f"{backend.__class__.__module__}.{backend.__class__.__name__} priority={priority}"
    except NoKeyringError as exc:
        return False, str(exc)
    except KeyringError as exc:
        return False, str(exc)
