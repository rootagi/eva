import json
import os
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from pydantic import BaseModel, Field

from eva.config import get_config_dir

__all__ = [
    "MODEL_PRICING",
    "Budget",
    "UsageStats",
    "atomic_write_json",
    "calculate_cost",
    "check_and_increment",
    "get_budget_file",
    "get_budget_lock_file",
    "get_config_dir",
    "get_live_budget",
    "load_budget",
    "normalize_usage_stats",
    "remaining_budget",
    "reset_provider_usage",
    "save_budget",
]

_budget_thread_lock = threading.RLock()

# Static model pricing table: (input_price_per_1M, output_price_per_1M) in USD
MODEL_PRICING: dict[str, tuple[float, float]] = {
    "llama-3.3-70b-versatile": (0.59, 0.79),
    "llama-3.1-70b-versatile": (0.59, 0.79),
    "llama-3.1-8b-instant": (0.05, 0.08),
    "llama-3.2-1b-preview": (0.04, 0.04),
    "llama-3.2-3b-preview": (0.06, 0.06),
    "llama-3.2-11b-vision-preview": (0.18, 0.18),
    "llama-3.2-90b-vision-preview": (0.90, 0.90),
    "llama-guard-3-8b": (0.20, 0.20),
    "gpt-4o": (2.50, 10.00),
    "gpt-4o-mini": (0.15, 0.60),
    "o1": (15.00, 60.00),
    "o1-mini": (3.00, 12.00),
    "o3-mini": (1.10, 4.40),
    "gemini-2.5-flash": (0.15, 0.60),
    "gemini-2.5-pro": (1.25, 5.00),
    "gemini-3-flash": (0.15, 0.60),
    "claude-3-5-sonnet-20241022": (3.00, 15.00),
    "claude-3-5-haiku-20241022": (0.80, 4.00),
    "deepseek-chat": (0.14, 0.28),
    "deepseek-reasoner": (0.55, 2.19),
}


def calculate_cost(model: str, input_tokens: int = 0, output_tokens: int = 0) -> float | None:
    """Calculate estimated cost in USD based on MODEL_PRICING table.
    Returns None if model is unknown.
    """
    if model in MODEL_PRICING:
        in_price, out_price = MODEL_PRICING[model]
        return (input_tokens * in_price + output_tokens * out_price) / 1_000_000.0

    for k, v in MODEL_PRICING.items():
        if k in model or model in k:
            in_price, out_price = v
            return (input_tokens * in_price + output_tokens * out_price) / 1_000_000.0

    return None


class UsageStats(BaseModel):
    requests_today: int = 0
    requests_this_minute: int = 0
    last_request_time: float = 0.0
    input_tokens: int = 0
    output_tokens: int = 0
    estimated_cost_usd: float | None = None
    last_model: str | None = None


class Budget(BaseModel):
    usage_by_provider: dict[str, UsageStats] = Field(default_factory=dict)
    stats: UsageStats = Field(default_factory=UsageStats)

    @property
    def requests_today(self) -> int:
        return self.stats.requests_today


def get_budget_file() -> Path:
    return get_config_dir() / "usage.json"


def get_budget_lock_file() -> Path:
    return get_config_dir() / "usage.lock"


def atomic_write_json(path: Path | str, data: dict) -> None:
    """Write dictionary to path atomically by writing to .tmp, flushing, fsyncing, and replacing."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = target.with_suffix(".tmp")
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp_path, target)


@contextmanager
def _locked_budget_file(lock_file: Path | None = None, timeout: float = 5.0):
    with _budget_thread_lock:
        target_lock = Path(lock_file) if lock_file is not None else get_budget_lock_file()
        target_lock.parent.mkdir(parents=True, exist_ok=True)
        start_t = time.monotonic()
        delay = 0.01

        try:
            import fcntl

            with open(target_lock, "a+") as lock:
                acquired = False
                while True:
                    try:
                        fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                        acquired = True
                        break
                    except (BlockingIOError, OSError):
                        if time.monotonic() - start_t >= timeout:
                            break
                        time.sleep(delay)
                        delay = min(delay * 1.5, 0.2)
                try:
                    yield acquired or lock
                finally:
                    if acquired:
                        try:
                            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
                        except OSError:
                            pass
        except ImportError:
            try:
                import msvcrt

                with open(target_lock, "a+") as lock:
                    acquired = False
                    while True:
                        try:
                            msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
                            acquired = True
                            break
                        except OSError:
                            if time.monotonic() - start_t >= timeout:
                                break
                            time.sleep(delay)
                            delay = min(delay * 1.5, 0.2)
                    try:
                        yield acquired or lock
                    finally:
                        if acquired:
                            try:
                                lock.seek(0)
                                msvcrt.locking(lock.fileno(), msvcrt.LK_UNLCK, 1)
                            except OSError:
                                pass
            except (ImportError, OSError):
                yield target_lock


def _load_budget_unlocked(budget_file: Path | None = None) -> Budget:
    target_file = Path(budget_file) if budget_file is not None else get_budget_file()
    if not target_file.exists():
        return Budget()

    try:
        content = target_file.read_text(encoding="utf-8").strip()
        if not content:
            return Budget()
        data = json.loads(content)
        return Budget(**data)
    except (json.JSONDecodeError, ValueError, OSError, UnicodeDecodeError):
        # Quarantine corrupt budget file to usage.json.corrupt-<timestamp>
        ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        corrupt_name = f"{target_file.name}.corrupt-{ts}"
        corrupt_dest = target_file.parent / corrupt_name
        try:
            os.replace(target_file, corrupt_dest)
        except OSError:
            pass
        return Budget()


def load_budget(budget_file: Path | None = None) -> Budget:
    target_file = Path(budget_file) if budget_file is not None else get_budget_file()
    with _locked_budget_file():
        return _load_budget_unlocked(target_file)


def _save_budget_unlocked(budget: Budget, budget_file: Path | None = None) -> None:
    target_file = Path(budget_file) if budget_file is not None else get_budget_file()
    atomic_write_json(target_file, budget.model_dump())


def save_budget(budget: Budget, budget_file: Path | None = None) -> None:
    target_file = Path(budget_file) if budget_file is not None else get_budget_file()
    with _locked_budget_file():
        _save_budget_unlocked(budget, target_file)


def normalize_usage_stats(stats: UsageStats, now: datetime | None = None) -> UsageStats:
    now = now or datetime.now(timezone.utc)
    current_timestamp = now.timestamp()

    if stats.last_request_time <= 0:
        stats.requests_this_minute = 0
        return stats

    last_time = datetime.fromtimestamp(stats.last_request_time, tz=timezone.utc)

    if last_time.date() < now.date():
        stats.requests_today = 0

    if (current_timestamp - stats.last_request_time) >= 60.0:
        stats.requests_this_minute = 0

    return stats


def get_live_budget() -> Budget:
    with _locked_budget_file():
        budget = _load_budget_unlocked()
        for stats in budget.usage_by_provider.values():
            normalize_usage_stats(stats)
        _save_budget_unlocked(budget)
        return budget


def check_and_increment(provider: str, max_rpm: int, max_rpd: int) -> bool:
    with _locked_budget_file():
        budget = _load_budget_unlocked()

        if provider not in budget.usage_by_provider:
            budget.usage_by_provider[provider] = UsageStats()

        stats = budget.usage_by_provider[provider]
        normalize_usage_stats(stats)

        if stats.requests_today >= max_rpd:
            return False

        if stats.requests_this_minute >= max_rpm:
            return False

        now = datetime.now(timezone.utc)
        stats.requests_today += 1
        stats.requests_this_minute += 1
        stats.last_request_time = now.timestamp()

        _save_budget_unlocked(budget)
        return True


def reset_provider_usage(provider: str):
    with _locked_budget_file():
        budget = _load_budget_unlocked()
        budget.usage_by_provider[provider] = UsageStats()
        _save_budget_unlocked(budget)


def remaining_budget(provider: str, max_rpm: int, max_rpd: int) -> tuple[int, int]:
    budget = get_live_budget()
    stats = budget.usage_by_provider.get(provider, UsageStats())
    return max(max_rpd - stats.requests_today, 0), max(max_rpm - stats.requests_this_minute, 0)
