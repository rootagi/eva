import json
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from pydantic import BaseModel, Field

from eva.config import get_config_dir


class UsageStats(BaseModel):
    requests_today: int = 0
    requests_this_minute: int = 0
    last_request_time: float = 0.0


class Budget(BaseModel):
    usage_by_provider: dict[str, UsageStats] = Field(default_factory=dict)


def get_budget_file() -> Path:
    return get_config_dir() / "usage.json"


def get_budget_lock_file() -> Path:
    return get_config_dir() / "usage.lock"


@contextmanager
def _locked_budget_file():
    lock_file = get_budget_lock_file()
    lock_file.parent.mkdir(parents=True, exist_ok=True)
    try:
        import fcntl
    except ImportError:
        yield
        return

    with open(lock_file, "a+") as lock:
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


def _load_budget_unlocked() -> Budget:
    budget_file = get_budget_file()
    if not budget_file.exists():
        return Budget()

    with open(budget_file, "r") as f:
        data = json.load(f)
    return Budget(**data)


def load_budget() -> Budget:
    with _locked_budget_file():
        return _load_budget_unlocked()


def _save_budget_unlocked(budget: Budget):
    budget_file = get_budget_file()
    budget_file.parent.mkdir(parents=True, exist_ok=True)
    with open(budget_file, "w") as f:
        json.dump(budget.model_dump(), f, indent=2)


def save_budget(budget: Budget):
    with _locked_budget_file():
        _save_budget_unlocked(budget)


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
