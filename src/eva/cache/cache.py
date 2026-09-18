from __future__ import annotations

import hashlib
import json
import sqlite3
import sys
import time
from pathlib import Path
from types import TracebackType
from typing import Any

if sys.version_info >= (3, 11):
    from typing import Self
else:
    from typing_extensions import Self

from eva.config import get_config_dir


class Cache:
    """A lightweight, thread-safe on-disk cache backed by SQLite with JSON serialization.

    Replaces third-party diskcache to eliminate unsafe pickle deserialization
    (CVE-2025-69872) while preserving context-manager semantics and TTL expiration.
    """

    def __init__(self, directory: Path | str):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.db_path = self.directory / "cache.db"
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=30.0)
        conn.execute("PRAGMA journal_mode=WAL;")
        return conn

    def _init_db(self) -> None:
        with self._get_conn() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS cache_entries (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    expires_at REAL
                )
                """
            )

    def get(self, key: str, default: Any = None) -> Any:
        now = time.time()
        try:
            with self._get_conn() as conn:
                cur = conn.cursor()
                cur.execute(
                    "SELECT value, expires_at FROM cache_entries WHERE key = ?",
                    (key,),
                )
                row = cur.fetchone()
                if row is None:
                    return default
                val_str, expires_at = row
                if expires_at is not None and expires_at <= now:
                    cur.execute("DELETE FROM cache_entries WHERE key = ?", (key,))
                    conn.commit()
                    return default
                return json.loads(val_str)
        except (sqlite3.Error, json.JSONDecodeError):
            return default

    def set(self, key: str, value: Any, expire: float | None = None) -> None:
        expires_at = (time.time() + expire) if expire is not None else None
        val_str = json.dumps(value)
        try:
            with self._get_conn() as conn:
                conn.execute(
                    """
                    INSERT INTO cache_entries (key, value, expires_at)
                    VALUES (?, ?, ?)
                    ON CONFLICT(key) DO UPDATE SET
                        value=excluded.value,
                        expires_at=excluded.expires_at
                    """,
                    (key, val_str, expires_at),
                )
        except sqlite3.Error:
            pass

    def delete(self, key: str) -> None:
        try:
            with self._get_conn() as conn:
                conn.execute("DELETE FROM cache_entries WHERE key = ?", (key,))
        except sqlite3.Error:
            pass

    def clear(self) -> None:
        try:
            with self._get_conn() as conn:
                conn.execute("DELETE FROM cache_entries")
        except sqlite3.Error:
            pass

    def close(self) -> None:
        pass

    def __contains__(self, key: str) -> bool:
        return self.get(key) is not None

    def __getitem__(self, key: str) -> Any:
        val = self.get(key)
        if val is None:
            raise KeyError(key)
        return val

    def __setitem__(self, key: str, value: Any) -> None:
        self.set(key, value)

    def __delitem__(self, key: str) -> None:
        self.delete(key)

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        self.close()


def get_cache_dir() -> Path:
    return get_config_dir() / "cache"


def get_cache() -> Cache:
    return Cache(get_cache_dir())


def generate_cache_key(model: str, system_prompt: str, user_prompt: str, context: str) -> str:
    key_data = {
        "model": model,
        "system_prompt": system_prompt,
        "user_prompt": user_prompt,
        "context_hash": hashlib.sha256(context.encode("utf-8")).hexdigest() if context else "",
    }
    key_str = json.dumps(key_data, sort_keys=True)
    return hashlib.sha256(key_str.encode("utf-8")).hexdigest()


def get_cached_response(key: str) -> str | None:
    with get_cache() as cache:
        return cache.get(key)


def set_cached_response(key: str, response: str, ttl_hours: int = 24):
    with get_cache() as cache:
        cache.set(key, response, expire=ttl_hours * 3600)


def clear_cache():
    with get_cache() as cache:
        cache.clear()
