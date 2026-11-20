"""SearXNG JSON Metasearch Engine Client with Secret Redaction and Passive Indexing."""

from __future__ import annotations

import logging
import os
import urllib.parse
from typing import Any

from eva.security.redaction import redact_secrets

logger = logging.getLogger(__name__)


class SearXNGError(Exception):
    """Raised when all SearXNG instance queries fail."""


class SearXNGClient:
    """Metasearch client querying SearXNG JSON endpoints."""

    def __init__(
        self,
        base_urls: list[str] | None = None,
        timeout: float = 10.0,
        passive_index: bool = True,
    ) -> None:
        env_url = os.environ.get("EVA_SEARXNG_URL")
        if env_url:
            self.base_urls = [env_url]
        elif base_urls:
            self.base_urls = base_urls
        else:
            self.base_urls = ["http://127.0.0.1:8081", "http://127.0.0.1:8080"]

        self.timeout = timeout
        self.passive_index = passive_index

    def search(
        self,
        query: str,
        category: str = "general",
        pageno: int = 1,
        limit: int = 10,
        offline: bool = False,
    ) -> list[dict[str, Any]]:
        """Search query with secret redaction and passive FTS5 caching."""
        # Redact secrets before network dispatch
        safe_query = redact_secrets(query)
        safe_query = safe_query.strip()
        if not safe_query:
            return []

        if offline:
            from eva.web.index import search_offline

            return search_offline(safe_query, limit=limit)

        import httpx

        errors: list[str] = []
        raw_results: list[dict[str, Any]] = []

        for base_url in self.base_urls:
            endpoint = urllib.parse.urljoin(base_url, "/search")
            params = {
                "q": safe_query,
                "format": "json",
                "categories": category,
                "pageno": pageno,
            }
            try:
                with httpx.Client(timeout=self.timeout) as client:
                    resp = client.get(endpoint, params=params)
                    if resp.status_code == 200:
                        data = resp.json()
                        raw_results = data.get("results", [])
                        break
                    errors.append(f"{base_url}: HTTP {resp.status_code}")
            except (httpx.HTTPError, OSError, RuntimeError, ValueError) as exc:
                errors.append(f"{base_url}: {exc}")

        # If live search returned results, format and passively index them
        if raw_results:
            formatted: list[dict[str, Any]] = []
            for item in raw_results[:limit]:
                img_url = (
                    item.get("img_src")
                    or item.get("thumbnail_src")
                    or item.get("thumbnail")
                    or item.get("image")
                    or item.get("url", "")
                )
                formatted.append(
                    {
                        "url": item.get("url", ""),
                        "title": item.get("title", ""),
                        "description": item.get("content", ""),
                        "score": item.get("score", 0.0),
                        "engine": item.get("engine", "searxng"),
                        "img_src": img_url,
                        "thumbnail_src": item.get("thumbnail_src") or item.get("thumbnail") or img_url,
                    }
                )

            if self.passive_index:
                try:
                    from eva.web.index import WebIndex

                    idx = WebIndex()
                    for doc in formatted:
                        if doc["url"]:
                            idx.index_document(
                                url=doc["url"],
                                title=doc["title"],
                                description=doc["description"],
                            )
                except (OSError, RuntimeError, ValueError) as exc:
                    logger.debug("Passive indexing failed: %s", exc)

            return formatted

        # Fallback to offline index if all instances failed or returned nothing
        try:
            from eva.web.index import search_offline

            offline_results = search_offline(safe_query, limit=limit)
            if offline_results:
                return offline_results
        except (OSError, RuntimeError, ValueError) as exc:
            logger.debug("Offline fallback search failed: %s", exc)

        return []


def search(
    query: str,
    category: str = "general",
    limit: int = 10,
    offline: bool = False,
    base_urls: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Convenience functional interface for web search."""
    client = SearXNGClient(base_urls=base_urls)
    return client.search(query=query, category=category, limit=limit, offline=offline)
