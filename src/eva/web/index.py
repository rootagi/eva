"""Local SQLite FTS5 Web Document Index with BM25 Ranking."""

from __future__ import annotations

import json
import sqlite3
import time
import urllib.parse
from pathlib import Path
from typing import Any

from platformdirs import user_data_dir


def get_default_web_db_path() -> Path:
    """Return default path to user's web_index.db."""
    base_dir = Path(user_data_dir("eva"))
    base_dir.mkdir(parents=True, exist_ok=True)
    return base_dir / "web_index.db"


class WebIndex:
    """Manages full-text search indexing of web pages via SQLite FTS5."""

    def __init__(self, db_path: str | Path | None = None) -> None:
        self.db_path = Path(db_path) if db_path else get_default_web_db_path()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS web_documents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    url TEXT UNIQUE NOT NULL,
                    domain TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    body_markdown TEXT NOT NULL,
                    image_urls TEXT NOT NULL,
                    fetched_at REAL NOT NULL,
                    workspace TEXT
                )
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS last_search_results (
                    item_index INTEGER PRIMARY KEY,
                    query TEXT,
                    url TEXT NOT NULL,
                    title TEXT,
                    description TEXT,
                    img_src TEXT,
                    timestamp REAL
                )
                """
            )
            cursor.execute(
                """
                CREATE VIRTUAL TABLE IF NOT EXISTS web_documents_fts USING fts5(
                    title,
                    description,
                    body_markdown,
                    content='web_documents',
                    content_rowid='id',
                    tokenize='porter unicode61'
                )
                """
            )
            # Create synchronization triggers for FTS5
            cursor.execute(
                """
                CREATE TRIGGER IF NOT EXISTS web_docs_ai AFTER INSERT ON web_documents BEGIN
                    INSERT INTO web_documents_fts(rowid, title, description, body_markdown)
                    VALUES (new.id, new.title, new.description, new.body_markdown);
                END;
                """
            )
            cursor.execute(
                """
                CREATE TRIGGER IF NOT EXISTS web_docs_ad AFTER DELETE ON web_documents BEGIN
                    INSERT INTO web_documents_fts(web_documents_fts, rowid, title, description, body_markdown)
                    VALUES('delete', old.id, old.title, old.description, old.body_markdown);
                END;
                """
            )
            cursor.execute(
                """
                CREATE TRIGGER IF NOT EXISTS web_docs_au AFTER UPDATE ON web_documents BEGIN
                    INSERT INTO web_documents_fts(web_documents_fts, rowid, title, description, body_markdown)
                    VALUES('delete', old.id, old.title, old.description, old.body_markdown);
                    INSERT INTO web_documents_fts(rowid, title, description, body_markdown)
                    VALUES (new.id, new.title, new.description, new.body_markdown);
                END;
                """
            )
            conn.commit()

    def index_document(
        self,
        url: str,
        title: str = "",
        description: str = "",
        body_markdown: str = "",
        image_urls: list[str] | None = None,
        workspace: str | None = None,
    ) -> int:
        """Insert or replace document in index, returning document ID."""
        domain = urllib.parse.urlparse(url).netloc or "unknown"
        images_json = json.dumps(image_urls or [])
        now = time.time()

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO web_documents (url, domain, title, description, body_markdown, image_urls, fetched_at, workspace)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(url) DO UPDATE SET
                    domain = excluded.domain,
                    title = excluded.title,
                    description = excluded.description,
                    body_markdown = excluded.body_markdown,
                    image_urls = excluded.image_urls,
                    fetched_at = excluded.fetched_at,
                    workspace = excluded.workspace
                """,
                (url, domain, title, description, body_markdown, images_json, now, workspace),
            )
            doc_id = cursor.lastrowid
            if not doc_id:
                # If updated, fetch existing id
                cursor.execute("SELECT id FROM web_documents WHERE url = ?", (url,))
                row = cursor.fetchone()
                doc_id = row[0] if row else 1
            conn.commit()
            return doc_id

    def search(self, query: str, limit: int = 10) -> list[dict[str, Any]]:
        """Search indexed documents using FTS5 BM25 relevance ranking."""
        cleaned_query = query.strip()
        if not cleaned_query:
            return []

        # Sanitize query for FTS5: strip boolean operators if bare, wrap terms or use simple match
        # Escape quotes
        safe_query = cleaned_query.replace('"', '""')
        # If no operators, quote individual tokens to avoid syntax errors on punctuation
        tokens = [f'"{token.replace(chr(34), "")}"' for token in safe_query.split() if token]
        fts_match = " ".join(tokens)
        if not fts_match:
            return []

        results: list[dict[str, Any]] = []
        with self._get_connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute(
                    """
                    SELECT d.id, d.url, d.domain, d.title, d.description, d.body_markdown,
                           d.image_urls, d.fetched_at, d.workspace,
                           bm25(web_documents_fts, 5.0, 2.0, 1.0) AS score
                    FROM web_documents_fts f
                    JOIN web_documents d ON d.id = f.rowid
                    WHERE web_documents_fts MATCH ?
                    ORDER BY score ASC
                    LIMIT ?
                    """,
                    (fts_match, limit),
                )
                rows = cursor.fetchall()
            except sqlite3.OperationalError:
                # Fallback to LIKE if FTS expression fails
                cursor.execute(
                    """
                    SELECT id, url, domain, title, description, body_markdown, image_urls, fetched_at, workspace, 0.0 as score
                    FROM web_documents
                    WHERE title LIKE ? OR description LIKE ? OR body_markdown LIKE ?
                    LIMIT ?
                    """,
                    (f"%{cleaned_query}%", f"%{cleaned_query}%", f"%{cleaned_query}%", limit),
                )
                rows = cursor.fetchall()

            for row in rows:
                results.append(
                    {
                        "id": row["id"],
                        "url": row["url"],
                        "domain": row["domain"],
                        "title": row["title"],
                        "description": row["description"],
                        "body_markdown": row["body_markdown"],
                        "image_urls": json.loads(row["image_urls"]) if row["image_urls"] else [],
                        "fetched_at": row["fetched_at"],
                        "workspace": row["workspace"],
                    }
                )
        return results

    def get_document(self, url_or_id: str | int) -> dict[str, Any] | None:
        """Fetch indexed document by URL or integer ID."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            if isinstance(url_or_id, int) or (isinstance(url_or_id, str) and url_or_id.isdigit()):
                cursor.execute("SELECT * FROM web_documents WHERE id = ?", (int(url_or_id),))
            else:
                cursor.execute("SELECT * FROM web_documents WHERE url = ?", (str(url_or_id),))
            row = cursor.fetchone()
            if not row:
                return None
            return {
                "id": row["id"],
                "url": row["url"],
                "domain": row["domain"],
                "title": row["title"],
                "description": row["description"],
                "body_markdown": row["body_markdown"],
                "image_urls": json.loads(row["image_urls"]) if row["image_urls"] else [],
                "fetched_at": row["fetched_at"],
                "workspace": row["workspace"],
            }

    def list_history(self, limit: int = 20) -> list[dict[str, Any]]:
        """List recently indexed or visited web pages."""
        results: list[dict[str, Any]] = []
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT id, url, domain, title, description, fetched_at
                FROM web_documents
                ORDER BY fetched_at DESC
                LIMIT ?
                """,
                (limit,),
            )
            for row in cursor.fetchall():
                results.append(
                    {
                        "id": row["id"],
                        "url": row["url"],
                        "domain": row["domain"],
                        "title": row["title"],
                        "description": row["description"],
                        "fetched_at": row["fetched_at"],
                    }
                )
        return results

    def save_last_search(self, results: list[dict[str, Any]], query: str = "") -> None:
        """Persist latest search results list for index-based retrieval."""
        now = time.time()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM last_search_results")
            for i, r in enumerate(results, start=1):
                cursor.execute(
                    """
                    INSERT INTO last_search_results (item_index, query, url, title, description, img_src, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        i,
                        query,
                        r.get("url", ""),
                        r.get("title", ""),
                        r.get("description") or r.get("content", "") or "",
                        r.get("img_src") or r.get("thumbnail_src") or "",
                        now,
                    ),
                )
            conn.commit()

    def get_last_search(self) -> list[dict[str, Any]]:
        """Retrieve all results from the most recent search."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT item_index, query, url, title, description, img_src, timestamp
                FROM last_search_results
                ORDER BY item_index ASC
                """
            )
            return [dict(row) for row in cursor.fetchall()]

    def get_last_search_item(self, index: int) -> dict[str, Any] | None:
        """Retrieve a specific search result by its 1-based index."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT item_index, query, url, title, description, img_src, timestamp
                FROM last_search_results
                WHERE item_index = ?
                """,
                (index,),
            )
            row = cursor.fetchone()
            return dict(row) if row else None


def search_offline(query: str, limit: int = 10, db_path: str | Path | None = None) -> list[dict[str, Any]]:
    """Convenience function to perform offline search over cached web documents."""
    idx = WebIndex(db_path=db_path)
    return idx.search(query=query, limit=limit)
