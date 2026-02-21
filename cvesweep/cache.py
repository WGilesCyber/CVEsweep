"""SQLite-backed CVE result cache with TTL invalidation."""

import hashlib
import json
import sqlite3
import time
from dataclasses import asdict
from pathlib import Path
from typing import List, Optional

from .models import CVEEntry

CACHE_DIR = Path.home() / ".cache" / "cvesweep"
CACHE_DB = CACHE_DIR / "cve_cache.db"
DEFAULT_TTL = 86400  # 24 hours

_SCHEMA = """
CREATE TABLE IF NOT EXISTS cve_cache (
    cache_key   TEXT PRIMARY KEY,
    query_type  TEXT NOT NULL,
    query_value TEXT NOT NULL,
    cve_data    TEXT NOT NULL,
    fetched_at  INTEGER NOT NULL,
    ttl         INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_fetched ON cve_cache(fetched_at);
"""


class CVECache:
    """
    Thread-safe SQLite cache for NVD API results.

    Results are stored keyed by SHA256(query_type:query_value).
    Expired entries are lazily checked on read; cleanup() removes them in bulk.
    """

    def __init__(self, db_path: Path = CACHE_DB, ttl: int = DEFAULT_TTL):
        self.db_path = db_path
        self.ttl = ttl
        self._init_db()

    def _init_db(self) -> None:
        """Create the cache directory and database schema if needed."""
        try:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            with self._connect() as conn:
                conn.executescript(_SCHEMA)
        except sqlite3.DatabaseError as exc:
            # DB is corrupt — delete and recreate
            self._reset_db(exc)

    def _reset_db(self, original_error: Exception) -> None:
        """Delete the corrupt database and recreate it."""
        import warnings
        warnings.warn(
            f"CVE cache database was corrupt ({original_error}), resetting.",
            RuntimeWarning,
            stacklevel=3,
        )
        try:
            self.db_path.unlink(missing_ok=True)
        except OSError:
            pass
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.executescript(_SCHEMA)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _make_key(query_type: str, query_value: str) -> str:
        """Return a stable SHA256 cache key for a query."""
        raw = f"{query_type}:{query_value}".encode("utf-8")
        return hashlib.sha256(raw).hexdigest()

    def get(self, query_type: str, query_value: str) -> Optional[List[CVEEntry]]:
        """
        Return cached CVE entries or None if cache miss or expired.

        Expiry is checked lazily on read; stale rows are not deleted here.
        """
        key = self._make_key(query_type, query_value)
        try:
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT cve_data, fetched_at, ttl FROM cve_cache WHERE cache_key = ?",
                    (key,),
                ).fetchone()

            if row is None:
                return None

            if time.time() > row["fetched_at"] + row["ttl"]:
                return None  # Expired

            entries = json.loads(row["cve_data"])
            return [CVEEntry(**e) for e in entries]

        except (sqlite3.DatabaseError, json.JSONDecodeError, TypeError):
            return None

    def set(self, query_type: str, query_value: str, cves: List[CVEEntry]) -> None:
        """Store CVE entries in the cache, replacing any existing entry."""
        key = self._make_key(query_type, query_value)
        data = json.dumps([asdict(c) for c in cves])
        try:
            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO cve_cache
                        (cache_key, query_type, query_value, cve_data, fetched_at, ttl)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (key, query_type, query_value, data, int(time.time()), self.ttl),
                )
        except sqlite3.DatabaseError:
            pass  # Cache write failure is non-fatal

    def invalidate(self, query_type: str, query_value: str) -> None:
        """Force-expire a specific cache entry (used by --update-cache)."""
        key = self._make_key(query_type, query_value)
        try:
            with self._connect() as conn:
                conn.execute(
                    "UPDATE cve_cache SET fetched_at = 0 WHERE cache_key = ?",
                    (key,),
                )
        except sqlite3.DatabaseError:
            pass

    def cleanup(self) -> int:
        """Delete all expired cache entries. Returns the number of rows deleted."""
        cutoff = time.time()  # float for precise comparison with integer fetched_at + ttl
        try:
            with self._connect() as conn:
                cursor = conn.execute(
                    "DELETE FROM cve_cache WHERE fetched_at + ttl <= ?",
                    (cutoff,),
                )
                return cursor.rowcount
        except sqlite3.DatabaseError:
            return 0

    def stats(self) -> dict:
        """Return cache statistics dict."""
        try:
            with self._connect() as conn:
                total = conn.execute("SELECT COUNT(*) FROM cve_cache").fetchone()[0]
                cutoff = int(time.time())
                expired = conn.execute(
                    "SELECT COUNT(*) FROM cve_cache WHERE fetched_at + ttl < ?",
                    (cutoff,),
                ).fetchone()[0]
            size = self.db_path.stat().st_size if self.db_path.exists() else 0
            return {
                "total_entries": total,
                "expired_entries": expired,
                "db_size_bytes": size,
                "db_path": str(self.db_path),
            }
        except (sqlite3.DatabaseError, OSError):
            return {"total_entries": 0, "expired_entries": 0, "db_size_bytes": 0}
