"""
MEOK Labs — Shared Persistence Layer for MCP Servers
Deploy to: ~/clawd/meok-labs-engine/shared/persistence.py

Replaces in-memory defaultdict/dict with SQLite persistence.
Each server gets its own database file in ~/.meok/data/

Usage in any server.py:
    import sys, os
    sys.path.insert(0, os.path.expanduser("~/clawd/meok-labs-engine/shared"))
    from persistence import ServerStore

    store = ServerStore("my-server-name")

    # Key-value storage
    store.set("alerts", [{"price": 100, "product": "X"}])
    alerts = store.get("alerts", default=[])

    # List operations (append, get all, clear)
    store.append("history", {"event": "price_change", "ts": "2026-04-15"})
    all_history = store.list("history")
    store.clear("history")

    # Dict operations (nested key-value)
    store.hset("users", "user123", {"name": "Nick", "tier": "pro"})
    user = store.hget("users", "user123")
    all_users = store.hgetall("users")
"""

import os
import json
import sqlite3
import threading
from datetime import datetime, timezone
from typing import Any, Optional


DB_DIR = os.path.expanduser("~/.meok/data")
os.makedirs(DB_DIR, exist_ok=True)

_connections: dict[str, sqlite3.Connection] = {}
_lock = threading.Lock()


def _get_db(server_name: str) -> sqlite3.Connection:
    """Get or create a SQLite connection for a server."""
    with _lock:
        if server_name not in _connections:
            db_path = os.path.join(DB_DIR, f"{server_name}.db")
            conn = sqlite3.connect(db_path, check_same_thread=False)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS kv (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS lists (
                    key TEXT NOT NULL,
                    idx INTEGER NOT NULL,
                    value TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    PRIMARY KEY (key, idx)
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS hashes (
                    key TEXT NOT NULL,
                    field TEXT NOT NULL,
                    value TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (key, field)
                )
            """)
            conn.commit()
            _connections[server_name] = conn
        return _connections[server_name]


class ServerStore:
    """Persistent storage for an MCP server."""

    def __init__(self, server_name: str):
        self.server_name = server_name
        self.db = _get_db(server_name)

    def _now(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    # ── Key-Value Operations ──

    def set(self, key: str, value: Any) -> None:
        """Store a value (any JSON-serializable type)."""
        self.db.execute(
            "INSERT OR REPLACE INTO kv (key, value, updated_at) VALUES (?, ?, ?)",
            (key, json.dumps(value, default=str), self._now()),
        )
        self.db.commit()

    def get(self, key: str, default: Any = None) -> Any:
        """Retrieve a value by key."""
        row = self.db.execute("SELECT value FROM kv WHERE key = ?", (key,)).fetchone()
        return json.loads(row[0]) if row else default

    def delete(self, key: str) -> bool:
        """Delete a key-value pair."""
        cursor = self.db.execute("DELETE FROM kv WHERE key = ?", (key,))
        self.db.commit()
        return cursor.rowcount > 0

    def keys(self, prefix: str = "") -> list[str]:
        """List all keys, optionally filtered by prefix."""
        if prefix:
            rows = self.db.execute("SELECT key FROM kv WHERE key LIKE ?", (f"{prefix}%",)).fetchall()
        else:
            rows = self.db.execute("SELECT key FROM kv").fetchall()
        return [r[0] for r in rows]

    # ── List Operations ──

    def append(self, key: str, value: Any) -> int:
        """Append to a list. Returns new length."""
        max_idx = self.db.execute("SELECT MAX(idx) FROM lists WHERE key = ?", (key,)).fetchone()[0]
        next_idx = (max_idx or 0) + 1
        self.db.execute(
            "INSERT INTO lists (key, idx, value, created_at) VALUES (?, ?, ?, ?)",
            (key, next_idx, json.dumps(value, default=str), self._now()),
        )
        self.db.commit()
        return next_idx

    def list(self, key: str, limit: int = 1000, offset: int = 0) -> list[Any]:
        """Get all items in a list."""
        rows = self.db.execute(
            "SELECT value FROM lists WHERE key = ? ORDER BY idx LIMIT ? OFFSET ?",
            (key, limit, offset),
        ).fetchall()
        return [json.loads(r[0]) for r in rows]

    def list_length(self, key: str) -> int:
        """Get the length of a list."""
        row = self.db.execute("SELECT COUNT(*) FROM lists WHERE key = ?", (key,)).fetchone()
        return row[0] if row else 0

    def clear(self, key: str) -> int:
        """Clear all items from a list."""
        cursor = self.db.execute("DELETE FROM lists WHERE key = ?", (key,))
        self.db.commit()
        return cursor.rowcount

    # ── Hash Operations ──

    def hset(self, key: str, field: str, value: Any) -> None:
        """Set a field in a hash."""
        self.db.execute(
            "INSERT OR REPLACE INTO hashes (key, field, value, updated_at) VALUES (?, ?, ?, ?)",
            (key, field, json.dumps(value, default=str), self._now()),
        )
        self.db.commit()

    def hget(self, key: str, field: str, default: Any = None) -> Any:
        """Get a field from a hash."""
        row = self.db.execute("SELECT value FROM hashes WHERE key = ? AND field = ?", (key, field)).fetchone()
        return json.loads(row[0]) if row else default

    def hgetall(self, key: str) -> dict[str, Any]:
        """Get all fields from a hash."""
        rows = self.db.execute("SELECT field, value FROM hashes WHERE key = ?", (key,)).fetchall()
        return {r[0]: json.loads(r[1]) for r in rows}

    def hdel(self, key: str, field: str) -> bool:
        """Delete a field from a hash."""
        cursor = self.db.execute("DELETE FROM hashes WHERE key = ? AND field = ?", (key, field))
        self.db.commit()
        return cursor.rowcount > 0

    # ── Utility ──

    def stats(self) -> dict:
        """Get storage statistics."""
        kv_count = self.db.execute("SELECT COUNT(*) FROM kv").fetchone()[0]
        list_count = self.db.execute("SELECT COUNT(DISTINCT key) FROM lists").fetchone()[0]
        list_items = self.db.execute("SELECT COUNT(*) FROM lists").fetchone()[0]
        hash_count = self.db.execute("SELECT COUNT(DISTINCT key) FROM hashes").fetchone()[0]
        hash_fields = self.db.execute("SELECT COUNT(*) FROM hashes").fetchone()[0]

        db_path = os.path.join(DB_DIR, f"{self.server_name}.db")
        size_bytes = os.path.getsize(db_path) if os.path.exists(db_path) else 0

        return {
            "server": self.server_name,
            "kv_keys": kv_count,
            "lists": list_count,
            "list_items": list_items,
            "hashes": hash_count,
            "hash_fields": hash_fields,
            "db_size_bytes": size_bytes,
            "db_path": db_path,
        }
