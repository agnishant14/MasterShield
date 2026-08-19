"""Optional SQLite persistence with an in-memory fallback for the demo."""

from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone


class EventStore:
    def __init__(self, path: str | None = None):
        self.path = path
        self.lock = threading.RLock()
        self.memory: dict[str, list[dict]] = {"feedback": [], "simulations": [], "audit": [], "models": []}
        self.connection = None
        if path:
            self.connection = sqlite3.connect(path, check_same_thread=False)
            self.connection.execute("CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT NOT NULL, payload TEXT NOT NULL, created_at TEXT NOT NULL)")
            self.connection.commit()

    def append(self, kind: str, payload: dict) -> dict:
        item = {"kind": kind, "payload": payload, "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")}
        with self.lock:
            if self.connection:
                self.connection.execute("INSERT INTO events(kind, payload, created_at) VALUES (?, ?, ?)", (kind, json.dumps(payload), item["created_at"]))
                self.connection.commit()
            else:
                self.memory.setdefault(kind, []).append(item)
        return item

    def list(self, kind: str, limit: int = 100) -> list[dict]:
        with self.lock:
            if self.connection:
                rows = self.connection.execute("SELECT payload, created_at FROM events WHERE kind = ? ORDER BY id DESC LIMIT ?", (kind, max(1, min(int(limit), 500)))).fetchall()
                return [{"kind": kind, "payload": json.loads(payload), "created_at": created_at} for payload, created_at in rows]
            return list(reversed(self.memory.get(kind, [])[-max(1, min(int(limit), 500)):]))
