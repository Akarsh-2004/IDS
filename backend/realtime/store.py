from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any


class EventStore:
    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self._lock = threading.Lock()
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS events(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts REAL NOT NULL,
                    label TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    score REAL NOT NULL,
                    source TEXT NOT NULL,
                    details_json TEXT NOT NULL
                )
                """
            )
            conn.commit()

    def add_event(
        self,
        label: str,
        severity: str,
        score: float,
        source: str,
        details: dict[str, Any],
    ) -> dict[str, Any]:
        now = time.time()
        details_json = json.dumps(details, ensure_ascii=True)
        with self._lock, self._connect() as conn:
            cur = conn.execute(
                "INSERT INTO events(ts,label,severity,score,source,details_json) VALUES(?,?,?,?,?,?)",
                (now, label, severity, score, source, details_json),
            )
            conn.commit()
            event_id = int(cur.lastrowid)
        return {
            "id": event_id,
            "ts": now,
            "label": label,
            "severity": severity,
            "score": score,
            "source": source,
            "details": details,
        }

    def list_events(self, limit: int = 100, severity: str | None = None) -> list[dict[str, Any]]:
        query = "SELECT * FROM events"
        params: list[Any] = []
        if severity:
            query += " WHERE severity = ?"
            params.append(severity)
        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [
            {
                "id": int(r["id"]),
                "ts": float(r["ts"]),
                "label": r["label"],
                "severity": r["severity"],
                "score": float(r["score"]),
                "source": r["source"],
                "details": json.loads(r["details_json"]),
            }
            for r in rows
        ]
