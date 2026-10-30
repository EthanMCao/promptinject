"""Transactional run history; each operation owns its SQLite connection."""

from contextlib import contextmanager
import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path


class Store:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute(
                "CREATE TABLE IF NOT EXISTS runs (id TEXT PRIMARY KEY, created TEXT NOT NULL, report TEXT NOT NULL)"
            )

    @contextmanager
    def connect(self):
        connection = sqlite3.connect(self.path, timeout=10)
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def save(self, report):
        id = str(uuid.uuid4())
        created = datetime.now(timezone.utc).isoformat()
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO runs VALUES (?, ?, ?)", (id, created, json.dumps(report))
            )
        return {"id": id, "created": created, **report}

    def get(self, id):
        with self.connect() as conn:
            row = conn.execute(
                "SELECT created, report FROM runs WHERE id=?", (id,)
            ).fetchone()
        return {"id": id, "created": row[0], **json.loads(row[1])} if row else None

    def list(self):
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT id, created, report FROM runs ORDER BY created DESC LIMIT 100"
            ).fetchall()
        return [
            {
                "id": id,
                "created": created,
                **{
                    k: v
                    for k, v in json.loads(raw).items()
                    if k not in {"results", "cases"}
                },
            }
            for id, created, raw in rows
        ]
