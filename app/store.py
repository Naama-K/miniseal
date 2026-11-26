"""The seal registry: one SQLite row per seal issued.

Why keep a record at all, if the seal is inside the image?
----------------------------------------------------------
The embedded seal proves "this key signed these pixels". The registry adds
what the image can't prove about itself: *when* it was sealed and *by whom*
(the API key's owner). It is also our own audit trail: a seal_id that verifies
cryptographically but is missing here was not issued by this service.

Why plain sqlite3 and not an ORM?
---------------------------------
One table, two queries. The standard library is enough, adds no dependency,
and the SQL is short enough to read in an interview.
"""
from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

_SCHEMA = """
CREATE TABLE IF NOT EXISTS seals (
    seal_id    TEXT PRIMARY KEY,
    pixel_hash TEXT NOT NULL,
    key_id     TEXT NOT NULL,
    owner      TEXT NOT NULL,
    created_at TEXT NOT NULL  -- ISO 8601, always UTC
)
"""


@dataclass(frozen=True)
class SealRecord:
    seal_id: str
    pixel_hash: str
    key_id: str
    owner: str
    created_at: datetime  # timezone-aware, UTC


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class SealStore:
    """Thin wrapper over one SQLite file.

    A new connection per operation: requests run on different threads
    (sealing runs in the threadpool), and a sqlite3 connection must not be
    shared across threads. Opening a local SQLite file is cheap.
    """

    def __init__(self, path: str | Path):
        self._path = Path(path)
        # So a path like /data/miniseal.db works on a fresh Docker volume.
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.execute(_SCHEMA)

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        # timeout: wait for a concurrent writer instead of failing at once.
        conn = sqlite3.connect(self._path, timeout=5)
        try:
            with conn:  # commits on success, rolls back on exception
                yield conn
        finally:
            conn.close()  # `with conn` alone does NOT close the connection

    def add(self, record: SealRecord) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO seals (seal_id, pixel_hash, key_id, owner, created_at) "
                "VALUES (?, ?, ?, ?, ?)",  # placeholders: never string-format SQL
                (
                    record.seal_id,
                    record.pixel_hash,
                    record.key_id,
                    record.owner,
                    record.created_at.astimezone(timezone.utc).isoformat(),
                ),
            )

    def get(self, seal_id: str) -> SealRecord | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT seal_id, pixel_hash, key_id, owner, created_at FROM seals WHERE seal_id = ?",
                (seal_id,),
            ).fetchone()
        if row is None:
            return None
        seal_id, pixel_hash, key_id, owner, created_at = row
        return SealRecord(seal_id, pixel_hash, key_id, owner, datetime.fromisoformat(created_at))
