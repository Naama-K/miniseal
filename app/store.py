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
    seal_id        TEXT PRIMARY KEY,
    pixel_hash     TEXT NOT NULL,
    key_id         TEXT NOT NULL,
    owner          TEXT NOT NULL,
    created_at     TEXT NOT NULL,  -- ISO 8601, always UTC
    detector_model TEXT,           -- the three detector_* columns are NULL
    detector_score REAL,           -- when no detection was recorded
    detector_label TEXT
)
"""

# Columns added after the first release. CREATE TABLE IF NOT EXISTS does
# nothing to a table that already exists, so an older database file would
# lack them and every INSERT would fail. Adding missing nullable columns on
# startup is a tiny, safe migration: old rows simply read back as "no detection".
_ADDED_COLUMNS = {
    "detector_model": "TEXT",
    "detector_score": "REAL",
    "detector_label": "TEXT",
}

_COLUMNS = "seal_id, pixel_hash, key_id, owner, created_at, detector_model, detector_score, detector_label"


@dataclass(frozen=True)
class RecordedDetection:
    """What the detector said when the image was sealed. No latency: that
    describes one request, not the image."""

    model: str
    score: float
    label: str


@dataclass(frozen=True)
class SealRecord:
    seal_id: str
    pixel_hash: str
    key_id: str
    owner: str
    created_at: datetime  # timezone-aware, UTC
    detection: RecordedDetection | None = None  # None: detector failed, or a pre-detector seal


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
            existing = {row[1] for row in conn.execute("PRAGMA table_info(seals)")}
            for name, sql_type in _ADDED_COLUMNS.items():
                if name not in existing:
                    # Names come from the constant above, never from input.
                    conn.execute(f"ALTER TABLE seals ADD COLUMN {name} {sql_type}")

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
        d = record.detection
        with self._connect() as conn:
            conn.execute(
                f"INSERT INTO seals ({_COLUMNS}) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (  # values only ever go through placeholders
                    record.seal_id,
                    record.pixel_hash,
                    record.key_id,
                    record.owner,
                    record.created_at.astimezone(timezone.utc).isoformat(),
                    d.model if d else None,
                    d.score if d else None,
                    d.label if d else None,
                ),
            )

    def get(self, seal_id: str) -> SealRecord | None:
        with self._connect() as conn:
            row = conn.execute(f"SELECT {_COLUMNS} FROM seals WHERE seal_id = ?", (seal_id,)).fetchone()
        if row is None:
            return None
        seal_id, pixel_hash, key_id, owner, created_at, model, score, label = row
        detection = RecordedDetection(model, score, label) if model is not None else None
        return SealRecord(seal_id, pixel_hash, key_id, owner, datetime.fromisoformat(created_at), detection)
