"""The registry: seals issued, and every detector run.

The seal in the image proves "this key signed these pixels". The registry adds
what the image can't prove about itself: when it was sealed and by whom. A seal
that verifies but is missing here was not issued by this service.

* seals      - one row per seal: the facts the seal certifies.
* detections - one row per detector run (at sealing, at a refused sealing, at
               every verification). Opinions, kept apart from the facts: many
               per image, failed runs included. The data for model quality,
               latency and usage analysis.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from app.detector import DetectorRun, Label

_SCHEMA = """
CREATE TABLE IF NOT EXISTS seals (
    seal_id    TEXT PRIMARY KEY,
    pixel_hash TEXT NOT NULL,
    key_id     TEXT NOT NULL,
    owner      TEXT NOT NULL,
    created_at TEXT NOT NULL  -- ISO 8601, always UTC
);

CREATE TABLE IF NOT EXISTS detections (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,                -- ISO 8601, UTC
    context    TEXT NOT NULL CHECK (context IN ('seal', 'seal_rejected', 'verify')),
    seal_id    TEXT REFERENCES seals(seal_id), -- NULL: refused, or verify of an unproven seal
    pixel_hash TEXT NOT NULL,                -- which pixels were scored
    model      TEXT NOT NULL,
    threshold  REAL NOT NULL,                -- the label is only meaningful with it
    score      REAL,                         -- NULL when the run failed
    label      TEXT,
    latency_ms REAL NOT NULL,
    error      TEXT                          -- NULL on success
);

CREATE INDEX IF NOT EXISTS seals_owner ON seals(owner, created_at);  -- "my seals"
CREATE INDEX IF NOT EXISTS detections_seal_id ON detections(seal_id);
CREATE INDEX IF NOT EXISTS detections_created_at ON detections(created_at);
"""

Context = Literal["seal", "seal_rejected", "verify"]


@dataclass(frozen=True)
class RecordedDetection:
    """The detector's verdict when an image was sealed (successful runs only)."""

    model: str
    score: float
    label: Label  # converted on read, so an unexpected stored value fails here
    threshold: float


@dataclass(frozen=True)
class SealRecord:
    seal_id: str
    pixel_hash: str
    key_id: str
    owner: str
    created_at: datetime  # timezone-aware, UTC
    detection: RecordedDetection | None = None


@dataclass(frozen=True)
class DetectionRow:
    """A row of the detections table, as read back."""

    id: int
    created_at: datetime
    context: str
    seal_id: str | None
    pixel_hash: str
    model: str
    threshold: float
    score: float | None
    label: str | None
    latency_ms: float
    error: str | None


def utc_now() -> datetime:
    return datetime.now(UTC)


def _iso(dt: datetime) -> str:
    return dt.astimezone(UTC).isoformat()


def _insert_detection(
    conn: sqlite3.Connection,
    run: DetectorRun,
    context: Context,
    pixel_hash: str,
    seal_id: str | None,
    created_at: datetime,
) -> None:
    conn.execute(
        "INSERT INTO detections (created_at, context, seal_id, pixel_hash, model, threshold, "
        "score, label, latency_ms, error) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            _iso(created_at),
            context,
            seal_id,
            pixel_hash,
            run.model,
            run.threshold,
            run.score,
            run.label,
            run.latency_ms,
            run.error,
        ),
    )


@contextmanager
def connect(path: Path) -> Iterator[sqlite3.Connection]:
    """A short-lived connection with this app's settings. Commits on success."""
    conn = sqlite3.connect(path, timeout=5)  # wait for a concurrent writer
    # SQLite ignores REFERENCES unless this is on, per connection.
    conn.execute("PRAGMA foreign_keys = ON")
    # With WAL, sync at checkpoints rather than every commit: a power cut can
    # lose the last commits but never corrupts the file.
    conn.execute("PRAGMA synchronous = NORMAL")
    try:
        with conn:
            yield conn
    finally:
        conn.close()  # `with conn` commits but does not close


def open_db(path: str | Path, schema: str) -> Path:
    """Create the file's folder, switch on WAL and apply `schema` (idempotent)."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with connect(path) as conn:
        # WAL: readers and the writer don't block each other. Persists in the
        # file. Needs a local filesystem, not a network share.
        conn.execute("PRAGMA journal_mode = WAL")
        conn.executescript(schema)
    return path


class SealStore:
    """The seals and detections tables in one SQLite file.

    A new connection per operation: requests run on different threads, and a
    sqlite3 connection must not be shared across threads.
    """

    def __init__(self, path: str | Path):
        self._path = open_db(path, _SCHEMA)

    def _connect(self) -> AbstractContextManager[sqlite3.Connection]:
        return connect(self._path)

    def ping(self) -> None:
        """Raise if the database can't be read right now."""
        with self._connect() as conn:
            conn.execute("SELECT 1 FROM seals LIMIT 1").fetchall()

    def add(self, record: SealRecord, run: DetectorRun | None = None) -> None:
        """Record a seal and the detector run made while sealing it.

        One transaction: a seal never exists without the verdict it was issued with.
        """
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO seals (seal_id, pixel_hash, key_id, owner, created_at) VALUES (?, ?, ?, ?, ?)",
                (record.seal_id, record.pixel_hash, record.key_id, record.owner, _iso(record.created_at)),
            )
            if run is not None:
                _insert_detection(conn, run, "seal", record.pixel_hash, record.seal_id, record.created_at)

    def log_detection(
        self, run: DetectorRun, context: Context, pixel_hash: str, seal_id: str | None = None
    ) -> None:
        """Record a run that is not part of issuing a seal (verify, refused seal)."""
        with self._connect() as conn:
            _insert_detection(conn, run, context, pixel_hash, seal_id, utc_now())

    def get(self, seal_id: str) -> SealRecord | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT seal_id, pixel_hash, key_id, owner, created_at FROM seals WHERE seal_id = ?",
                (seal_id,),
            ).fetchone()
            if row is None:
                return None
            det = conn.execute(
                "SELECT model, score, label, threshold FROM detections "
                "WHERE seal_id = ? AND context = 'seal' AND error IS NULL "
                "ORDER BY id LIMIT 1",
                (seal_id,),
            ).fetchone()
        seal_id, pixel_hash, key_id, owner, created_at = row
        return SealRecord(
            seal_id,
            pixel_hash,
            key_id,
            owner,
            datetime.fromisoformat(created_at),
            RecordedDetection(det[0], det[1], Label(det[2]), det[3]) if det else None,
        )

    def list_by_owner(self, owner: str, limit: int = 50) -> list[SealRecord]:
        """An owner's seals, newest first, each with its seal-time verdict."""
        with self._connect() as conn:
            ids = [
                r[0]
                for r in conn.execute(
                    "SELECT seal_id FROM seals WHERE owner = ? ORDER BY created_at DESC, seal_id LIMIT ?",
                    (owner, limit),
                )
            ]
        return [r for r in map(self.get, ids) if r is not None]

    def detections(self, seal_id: str | None = None, context: Context | None = None) -> list[DetectionRow]:
        """Detector runs, oldest first, optionally filtered."""
        sql = "SELECT * FROM detections WHERE 1 = 1"
        args: list[str] = []
        if seal_id is not None:
            sql += " AND seal_id = ?"
            args.append(seal_id)
        if context is not None:
            sql += " AND context = ?"
            args.append(context)
        with self._connect() as conn:
            rows = conn.execute(sql + " ORDER BY id", args).fetchall()
        return [DetectionRow(r[0], datetime.fromisoformat(r[1]), *r[2:]) for r in rows]
