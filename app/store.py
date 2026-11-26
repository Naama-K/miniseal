"""The registry: seals issued, and every detector run.

Why keep a record at all, if the seal is inside the image?
----------------------------------------------------------
The embedded seal proves "this key signed these pixels". The registry adds
what the image can't prove about itself: *when* it was sealed and *by whom*
(the API key's owner). It is also our own audit trail: a seal_id that verifies
cryptographically but is missing here was not issued by this service.

Two tables
----------
* seals      - one row per seal issued. The facts the seal certifies.
* detections - one row per detector run: at sealing, at a refused sealing,
               and at every verification. Opinions about content, kept apart
               from the facts: different lifecycle (many per image, failed runs
               included), and it is the data for insight later: score
               distribution per model, latency, failure rate, how often the
               policy refuses, whether a newer model disagrees with an older one.

Why plain sqlite3 and not an ORM?
---------------------------------
Two tables, a handful of queries. The standard library is enough, adds no
dependency, and the SQL is short enough to read in an interview.
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
    """The detector's verdict when an image was sealed (a successful run only)."""

    model: str
    score: float
    label: Label  # checked on read: an unknown value in the DB fails here
    threshold: float


@dataclass(frozen=True)
class SealRecord:
    seal_id: str
    pixel_hash: str
    key_id: str
    owner: str
    created_at: datetime  # timezone-aware, UTC
    # Filled in by get(), from the detections table. None if the detector
    # failed at sealing time (policy "always") or no run was recorded.
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
        (  # values only ever go through placeholders, never string formatting
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
    """One short-lived connection: the only way this app talks to SQLite.

    Shared by every store on the same file (seals, API keys), so all of them
    get the same settings. Commits on success, rolls back on exception.
    """
    # timeout: wait for a concurrent writer instead of failing at once.
    conn = sqlite3.connect(path, timeout=5)
    # SQLite ignores REFERENCES unless this is switched on, per connection.
    conn.execute("PRAGMA foreign_keys = ON")
    # With WAL, NORMAL syncs to disk at checkpoints instead of every
    # commit: much cheaper writes. A power cut can lose the last few
    # commits but never corrupts the file. Per connection, like the above.
    conn.execute("PRAGMA synchronous = NORMAL")
    try:
        with conn:  # commits on success, rolls back on exception
            yield conn
    finally:
        conn.close()  # `with conn` alone does NOT close the connection


def open_db(path: str | Path, schema: str) -> Path:
    """Create the file's folder, switch on WAL and apply `schema` (idempotent)."""
    path = Path(path)
    # So a path like /data/miniseal.db works on a fresh Docker volume.
    path.parent.mkdir(parents=True, exist_ok=True)
    with connect(path) as conn:
        # WAL (write-ahead log): readers no longer block the writer and the
        # writer no longer blocks readers, so GET /seals and /verify lookups
        # keep flowing while a seal is being written. It is a property of
        # the file (it persists), so setting it on open is enough.
        # Caveat: WAL needs a local filesystem, not a network share.
        conn.execute("PRAGMA journal_mode = WAL")
        conn.executescript(schema)
    return path


class SealStore:
    """Thin wrapper over one SQLite file.

    A new connection per operation: requests run on different threads
    (sealing runs in the threadpool), and a sqlite3 connection must not be
    shared across threads. Opening a local SQLite file is cheap.
    """

    def __init__(self, path: str | Path):
        self._path = open_db(path, _SCHEMA)

    def _connect(self) -> AbstractContextManager[sqlite3.Connection]:
        return connect(self._path)

    def ping(self) -> None:
        """Raise if the database can't be read right now (readiness check)."""
        with self._connect() as conn:
            conn.execute("SELECT 1 FROM seals LIMIT 1").fetchall()

    def add(self, record: SealRecord, run: DetectorRun | None = None) -> None:
        """Record a seal and, if given, the detector run made while sealing it.

        One transaction: either both rows exist or neither does, so a seal can
        never lose the verdict it was issued with.
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
        # A query per seal keeps one code path for "a seal with its verdict"
        # (get). Fine for a page of 50 local rows; a JOIN when it matters.
        return [r for r in map(self.get, ids) if r is not None]

    def detections(self, seal_id: str | None = None, context: Context | None = None) -> list[DetectionRow]:
        """Detector runs, oldest first, optionally filtered. For tests and analysis."""
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
