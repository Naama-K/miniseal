"""API keys: who is calling. The owner recorded on every seal comes from here.

Design, and why
---------------
* Keys are random, from the OS's secure generator: 32 bytes = 256 bits.
  Nobody can guess one, so brute force is not a threat worth designing for.
* We store only a SHA-256 hash of each key, never the key itself. Whoever
  reads the database (a backup, a leaked file) gets nothing they can call
  the API with. The key is shown exactly once, when it is created.
* A plain SHA-256 is enough here, unlike passwords (which need bcrypt or
  argon2): slow hashing only protects low-entropy secrets that can be
  guessed. Nobody can enumerate 2**256 keys, fast hash or not.
* Lookup is by hash, so a timing difference in the database lookup tells an
  attacker about the hash of what they sent, which they can't steer. That is
  why there is no hand-rolled string comparison here at all.
* Keys start with "msk_": recognisable in logs and code, so secret scanners
  (e.g. GitHub's) can catch one that was committed by mistake.
* Keys live in a table, not in an env var, so a leaked key can be revoked
  at once, without a restart. Revoking a key does NOT invalidate the seals
  made with it: those are signed by the service's key and stay valid.
* Missing, wrong and revoked keys all get the same 401 with the same message,
  so the answer doesn't tell an attacker whether a key ever existed.

Managing keys (no endpoint for it on purpose: creating keys over the API
would need its own admin authentication):
    python -m app.auth create alice
    python -m app.auth list
    python -m app.auth revoke <id>
"""

from __future__ import annotations

import argparse
import hashlib
import re
import secrets
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from app.store import connect, open_db, utc_now

KEY_PREFIX = "msk_"
OWNER_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS api_keys (
    id         TEXT PRIMARY KEY,      -- public handle, for listing and revoking
    key_hash   TEXT NOT NULL UNIQUE,  -- sha256 of the key; the key itself is never stored
    owner      TEXT NOT NULL,
    created_at TEXT NOT NULL,         -- ISO 8601, UTC
    revoked_at TEXT                   -- NULL while the key is active
);
"""


class OwnerTakenError(Exception):
    """Sign-up for a name that already has keys."""


def hash_key(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class ApiKeyInfo:
    """A key as listed: everything except the key, which we don't have."""

    id: str
    owner: str
    created_at: datetime
    revoked_at: datetime | None


class ApiKeyStore:
    """The api_keys table. Lives in the same SQLite file as the seals."""

    def __init__(self, path: str | Path):
        self._path = open_db(path, _SCHEMA)

    def create(self, owner: str) -> tuple[str, str]:
        """New key for `owner` (admin: also for an existing owner, e.g. to
        rotate). Returns (id, key): the only time the key exists in plain text."""
        return self._insert(owner, new_owner_only=False)

    def signup(self, owner: str) -> tuple[str, str]:
        """New key for a NEW owner only (self-service sign-up).

        Without this, signing up as "alice" would hand a stranger a key to
        Alice's account and all her seals. The name check is case-insensitive
        so "Alice" can't pose as "alice". Raises OwnerTakenError.
        """
        return self._insert(owner, new_owner_only=True)

    def _insert(self, owner: str, new_owner_only: bool) -> tuple[str, str]:
        # Owners are restricted to a safe character set because they appear
        # in responses, logs, the UI and the CLI's output.
        if not OWNER_RE.fullmatch(owner):
            raise ValueError("owner must be 1-64 characters: letters, digits, '_', '.', '-'")
        key = KEY_PREFIX + secrets.token_urlsafe(32)  # 32 random bytes
        key_id = secrets.token_hex(4)
        values = (key_id, hash_key(key), owner, utc_now().isoformat())
        with connect(self._path) as conn:
            if new_owner_only:
                # Check and insert in ONE statement: two simultaneous sign-ups
                # for the same name can't both pass the check (no check-then-
                # insert race; the same lost-update problem, solved in SQL).
                cur = conn.execute(
                    "INSERT INTO api_keys (id, key_hash, owner, created_at) "
                    "SELECT ?, ?, ?, ? WHERE NOT EXISTS "
                    "(SELECT 1 FROM api_keys WHERE lower(owner) = lower(?))",
                    (*values, owner),
                )
                if cur.rowcount == 0:
                    raise OwnerTakenError(owner)
            else:
                conn.execute(
                    "INSERT INTO api_keys (id, key_hash, owner, created_at) VALUES (?, ?, ?, ?)", values
                )
        return key_id, key

    def owner_for(self, key: str) -> str | None:
        """The owner of an active key, or None (unknown or revoked)."""
        if not key.startswith(KEY_PREFIX):
            return None  # not one of ours: no need to touch the database
        with connect(self._path) as conn:
            row = conn.execute(
                "SELECT owner FROM api_keys WHERE key_hash = ? AND revoked_at IS NULL",
                (hash_key(key),),
            ).fetchone()
        return row[0] if row else None

    def revoke(self, key_id: str) -> bool:
        """Revoke by id. False if there is no such active key."""
        with connect(self._path) as conn:
            cur = conn.execute(
                "UPDATE api_keys SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL",
                (utc_now().isoformat(), key_id),
            )
        return cur.rowcount == 1

    def list(self) -> list[ApiKeyInfo]:
        with connect(self._path) as conn:
            rows = conn.execute(
                "SELECT id, owner, created_at, revoked_at FROM api_keys ORDER BY created_at"
            ).fetchall()
        return [
            ApiKeyInfo(i, o, datetime.fromisoformat(c), datetime.fromisoformat(r) if r else None)
            for i, o, c, r in rows
        ]


def main(argv: list[str] | None = None) -> int:
    from app.config import get_settings  # here, so importing auth needs no settings

    parser = argparse.ArgumentParser(prog="python -m app.auth", description="Manage MiniSeal API keys.")
    parser.add_argument("--db", help="SQLite file (default: MINISEAL_DB_PATH)")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("create", help="create a key and print it once").add_argument("owner")
    sub.add_parser("list", help="list keys (ids and owners, never the keys)")
    sub.add_parser("revoke", help="revoke a key by its id").add_argument("id")
    args = parser.parse_args(argv)

    store = ApiKeyStore(args.db or get_settings().db_path)
    if args.cmd == "create":
        try:
            key_id, key = store.create(args.owner)
        except ValueError as exc:
            parser.error(str(exc))
        print(f"id:    {key_id}\nowner: {args.owner}\nkey:   {key}")
        print("Store the key now: it is not saved anywhere and cannot be shown again.")
    elif args.cmd == "list":
        for k in store.list():
            state = f"revoked {k.revoked_at:%Y-%m-%d %H:%M}" if k.revoked_at else "active"
            print(f"{k.id}  {k.owner:<20} created {k.created_at:%Y-%m-%d %H:%M}  {state}")
    elif args.cmd == "revoke":
        if not store.revoke(args.id):
            print(f"no active key with id {args.id}")
            return 1
        print(f"revoked {args.id}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
