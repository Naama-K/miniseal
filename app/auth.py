"""API keys: who is calling. The owner recorded on every seal comes from here.

* Keys are 256 random bits, prefixed "msk_" so secret scanners can spot one
  committed by mistake. A key is shown once, at creation.
* Only a SHA-256 of each key is stored, so a leaked database can't be used to
  call the API. A fast hash is enough: slow hashing (bcrypt) protects guessable
  passwords, and nobody can guess 256 random bits.
* Lookup is by hash, so there is no string comparison an attacker could time.
* Revoking a key takes effect on the next request. Seals made with it stay
  valid: they are signed by the service, not by the API key.

Keys are managed by an operator, not over the API:
    python -m app.auth create <owner>
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
# Owner names appear in responses, logs and the UI: a safe character set only.
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
    """A key as listed: everything except the key itself."""

    id: str
    owner: str
    created_at: datetime
    revoked_at: datetime | None


class ApiKeyStore:
    """The api_keys table, in the same SQLite file as the seals."""

    def __init__(self, path: str | Path):
        self._path = open_db(path, _SCHEMA)

    def create(self, owner: str) -> tuple[str, str]:
        """New key for `owner`, new or existing (e.g. rotation). Returns (id, key)."""
        return self._insert(owner, new_owner_only=False)

    def signup(self, owner: str) -> tuple[str, str]:
        """New key for a new owner only, so sign-up can't take over an account.

        Case-insensitive: "Alice" can't pose as "alice". Raises OwnerTakenError.
        """
        return self._insert(owner, new_owner_only=True)

    def _insert(self, owner: str, new_owner_only: bool) -> tuple[str, str]:
        if not OWNER_RE.fullmatch(owner):
            raise ValueError("owner must be 1-64 characters: letters, digits, '_', '.', '-'")
        key = KEY_PREFIX + secrets.token_urlsafe(32)
        key_id = secrets.token_hex(4)
        values = (key_id, hash_key(key), owner, utc_now().isoformat())
        with connect(self._path) as conn:
            if new_owner_only:
                # Check and insert in one statement, so two simultaneous
                # sign-ups for the same name can't both succeed.
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
            return None
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
    from app.config import get_settings

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
