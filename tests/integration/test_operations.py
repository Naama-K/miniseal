"""What operators live through: restarts, key changes, missing config, a busy database."""

import sqlite3
import threading

from app.crypto import generate_key_b64
from tests.integration.conftest import image_bytes, seal, signup, verify


def test_seals_and_keys_survive_a_restart(server):
    # What the Docker volume relies on: everything lives in the DB file.
    account = signup(server, "alice")
    sealed = seal(server.client(account["key"]), image_bytes())
    seal_id = sealed.headers["x-miniseal-seal-id"]

    server.restart()  # same key, same database file

    alice = server.client(account["key"])
    assert alice.get("/me").json() == {"owner": "alice"}  # API key still valid
    assert alice.get(f"/seals/{seal_id}").json()["detector_at_seal"] is not None
    body = verify(server.client(), sealed.content)
    assert body["status"] == "sealed_intact" and body["seal"]["owner"] == "alice"


def test_changing_the_signing_key_orphans_old_seals(server):
    # Today we trust exactly one key. Replacing it (instead of rotating with
    # a set of trusted keys) makes every earlier seal "unknown_key". This
    # test documents that limitation; the README explains real rotation.
    key = signup(server, "alice")["key"]
    old = seal(server.client(key), image_bytes()).content

    server.restart(MINISEAL_SIGNING_KEY=generate_key_b64())

    body = verify(server.client(), old)
    assert (body["status"], body["reason"], body["seal"]) == ("sealed_tampered", "unknown_key", None)
    new = seal(server.client(key), image_bytes(color=(9, 9, 9))).content
    assert verify(server.client(), new)["status"] == "sealed_intact"


def test_missing_signing_key_is_503_but_health_stays_up(server):
    key = signup(server, "alice")["key"]
    server.restart(MINISEAL_SIGNING_KEY=None)

    client = server.client(key)
    assert client.get("/health").status_code == 200  # the process is fine...
    resp = seal(client, image_bytes())
    assert resp.status_code == 503  # ...it just can't sign: says what to fix
    assert "MINISEAL_SIGNING_KEY" in resp.json()["detail"]
    assert client.post("/verify", files={"file": ("x.png", image_bytes(), "image/png")}).status_code == 503


def test_unusable_database_fails_cleanly(server, tmp_path):
    # The DB path points *inside a file*: the folder can't be created.
    blocker = tmp_path / "not-a-folder"
    blocker.write_text("x")
    server.restart(MINISEAL_DB_PATH=str(blocker / "miniseal.db"))

    client = server.client("msk_anything")
    assert client.get("/health").status_code == 200
    resp = seal(client, image_bytes())
    assert resp.status_code == 500
    assert resp.text == "Internal Server Error"  # no traceback or paths leak to the client


def test_seal_is_never_returned_if_it_cannot_be_recorded(server):
    # Another writer holds the database for longer than our 5 s busy timeout.
    # The seal must fail as a whole: no PNG handed out for an unrecorded seal.
    key = signup(server, "alice")["key"]
    verify(server.client(), image_bytes())  # warm up: the seals table now exists
    holder = sqlite3.connect(server.db, timeout=0, isolation_level=None)
    holder.execute("BEGIN IMMEDIATE")  # take the write lock and keep it
    try:
        resp = seal(server.client(key), image_bytes())
    finally:
        holder.execute("ROLLBACK")
        holder.close()

    assert resp.status_code == 500
    assert not resp.headers.get("content-type", "").startswith("image/")
    with sqlite3.connect(server.db) as conn:
        assert conn.execute("SELECT COUNT(*) FROM seals").fetchone()[0] == 0
    # And once the lock is gone, the service recovers by itself.
    assert seal(server.client(key), image_bytes()).status_code == 200


def test_verify_still_answers_while_the_database_is_locked(server):
    # The verdict needs only reads, and WAL lets reads through a held write
    # lock. The log row does wait for the lock: it gives up after the 5 s
    # busy timeout (best-effort) and the correct answer still goes out.
    # Measured cost: a stuck writer delays /verify by up to 5 s. That delay
    # is the argument for moving log writes off the request path at scale.
    import time

    key = signup(server, "alice")["key"]
    sealed = seal(server.client(key), image_bytes()).content

    holder = sqlite3.connect(server.db, timeout=0, isolation_level=None)
    holder.execute("BEGIN IMMEDIATE")
    result = {}
    try:
        start = time.monotonic()
        t = threading.Thread(target=lambda: result.update(verify(server.client(), sealed)))
        t.start()
        t.join(timeout=15)
        elapsed = time.monotonic() - start
        answered_while_locked = not t.is_alive()
    finally:
        holder.execute("ROLLBACK")
        holder.close()
    t.join()

    assert answered_while_locked  # answered before the lock was released
    assert result["status"] == "sealed_intact" and result["seal"]["owner"] == "alice"
    assert 4 < elapsed < 12  # waited for the log write's busy timeout, then gave up
    with sqlite3.connect(server.db) as conn:  # the log row was dropped, as designed
        n = conn.execute("SELECT COUNT(*) FROM detections WHERE context = 'verify'").fetchone()[0]
    assert n == 0
