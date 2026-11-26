"""API keys: the key store, the 401s, owner-only reads, and the CLI."""
import io

import pytest
from fastapi.testclient import TestClient
from PIL import Image

from app.auth import KEY_PREFIX, ApiKeyStore, hash_key, main
from app.config import Settings, get_settings
from app.crypto import generate_key_b64
from app.main import create_app, get_detector
from tests.test_detector import FixedDetector


def png_bytes(color=(10, 120, 200)) -> bytes:
    out = io.BytesIO()
    Image.new("RGB", (16, 16), color).save(out, format="PNG")
    return out.getvalue()


@pytest.fixture
def db(tmp_path):
    return tmp_path / "auth.db"


@pytest.fixture
def keys(db) -> ApiKeyStore:
    return ApiKeyStore(db)


@pytest.fixture
def app(db):
    settings = Settings(_env_file=None, signing_key=generate_key_b64(), db_path=str(db))
    app = create_app()
    app.dependency_overrides[get_settings] = lambda: settings
    return app


def client_for(app, key: str | None) -> TestClient:
    return TestClient(app, headers={"X-API-Key": key} if key else {})


def seal(client, data=None):
    return client.post("/seal", files={"file": ("x.png", data or png_bytes(), "image/png")})


def verify(client, data):
    return client.post("/verify", files={"file": ("x.png", data, "image/png")})


# ---------- key store ----------

def test_created_key_identifies_its_owner(keys):
    key_id, key = keys.create("alice")
    assert key.startswith(KEY_PREFIX) and len(key) > 40
    assert keys.owner_for(key) == "alice"
    assert [(k.id, k.owner, k.revoked_at) for k in keys.list()] == [(key_id, "alice", None)]


def test_every_key_is_different(keys):
    assert keys.create("alice")[1] != keys.create("alice")[1]


def test_only_the_hash_is_stored(db, keys):
    # Whoever gets the database file gets nothing they can call the API with.
    _, key = keys.create("alice")
    # With WAL, recent writes may still be in the -wal side file: scan both.
    raw = b"".join(p.read_bytes() for p in db.parent.glob(db.name + "*"))
    assert key.encode() not in raw
    assert key[len(KEY_PREFIX):].encode() not in raw
    assert hash_key(key).encode() in raw


@pytest.mark.parametrize("bad", ["", "msk_", "msk_nope", "not-even-prefixed"])
def test_unknown_keys_have_no_owner(keys, bad):
    keys.create("alice")
    assert keys.owner_for(bad) is None


def test_revoked_key_stops_working_and_revoking_is_once(keys):
    key_id, key = keys.create("alice")
    assert keys.revoke(key_id) is True
    assert keys.owner_for(key) is None
    assert keys.revoke(key_id) is False  # already revoked
    assert keys.revoke("nope") is False
    assert keys.list()[0].revoked_at is not None


@pytest.mark.parametrize("owner", ["", "a b", "alice<script>", "x" * 65, "אליס"])
def test_owner_names_are_restricted(keys, owner):
    with pytest.raises(ValueError):
        keys.create(owner)


# ---------- 401 ----------

@pytest.mark.parametrize("key", [None, "", "msk_wrong", "Bearer something"])
def test_seal_without_a_valid_key_is_401(app, key):
    resp = seal(client_for(app, key))
    assert resp.status_code == 401
    assert resp.headers["www-authenticate"] == "ApiKey"


def test_missing_wrong_and_revoked_keys_get_the_same_answer(app, keys):
    # The response must not reveal whether a key exists or was revoked.
    key_id, key = keys.create("alice")
    keys.revoke(key_id)
    answers = {seal(client_for(app, k)).json()["detail"] for k in (None, "msk_wrong", key)}
    assert len(answers) == 1


def test_revocation_takes_effect_immediately(app, keys):
    key_id, key = keys.create("alice")
    client = client_for(app, key)
    assert seal(client).status_code == 200
    keys.revoke(key_id)
    assert seal(client).status_code == 401  # no restart needed


def test_unauthenticated_seal_does_no_work(app, db):
    # 401 comes before decoding, the detector, signing and the database.
    calls = []

    class Spy(FixedDetector):
        def score(self, img):
            calls.append(1)
            return super().score(img)

    app.dependency_overrides[get_detector] = lambda: Spy(0.1)
    assert seal(client_for(app, None)).status_code == 401
    assert calls == []
    import sqlite3

    with sqlite3.connect(db) as conn:
        assert conn.execute("SELECT COUNT(*) FROM seals").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM detections").fetchone()[0] == 0


# ---------- owner ----------

def test_seal_is_recorded_under_the_keys_owner(app, keys):
    alice = client_for(app, keys.create("alice")[1])
    seal_id = seal(alice).headers["x-miniseal-seal-id"]
    assert alice.get(f"/seals/{seal_id}").json()["owner"] == "alice"


def test_seals_can_only_be_read_by_their_owner(app, keys):
    alice = client_for(app, keys.create("alice")[1])
    bob = client_for(app, keys.create("bob")[1])
    seal_id = seal(alice).headers["x-miniseal-seal-id"]

    assert alice.get(f"/seals/{seal_id}").status_code == 200
    theirs = bob.get(f"/seals/{seal_id}")
    missing = bob.get(f"/seals/{'0' * 32}")
    # Someone else's seal looks exactly like one that doesn't exist.
    assert theirs.status_code == missing.status_code == 404
    assert theirs.json() == missing.json()


def test_reading_a_seal_needs_a_key(app, keys):
    seal_id = seal(client_for(app, keys.create("alice")[1])).headers["x-miniseal-seal-id"]
    assert client_for(app, None).get(f"/seals/{seal_id}").status_code == 401


def test_same_owner_with_a_second_key_can_read_their_seals(app, keys):
    # Ownership belongs to the owner, not to one key: rotating keys keeps access.
    old_id, old = keys.create("alice")
    seal_id = seal(client_for(app, old)).headers["x-miniseal-seal-id"]
    keys.revoke(old_id)
    _, new = keys.create("alice")
    assert client_for(app, new).get(f"/seals/{seal_id}").status_code == 200


# ---------- public endpoints ----------

def test_health_and_verify_are_public(app, keys):
    sealed = seal(client_for(app, keys.create("alice")[1])).content
    anyone = client_for(app, None)
    assert anyone.get("/health").status_code == 200
    body = verify(anyone, sealed).json()
    # Whoever holds the image can check it and see who sealed it.
    assert body["status"] == "sealed_intact"
    assert body["seal"]["owner"] == "alice"


def test_seals_stay_valid_after_their_key_is_revoked(app, keys):
    # The seal is signed by the service, not by the API key: revoking a
    # leaked key stops new seals, it doesn't un-seal the owner's images.
    key_id, key = keys.create("alice")
    sealed = seal(client_for(app, key)).content
    keys.revoke(key_id)
    assert verify(client_for(app, None), sealed).json()["status"] == "sealed_intact"


# ---------- CLI ----------

def test_cli_create_list_revoke(db, capsys):
    assert main(["--db", str(db), "create", "alice"]) == 0
    out = capsys.readouterr().out
    key = next(line.split()[-1] for line in out.splitlines() if line.startswith("key:"))
    key_id = next(line.split()[-1] for line in out.splitlines() if line.startswith("id:"))
    assert ApiKeyStore(db).owner_for(key) == "alice"

    assert main(["--db", str(db), "list"]) == 0
    listed = capsys.readouterr().out
    assert key_id in listed and "active" in listed and key not in listed  # never re-shown

    assert main(["--db", str(db), "revoke", key_id]) == 0
    assert main(["--db", str(db), "revoke", key_id]) == 1
    assert ApiKeyStore(db).owner_for(key) is None


def test_cli_rejects_a_bad_owner(db):
    with pytest.raises(SystemExit):
        main(["--db", str(db), "create", "bad owner"])
