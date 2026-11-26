"""Running it: the signing key from a file (containers), readiness, Docker hygiene."""

import sys
import threading
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import Settings, get_settings
from app.crypto import Signer, ensure_key_file, generate_key_b64
from app.main import create_app

ROOT = Path(__file__).parents[1]


def client(**settings_kw) -> TestClient:
    settings = Settings(_env_file=None, **settings_kw)
    app = create_app()
    app.dependency_overrides[get_settings] = lambda: settings
    return TestClient(app)


# ---------- ensure_key_file (run by the container on start) ----------


def test_key_file_is_created_once_and_then_reused(tmp_path):
    path = tmp_path / "nested" / "signing.key"
    first = ensure_key_file(path)
    again = ensure_key_file(path)
    assert first.key_id == again.key_id  # same key across restarts
    assert Signer.from_b64(path.read_text().strip()).key_id == first.key_id


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions")
def test_key_file_is_readable_by_owner_only(tmp_path):
    path = tmp_path / "signing.key"
    ensure_key_file(path)
    assert (path.stat().st_mode & 0o777) == 0o600


def test_simultaneous_starts_agree_on_one_key(tmp_path):
    path = tmp_path / "signing.key"
    ids = []
    threads = [threading.Thread(target=lambda: ids.append(ensure_key_file(path).key_id)) for _ in range(10)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert len(set(ids)) == 1


def test_existing_garbage_key_file_is_an_error_not_replaced(tmp_path):
    # Never silently mint a new key over an existing file: that would orphan
    # every seal made with the old one.
    path = tmp_path / "signing.key"
    path.write_text("not a key")
    with pytest.raises(ValueError):
        ensure_key_file(path)
    assert path.read_text() == "not a key"


# ---------- the app reading the key file ----------


def test_app_signs_with_the_key_from_the_file(tmp_path):
    key_file = tmp_path / "signing.key"
    expected = ensure_key_file(key_file).key_id
    c = client(signing_key_file=str(key_file), db_path=str(tmp_path / "x.db"))
    assert c.get("/ready").json()["checks"]["signing_key"] == f"ok ({expected})"


def test_missing_key_file_is_not_ready_and_not_created(tmp_path):
    key_file = tmp_path / "missing.key"
    c = client(signing_key_file=str(key_file), db_path=str(tmp_path / "x.db"))
    resp = c.get("/ready")
    assert resp.status_code == 503
    assert resp.json()["checks"]["signing_key"].startswith("failed: MINISEAL_SIGNING_KEY_FILE cannot be read")
    assert str(tmp_path) not in resp.text  # no paths leak
    assert not key_file.exists()  # the app only reads; creating is explicit
    assert c.get("/health").status_code == 200  # alive, just not ready


def test_key_and_key_file_together_is_refused(tmp_path):
    key_file = tmp_path / "signing.key"
    ensure_key_file(key_file)
    c = client(signing_key=generate_key_b64(), signing_key_file=str(key_file), db_path=str(tmp_path / "x.db"))
    assert "not both" in c.get("/ready").json()["checks"]["signing_key"]


# ---------- /ready ----------


def test_ready_when_key_and_database_are_fine(tmp_path):
    resp = client(signing_key=generate_key_b64(), db_path=str(tmp_path / "x.db")).get("/ready")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ready" and resp.json()["checks"]["database"] == "ok"


def test_not_ready_when_the_database_is_unusable(tmp_path):
    blocker = tmp_path / "file"
    blocker.write_text("x")
    c = client(signing_key=generate_key_b64(), db_path=str(blocker / "x.db"))
    resp = c.get("/ready")
    assert resp.status_code == 503
    assert resp.json()["checks"]["database"].startswith("failed: ")
    assert str(tmp_path) not in resp.text
    assert c.get("/health").status_code == 200


def test_not_ready_without_a_signing_key(tmp_path):
    resp = client(db_path=str(tmp_path / "x.db")).get("/ready")
    assert resp.status_code == 503 and resp.json()["status"] == "not_ready"


# ---------- Docker hygiene ----------


def test_secrets_and_local_data_never_enter_the_image():
    ignored = (ROOT / ".dockerignore").read_text().split()
    for pattern in (".env", "*.db", "*.db-wal", ".venv/", ".git/"):
        assert pattern in ignored


def test_container_runs_as_non_root_with_a_readiness_healthcheck():
    dockerfile = (ROOT / "Dockerfile").read_text()
    assert "\nUSER miniseal\n" in dockerfile
    assert "/ready" in dockerfile.split("HEALTHCHECK", 1)[1]


def test_entrypoint_has_unix_line_endings():
    # A CRLF shell script fails inside Linux with a confusing error.
    assert b"\r\n" not in (ROOT / "docker-entrypoint.sh").read_bytes()


def test_compose_project_name_is_fixed():
    # The volume (all seals and the signing key) is named after the project.
    # Without a fixed name, cloning into another folder silently starts empty.
    assert "\nname: miniseal\n" in (ROOT / "compose.yaml").read_text()
