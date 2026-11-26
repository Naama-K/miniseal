"""Detector verdict recorded at sealing time, and the optional seal policy."""
import io
import sqlite3
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from PIL import Image
from pydantic import ValidationError

from app.config import Settings, get_settings
from app.crypto import generate_key_b64
from app.main import create_app, get_detector
from app.store import RecordedDetection, SealRecord, SealStore
from tests.test_detector import CrashingDetector, FixedDetector


def png_bytes(color=(10, 120, 200)) -> bytes:
    out = io.BytesIO()
    Image.new("RGB", (16, 16), color).save(out, format="PNG")
    return out.getvalue()


@pytest.fixture
def db(tmp_path):
    return tmp_path / "seals.db"


def make_client(db, detector=None, **settings_kw) -> TestClient:
    settings = Settings(_env_file=None, signing_key=generate_key_b64(), db_path=str(db), **settings_kw)
    app = create_app()
    app.dependency_overrides[get_settings] = lambda: settings
    if detector is not None:
        app.dependency_overrides[get_detector] = lambda: detector
    return TestClient(app)


def seal(client, data=None):
    return client.post("/seal", files={"file": ("x.png", data or png_bytes(), "image/png")})


def rows(db) -> int:
    with sqlite3.connect(db) as conn:
        return conn.execute("SELECT COUNT(*) FROM seals").fetchone()[0]


# ---------- store ----------

def test_detection_round_trips_through_the_store(db):
    store = SealStore(db)
    now = datetime.now(timezone.utc)
    with_det = SealRecord("a" * 32, "ab" * 32, "k", "alice", now, RecordedDetection("m", 0.25, "likely_real"))
    without = SealRecord("b" * 32, "cd" * 32, "k", "alice", now)
    store.add(with_det)
    store.add(without)
    assert store.get("a" * 32) == with_det
    assert store.get("b" * 32).detection is None


def test_old_database_is_migrated_in_place(db):
    # A database file created before detection existed: 5 columns, one row.
    with sqlite3.connect(db) as conn:
        conn.execute(
            "CREATE TABLE seals (seal_id TEXT PRIMARY KEY, pixel_hash TEXT NOT NULL, "
            "key_id TEXT NOT NULL, owner TEXT NOT NULL, created_at TEXT NOT NULL)"
        )
        conn.execute(
            "INSERT INTO seals VALUES (?, ?, ?, ?, ?)",
            ("o" * 32, "ab" * 32, "k", "alice", "2026-11-25T10:00:00+00:00"),
        )

    store = SealStore(db)  # opening it runs the migration

    old = store.get("o" * 32)
    assert old.owner == "alice" and old.detection is None  # old data kept
    new = SealRecord("n" * 32, "cd" * 32, "k", "bob", datetime.now(timezone.utc),
                     RecordedDetection("m", 0.9, "suspicious"))
    store.add(new)  # would fail with "no column named detector_model" unmigrated
    assert store.get("n" * 32) == new
    SealStore(db)  # running the migration twice is harmless


# ---------- policy "always" (default) ----------

def test_default_policy_is_always():
    assert Settings(_env_file=None).seal_policy == "always"


def test_policy_setting_rejects_unknown_values():
    with pytest.raises(ValidationError):
        Settings(_env_file=None, seal_policy="sometimes")


@pytest.mark.parametrize("score, label", [(0.1, "likely_real"), (0.9, "suspicious")])
def test_always_seals_and_records_the_verdict(db, score, label):
    client = make_client(db, detector=FixedDetector(score, name="m1"))
    resp = seal(client)
    assert resp.status_code == 200  # suspicious images are sealed too
    assert resp.headers["x-miniseal-detector-label"] == label
    assert float(resp.headers["x-miniseal-detector-score"]) == score

    info = client.get(f"/seals/{resp.headers['x-miniseal-seal-id']}").json()
    assert info["detector_at_seal"] == {"model": "m1", "score": score, "label": label}


def test_always_still_seals_when_the_detector_fails(db):
    client = make_client(db, detector=CrashingDetector())
    resp = seal(client)
    assert resp.status_code == 200
    assert "x-miniseal-detector-label" not in resp.headers
    info = client.get(f"/seals/{resp.headers['x-miniseal-seal-id']}").json()
    assert info["detector_at_seal"] is None


def test_verify_shows_both_the_verdict_at_seal_and_now(db):
    # Same pixels, same deterministic dummy: the two verdicts agree. With a
    # real model they could differ (a newer model, or a tuned threshold),
    # which is exactly why both are worth showing.
    client = make_client(db)
    sealed = seal(client).content
    body = client.post("/verify", files={"file": ("x.png", sealed, "image/png")}).json()
    assert body["status"] == "sealed_intact"
    assert body["seal"]["detector_at_seal"]["score"] == body["detector"]["score"]
    assert body["seal"]["detector_at_seal"]["model"] == "dummy-hash-v1"


# ---------- policy "reject_suspicious" ----------

def test_reject_policy_refuses_suspicious_images(db):
    client = make_client(db, detector=FixedDetector(0.9, name="m1"), seal_policy="reject_suspicious")
    resp = seal(client)
    assert resp.status_code == 422
    detail = resp.json()["detail"]
    assert detail["policy"] == "reject_suspicious"
    assert detail["detector"] == {"model": "m1", "score": 0.9, "label": "suspicious"}
    assert rows(db) == 0  # no seal issued, nothing recorded


def test_reject_policy_seals_likely_real_images(db):
    client = make_client(db, detector=FixedDetector(0.1), seal_policy="reject_suspicious")
    resp = seal(client)
    assert resp.status_code == 200
    assert resp.headers["x-miniseal-detector-label"] == "likely_real"
    assert rows(db) == 1


def test_reject_policy_uses_the_threshold(db):
    detector = FixedDetector(0.3)
    strict = make_client(db, detector=detector, seal_policy="reject_suspicious", detector_threshold=0.2)
    assert seal(strict).status_code == 422
    lenient = make_client(db, detector=detector, seal_policy="reject_suspicious", detector_threshold=0.5)
    assert seal(lenient).status_code == 200


def test_reject_policy_fails_closed_when_the_detector_fails(db):
    # The policy promises "only checked images get sealed": an image we
    # could not check is not sealed. 503, because the fault is ours.
    client = make_client(db, detector=CrashingDetector(), seal_policy="reject_suspicious")
    resp = seal(client)
    assert resp.status_code == 503
    assert "detector unavailable" in resp.json()["detail"]
    assert rows(db) == 0


def test_already_sealed_check_runs_before_the_detector(db):
    # 409 must not depend on the detector's mood: a resealed image is a
    # conflict whatever the score.
    sealed = seal(make_client(db)).content
    client = make_client(db, detector=CrashingDetector(), seal_policy="reject_suspicious")
    assert seal(client, sealed).status_code == 409
