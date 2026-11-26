"""The detections table, the verdict recorded at sealing time, and the seal policy."""

import io
import sqlite3
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient
from PIL import Image
from pydantic import ValidationError

from app.config import Settings, get_settings
from app.crypto import generate_key_b64
from app.detector import run_detector
from app.main import create_app, get_detector, get_store
from app.store import RecordedDetection, SealRecord, SealStore
from tests.conftest import keyed_client
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
    return keyed_client(app, db)


def seal(client, data=None):
    return client.post("/seal", files={"file": ("x.png", data or png_bytes(), "image/png")})


def rows(db, table="seals") -> int:
    # A table name can't be a ? placeholder, so it goes into the SQL text:
    # allow only known names, never arbitrary input.
    if table not in ("seals", "detections"):
        raise ValueError(f"unknown table {table!r}")
    with sqlite3.connect(db) as conn:
        return conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]  # noqa: S608


def record(seal_id="a" * 32, pixel_hash="ab" * 32) -> SealRecord:
    return SealRecord(seal_id, pixel_hash, "k", "alice", datetime.now(UTC))


def a_run(detector=None, threshold=0.5):
    return run_detector(detector or FixedDetector(0.1), Image.new("RGB", (2, 2)), threshold)


# ---------- store: detections table ----------


def test_seal_and_its_detection_are_written_together(db):
    store = SealStore(db)
    store.add(record(), a_run(FixedDetector(0.25, name="m")))

    assert store.get("a" * 32).detection == RecordedDetection("m", 0.25, "likely_real", 0.5)
    (row,) = store.detections(seal_id="a" * 32)
    assert (row.context, row.pixel_hash, row.model, row.score, row.label) == (
        "seal",
        "ab" * 32,
        "m",
        0.25,
        "likely_real",
    )
    assert (row.threshold, row.error) == (0.5, None) and row.latency_ms >= 0


def test_failed_seal_time_run_is_logged_but_not_shown_as_a_verdict(db):
    store = SealStore(db)
    store.add(record(), a_run(CrashingDetector()))
    assert store.get("a" * 32).detection is None  # no verdict to show...
    (row,) = store.detections()
    assert row.error.startswith("RuntimeError") and row.score is None  # ...but the failure is kept


def test_seal_without_run_has_no_detection(db):
    store = SealStore(db)
    store.add(record())
    assert store.get("a" * 32).detection is None
    assert store.detections() == []


def test_seal_and_detection_rows_are_one_transaction(db):
    # If the detection row can't be written, the seal row must not stay
    # behind on its own: a seal never loses the verdict it was issued with.
    store = SealStore(db)
    bad_run = a_run()
    object.__setattr__(bad_run, "model", None)  # violates detections.model NOT NULL
    with pytest.raises(sqlite3.IntegrityError):
        store.add(record(), bad_run)
    assert rows(db, "seals") == 0 and rows(db, "detections") == 0


def test_detection_cannot_point_at_a_seal_that_does_not_exist(db):
    # Foreign keys are on: an orphan link is refused, not stored.
    with pytest.raises(sqlite3.IntegrityError):
        SealStore(db).log_detection(a_run(), "verify", "ab" * 32, seal_id="f" * 32)


def test_unknown_context_is_refused(db):
    with pytest.raises(sqlite3.IntegrityError):
        SealStore(db).log_detection(a_run(), "training", "ab" * 32)


def test_database_from_an_earlier_version_still_works(db):
    # A file created before the detections table existed, with extra columns on seals.
    with sqlite3.connect(db) as conn:
        conn.execute(
            "CREATE TABLE seals (seal_id TEXT PRIMARY KEY, pixel_hash TEXT NOT NULL, "
            "key_id TEXT NOT NULL, owner TEXT NOT NULL, created_at TEXT NOT NULL, "
            "detector_model TEXT, detector_score REAL, detector_label TEXT)"
        )
        conn.execute(
            "INSERT INTO seals (seal_id, pixel_hash, key_id, owner, created_at) VALUES (?, ?, ?, ?, ?)",
            ("o" * 32, "ab" * 32, "k", "alice", "2026-11-25T10:00:00+00:00"),
        )
    store = SealStore(db)  # creates the detections table, leaves seals alone
    assert store.get("o" * 32).owner == "alice"
    store.add(record("n" * 32), a_run(FixedDetector(0.9)))
    assert store.get("n" * 32).detection.label == "suspicious"


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
    assert info["detector_at_seal"] == {"model": "m1", "score": score, "label": label, "threshold": 0.5}


def test_always_still_seals_when_the_detector_fails(db):
    client = make_client(db, detector=CrashingDetector())
    resp = seal(client)
    assert resp.status_code == 200
    assert "x-miniseal-detector-label" not in resp.headers
    seal_id = resp.headers["x-miniseal-seal-id"]
    assert client.get(f"/seals/{seal_id}").json()["detector_at_seal"] is None
    (row,) = SealStore(db).detections(seal_id=seal_id)
    assert row.context == "seal" and row.error == "RuntimeError: model server unreachable"


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
    assert rows(db) == 0  # no seal issued
    (row,) = SealStore(db).detections()  # but the refusal is counted
    assert (row.context, row.seal_id, row.score) == ("seal_rejected", None, 0.9)


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
    (row,) = SealStore(db).detections()
    assert row.context == "seal_rejected" and row.error is not None


def test_already_sealed_check_runs_before_the_detector(db):
    # 409 must not depend on the detector's mood: a resealed image is a
    # conflict whatever the score.
    sealed = seal(make_client(db)).content
    client = make_client(db, detector=CrashingDetector(), seal_policy="reject_suspicious")
    assert seal(client, sealed).status_code == 409


# ---------- /verify logging ----------


def verify(client, data):
    return client.post("/verify", files={"file": ("x.png", data, "image/png")})


def test_every_verify_is_logged_and_linked_only_to_proven_seals(db):
    client = make_client(db)
    original = png_bytes()
    sealed = seal(client, original).content
    seal_id = SealStore(db).detections(context="seal")[0].seal_id

    verify(client, sealed)  # intact: linked to its seal
    verify(client, original)  # unsealed: no seal to link

    logged = SealStore(db).detections(context="verify")
    assert [r.seal_id for r in logged] == [seal_id, None]
    # Same pixels both times (sealing doesn't change them): same hash logged.
    assert logged[0].pixel_hash == logged[1].pixel_hash
    assert all(r.model == "dummy-hash-v1" and r.error is None for r in logged)


def test_forged_seal_id_is_not_linked_in_the_log(db):
    # An attacker writes a real seal_id into a seal we never signed. The log
    # must not tie this run to that seal: only proven seals are linked.
    import json

    from PIL import PngImagePlugin

    client = make_client(db)
    seal(client)
    real_id = SealStore(db).detections(context="seal")[0].seal_id
    fake = {
        "v": 2,
        "alg": "Ed25519",
        "seal_id": real_id,
        "pixel_hash": "00" * 32,
        "signature": "AAAA",
        "key_id": "x",
    }
    info = PngImagePlugin.PngInfo()
    info.add_itxt("miniseal", json.dumps(fake))
    out = io.BytesIO()
    Image.new("RGB", (16, 16), (5, 5, 5)).save(out, format="PNG", pnginfo=info)

    assert verify(client, out.getvalue()).json()["status"] == "sealed_tampered"
    assert SealStore(db).detections(context="verify")[0].seal_id is None


def test_verify_still_answers_if_the_log_write_fails(db):
    class LogFails(SealStore):
        def log_detection(self, *a, **kw):
            raise sqlite3.OperationalError("database is locked")

    client = make_client(db)
    sealed = seal(client).content
    client.app.dependency_overrides[get_store] = lambda: LogFails(db)
    resp = verify(client, sealed)
    assert resp.status_code == 200
    assert resp.json()["status"] == "sealed_intact"
    assert resp.json()["detector"] is not None


def test_database_uses_write_ahead_logging(db):
    # Readers and the writer don't block each other (see SealStore.__init__).
    SealStore(db)
    with sqlite3.connect(db) as conn:
        assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
