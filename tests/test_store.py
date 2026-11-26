import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from app.store import SealRecord, SealStore, utc_now


def record(seal_id="a" * 32, **kw) -> SealRecord:
    fields = dict(
        seal_id=seal_id,
        pixel_hash="ab" * 32,
        key_id="0123456789abcdef",
        owner="alice",
        created_at=datetime(2026, 11, 26, 12, 30, 15, 123456, tzinfo=timezone.utc),
    )
    fields.update(kw)
    return SealRecord(**fields)


@pytest.fixture
def store(tmp_path) -> SealStore:
    return SealStore(tmp_path / "seals.db")


def test_add_then_get_round_trips_every_field(store):
    rec = record()
    store.add(rec)
    assert store.get(rec.seal_id) == rec


def test_unknown_id_is_none(store):
    assert store.get("f" * 32) is None


def test_data_survives_a_new_store_on_the_same_file(tmp_path):
    # Simulates a restart: the registry must not live only in memory.
    SealStore(tmp_path / "seals.db").add(record())
    assert SealStore(tmp_path / "seals.db").get("a" * 32) == record()


def test_creates_missing_parent_directory(tmp_path):
    path = tmp_path / "data" / "nested" / "seals.db"
    SealStore(path).add(record())
    assert path.exists()


def test_non_utc_time_is_stored_as_utc(store):
    israel = timezone(timedelta(hours=2))
    store.add(record(created_at=datetime(2026, 11, 26, 14, 30, tzinfo=israel)))
    got = store.get("a" * 32).created_at
    assert got == datetime(2026, 11, 26, 12, 30, tzinfo=timezone.utc)
    assert got.utcoffset() == timedelta(0)


def test_utc_now_is_timezone_aware():
    assert utc_now().utcoffset() == timedelta(0)


def test_duplicate_seal_id_is_rejected(store):
    # PRIMARY KEY: a seal_id can never be silently re-assigned to other pixels.
    store.add(record())
    with pytest.raises(sqlite3.IntegrityError):
        store.add(record(pixel_hash="cd" * 32))
    assert store.get("a" * 32).pixel_hash == "ab" * 32


def test_id_is_a_parameter_not_sql(store):
    store.add(record())
    assert store.get("' OR '1'='1") is None
    assert store.get("a" * 32) is not None
