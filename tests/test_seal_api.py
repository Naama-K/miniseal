import base64
import io
import sqlite3
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from PIL import Image, PngImagePlugin

from app.config import Settings, get_settings
from app.crypto import Signer, generate_key_b64, pixel_hash, seal_message
from app.embed import extract, load_image
from app.main import create_app, get_owner, get_store, sealed_filename


def image_bytes(fmt="PNG", size=(16, 16), color=(10, 120, 200), **kw) -> bytes:
    buf = io.BytesIO()
    Image.new("RGB", size, color).save(buf, format=fmt, **kw)
    return buf.getvalue()


@pytest.fixture
def make_client(tmp_path):
    """Factory: a client with given settings and its own throwaway database."""

    def _make(**settings_overrides) -> TestClient:
        settings_overrides.setdefault("db_path", str(tmp_path / "seals.db"))
        # _env_file=None: tests never read a developer's real .env.
        settings = Settings(_env_file=None, **settings_overrides)
        app = create_app()
        app.dependency_overrides[get_settings] = lambda: settings
        return TestClient(app)

    return _make


@pytest.fixture
def key() -> str:
    return generate_key_b64()


@pytest.fixture
def client(key, make_client) -> TestClient:
    return make_client(signing_key=key)


def post(client, data: bytes, filename="photo.png", content_type="image/png"):
    return client.post("/seal", files={"file": (filename, data, content_type)})


# ---------- happy path ----------

@pytest.mark.parametrize("fmt", ["PNG", "JPEG", "WEBP"])
def test_seal_returns_verifiable_png(client, key, fmt):
    resp = post(client, image_bytes(fmt), filename=f"photo.{fmt.lower()}")
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "image/png"
    assert resp.content.startswith(b"\x89PNG\r\n\x1a\n")

    img = load_image(resp.content)
    payload = extract(img)
    signer = Signer.from_b64(key)
    digest = pixel_hash(img)
    assert payload.pixel_hash == digest.hex()
    message = seal_message(payload.seal_id, digest)
    assert signer.verify(message, base64.b64decode(payload.signature))
    assert payload.key_id == signer.key_id
    assert resp.headers["x-miniseal-seal-id"] == payload.seal_id
    assert resp.headers["x-miniseal-key-id"] == payload.key_id


def test_each_seal_gets_a_unique_id(client):
    a = post(client, image_bytes()).headers["x-miniseal-seal-id"]
    b = post(client, image_bytes()).headers["x-miniseal-seal-id"]
    assert a != b


def test_download_filename(client):
    resp = post(client, image_bytes("JPEG"), filename="My Photo.jpg")
    assert resp.headers["content-disposition"] == 'attachment; filename="My_Photo.sealed.png"'


@pytest.mark.parametrize(
    "original, expected",
    [
        ("cat.png", "cat.sealed.png"),
        (None, "image.sealed.png"),
        ('evil"\r\nX-Injected: 1.png', "evil_X-Injected_1.sealed.png"),
        ("../../etc/passwd", "passwd.sealed.png"),
        ("C:\\Users\\me\\cat.jpg", "cat.sealed.png"),
        ("תמונה.jpg", "image.sealed.png"),
    ],
)
def test_sealed_filename_is_header_safe(original, expected):
    assert sealed_filename(original) == expected


# ---------- rejections ----------

def test_missing_key_is_503_and_health_still_works(make_client):
    client = make_client(signing_key=None)
    resp = post(client, image_bytes())
    assert resp.status_code == 503
    assert "MINISEAL_SIGNING_KEY" in resp.json()["detail"]
    assert client.get("/health").status_code == 200


def test_not_an_image_is_400(client):
    resp = post(client, b"definitely not an image", filename="x.png")
    assert resp.status_code == 400


def test_missing_file_field_is_422(client):
    assert client.post("/seal").status_code == 422


def test_file_over_byte_limit_is_413(key, make_client):
    data = image_bytes()
    client = make_client(signing_key=key, max_upload_bytes=len(data) - 1)
    assert post(client, data).status_code == 413


def test_image_over_pixel_limit_is_413(key, make_client):
    client = make_client(signing_key=key, max_image_pixels=100)
    assert post(client, image_bytes(size=(11, 10))).status_code == 413


def test_already_sealed_is_409(client):
    sealed = post(client, image_bytes()).content
    assert post(client, sealed).status_code == 409


def test_malformed_seal_chunk_is_409(client):
    info = PngImagePlugin.PngInfo()
    info.add_itxt("miniseal", "garbage")
    assert post(client, image_bytes(pnginfo=info)).status_code == 409


# ---------- registry: GET /seals/{id} ----------

def db_rows(client) -> int:
    path = client.app.dependency_overrides[get_settings]().db_path
    with sqlite3.connect(path) as conn:
        return conn.execute("SELECT COUNT(*) FROM seals").fetchone()[0]


def test_sealed_image_is_registered_and_retrievable(client):
    before = datetime.now(timezone.utc)
    resp = post(client, image_bytes())
    after = datetime.now(timezone.utc)
    payload = extract(load_image(resp.content))

    info = client.get(f"/seals/{payload.seal_id}")
    assert info.status_code == 200
    body = info.json()
    assert body["seal_id"] == payload.seal_id
    assert body["pixel_hash"] == payload.pixel_hash
    assert body["key_id"] == payload.key_id
    assert body["owner"] == "anonymous"
    created = datetime.fromisoformat(body["created_at"])
    assert created.utcoffset() == timedelta(0)  # always UTC, with offset
    assert before <= created <= after
    assert "signature" not in body


def test_unknown_seal_id_is_404(client):
    assert client.get(f"/seals/{'0' * 32}").status_code == 404


def test_owner_comes_from_the_owner_dependency(client):
    # Task 7 swaps get_owner for an API-key lookup; this pins the wiring.
    client.app.dependency_overrides[get_owner] = lambda: "alice"
    seal_id = post(client, image_bytes()).headers["x-miniseal-seal-id"]
    assert client.get(f"/seals/{seal_id}").json()["owner"] == "alice"


def test_rejected_uploads_are_not_registered(client):
    post(client, b"not an image")  # 400
    sealed = post(client, image_bytes()).content
    post(client, sealed)  # 409
    assert db_rows(client) == 1  # only the one successful seal


def test_image_is_not_returned_if_it_cannot_be_registered(client):
    class BrokenStore:
        def add(self, record):
            raise sqlite3.OperationalError("disk I/O error")

    client.app.dependency_overrides[get_store] = lambda: BrokenStore()
    # The error propagates (500 in production): no unregistered seal leaves.
    with pytest.raises(sqlite3.OperationalError):
        post(client, image_bytes())
