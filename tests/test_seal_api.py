import base64
import io

import pytest
from fastapi.testclient import TestClient
from PIL import Image, PngImagePlugin

from app.config import Settings, get_settings
from app.crypto import Signer, generate_key_b64, pixel_hash
from app.embed import extract, load_image
from app.main import create_app, sealed_filename


def image_bytes(fmt="PNG", size=(16, 16), color=(10, 120, 200), **kw) -> bytes:
    buf = io.BytesIO()
    Image.new("RGB", size, color).save(buf, format=fmt, **kw)
    return buf.getvalue()


def make_client(**settings_overrides) -> TestClient:
    # _env_file=None: tests never read a developer's real .env.
    settings = Settings(_env_file=None, **settings_overrides)
    app = create_app()
    app.dependency_overrides[get_settings] = lambda: settings
    return TestClient(app)


@pytest.fixture
def key() -> str:
    return generate_key_b64()


@pytest.fixture
def client(key) -> TestClient:
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
    assert signer.verify(digest, base64.b64decode(payload.signature))
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

def test_missing_key_is_503_and_health_still_works():
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


def test_file_over_byte_limit_is_413(key):
    data = image_bytes()
    client = make_client(signing_key=key, max_upload_bytes=len(data) - 1)
    assert post(client, data).status_code == 413


def test_image_over_pixel_limit_is_413(key):
    client = make_client(signing_key=key, max_image_pixels=100)
    assert post(client, image_bytes(size=(11, 10))).status_code == 413


def test_already_sealed_is_409(client):
    sealed = post(client, image_bytes()).content
    assert post(client, sealed).status_code == 409


def test_malformed_seal_chunk_is_409(client):
    info = PngImagePlugin.PngInfo()
    info.add_itxt("miniseal", "garbage")
    assert post(client, image_bytes(pnginfo=info)).status_code == 409
