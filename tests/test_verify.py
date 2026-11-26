"""Every verdict and every tampering reason, plus the /verify endpoint."""
import dataclasses
import io
import json

import pytest
from fastapi.testclient import TestClient
from PIL import Image, PngImagePlugin

from app.config import Settings, get_settings
from app.crypto import Signer, generate_key_b64, pixel_hash
from app.embed import CHUNK_KEY, SealPayload
from app.main import create_app
from app.seal import seal_image
from app.store import SealRecord, SealStore, utc_now
from app.verify import Reason, Status, verify_image


# ---------- helpers ----------

@pytest.fixture
def signer() -> Signer:
    return Signer.from_b64(generate_key_b64())


@pytest.fixture
def store(tmp_path) -> SealStore:
    return SealStore(tmp_path / "seals.db")


def photo(color=(10, 120, 200), mode="RGB", size=(16, 16)) -> Image.Image:
    return Image.new(mode, size, color)


def seal_and_register(signer, store, img=None, owner="alice", register=True):
    png, payload = seal_image(img if img is not None else photo(), signer)
    if register:
        store.add(SealRecord(payload.seal_id, payload.pixel_hash, payload.key_id, owner, utc_now()))
    return png, payload


def load(png: bytes) -> Image.Image:
    img = Image.open(io.BytesIO(png))
    img.load()
    return img


def resave(img: Image.Image, chunk: str | None, **save_kw) -> bytes:
    """Save `img` as PNG with the given raw chunk text (None = no chunk)."""
    info = PngImagePlugin.PngInfo()
    if chunk is not None:
        info.add_itxt(CHUNK_KEY, chunk)
    out = io.BytesIO()
    img.save(out, format="PNG", pnginfo=info, **save_kw)
    return out.getvalue()


def with_payload(png: bytes, payload: SealPayload) -> bytes:
    """Same pixels, different seal: what an attacker editing the chunk produces."""
    return resave(load(png), payload.to_json())


def edit_pixel(png: bytes, xy=(0, 0), value=(255, 0, 0)) -> bytes:
    """Change one pixel and keep the original seal chunk untouched."""
    img = load(png)
    chunk = img.text[CHUNK_KEY]
    img.putpixel(xy, value)
    return resave(img, chunk)


def check(png: bytes, signer, store):
    return verify_image(load(png), signer, store)


# ---------- intact ----------

def test_untouched_sealed_image_is_intact(signer, store):
    png, payload = seal_and_register(signer, store, owner="alice")
    result = check(png, signer, store)
    assert result.status == Status.SEALED_INTACT
    assert result.reason is None
    assert result.record.seal_id == payload.seal_id
    assert result.record.owner == "alice"


def test_lossless_re_encoding_stays_intact(signer, store):
    # Different compression = different file bytes, same pixels. Hashing the
    # pixels (not the file) is what makes this an honest "intact".
    png, _ = seal_and_register(signer, store)
    img = load(png)
    again = resave(img, img.text[CHUNK_KEY], compress_level=0)
    assert again != png
    assert check(again, signer, store).status == Status.SEALED_INTACT


def test_16bit_sealed_image_is_intact_and_high_value_edit_is_caught(signer, store):
    img = Image.new("I;16", (8, 8), 1000)
    png, _ = seal_and_register(signer, store, img=img)
    assert check(png, signer, store).status == Status.SEALED_INTACT
    edited = edit_pixel(png, value=5000)  # both values above 255
    assert check(edited, signer, store).reason == Reason.PIXELS_MODIFIED


# ---------- unsealed ----------

def test_plain_png_is_unsealed(signer, store):
    result = check(resave(photo(), None), signer, store)
    assert result.status == Status.UNSEALED
    assert result.reason is None and result.record is None


def test_converting_to_jpeg_strips_the_seal(signer, store):
    # Known limitation, documented: metadata-based seals don't survive
    # format conversion. The honest answer is "unsealed", not "tampered".
    png, _ = seal_and_register(signer, store)
    out = io.BytesIO()
    load(png).save(out, format="JPEG")
    assert check(out.getvalue(), signer, store).status == Status.UNSEALED


# ---------- tampered ----------

def test_one_changed_pixel_is_pixels_modified_and_shows_original_owner(signer, store):
    png, payload = seal_and_register(signer, store, owner="alice")
    result = check(edit_pixel(png), signer, store)
    assert result.status == Status.SEALED_TAMPERED
    assert result.reason == Reason.PIXELS_MODIFIED
    # The seal itself is genuine, so we can say whose image was altered.
    assert result.record.owner == "alice"
    assert result.record.seal_id == payload.seal_id


@pytest.mark.parametrize(
    "chunk",
    [
        "garbage",
        json.dumps({"v": 99, "alg": "Ed25519"}),
        json.dumps({"v": 1, "alg": "RSA"}),
    ],
)
def test_unparseable_seal_is_malformed(signer, store, chunk):
    result = check(resave(photo(), chunk), signer, store)
    assert (result.status, result.reason) == (Status.SEALED_TAMPERED, Reason.MALFORMED_SEAL)


@pytest.mark.parametrize(
    "field, value",
    [
        ("signature", "not base64!!"),
        ("signature", 12345),
        ("pixel_hash", "zz"),
        ("pixel_hash", None),
    ],
)
def test_wrong_field_contents_are_malformed_not_a_crash(signer, store, field, value):
    png, payload = seal_and_register(signer, store)
    data = json.loads(payload.to_json())
    data[field] = value
    result = check(resave(load(png), json.dumps(data)), signer, store)
    assert result.reason == Reason.MALFORMED_SEAL


def test_seal_from_another_key_is_unknown_key(signer, store):
    other = Signer.from_b64(generate_key_b64())
    png, _ = seal_and_register(other, store)
    assert check(png, signer, store).reason == Reason.UNKNOWN_KEY


def test_other_key_pretending_to_be_ours_is_invalid_signature(signer, store):
    # key_id is only a label: copying ours doesn't make their signature valid.
    other = Signer.from_b64(generate_key_b64())
    png, payload = seal_and_register(other, store)
    forged = with_payload(png, dataclasses.replace(payload, key_id=signer.key_id))
    assert check(forged, signer, store).reason == Reason.INVALID_SIGNATURE


def test_editing_pixels_and_updating_the_hash_is_invalid_signature(signer, store):
    # The attacker edits the image AND writes the new hash into the seal.
    # They can't produce a matching signature without our private key.
    png, payload = seal_and_register(signer, store)
    edited = edit_pixel(png)
    new_hash = pixel_hash(load(edited)).hex()
    forged = with_payload(edited, dataclasses.replace(payload, pixel_hash=new_hash))
    assert check(forged, signer, store).reason == Reason.INVALID_SIGNATURE


def test_valid_seal_missing_from_registry_is_unknown_seal(signer, store):
    png, _ = seal_and_register(signer, store, register=False)
    result = check(png, signer, store)
    assert result.reason == Reason.UNKNOWN_SEAL
    assert result.record is None


def test_seal_id_swapped_to_another_users_is_registry_mismatch(signer, store):
    # Mallory seals her own image, then relabels it with Alice's seal_id to
    # borrow Alice's identity. The signature still verifies (it covers only
    # the hash), so only the registry check catches this.
    _, alice = seal_and_register(signer, store, img=photo((1, 2, 3)), owner="alice")
    mallory_png, mallory = seal_and_register(signer, store, img=photo((9, 9, 9)), owner="mallory")
    forged = with_payload(mallory_png, dataclasses.replace(mallory, seal_id=alice.seal_id))
    result = check(forged, signer, store)
    assert result.reason == Reason.REGISTRY_MISMATCH
    assert result.record is None  # Alice's details must not be shown


# ---------- POST /verify ----------

@pytest.fixture
def client(tmp_path):
    settings = Settings(_env_file=None, signing_key=generate_key_b64(), db_path=str(tmp_path / "api.db"))
    app = create_app()
    app.dependency_overrides[get_settings] = lambda: settings
    return TestClient(app)


def upload(client, path, data: bytes, name="x.png"):
    return client.post(path, files={"file": (name, data, "image/png")})


def test_api_seal_then_verify_round_trip(client):
    sealed = upload(client, "/seal", resave(photo(), None))
    seal_id = sealed.headers["x-miniseal-seal-id"]

    resp = upload(client, "/verify", sealed.content)
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "sealed_intact"
    assert body["reason"] is None
    assert body["seal"]["seal_id"] == seal_id
    assert body["seal"]["owner"] == "anonymous"
    assert body["seal"] == client.get(f"/seals/{seal_id}").json()


def test_api_tampered_is_200_with_reason(client):
    sealed = upload(client, "/seal", resave(photo(), None)).content
    resp = upload(client, "/verify", edit_pixel(sealed))
    assert resp.status_code == 200  # the request worked; the image failed
    assert resp.json()["status"] == "sealed_tampered"
    assert resp.json()["reason"] == "pixels_modified"


def test_api_unsealed(client):
    body = upload(client, "/verify", resave(photo(), None)).json()
    assert body == {"status": "unsealed", "reason": None, "seal": None}


def test_api_not_an_image_is_400(client):
    assert upload(client, "/verify", b"nope").status_code == 400


def test_api_upload_limits_apply_to_verify(tmp_path):
    settings = Settings(
        _env_file=None,
        signing_key=generate_key_b64(),
        db_path=str(tmp_path / "x.db"),
        max_upload_bytes=10,
    )
    app = create_app()
    app.dependency_overrides[get_settings] = lambda: settings
    resp = upload(TestClient(app), "/verify", resave(photo(), None))
    assert resp.status_code == 413


def test_api_verify_without_key_is_503(tmp_path):
    settings = Settings(_env_file=None, signing_key=None, db_path=str(tmp_path / "x.db"))
    app = create_app()
    app.dependency_overrides[get_settings] = lambda: settings
    assert upload(TestClient(app), "/verify", resave(photo(), None)).status_code == 503
