import io

import pytest
from PIL import Image, PngImagePlugin

from app.crypto import Signer, SigningKeyError, generate_key_b64, pixel_hash


def make_image(color=(200, 100, 50), size=(8, 8)) -> Image.Image:
    return Image.new("RGB", size, color)


# ---------- pixel_hash ----------

def test_hash_is_deterministic():
    assert pixel_hash(make_image()) == pixel_hash(make_image())


def test_one_pixel_change_changes_hash():
    a = make_image()
    b = make_image()
    b.putpixel((3, 3), (201, 100, 50))  # off by one in a single channel
    assert pixel_hash(a) != pixel_hash(b)


def test_hash_ignores_png_metadata():
    """The core reason we hash pixels: adding a text chunk must not change the hash."""
    img = make_image()

    plain = io.BytesIO()
    img.save(plain, format="PNG")

    meta = PngImagePlugin.PngInfo()
    meta.add_text("miniseal", "some signature data")
    with_meta = io.BytesIO()
    img.save(with_meta, format="PNG", pnginfo=meta)

    assert plain.getvalue() != with_meta.getvalue()  # file bytes differ...
    assert pixel_hash(Image.open(plain)) == pixel_hash(Image.open(with_meta))  # ...pixels don't


def test_same_bytes_different_shape_do_not_collide():
    a = Image.new("RGBA", (2, 8), (1, 2, 3, 4))
    b = Image.new("RGBA", (4, 4), (1, 2, 3, 4))
    assert a.tobytes() == b.tobytes()
    assert pixel_hash(a) != pixel_hash(b)


def test_mode_is_normalized():
    rgb = make_image()
    assert pixel_hash(rgb) == pixel_hash(rgb.convert("RGBA"))


# ---------- Signer ----------

@pytest.fixture
def signer() -> Signer:
    return Signer.from_b64(generate_key_b64())


def test_sign_then_verify(signer):
    digest = pixel_hash(make_image())
    assert signer.verify(digest, signer.sign(digest))


def test_verify_fails_for_other_digest(signer):
    sig = signer.sign(pixel_hash(make_image()))
    other = pixel_hash(make_image(color=(0, 0, 0)))
    assert not signer.verify(other, sig)


def test_verify_fails_with_other_key(signer):
    digest = pixel_hash(make_image())
    sig = signer.sign(digest)
    stranger = Signer.from_b64(generate_key_b64())
    assert not stranger.verify(digest, sig)


def test_same_key_loads_same_public_key():
    key = generate_key_b64()
    assert Signer.from_b64(key).public_key_b64 == Signer.from_b64(key).public_key_b64


@pytest.mark.parametrize("bad", [None, "", "not base64!!", "c2hvcnQ="])  # last = b"short"
def test_bad_key_raises_clear_error(bad):
    with pytest.raises(SigningKeyError):
        Signer.from_b64(bad)
