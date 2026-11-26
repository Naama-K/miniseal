import io

import pytest
from PIL import Image, PngImagePlugin

from app.crypto import SEAL_MESSAGE_DOMAIN, Signer, SigningKeyError, generate_key_b64, pixel_hash, seal_message


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


# ---------- high bit depth (16-bit grayscale, 32-bit int, float) ----------
# Regression: pixel_hash used to convert everything to 8-bit RGBA, which clips
# every 16-bit value above 255 to 255. Changing 1000 -> 5000 left the hash
# unchanged, so tampering with a sealed 16-bit PNG went undetected.

WIDE_INT_MODES = ["I;16", "I;16B", "I;16L", "I;16N", "I"]


def wide(mode: str, value, size=(4, 4), changed_pixel=None) -> Image.Image:
    img = Image.new(mode, size, value)
    if changed_pixel is not None:
        img.putpixel((1, 2), changed_pixel)
    return img


@pytest.mark.parametrize("mode", WIDE_INT_MODES)
@pytest.mark.parametrize("new_value", [1001, 5000, 65535, 256])
def test_wide_pixel_change_above_255_changes_hash(mode, new_value):
    assert pixel_hash(wide(mode, 1000)) != pixel_hash(wide(mode, 1000, changed_pixel=new_value))


@pytest.mark.parametrize("mode", WIDE_INT_MODES)
def test_wide_images_with_different_bright_values_do_not_collide(mode):
    assert pixel_hash(wide(mode, 300)) != pixel_hash(wide(mode, 60000))


def test_float_image_change_changes_hash():
    assert pixel_hash(wide("F", 1.5)) != pixel_hash(wide("F", 1.5, changed_pixel=1.25))


@pytest.mark.parametrize("mode", WIDE_INT_MODES)
def test_integer_modes_with_same_values_hash_the_same(mode):
    """Like 8-bit mode normalization: a 16-bit PNG may decode as I;16 in one
    Pillow version and as I in another. Same values must give the same hash."""
    assert pixel_hash(wide(mode, 1234)) == pixel_hash(wide("I", 1234))


def test_8bit_and_wide_encodings_never_collide():
    """Value 255 as 8-bit L and as 16-bit must not hash equal: they are
    hashed under different domains, so the byte streams can't be confused."""
    assert pixel_hash(Image.new("L", (4, 4), 255)) != pixel_hash(wide("I;16", 255))


def test_16bit_png_roundtrip_keeps_hash():
    """What we seal is what a verifier decodes: 16-bit survives PNG losslessly."""
    img = wide("I;16", 1000, changed_pixel=40000)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    assert pixel_hash(Image.open(buf)) == pixel_hash(img)


def test_8bit_hash_unchanged_by_this_fix():
    """Existing 8-bit hashes must stay byte-identical (no silent re-hash)."""
    import hashlib
    import struct

    img = Image.new("RGB", (2, 1), (1, 2, 3))
    expected = hashlib.sha256(
        b"miniseal/pixels/v1" + struct.pack(">II", 2, 1) + img.convert("RGBA").tobytes()
    ).digest()
    assert pixel_hash(img) == expected


# ---------- what the signature covers ----------

DIGEST = bytes(range(32))


def test_seal_message_layout():
    msg = seal_message("abc123", DIGEST)
    assert msg == SEAL_MESSAGE_DOMAIN + DIGEST + b"abc123"


def test_seal_message_differs_per_seal_id_and_per_digest():
    assert seal_message("a" * 32, DIGEST) != seal_message("b" * 32, DIGEST)
    assert seal_message("a" * 32, DIGEST) != seal_message("a" * 32, bytes(32))


def test_signature_does_not_transfer_to_another_seal_id():
    signer = Signer.from_b64(generate_key_b64())
    sig = signer.sign(seal_message("a" * 32, DIGEST))
    assert signer.verify(seal_message("a" * 32, DIGEST), sig)
    assert not signer.verify(seal_message("b" * 32, DIGEST), sig)
    assert not signer.verify(DIGEST, sig)  # nor to a bare (v1-style) hash


@pytest.mark.parametrize("digest", [b"", bytes(31), bytes(33)])
def test_seal_message_rejects_wrong_digest_size(digest):
    with pytest.raises(ValueError):
        seal_message("a" * 32, digest)


def test_seal_message_rejects_non_ascii_id():
    with pytest.raises(ValueError):  # UnicodeEncodeError is a ValueError
        seal_message("שלום", DIGEST)
