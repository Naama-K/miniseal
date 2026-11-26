import base64
import io

import pytest
from PIL import Image

from app.crypto import Signer, generate_key_b64, pixel_hash, seal_message
from app.embed import (
    InvalidImageError,
    MalformedSealError,
    SealPayload,
    embed,
    extract,
    load_image,
    prepare_for_sealing,
)
from app.seal import seal_image


def gradient(size=(32, 32), mode="RGB") -> Image.Image:
    img = Image.new("RGB", size)
    for x in range(size[0]):
        for y in range(size[1]):
            img.putpixel((x, y), (x * 7 % 256, y * 7 % 256, (x + y) * 3 % 256))
    return img.convert(mode)


def to_bytes(img: Image.Image, fmt: str, **kw) -> bytes:
    buf = io.BytesIO()
    img.save(buf, format=fmt, **kw)
    return buf.getvalue()


def fake_payload(**overrides) -> SealPayload:
    fields = dict(seal_id="abc", pixel_hash="00" * 32, signature="c2ln", key_id="k1")
    fields.update(overrides)
    return SealPayload(**fields)


def seal(img: Image.Image, signer: Signer) -> tuple[bytes, SealPayload]:
    return seal_image(img, signer)  # the real pipeline, not a copy of it


@pytest.fixture
def signer() -> Signer:
    return Signer.from_b64(generate_key_b64())


# ---------- round trip ----------


def test_embed_then_extract_roundtrip():
    png = embed(gradient(), fake_payload())
    assert extract(load_image(png)) == fake_payload()


def test_output_is_png_even_for_jpeg_input(signer):
    jpeg = load_image(to_bytes(gradient(), "JPEG"))
    sealed, _ = seal(jpeg, signer)
    assert sealed.startswith(b"\x89PNG\r\n\x1a\n")  # PNG magic bytes


@pytest.mark.parametrize("fmt", ["PNG", "JPEG"])
def test_embedding_does_not_change_pixel_hash(signer, fmt):
    """The hash we signed must equal the hash a verifier computes from the output file."""
    original = load_image(to_bytes(gradient(), fmt))
    sealed, payload = seal(original, signer)
    assert pixel_hash(load_image(sealed)).hex() == payload.pixel_hash


def test_full_signature_survives_the_file(signer):
    sealed, _ = seal(gradient(), signer)
    decoded = load_image(sealed)
    payload = extract(decoded)
    digest = pixel_hash(decoded)
    assert digest.hex() == payload.pixel_hash
    message = seal_message(payload.seal_id, digest)
    assert signer.verify(message, base64.b64decode(payload.signature))


# ---------- absent / stripped / malformed ----------


def test_plain_png_has_no_seal():
    assert extract(load_image(to_bytes(gradient(), "PNG"))) is None


def test_jpeg_has_no_seal():
    assert extract(load_image(to_bytes(gradient(), "JPEG"))) is None


def test_stripping_metadata_removes_seal(signer):
    """Known limitation, demonstrated: re-saving without the chunk = unsealed."""
    sealed, _ = seal(gradient(), signer)
    stripped = to_bytes(load_image(sealed), "PNG")  # no pnginfo -> chunk gone
    assert extract(load_image(stripped)) is None


@pytest.mark.parametrize("raw", ["not json", "[]", '{"v": 99, "alg": "Ed25519"}', '{"v": 1}'])
def test_malformed_chunk_raises(raw):
    from PIL import PngImagePlugin

    info = PngImagePlugin.PngInfo()
    info.add_itxt("miniseal", raw)
    png = to_bytes(gradient(), "PNG", pnginfo=info)
    with pytest.raises(MalformedSealError):
        extract(load_image(png))


# ---------- input handling ----------


def test_garbage_bytes_rejected():
    with pytest.raises(InvalidImageError):
        load_image(b"this is not an image")


def test_truncated_png_rejected():
    png = to_bytes(gradient(), "PNG")
    with pytest.raises(InvalidImageError):
        load_image(png[: len(png) // 2])


def test_cmyk_is_converted_to_png_safe_mode():
    assert prepare_for_sealing(gradient(mode="CMYK")).mode == "RGB"


def test_exif_rotation_is_baked_in():
    img = gradient(size=(40, 20))  # landscape
    exif = Image.Exif()
    exif[0x0112] = 6  # Orientation: rotate 90 CW when displayed
    rotated = load_image(to_bytes(img, "JPEG", exif=exif.tobytes()))
    assert rotated.size == (40, 20)  # stored sideways...
    assert prepare_for_sealing(rotated).size == (20, 40)  # ...displayed upright
