"""Real-world files through the full HTTP path: what phones, editors and the web produce."""

import io

import pytest
from PIL import Image

from tests.integration.conftest import image_bytes, seal, signup, verify


@pytest.fixture(scope="module")
def customer(shared_server):
    return shared_server.client(signup(shared_server, "photo-desk")["key"])


def phone_jpeg_sideways() -> bytes:
    # Phones store photos sideways plus an EXIF "rotate 90°" flag.
    img = Image.new("RGB", (60, 40), (200, 30, 30))
    img.paste((30, 30, 200), (0, 0, 20, 40))  # a marker on the left edge
    exif = Image.Exif()
    exif[0x0112] = 6  # Orientation: rotate 90° clockwise to display
    out = io.BytesIO()
    img.save(out, format="JPEG", exif=exif, quality=95)
    return out.getvalue()


def palette_png() -> bytes:
    out = io.BytesIO()
    Image.new("RGB", (32, 32), (10, 200, 90)).convert("P", palette=Image.Palette.ADAPTIVE).save(
        out, format="PNG"
    )
    return out.getvalue()


def sixteen_bit_png() -> bytes:
    out = io.BytesIO()
    Image.new("I;16", (32, 32), 40000).save(out, format="PNG")  # medical / scientific
    return out.getvalue()


CASES = {
    "jpeg": (image_bytes("JPEG", quality=90), "image/jpeg"),
    "phone-jpeg-exif-rotated": (phone_jpeg_sideways(), "image/jpeg"),
    "cmyk-jpeg (print)": (image_bytes("JPEG", mode="CMYK", color=(0, 80, 160, 20)), "image/jpeg"),
    "transparent-png": (image_bytes(mode="RGBA", color=(255, 0, 0, 90)), "image/png"),
    "palette-png": (palette_png(), "image/png"),
    "grayscale-png": (image_bytes(mode="L", color=128), "image/png"),
    "16-bit-png": (sixteen_bit_png(), "image/png"),
    "webp": (image_bytes("WEBP", lossless=True), "image/webp"),
}


@pytest.mark.parametrize("name", CASES)
def test_every_common_format_seals_and_verifies_intact(customer, shared_server, name):
    data, ctype = CASES[name]
    resp = seal(customer, data, name=f"in.{ctype.split('/')[1]}", ctype=ctype)
    assert resp.status_code == 200, resp.text
    out = Image.open(io.BytesIO(resp.content))
    assert out.format == "PNG"

    body = verify(shared_server.client(), resp.content)
    assert body["status"] == "sealed_intact", body
    assert body["seal"]["owner"] == "photo-desk"


def test_exif_rotation_is_baked_into_the_sealed_pixels(customer):
    # Otherwise the sealed photo would come out sideways (EXIF is not kept).
    out = Image.open(io.BytesIO(seal(customer, phone_jpeg_sideways(), ctype="image/jpeg").content))
    assert out.size == (40, 60)  # rotated: portrait now
    assert out.getpixel((20, 2))[2] > 150  # the left-edge marker is now on top


def test_16_bit_edit_is_caught(customer, shared_server):
    # Two values that both read as "white" in 8 bits must still differ.
    sealed = seal(customer, sixteen_bit_png()).content
    img = Image.open(io.BytesIO(sealed))
    img.load()
    from PIL import PngImagePlugin

    info = PngImagePlugin.PngInfo()
    info.add_itxt("miniseal", img.text["miniseal"])
    img.putpixel((0, 0), 40001)
    out = io.BytesIO()
    img.save(out, format="PNG", pnginfo=info)
    assert verify(shared_server.client(), out.getvalue())["reason"] == "pixels_modified"


def test_not_an_image_is_400(customer):
    assert seal(customer, b"%PDF-1.7 definitely not an image", ctype="image/png").status_code == 400


def test_upload_limits_are_enforced_by_the_real_server(server):
    key = signup(server, "x")["key"]
    server.restart(MINISEAL_MAX_UPLOAD_BYTES="2000", MINISEAL_MAX_IMAGE_PIXELS="10000")
    client = server.client(key)
    # Too many bytes: random noise doesn't compress, so this PNG is big.
    import os

    noisy = Image.frombytes("RGB", (60, 60), os.urandom(60 * 60 * 3))
    buf = io.BytesIO()
    noisy.save(buf, format="PNG")
    assert seal(client, buf.getvalue()).status_code == 413
    # A "decompression bomb": tiny file, too many pixels once decoded.
    bomb = image_bytes(size=(200, 200), color=(0, 0, 0))
    assert len(bomb) < 2000
    assert seal(client, bomb).status_code == 413
