"""Embedding the seal inside a PNG file, and reading it back.

Design
------
* Output is ALWAYS PNG, whatever the input format. PNG is lossless, so the
  pixels we hashed are exactly the pixels a verifier will decode. Re-encoding
  as JPEG would alter most pixels (lossy) and every honest image would then
  verify as "tampered".
* The seal lives in a PNG iTXt chunk named "miniseal", holding a small JSON
  document. Viewers skip chunks they don't know, so the image still opens
  everywhere and looks identical.
* Known limitation: anything that strips metadata (WhatsApp, screenshots,
  many editors) removes the chunk and the image then reads as unsealed.
  Surviving that needs a watermark inside the pixels.
"""
from __future__ import annotations

import io
import json
from dataclasses import asdict, dataclass

from PIL import Image, ImageOps, PngImagePlugin, UnidentifiedImageError

CHUNK_KEY = "miniseal"
# v2: the signature covers seal_id + pixel hash (v1 signed the hash only).
# v1 seals are rejected, not migrated: none were issued outside development.
PAYLOAD_VERSION = 2
ALGORITHM = "Ed25519"

# Modes that survive a PNG round-trip unchanged; anything else is converted.
_PNG_SAFE_MODES = {"1", "L", "LA", "RGB", "RGBA", "I;16"}


class InvalidImageError(ValueError):
    """The bytes are not an image Pillow can decode."""


class ImageTooLargeError(InvalidImageError):
    """The image decodes to more pixels than we are willing to hold in memory."""


class MalformedSealError(ValueError):
    """A miniseal chunk exists but can't be parsed. Treated as tampering upstream."""


@dataclass(frozen=True)
class SealPayload:
    seal_id: str
    pixel_hash: str  # hex SHA-256 of the canonical pixels
    signature: str  # base64 Ed25519 signature over crypto.seal_message(seal_id, hash)
    key_id: str  # which key signed (label only, see Signer.key_id)
    alg: str = ALGORITHM
    v: int = PAYLOAD_VERSION

    def to_json(self) -> str:
        return json.dumps(asdict(self), separators=(",", ":"), sort_keys=True)

    @classmethod
    def from_json(cls, raw: str) -> "SealPayload":
        try:
            data = json.loads(raw)
            if data.get("v") != PAYLOAD_VERSION or data.get("alg") != ALGORITHM:
                raise MalformedSealError(f"unsupported seal version/alg: {data.get('v')}/{data.get('alg')}")
            return cls(**data)
        except (json.JSONDecodeError, TypeError, AttributeError) as exc:
            raise MalformedSealError("seal chunk is not valid miniseal JSON") from exc


def load_image(data: bytes, max_pixels: int | None = None) -> Image.Image:
    """Decode bytes into a fully-loaded Pillow image, or raise InvalidImageError.

    If `max_pixels` is given, the size is checked from the header *before* the
    pixels are decoded, so an oversized image is rejected without allocating it.
    """
    try:
        img = Image.open(io.BytesIO(data))
        width, height = img.size
        if max_pixels is not None and width * height > max_pixels:
            raise ImageTooLargeError(f"image is {width}x{height}, over the {max_pixels} pixel limit")
        img.load()  # force full decode now, so truncated files fail here
        return img
    except Image.DecompressionBombError as exc:
        raise ImageTooLargeError("image is too large to decode safely") from exc
    except (UnidentifiedImageError, OSError, SyntaxError) as exc:
        raise InvalidImageError("file is not a valid image") from exc


def has_seal_chunk(img: Image.Image) -> bool:
    """True if the image carries a miniseal chunk, valid or not."""
    return CHUNK_KEY in getattr(img, "text", {})


def prepare_for_sealing(img: Image.Image) -> Image.Image:
    """Return the exact image that will be hashed AND written to the PNG.

    1. Apply EXIF orientation: phone JPEGs are often stored sideways with an
       EXIF "rotate me" flag. We drop EXIF in the output, so we bake the
       rotation into the pixels first or the sealed image would come out sideways.
    2. Convert to a PNG-safe mode (e.g. CMYK JPEGs can't be stored as PNG).
    The caller must hash the *returned* image, not the original.
    """
    img = ImageOps.exif_transpose(img)
    if img.mode in _PNG_SAFE_MODES:
        return img
    has_alpha = img.mode in ("PA", "RGBa", "La") or "transparency" in img.info
    return img.convert("RGBA" if has_alpha else "RGB")


def embed(img: Image.Image, payload: SealPayload) -> bytes:
    """Encode `img` as PNG with the seal in an iTXt chunk. Pixels are untouched."""
    info = PngImagePlugin.PngInfo()
    info.add_itxt(CHUNK_KEY, payload.to_json())
    out = io.BytesIO()
    img.save(out, format="PNG", pnginfo=info)
    return out.getvalue()


def extract(img: Image.Image) -> SealPayload | None:
    """Read the seal from a decoded image. None if absent; raises if malformed."""
    # .text exists only on PNG images; JPEG/WebP have no PNG chunks at all.
    raw = getattr(img, "text", {}).get(CHUNK_KEY)
    if raw is None:
        return None
    return SealPayload.from_json(raw)
