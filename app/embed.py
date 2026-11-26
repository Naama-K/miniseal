"""Embedding the seal inside a PNG file, and reading it back.

* Output is always PNG. It's lossless, so the pixels we hashed are exactly the
  pixels a verifier decodes; a JPEG re-encode would make every honest image
  verify as tampered.
* The seal is a JSON document in an iTXt chunk named "miniseal". Viewers skip
  unknown chunks, so the image opens everywhere and looks identical.
* Anything that strips metadata (messaging apps, screenshots) removes the
  chunk, and the image then reads as unsealed.
"""

from __future__ import annotations

import io
import json
from dataclasses import asdict, dataclass

from PIL import Image, ImageOps, PngImagePlugin, UnidentifiedImageError

CHUNK_KEY = "miniseal"
# v2: the signature covers seal_id + pixel hash. Older versions are rejected.
PAYLOAD_VERSION = 2
ALGORITHM = "Ed25519"

# Modes that survive a PNG round-trip unchanged; anything else is converted.
_PNG_SAFE_MODES = {"1", "L", "LA", "RGB", "RGBA", "I;16"}


class InvalidImageError(ValueError):
    """The bytes are not an image Pillow can decode."""


class ImageTooLargeError(InvalidImageError):
    """The image decodes to more pixels than we are willing to hold in memory."""


class MalformedSealError(ValueError):
    """A miniseal chunk exists but can't be parsed."""


@dataclass(frozen=True)
class SealPayload:
    seal_id: str
    pixel_hash: str  # hex SHA-256 of the canonical pixels
    signature: str  # base64 Ed25519 signature over crypto.seal_message(seal_id, hash)
    key_id: str  # which key signed: a label, see Signer.key_id
    alg: str = ALGORITHM
    v: int = PAYLOAD_VERSION

    def to_json(self) -> str:
        return json.dumps(asdict(self), separators=(",", ":"), sort_keys=True)

    @classmethod
    def from_json(cls, raw: str) -> SealPayload:
        try:
            data = json.loads(raw)
            if data.get("v") != PAYLOAD_VERSION or data.get("alg") != ALGORITHM:
                raise MalformedSealError(f"unsupported seal version/alg: {data.get('v')}/{data.get('alg')}")
            return cls(**data)
        except (json.JSONDecodeError, TypeError, AttributeError) as exc:
            raise MalformedSealError("seal chunk is not valid miniseal JSON") from exc


def load_image(data: bytes, max_pixels: int | None = None) -> Image.Image:
    """Decode bytes into a fully loaded image, or raise InvalidImageError.

    The size is checked from the header before decoding, so an oversized image
    (a "decompression bomb") is rejected without allocating it.
    """
    try:
        img = Image.open(io.BytesIO(data))
        width, height = img.size
        if max_pixels is not None and width * height > max_pixels:
            raise ImageTooLargeError(f"image is {width}x{height}, over the {max_pixels} pixel limit")
        img.load()  # decode now, so truncated files fail here
        return img
    except Image.DecompressionBombError as exc:
        raise ImageTooLargeError("image is too large to decode safely") from exc
    except (UnidentifiedImageError, OSError, SyntaxError) as exc:
        raise InvalidImageError("file is not a valid image") from exc


def has_seal_chunk(img: Image.Image) -> bool:
    """True if the image carries a miniseal chunk, valid or not."""
    return CHUNK_KEY in getattr(img, "text", {})


def prepare_for_sealing(img: Image.Image) -> Image.Image:
    """The exact image that will be hashed and written to the PNG.

    EXIF orientation is applied to the pixels, because EXIF is not kept and a
    phone photo would otherwise come out sideways. Modes PNG can't store
    (e.g. CMYK) are converted. Hash the returned image, not the original.
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
    raw = getattr(img, "text", {}).get(CHUNK_KEY)  # only PNGs have .text
    if raw is None:
        return None
    return SealPayload.from_json(raw)
