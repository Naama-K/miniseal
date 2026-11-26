"""Pixel hashing and Ed25519 signing.

Why hash the *decoded pixels* and not the file bytes?
-----------------------------------------------------
The signature is embedded inside the image file itself (PNG text chunk, task 3).
Embedding it changes the file's bytes, so a hash over the file would no longer
match the hash that was signed: the seal would break itself. A hash over the
decoded pixels ignores metadata and container details (chunk order, compression
level, EXIF), so it stays stable across embedding, and changes when even one
pixel changes, which is exactly the property we want.
"""

from __future__ import annotations

import array
import base64
import hashlib
import struct
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from PIL import Image

# Version tag mixed into the hash. If we ever change the canonical form,
# old and new hashes can never be confused with each other.
HASH_DOMAIN = b"miniseal/pixels/v1"

# All 8-bit images are normalized to one mode before hashing, so the same
# visible picture gives the same hash whether it was loaded as RGB, P or L.
CANONICAL_MODE = "RGBA"

# High-bit-depth images can NOT go through RGBA: Pillow clips every value above
# 255 to 255, so a 16-bit pixel changed from 1000 to 5000 would hash the same
# and tampering would go undetected. They are hashed at native precision under
# a separate domain instead. The domain differs from HASH_DOMAIN early
# ("wide-" vs "pixels"), so an 8-bit and a wide byte stream can never collide.
WIDE_HASH_DOMAIN = b"miniseal/wide-pixels/v1:"

# Integer modes Pillow widens to 32-bit "I" losslessly. All of them hash as
# int32, so a 16-bit PNG gives the same hash whether a Pillow version decodes
# it as "I;16" or as "I".
_WIDENABLE_INT_MODES = {"I;16", "I;16B", "I;16L", "I"}
# Pillow 12 clips I;16N to 255 when converting to "I" (verified), so its values
# are read one by one instead. It never comes out of a PNG decoder; rare path.
_SLOW_INT_MODES = {"I;16N"}


def _be_bytes(samples: array.array) -> bytes:
    """Fixed big-endian byte order, so the hash doesn't depend on the CPU."""
    if sys.byteorder == "little":
        samples.byteswap()
    return samples.tobytes()


def _wide_canonical(image: Image.Image) -> tuple[bytes, bytes] | None:
    """(format tag, big-endian samples) for wide modes; None for 8-bit modes."""
    if image.mode in _WIDENABLE_INT_MODES:
        samples = array.array("i")  # 4-byte signed int on all supported platforms
        samples.frombytes(image.convert("I").tobytes("raw", "I"))  # C speed
        return b"i32", _be_bytes(samples)
    if image.mode in _SLOW_INT_MODES:
        return b"i32", _be_bytes(array.array("i", image.get_flattened_data()))
    if image.mode == "F":
        samples = array.array("f")  # Pillow "F" is float32: lossless
        samples.frombytes(image.tobytes("raw", "F"))
        return b"f32", _be_bytes(samples)
    return None


def pixel_hash(image: Image.Image) -> bytes:
    """SHA-256 over a canonical encoding of the image's pixels.

    The image size is part of the hash: without it, a 2x8 and a 4x4 image with
    the same pixel bytes would collide.
    """
    width, height = image.size
    size = struct.pack(">II", width, height)  # fixed-width, big-endian
    h = hashlib.sha256()

    wide = _wide_canonical(image)
    if wide is None:
        h.update(HASH_DOMAIN)
        h.update(size)
        h.update(image.convert(CANONICAL_MODE).tobytes())
    else:
        fmt, samples = wide
        h.update(WIDE_HASH_DOMAIN + fmt + b"\x00")  # NUL ends the tag unambiguously
        h.update(size)
        h.update(samples)
    return h.digest()


# What the signature covers. Domain-separated from the pixel-hash domains, so a
# signed seal message can never be mistaken for any other signed data.
SEAL_MESSAGE_DOMAIN = b"miniseal/seal/v2\x00"
_DIGEST_SIZE = hashlib.sha256().digest_size


def seal_message(seal_id: str, digest: bytes) -> bytes:
    """The exact bytes that get signed: binds the seal_id to the pixel hash.

    Signing the hash alone (v1) left the seal_id unprotected: a genuine
    signature could be moved onto a different seal_id and borrow that
    record's owner and time. With the seal_id inside the message, changing
    either the pixels or the seal_id breaks the signature.

    Layout: domain | 32-byte digest | seal_id. The digest is fixed-size and
    comes first, so the boundary is unambiguous without a length prefix.
    """
    if len(digest) != _DIGEST_SIZE:
        raise ValueError(f"digest must be {_DIGEST_SIZE} bytes, got {len(digest)}")
    return SEAL_MESSAGE_DOMAIN + digest + seal_id.encode("ascii")


class SigningKeyError(ValueError):
    """Raised when the signing key is missing or malformed."""


class Signer:
    """Signs and verifies pixel hashes with an Ed25519 key pair."""

    def __init__(self, private_key: Ed25519PrivateKey):
        self._private_key = private_key
        self._public_key: Ed25519PublicKey = private_key.public_key()

    @classmethod
    def from_b64(cls, key_b64: str | None) -> Signer:
        """Load from a base64-encoded 32-byte Ed25519 seed (the env var format)."""
        if not key_b64:
            raise SigningKeyError("MINISEAL_SIGNING_KEY is not set. Generate one with: python -m app.crypto")
        try:
            raw = base64.b64decode(key_b64, validate=True)
        except ValueError as exc:
            raise SigningKeyError("MINISEAL_SIGNING_KEY is not valid base64") from exc
        if len(raw) != 32:
            raise SigningKeyError(f"MINISEAL_SIGNING_KEY must decode to 32 bytes, got {len(raw)}")
        return cls(Ed25519PrivateKey.from_private_bytes(raw))

    def sign(self, message: bytes) -> bytes:
        return self._private_key.sign(message)

    def verify(self, message: bytes, signature: bytes) -> bool:
        try:
            self._public_key.verify(signature, message)
            return True
        except InvalidSignature:
            return False

    @property
    def public_key_b64(self) -> str:
        return base64.b64encode(self._public_raw()).decode()

    @property
    def key_id(self) -> str:
        """Short fingerprint of the public key (first 8 bytes of its SHA-256).

        Stored next to each signature so that after a key rotation we know
        which key signed an old image. It is a *label*, not a trust anchor:
        verification always uses the key we hold, never one read from the file.
        """
        return hashlib.sha256(self._public_raw()).hexdigest()[:16]

    def _public_raw(self) -> bytes:
        return self._public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)


def generate_key_b64() -> str:
    """A fresh random Ed25519 seed, base64-encoded, for MINISEAL_SIGNING_KEY."""
    from cryptography.hazmat.primitives.serialization import NoEncryption, PrivateFormat

    key = Ed25519PrivateKey.generate()
    raw = key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    return base64.b64encode(raw).decode()


def ensure_key_file(path) -> Signer:
    """Load the signing key from `path`, creating it first if it doesn't exist.

    For containers: the key is generated once, on first start, inside the
    data volume, so `docker compose up` works with no setup and the key
    survives restarts and rebuilds. Created with O_EXCL (two processes
    starting at once can't both write one) and mode 0600 (owner-only).

    Trade-off, stated in the README: the key lives next to the database, so
    whoever has the volume can sign. Production keeps it in a KMS/HSM, and
    losing the volume means losing the key: every seal becomes unknown_key.
    """
    import os
    from pathlib import Path

    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        pass  # created earlier (or by a concurrent start): just load it
    else:
        with os.fdopen(fd, "w") as f:
            f.write(generate_key_b64() + "\n")
    return Signer.from_b64(path.read_text().strip())


if __name__ == "__main__":
    # python -m app.crypto               -> prints a new key for your .env file
    # python -m app.crypto ensure PATH   -> creates PATH if missing; prints the key id, never the key
    if len(sys.argv) == 3 and sys.argv[1] == "ensure":
        print(f"signing key ready, key_id={ensure_key_file(sys.argv[2]).key_id}")
    else:
        print(f"MINISEAL_SIGNING_KEY={generate_key_b64()}")
