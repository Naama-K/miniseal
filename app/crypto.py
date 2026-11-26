"""Pixel hashing and Ed25519 signing.

The seal is stored inside the image file, which changes the file's bytes, so a
hash over the file would break the moment the seal is embedded. We hash the
decoded pixels instead: stable across embedding and lossless re-encoding, yet
different if a single pixel changes.
"""

from __future__ import annotations

import array
import base64
import hashlib
import os
import struct
import sys
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from PIL import Image

# Versioned domain tags: a future change to the canonical form can never be
# confused with today's hashes.
HASH_DOMAIN = b"miniseal/pixels/v1"

# 8-bit images are normalized to one mode, so the same picture hashes the same
# whether it was decoded as RGB, P or L.
CANONICAL_MODE = "RGBA"

# High-bit-depth images must not go through RGBA: Pillow clips values above
# 255, so a 16-bit edit from 1000 to 5000 would go unnoticed. They are hashed
# at native precision under their own domain.
WIDE_HASH_DOMAIN = b"miniseal/wide-pixels/v1:"

# Integer modes Pillow widens to 32-bit "I" losslessly, so a 16-bit PNG hashes
# the same whichever of these modes a Pillow version decodes it as.
_WIDENABLE_INT_MODES = {"I;16", "I;16B", "I;16L", "I"}
# Pillow clips I;16N when converting to "I", so it's read value by value.
_SLOW_INT_MODES = {"I;16N"}


def _be_bytes(samples: array.array) -> bytes:
    """Big-endian bytes, so the hash doesn't depend on the CPU."""
    if sys.byteorder == "little":
        samples.byteswap()
    return samples.tobytes()


def _wide_canonical(image: Image.Image) -> tuple[bytes, bytes] | None:
    """(format tag, big-endian samples) for wide modes; None for 8-bit modes."""
    if image.mode in _WIDENABLE_INT_MODES:
        samples = array.array("i")
        samples.frombytes(image.convert("I").tobytes("raw", "I"))
        return b"i32", _be_bytes(samples)
    if image.mode in _SLOW_INT_MODES:
        return b"i32", _be_bytes(array.array("i", image.get_flattened_data()))
    if image.mode == "F":
        floats = array.array("f")
        floats.frombytes(image.tobytes("raw", "F"))
        return b"f32", _be_bytes(floats)
    return None


def pixel_hash(image: Image.Image) -> bytes:
    """SHA-256 over a canonical encoding of the image's pixels.

    The size is included: otherwise a 2x8 and a 4x4 image with the same pixel
    bytes would collide.
    """
    width, height = image.size
    size = struct.pack(">II", width, height)
    h = hashlib.sha256()

    wide = _wide_canonical(image)
    if wide is None:
        h.update(HASH_DOMAIN)
        h.update(size)
        h.update(image.convert(CANONICAL_MODE).tobytes())
    else:
        fmt, samples = wide
        h.update(WIDE_HASH_DOMAIN + fmt + b"\x00")
        h.update(size)
        h.update(samples)
    return h.digest()


SEAL_MESSAGE_DOMAIN = b"miniseal/seal/v2\x00"
_DIGEST_SIZE = hashlib.sha256().digest_size


def seal_message(seal_id: str, digest: bytes) -> bytes:
    """The exact bytes that get signed: the pixel hash bound to the seal_id.

    Signing the hash alone would let a genuine signature be moved onto another
    seal_id and borrow that record's owner and time.

    Layout: domain | 32-byte digest | seal_id. The digest has a fixed size, so
    the boundary is unambiguous without a length prefix.
    """
    if len(digest) != _DIGEST_SIZE:
        raise ValueError(f"digest must be {_DIGEST_SIZE} bytes, got {len(digest)}")
    return SEAL_MESSAGE_DOMAIN + digest + seal_id.encode("ascii")


class SigningKeyError(ValueError):
    """The signing key is missing or malformed."""


class Signer:
    """Signs and verifies seal messages with an Ed25519 key pair."""

    def __init__(self, private_key: Ed25519PrivateKey):
        self._private_key = private_key
        self._public_key: Ed25519PublicKey = private_key.public_key()

    @classmethod
    def from_b64(cls, key_b64: str | None) -> Signer:
        """Load from a base64-encoded 32-byte Ed25519 seed."""
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
        """Short fingerprint of the public key, stored with each seal.

        A label for key rotation, not a trust anchor: verification always uses
        the key we hold, never one named in the file.
        """
        return hashlib.sha256(self._public_raw()).hexdigest()[:16]

    def _public_raw(self) -> bytes:
        return self._public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)


def generate_key_b64() -> str:
    """A fresh random Ed25519 seed, base64-encoded."""
    from cryptography.hazmat.primitives.serialization import NoEncryption, PrivateFormat

    key = Ed25519PrivateKey.generate()
    raw = key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    return base64.b64encode(raw).decode()


def ensure_key_file(path: str | os.PathLike[str]) -> Signer:
    """Load the signing key from `path`, creating it first if missing.

    Used by the container on start. O_EXCL means two processes starting at
    once can't both write a key; mode 0600 keeps it owner-only. An existing
    file is never replaced: a new key would orphan every existing seal.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        pass
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
