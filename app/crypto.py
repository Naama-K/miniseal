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

import base64
import hashlib
import struct

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

# All images are normalized to one mode before hashing, so the same visible
# picture gives the same hash whether it was loaded as RGB, P (palette) or L.
CANONICAL_MODE = "RGBA"


def pixel_hash(image: Image.Image) -> bytes:
    """SHA-256 over a canonical encoding of the image's pixels.

    The image size is part of the hash: without it, a 2x8 and a 4x4 image with
    the same pixel bytes would collide.
    """
    canonical = image.convert(CANONICAL_MODE)
    width, height = canonical.size
    h = hashlib.sha256()
    h.update(HASH_DOMAIN)
    h.update(struct.pack(">II", width, height))  # fixed-width, big-endian
    h.update(canonical.tobytes())
    return h.digest()


class SigningKeyError(ValueError):
    """Raised when the signing key is missing or malformed."""


class Signer:
    """Signs and verifies pixel hashes with an Ed25519 key pair."""

    def __init__(self, private_key: Ed25519PrivateKey):
        self._private_key = private_key
        self._public_key: Ed25519PublicKey = private_key.public_key()

    @classmethod
    def from_b64(cls, key_b64: str | None) -> "Signer":
        """Load from a base64-encoded 32-byte Ed25519 seed (the env var format)."""
        if not key_b64:
            raise SigningKeyError(
                "MINISEAL_SIGNING_KEY is not set. "
                "Generate one with: python -m app.crypto"
            )
        try:
            raw = base64.b64decode(key_b64, validate=True)
        except ValueError as exc:
            raise SigningKeyError("MINISEAL_SIGNING_KEY is not valid base64") from exc
        if len(raw) != 32:
            raise SigningKeyError(f"MINISEAL_SIGNING_KEY must decode to 32 bytes, got {len(raw)}")
        return cls(Ed25519PrivateKey.from_private_bytes(raw))

    def sign(self, digest: bytes) -> bytes:
        return self._private_key.sign(digest)

    def verify(self, digest: bytes, signature: bytes) -> bool:
        try:
            self._public_key.verify(signature, digest)
            return True
        except InvalidSignature:
            return False

    @property
    def public_key_b64(self) -> str:
        raw = self._public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        return base64.b64encode(raw).decode()


def generate_key_b64() -> str:
    """A fresh random Ed25519 seed, base64-encoded, for MINISEAL_SIGNING_KEY."""
    from cryptography.hazmat.primitives.serialization import NoEncryption, PrivateFormat

    key = Ed25519PrivateKey.generate()
    raw = key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    return base64.b64encode(raw).decode()


if __name__ == "__main__":
    # Usage: python -m app.crypto   -> prints a new key for your .env file
    print(f"MINISEAL_SIGNING_KEY={generate_key_b64()}")
