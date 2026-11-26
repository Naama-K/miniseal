"""Verification: is this image one we sealed, and is it unchanged?

* unsealed         - no seal at all (never sealed, or metadata stripped).
* sealed_tampered  - a seal is present but a check fails; the reason says which.
* sealed_intact    - every check passes.

Nothing read from the file is trusted until a check proves it: the seal_id,
hash and key_id in it are claims. Only our own key and registry are trusted.

Checks, in order (the first failure is the reason reported):
1. malformed_seal    - the seal can't be parsed.
2. unknown_key       - signed by a key we don't hold.
3. invalid_signature - our key did not sign this (seal_id, hash) pair.
4. unknown_seal      - genuine signature, but we never issued this seal_id.
5. registry_mismatch - our record holds a different hash: the registry was
                       altered, or the key leaked. Defence in depth.
6. pixels_modified   - genuine, registered seal, but the pixels changed.
                       Last, because hashing every pixel is the costly step,
                       and by then we can say who sealed the original.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
from enum import StrEnum

from PIL import Image

from app.crypto import Signer, pixel_hash, seal_message
from app.embed import MalformedSealError, extract
from app.store import SealRecord, SealStore


class Status(StrEnum):
    SEALED_INTACT = "sealed_intact"
    SEALED_TAMPERED = "sealed_tampered"
    UNSEALED = "unsealed"


class Reason(StrEnum):
    MALFORMED_SEAL = "malformed_seal"
    UNKNOWN_KEY = "unknown_key"
    INVALID_SIGNATURE = "invalid_signature"
    PIXELS_MODIFIED = "pixels_modified"
    UNKNOWN_SEAL = "unknown_seal"
    REGISTRY_MISMATCH = "registry_mismatch"


@dataclass(frozen=True)
class VerifyResult:
    status: Status
    reason: Reason | None = None
    # Set only once the record is proven to belong to this seal, so a forged
    # seal can never display someone else's owner and time.
    record: SealRecord | None = None


def _tampered(reason: Reason, record: SealRecord | None = None) -> VerifyResult:
    return VerifyResult(Status.SEALED_TAMPERED, reason, record)


def verify_image(
    img: Image.Image, signer: Signer, store: SealStore, digest: bytes | None = None
) -> VerifyResult:
    """`digest`: pixel_hash(img), if the caller already computed it."""
    try:
        payload = extract(img)
    except MalformedSealError:
        return _tampered(Reason.MALFORMED_SEAL)
    if payload is None:
        return VerifyResult(Status.UNSEALED)

    # A broken seal is tampering, not "unsealed": otherwise an attacker could
    # downgrade the verdict by corrupting it.
    try:
        signature = base64.b64decode(payload.signature, validate=True)
        claimed = bytes.fromhex(payload.pixel_hash)
        seal_id = payload.seal_id
        if not isinstance(seal_id, str):
            raise TypeError("seal_id must be a string")
        message = seal_message(seal_id, claimed)
    except binascii.Error, ValueError, TypeError:
        return _tampered(Reason.MALFORMED_SEAL)

    if payload.key_id != signer.key_id:
        return _tampered(Reason.UNKNOWN_KEY)
    if not signer.verify(message, signature):
        return _tampered(Reason.INVALID_SIGNATURE)

    record = store.get(seal_id)
    if record is None:
        return _tampered(Reason.UNKNOWN_SEAL)
    if record.pixel_hash != claimed.hex():
        return _tampered(Reason.REGISTRY_MISMATCH)

    actual = digest if digest is not None else pixel_hash(img)
    if actual != claimed:
        return _tampered(Reason.PIXELS_MODIFIED, record)
    return VerifyResult(Status.SEALED_INTACT, None, record)
