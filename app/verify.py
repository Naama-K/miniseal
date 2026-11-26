"""Verification: is this image one we sealed, and is it unchanged?

Three answers, from the spec:
* unsealed         - no miniseal chunk at all (never sealed, or metadata stripped).
* sealed_tampered  - a seal is present but something doesn't check out.
* sealed_intact    - every check below passes.

Trust rule: nothing read from the file is believed until a check proves it.
The payload's pixel_hash, key_id and seal_id are all *claims* by whoever
produced the file. Only our own key and our own registry are trusted.

The checks, in order (the first failure is the reason reported):
1. malformed_seal    - chunk can't be parsed (bad JSON, bad base64/hex, wrong types).
2. unknown_key       - claims a key we don't hold (other issuer, or a rotated-out key).
3. invalid_signature - our key did not sign the claimed hash: the seal was forged or edited.
4. unknown_seal      - genuine signature, but the seal_id was never issued by us
                       (registry lost, or a seal_id invented by someone who can sign).
5. registry_mismatch - the seal_id exists but belongs to a different image.
                       Needed because the signature covers the hash only, not the
                       seal_id: without this check, a valid seal could be relabelled
                       with someone else's seal_id and borrow their owner and time.
6. pixels_modified   - the seal is genuine and registered, but the pixels changed.
                       Checked last: hashing every pixel is the expensive step, and by
                       then we know which record the seal belongs to, so the answer
                       can say who sealed the original.
"""
from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
from enum import StrEnum

from PIL import Image

from app.crypto import Signer, pixel_hash
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
    # The registry record, only when it is proven to belong to this seal
    # (signature valid AND registry hash == signed hash). Never a record
    # looked up from an unverified seal_id: that would let a forged seal
    # display someone else's owner and time.
    record: SealRecord | None = None


def _tampered(reason: Reason, record: SealRecord | None = None) -> VerifyResult:
    return VerifyResult(Status.SEALED_TAMPERED, reason, record)


def verify_image(img: Image.Image, signer: Signer, store: SealStore) -> VerifyResult:
    try:
        payload = extract(img)
    except MalformedSealError:
        return _tampered(Reason.MALFORMED_SEAL)
    if payload is None:
        return VerifyResult(Status.UNSEALED)

    # A present-but-broken seal is tampering, not "unsealed": someone touched
    # it, and calling it unsealed would let an attacker downgrade the verdict.
    try:
        signature = base64.b64decode(payload.signature, validate=True)
        claimed = bytes.fromhex(payload.pixel_hash)
        seal_id = str(payload.seal_id)
    except (binascii.Error, ValueError, TypeError):
        return _tampered(Reason.MALFORMED_SEAL)

    if payload.key_id != signer.key_id:
        return _tampered(Reason.UNKNOWN_KEY)
    if not signer.verify(claimed, signature):
        return _tampered(Reason.INVALID_SIGNATURE)

    # From here the claimed hash is genuine: our key signed it.
    record = store.get(seal_id)
    if record is None:
        return _tampered(Reason.UNKNOWN_SEAL)
    if record.pixel_hash != claimed.hex():
        return _tampered(Reason.REGISTRY_MISMATCH)

    # Record proven to belong to this seal: safe to show who sealed it, even
    # if the pixels were changed since ("sealed by alice, then modified").
    if pixel_hash(img) != claimed:
        return _tampered(Reason.PIXELS_MODIFIED, record)
    return VerifyResult(Status.SEALED_INTACT, None, record)
