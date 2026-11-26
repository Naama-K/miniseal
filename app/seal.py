"""The sealing pipeline: image in, sealed PNG + payload out.

Kept free of FastAPI so it can be tested and reused (CLI, batch jobs) directly.
"""

from __future__ import annotations

import base64
import uuid

from PIL import Image

from app.crypto import Signer, pixel_hash, seal_message
from app.embed import SealPayload, embed, prepare_for_sealing


def seal_image(img: Image.Image, signer: Signer) -> tuple[bytes, SealPayload]:
    """Hash, sign and embed. Returns the sealed PNG bytes and the payload written."""
    # Hash the *prepared* image: it is exactly what ends up in the PNG.
    prepared = prepare_for_sealing(img)
    digest = pixel_hash(prepared)
    seal_id = uuid.uuid4().hex
    payload = SealPayload(
        seal_id=seal_id,
        pixel_hash=digest.hex(),
        signature=base64.b64encode(signer.sign(seal_message(seal_id, digest))).decode(),
        key_id=signer.key_id,
    )
    return embed(prepared, payload), payload
