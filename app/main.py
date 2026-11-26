"""FastAPI entrypoint."""
import re
from datetime import datetime
from functools import lru_cache

from fastapi import Depends, FastAPI, File, HTTPException, Response, UploadFile, status
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel

from app.config import Settings, get_settings
from app.crypto import Signer, SigningKeyError
from app.embed import ImageTooLargeError, InvalidImageError, has_seal_chunk, load_image
from app.seal import seal_image
from app.store import SealRecord, SealStore, utc_now
from app.verify import Reason, Status, verify_image


@lru_cache
def _signer_for(key_b64: str) -> Signer:
    # One Signer per key value; failures raise and are not cached.
    return Signer.from_b64(key_b64)


def get_signer(settings: Settings = Depends(get_settings)) -> Signer:
    """The configured signer. 503 (not a crash at startup) when no key is set,
    so /health keeps working and the error says exactly what to fix."""
    key = settings.signing_key.get_secret_value() if settings.signing_key else None
    try:
        return _signer_for(key or "")
    except SigningKeyError as exc:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, str(exc)) from exc


@lru_cache
def _store_for(path: str) -> SealStore:
    # One store per path: the schema check runs once, not on every request.
    return SealStore(path)


def get_store(settings: Settings = Depends(get_settings)) -> SealStore:
    return _store_for(settings.db_path)


def get_owner() -> str:
    """Who is making the request. Placeholder until API keys exist (task 7),
    which will replace this one function with a lookup of the caller's key.
    Endpoints already depend on it, so they won't change then."""
    return "anonymous"


class SealInfo(BaseModel):
    """Public record of a seal. The signature itself is not here: it lives
    in the image, and this endpoint answers "when and by whom", not "is it valid"."""

    seal_id: str
    created_at: datetime
    pixel_hash: str
    key_id: str
    owner: str

    @classmethod
    def from_record(cls, record: SealRecord) -> "SealInfo":
        return cls(
            seal_id=record.seal_id,
            created_at=record.created_at,
            pixel_hash=record.pixel_hash,
            key_id=record.key_id,
            owner=record.owner,
        )


class VerifyResponse(BaseModel):
    status: Status
    # Why it is tampered; null when intact or unsealed.
    reason: Reason | None = None
    # Who sealed it and when. Only set once the seal is proven to be ours and
    # to belong to this image's seal_id (see app/verify.py), so a forged seal
    # can never borrow another user's identity.
    seal: SealInfo | None = None


def sealed_filename(original: str | None) -> str:
    """'My Photo.jpg' -> 'My_Photo.sealed.png'. Only safe characters reach the header."""
    name = re.split(r"[\\/]", original or "")[-1]  # drop any client-side path
    stem = name.rsplit(".", 1)[0] if "." in name else name
    stem = re.sub(r"[^A-Za-z0-9._-]+", "_", stem).strip("._") or "image"
    return f"{stem[:100]}.sealed.png"


async def read_upload(file: UploadFile, settings: Settings) -> bytes:
    """The upload's bytes, or 413 if over the byte limit."""
    # Read one byte past the limit: enough to know it's too big, without
    # pulling an arbitrarily large upload into memory.
    data = await file.read(settings.max_upload_bytes + 1)
    if len(data) > settings.max_upload_bytes:
        raise HTTPException(status.HTTP_413_CONTENT_TOO_LARGE, "file is too large")
    return data


def decode_upload(data: bytes, settings: Settings):
    """Bytes -> decoded image, translating failures into 413 / 400."""
    try:
        return load_image(data, max_pixels=settings.max_image_pixels)
    except ImageTooLargeError as exc:
        raise HTTPException(status.HTTP_413_CONTENT_TOO_LARGE, str(exc)) from exc
    except InvalidImageError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc


def _seal_bytes(data: bytes, settings: Settings, signer: Signer, store: SealStore, owner: str):
    """Upload bytes -> (sealed PNG, payload). Runs in the threadpool."""
    img = decode_upload(data, settings)

    # Refuse to overwrite an existing seal: re-sealing would silently replace
    # the original seal_id and hide that the image was already sealed.
    if has_seal_chunk(img):
        raise HTTPException(status.HTTP_409_CONFLICT, "image is already sealed")

    sealed, payload = seal_image(img, signer)
    # Record before returning: a seal we hand out but never recorded would
    # later look like it wasn't issued by us. If the insert fails, the
    # request fails and the client never gets an unregistered seal.
    store.add(
        SealRecord(
            seal_id=payload.seal_id,
            pixel_hash=payload.pixel_hash,
            key_id=payload.key_id,
            owner=owner,
            created_at=utc_now(),
        )
    )
    return sealed, payload


def create_app() -> FastAPI:
    # App factory: lets tests build a fresh app with different settings.
    settings = get_settings()
    app = FastAPI(title=settings.app_name, version=settings.version)

    @app.get("/health", tags=["ops"])
    def health() -> dict:
        return {"status": "ok", "version": settings.version}

    @app.post(
        "/seal",
        tags=["seal"],
        response_class=Response,
        responses={200: {"content": {"image/png": {}}, "description": "The sealed image, always PNG."}},
    )
    async def seal(
        file: UploadFile = File(..., description="Image to seal (PNG, JPEG, WebP, ...)"),
        settings: Settings = Depends(get_settings),
        signer: Signer = Depends(get_signer),
        store: SealStore = Depends(get_store),
        owner: str = Depends(get_owner),
    ) -> Response:
        data = await read_upload(file, settings)
        # Decoding, hashing and PNG encoding are CPU-bound: run them off the
        # event loop so one large image doesn't stall every other request.
        sealed, payload = await run_in_threadpool(_seal_bytes, data, settings, signer, store, owner)
        return Response(
            content=sealed,
            media_type="image/png",
            headers={
                "Content-Disposition": f'attachment; filename="{sealed_filename(file.filename)}"',
                "X-Miniseal-Seal-Id": payload.seal_id,
                "X-Miniseal-Key-Id": payload.key_id,
            },
        )

    @app.get("/seals/{seal_id}", tags=["seal"], response_model=SealInfo)
    def get_seal(seal_id: str, store: SealStore = Depends(get_store)) -> SealInfo:
        # Plain `def`: FastAPI runs it in the threadpool, so the blocking
        # SQLite read doesn't stall the event loop.
        record = store.get(seal_id)
        if record is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "no seal with this id")
        return SealInfo.from_record(record)

    @app.post("/verify", tags=["verify"], response_model=VerifyResponse)
    async def verify(
        file: UploadFile = File(..., description="Image to check (any format; only PNGs can carry a seal)"),
        settings: Settings = Depends(get_settings),
        signer: Signer = Depends(get_signer),
        store: SealStore = Depends(get_store),
    ) -> VerifyResponse:
        # Always 200 for a verdict, tampered included: the request succeeded,
        # the *image* failed. 4xx is kept for requests we couldn't evaluate.
        data = await read_upload(file, settings)

        def check():
            return verify_image(decode_upload(data, settings), signer, store)

        result = await run_in_threadpool(check)  # decode + hash are CPU-bound
        return VerifyResponse(
            status=result.status,
            reason=result.reason,
            seal=SealInfo.from_record(result.record) if result.record else None,
        )

    return app


app = create_app()
