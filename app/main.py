"""FastAPI entrypoint."""
import re
from functools import lru_cache

from fastapi import Depends, FastAPI, File, HTTPException, Response, UploadFile, status
from fastapi.concurrency import run_in_threadpool

from app.config import Settings, get_settings
from app.crypto import Signer, SigningKeyError
from app.embed import ImageTooLargeError, InvalidImageError, has_seal_chunk, load_image
from app.seal import seal_image


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


def sealed_filename(original: str | None) -> str:
    """'My Photo.jpg' -> 'My_Photo.sealed.png'. Only safe characters reach the header."""
    name = re.split(r"[\\/]",original or "")[-1]  # drop any client-side path
    stem = name.rsplit(".", 1)[0] if "." in name else name
    stem = re.sub(r"[^A-Za-z0-9._-]+", "_", stem).strip("._") or "image"
    return f"{stem[:100]}.sealed.png"


def _seal_bytes(data: bytes, settings: Settings, signer: Signer):
    """Upload bytes -> (sealed PNG, payload), translating failures into HTTP errors."""
    try:
        img = load_image(data, max_pixels=settings.max_image_pixels)
    except ImageTooLargeError as exc:
        raise HTTPException(status.HTTP_413_CONTENT_TOO_LARGE, str(exc)) from exc
    except InvalidImageError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc

    # Refuse to overwrite an existing seal: re-sealing would silently replace
    # the original seal_id and hide that the image was already sealed.
    if has_seal_chunk(img):
        raise HTTPException(status.HTTP_409_CONFLICT, "image is already sealed")

    return seal_image(img, signer)


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
    ) -> Response:
        # Read one byte past the limit: enough to know it's too big, without
        # pulling an arbitrarily large upload into memory.
        data = await file.read(settings.max_upload_bytes + 1)
        if len(data) > settings.max_upload_bytes:
            raise HTTPException(status.HTTP_413_CONTENT_TOO_LARGE, "file is too large")

        # Decoding, hashing and PNG encoding are CPU-bound: run them off the
        # event loop so one large image doesn't stall every other request.
        sealed, payload = await run_in_threadpool(_seal_bytes, data, settings, signer)
        return Response(
            content=sealed,
            media_type="image/png",
            headers={
                "Content-Disposition": f'attachment; filename="{sealed_filename(file.filename)}"',
                "X-Miniseal-Seal-Id": payload.seal_id,
                "X-Miniseal-Key-Id": payload.key_id,
            },
        )

    return app


app = create_app()
