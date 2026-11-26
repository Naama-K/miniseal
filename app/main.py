"""FastAPI entrypoint: HTTP routes and the wiring of their dependencies."""

import logging
import re
from datetime import datetime
from functools import lru_cache
from pathlib import Path

from fastapi import Depends, FastAPI, File, HTTPException, Query, Response, Security, UploadFile, status
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import FileResponse
from fastapi.security import APIKeyHeader
from fastapi.staticfiles import StaticFiles
from PIL import Image
from pydantic import BaseModel, Field

from app.auth import OWNER_RE, ApiKeyStore, OwnerTakenError
from app.config import Settings, get_settings
from app.crypto import Signer, SigningKeyError, pixel_hash
from app.detector import Detector, DetectorRun, DummyDetector, Label, run_detector
from app.embed import (
    ImageTooLargeError,
    InvalidImageError,
    SealPayload,
    has_seal_chunk,
    load_image,
    prepare_for_sealing,
)
from app.seal import seal_image
from app.store import Context, SealRecord, SealStore, utc_now
from app.verify import Reason, Status, VerifyResult, verify_image


@lru_cache
def _signer_for(key_b64: str) -> Signer:
    return Signer.from_b64(key_b64)


@lru_cache
def _signer_from_file(path: str) -> Signer:
    # Failures aren't cached: creating the file later fixes the service without a restart.
    try:
        text = Path(path).read_text(encoding="ascii").strip()
    except (OSError, UnicodeDecodeError) as exc:
        raise SigningKeyError(f"MINISEAL_SIGNING_KEY_FILE cannot be read ({type(exc).__name__})") from exc
    return Signer.from_b64(text)


def load_signer(settings: Settings) -> Signer:
    """The configured signer, or SigningKeyError saying what to fix."""
    key = settings.signing_key.get_secret_value() if settings.signing_key else None
    if key and settings.signing_key_file:
        # Picking one silently could sign with a key the operator didn't expect.
        raise SigningKeyError("set MINISEAL_SIGNING_KEY or MINISEAL_SIGNING_KEY_FILE, not both")
    if settings.signing_key_file:
        return _signer_from_file(settings.signing_key_file)
    return _signer_for(key or "")


def get_signer(settings: Settings = Depends(get_settings)) -> Signer:
    """503 rather than a crash at startup, so /health still answers."""
    try:
        return load_signer(settings)
    except SigningKeyError as exc:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, str(exc)) from exc


@lru_cache
def _store_for(path: str) -> SealStore:
    return SealStore(path)


def get_store(settings: Settings = Depends(get_settings)) -> SealStore:
    return _store_for(settings.db_path)


@lru_cache
def get_detector() -> Detector:
    """The content detector: the one line to change for a real model."""
    return DummyDetector()


@lru_cache
def _key_store_for(path: str) -> ApiKeyStore:
    return ApiKeyStore(path)


def get_key_store(settings: Settings = Depends(get_settings)) -> ApiKeyStore:
    return _key_store_for(settings.db_path)


# auto_error=False: FastAPI would answer 403 ("you may not"); a missing key is
# a 401 ("who are you?"), raised in get_owner.
api_key_header = APIKeyHeader(
    name="X-API-Key", auto_error=False, description="Your MiniSeal API key (msk_...)"
)


def get_owner(
    key: str | None = Security(api_key_header),
    keys: ApiKeyStore = Depends(get_key_store),
) -> str:
    """Who is calling, from their API key.

    Missing, wrong and revoked keys get the same 401, so the answer never
    tells an attacker whether a key exists.
    """
    owner = keys.owner_for(key) if key else None
    if owner is None:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "missing or invalid API key (send it in the X-API-Key header)",
            headers={"WWW-Authenticate": "ApiKey"},
        )
    return owner


class DetectionAtSeal(BaseModel):
    """The detector's verdict when the image was sealed. An opinion, not
    part of what the seal certifies."""

    model: str
    score: float
    label: Label
    threshold: float


class SealInfo(BaseModel):
    """The registry record of a seal: when and by whom."""

    seal_id: str
    created_at: datetime
    pixel_hash: str
    key_id: str
    owner: str
    detector_at_seal: DetectionAtSeal | None = None  # null if the detector failed

    @classmethod
    def from_record(cls, record: SealRecord) -> SealInfo:
        d = record.detection
        return cls(
            seal_id=record.seal_id,
            created_at=record.created_at,
            pixel_hash=record.pixel_hash,
            key_id=record.key_id,
            owner=record.owner,
            detector_at_seal=(
                DetectionAtSeal(model=d.model, score=d.score, label=d.label, threshold=d.threshold)
                if d
                else None
            ),
        )


class SignupRequest(BaseModel):
    owner: str = Field(pattern=OWNER_RE.pattern, description="Your account name: 1-64 of A-Z a-z 0-9 _ . -")


class SignupResponse(BaseModel):
    id: str
    owner: str
    key: str  # shown once; only its hash is stored


class DetectorInfo(BaseModel):
    model: str
    score: float  # 0 = looks real, 1 = looks fake
    label: Label
    latency_ms: float


class VerifyResponse(BaseModel):
    status: Status
    reason: Reason | None = None  # why it is tampered
    # Set only when the seal is proven ours, so a forged seal can never show
    # someone else's identity.
    seal: SealInfo | None = None
    # Independent of the seal; null only if the detector failed.
    detector: DetectorInfo | None = None


def sealed_filename(original: str | None) -> str:
    """'My Photo.jpg' -> 'My_Photo.sealed.png'. Only safe characters reach the header."""
    name = re.split(r"[\\/]", original or "")[-1]
    stem = name.rsplit(".", 1)[0] if "." in name else name
    stem = re.sub(r"[^A-Za-z0-9._-]+", "_", stem).strip("._") or "image"
    return f"{stem[:100]}.sealed.png"


async def read_upload(file: UploadFile, settings: Settings) -> bytes:
    """The upload's bytes, or 413 if over the byte limit."""
    # One byte past the limit is enough to know, without reading the rest.
    data = await file.read(settings.max_upload_bytes + 1)
    if len(data) > settings.max_upload_bytes:
        raise HTTPException(status.HTTP_413_CONTENT_TOO_LARGE, "file is too large")
    return data


def decode_upload(data: bytes, settings: Settings) -> Image.Image:
    """Bytes -> decoded image, translating failures into 413 / 400."""
    try:
        return load_image(data, max_pixels=settings.max_image_pixels)
    except ImageTooLargeError as exc:
        raise HTTPException(status.HTTP_413_CONTENT_TOO_LARGE, str(exc)) from exc
    except InvalidImageError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc


log = logging.getLogger(__name__)


def _log_detection_best_effort(
    store: SealStore, run: DetectorRun, context: Context, pixel_hash_hex: str, seal_id: str | None = None
) -> None:
    """Analytics only: a failed log write never fails the request."""
    try:
        store.log_detection(run, context, pixel_hash_hex, seal_id)
    except Exception:
        log.exception("could not log %s detection", context)


def _check_seal_policy(run: DetectorRun, settings: Settings) -> None:
    """Raise if the configured policy forbids sealing this image."""
    if settings.seal_policy != "reject_suspicious":
        return
    if not run.ok:
        # Fail closed: the policy promises only checked images get sealed.
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "detector unavailable; policy reject_suspicious requires a check before sealing",
        )
    if run.label == Label.SUSPICIOUS:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            {
                "message": "image rejected by seal policy: detector labelled it suspicious",
                "policy": settings.seal_policy,
                "detector": {"model": run.model, "score": run.score, "label": run.label},
            },
        )


def _seal_bytes(
    data: bytes, settings: Settings, signer: Signer, store: SealStore, owner: str, detector: Detector
) -> tuple[bytes, SealPayload, DetectorRun]:
    """Upload bytes -> (sealed PNG, payload, detector run). Runs in the threadpool."""
    img = decode_upload(data, settings)

    # Re-sealing would silently replace the original seal_id.
    if has_seal_chunk(img):
        raise HTTPException(status.HTTP_409_CONFLICT, "image is already sealed")

    # Score exactly the pixels that get signed.
    prepared = prepare_for_sealing(img)
    run = run_detector(detector, prepared, settings.detector_threshold)
    try:
        _check_seal_policy(run, settings)
    except HTTPException:
        _log_detection_best_effort(store, run, "seal_rejected", pixel_hash(prepared).hex())
        raise

    sealed, payload = seal_image(prepared, signer)
    # Recorded before the image is returned: if this fails, the client never
    # receives a seal we have no record of.
    store.add(
        SealRecord(
            seal_id=payload.seal_id,
            pixel_hash=payload.pixel_hash,
            key_id=payload.key_id,
            owner=owner,
            created_at=utc_now(),
        ),
        run,
    )
    return sealed, payload, run


STATIC_DIR = Path(__file__).parent / "static"

# Only our own scripts may run, so injected text can never execute in the page
# that holds the API key. blob: is for previews of the user's own files.
UI_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' blob: data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
}


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(title=settings.app_name, version=settings.version)
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    @app.get("/", include_in_schema=False)
    def ui() -> FileResponse:
        """The web app: sign up, seal, and verify."""
        return FileResponse(STATIC_DIR / "index.html", headers=UI_HEADERS)

    @app.post(
        "/signup",
        tags=["account"],
        response_model=SignupResponse,
        status_code=status.HTTP_201_CREATED,
        responses={404: {"description": "Sign-up is disabled"}, 409: {"description": "Name taken"}},
    )
    def signup(
        body: SignupRequest,
        response: Response,
        settings: Settings = Depends(get_settings),
        keys: ApiKeyStore = Depends(get_key_store),
    ) -> SignupResponse:
        """Self-service sign-up: choose a free name, get an API key (shown once).

        Enabled with MINISEAL_OPEN_SIGNUP=true; otherwise keys are issued by an operator."""
        if not settings.open_signup:
            # 404, as if the route didn't exist.
            raise HTTPException(status.HTTP_404_NOT_FOUND, "sign-up is disabled")
        try:
            key_id, key = keys.signup(body.owner)
        except OwnerTakenError as exc:
            raise HTTPException(status.HTTP_409_CONFLICT, "this name is taken") from exc
        response.headers["Cache-Control"] = "no-store"  # the body holds the key
        return SignupResponse(id=key_id, owner=body.owner, key=key)

    @app.get("/health", tags=["ops"])
    def health() -> dict:
        """Liveness: the process is up. Deliberately checks nothing else, since
        a restart can't fix a missing key and would only loop."""
        return {"status": "ok", "version": settings.version}

    @app.get("/ready", tags=["ops"], responses={503: {"description": "Not ready; see checks"}})
    def ready(response: Response, settings: Settings = Depends(get_settings)) -> dict:
        """Readiness: can this instance serve seals now? Names what failed,
        never secrets or file paths."""
        checks = {}
        try:
            checks["signing_key"] = f"ok ({load_signer(settings).key_id})"
        except SigningKeyError as exc:
            checks["signing_key"] = f"failed: {exc}"
        try:
            _store_for(settings.db_path).ping()
            _key_store_for(settings.db_path)
            checks["database"] = "ok"
        except Exception as exc:
            log.exception("readiness: database check failed")
            checks["database"] = f"failed: {type(exc).__name__}"
        ok = all(v.startswith("ok") for v in checks.values())
        if not ok:
            response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return {"status": "ready" if ok else "not_ready", "checks": checks}

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
        detector: Detector = Depends(get_detector),
    ) -> Response:
        data = await read_upload(file, settings)
        # CPU-bound work runs off the event loop, so one large image doesn't
        # stall every other request.
        sealed, payload, run = await run_in_threadpool(
            _seal_bytes, data, settings, signer, store, owner, detector
        )
        headers = {
            "Content-Disposition": f'attachment; filename="{sealed_filename(file.filename)}"',
            "X-Miniseal-Seal-Id": payload.seal_id,
            "X-Miniseal-Key-Id": payload.key_id,
        }
        if verdict := run.verdict:  # the body is the image, so the verdict goes in headers
            score, label = verdict
            headers["X-Miniseal-Detector-Label"] = label
            headers["X-Miniseal-Detector-Score"] = repr(score)
        return Response(content=sealed, media_type="image/png", headers=headers)

    @app.get("/me", tags=["account"])
    def me(owner: str = Depends(get_owner)) -> dict:
        """Who this API key belongs to."""
        return {"owner": owner}

    @app.get("/seals", tags=["seal"], response_model=list[SealInfo])
    def my_seals(
        limit: int = Query(50, ge=1, le=200),
        store: SealStore = Depends(get_store),
        owner: str = Depends(get_owner),
    ) -> list[SealInfo]:
        """Your own seals, newest first."""
        return [SealInfo.from_record(r) for r in store.list_by_owner(owner, limit)]

    @app.get("/seals/{seal_id}", tags=["seal"], response_model=SealInfo)
    def get_seal(
        seal_id: str,
        store: SealStore = Depends(get_store),
        owner: str = Depends(get_owner),
    ) -> SealInfo:
        record = store.get(seal_id)
        # Someone else's seal gets the same 404 as a missing one: a 403 would
        # confirm it exists. (Anyone holding the image learns the owner via /verify.)
        if record is None or record.owner != owner:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "no seal with this id")
        return SealInfo.from_record(record)

    @app.post("/verify", tags=["verify"], response_model=VerifyResponse)
    async def verify(
        file: UploadFile = File(..., description="Image to check (any format; only PNGs can carry a seal)"),
        settings: Settings = Depends(get_settings),
        signer: Signer = Depends(get_signer),
        store: SealStore = Depends(get_store),
        detector: Detector = Depends(get_detector),
    ) -> VerifyResponse:
        # Every verdict is a 200, tampered included: the request worked, the
        # image didn't. 4xx means we couldn't evaluate the request.
        data = await read_upload(file, settings)

        def check() -> tuple[VerifyResult, DetectorRun]:
            img = decode_upload(data, settings)
            digest = pixel_hash(img)
            result = verify_image(img, signer, store, digest=digest)
            run = run_detector(detector, img, settings.detector_threshold)
            # Link the log row only to a proven seal, never to a merely claimed seal_id.
            seal_id = result.record.seal_id if result.record else None
            _log_detection_best_effort(store, run, "verify", digest.hex(), seal_id)
            return result, run

        result, run = await run_in_threadpool(check)
        detector_info = None
        if verdict := run.verdict:
            score, label = verdict
            detector_info = DetectorInfo(model=run.model, score=score, label=label, latency_ms=run.latency_ms)
        return VerifyResponse(
            status=result.status,
            reason=result.reason,
            seal=SealInfo.from_record(result.record) if result.record else None,
            detector=detector_info,
        )

    return app


app = create_app()
