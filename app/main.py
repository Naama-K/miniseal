"""FastAPI entrypoint."""
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
from pydantic import BaseModel, Field

from app.auth import OWNER_RE, ApiKeyStore, OwnerTakenError
from app.config import Settings, get_settings
from app.crypto import Signer, SigningKeyError, pixel_hash
from app.detector import Detector, DetectorRun, DummyDetector, Label, run_detector
from app.embed import ImageTooLargeError, InvalidImageError, has_seal_chunk, load_image, prepare_for_sealing
from app.seal import seal_image
from app.store import SealRecord, SealStore, utc_now
from app.verify import Reason, Status, verify_image


@lru_cache
def _signer_for(key_b64: str) -> Signer:
    # One Signer per key value; failures raise and are not cached.
    return Signer.from_b64(key_b64)


@lru_cache
def _signer_from_file(path: str) -> Signer:
    # Cached per path; a failure (missing file) is not cached, so creating
    # the file later fixes the service without a restart.
    try:
        text = Path(path).read_text(encoding="ascii").strip()
    except (OSError, UnicodeDecodeError) as exc:
        raise SigningKeyError(f"MINISEAL_SIGNING_KEY_FILE cannot be read ({type(exc).__name__})") from exc
    return Signer.from_b64(text)


def load_signer(settings: Settings) -> Signer:
    """The configured signer, or SigningKeyError saying what to fix."""
    key = settings.signing_key.get_secret_value() if settings.signing_key else None
    if key and settings.signing_key_file:
        # Two sources could disagree; picking one silently would sign with
        # a key the operator didn't expect.
        raise SigningKeyError("set MINISEAL_SIGNING_KEY or MINISEAL_SIGNING_KEY_FILE, not both")
    if settings.signing_key_file:
        return _signer_from_file(settings.signing_key_file)
    return _signer_for(key or "")


def get_signer(settings: Settings = Depends(get_settings)) -> Signer:
    """The configured signer. 503 (not a crash at startup) when no key is set,
    so /health keeps working and the error says exactly what to fix."""
    try:
        return load_signer(settings)
    except SigningKeyError as exc:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, str(exc)) from exc


@lru_cache
def _store_for(path: str) -> SealStore:
    # One store per path: the schema check runs once, not on every request.
    return SealStore(path)


def get_store(settings: Settings = Depends(get_settings)) -> SealStore:
    return _store_for(settings.db_path)


@lru_cache
def get_detector() -> Detector:
    """The content detector. The one line to change for a real model."""
    return DummyDetector()


@lru_cache
def _key_store_for(path: str) -> ApiKeyStore:
    return ApiKeyStore(path)


def get_key_store(settings: Settings = Depends(get_settings)) -> ApiKeyStore:
    return _key_store_for(settings.db_path)


# auto_error=False: we raise our own 401 (FastAPI's default is 403, which
# means "I know who you are and you may not", the wrong answer for "who are you?").
# Declaring it with Security also adds the "Authorize" button to /docs.
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False, description="Your MiniSeal API key (msk_...)")


def get_owner(
    key: str | None = Security(api_key_header),
    keys: ApiKeyStore = Depends(get_key_store),
) -> str:
    """Who is calling, from their API key. 401 if missing, wrong or revoked.

    One message for all three: the answer must not tell an attacker whether
    a key exists or was revoked. (Our own logs can tell them apart.)
    """
    owner = keys.owner_for(key) if key else None
    if owner is None:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "missing or invalid API key (send it in the X-API-Key header)",
            # 401 must say how to authenticate (RFC 9110).
            headers={"WWW-Authenticate": "ApiKey"},
        )
    return owner


class DetectionAtSeal(BaseModel):
    """The detector's verdict at the moment of sealing, kept for the record.
    An opinion about the content, not part of what the seal certifies."""

    model: str
    score: float
    label: Label
    threshold: float  # the label is only meaningful together with it


class SealInfo(BaseModel):
    """Public record of a seal. The signature itself is not here: it lives
    in the image, and this endpoint answers "when and by whom", not "is it valid"."""

    seal_id: str
    created_at: datetime
    pixel_hash: str
    key_id: str
    owner: str
    # Null if the detector failed at sealing time (only possible under
    # policy "always"); the failure itself is in the detections table.
    detector_at_seal: DetectionAtSeal | None = None

    @classmethod
    def from_record(cls, record: SealRecord) -> "SealInfo":
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
    id: str  # the key's public id
    owner: str
    key: str  # shown this once; we only keep its hash


class DetectorInfo(BaseModel):
    model: str
    score: float  # 0 = looks real, 1 = looks fake
    label: Label
    latency_ms: float


class VerifyResponse(BaseModel):
    status: Status
    # Why it is tampered; null when intact or unsealed.
    reason: Reason | None = None
    # Who sealed it and when. Only set once the seal is proven to be ours and
    # to belong to this image's seal_id (see app/verify.py), so a forged seal
    # can never borrow another user's identity.
    seal: SealInfo | None = None
    # Content check, independent of the seal. Null only if the detector failed:
    # the seal verdict is still valid and is returned regardless.
    detector: DetectorInfo | None = None


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


log = logging.getLogger(__name__)


def _log_detection_best_effort(store: SealStore, run: DetectorRun, context, pixel_hash_hex, seal_id=None):
    """Analytics, not part of the answer: a failed log write must never fail
    the request. (Seal-time runs are NOT written this way: see store.add.)"""
    try:
        store.log_detection(run, context, pixel_hash_hex, seal_id)
    except Exception:
        log.exception("could not log %s detection", context)


def _check_seal_policy(run: DetectorRun, settings: Settings) -> None:
    """Raise if the configured policy forbids sealing this image."""
    if settings.seal_policy != "reject_suspicious":
        return  # "always": the verdict is recorded, never used as a gate
    if not run.ok:
        # Fail closed: this policy promises we only seal checked images,
        # so an image we could not check is not sealed.
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
):
    """Upload bytes -> (sealed PNG, payload, detector run). Runs in the threadpool."""
    img = decode_upload(data, settings)

    # Refuse to overwrite an existing seal: re-sealing would silently replace
    # the original seal_id and hide that the image was already sealed.
    if has_seal_chunk(img):
        raise HTTPException(status.HTTP_409_CONFLICT, "image is already sealed")

    # Score the prepared image: exactly the pixels that get signed, and the
    # ones /verify will see later. (seal_image prepares again; that's a no-op
    # on an already prepared image.)
    prepared = prepare_for_sealing(img)
    run = run_detector(detector, prepared, settings.detector_threshold)
    try:
        _check_seal_policy(run, settings)  # before signing: a refused image gets no seal
    except HTTPException:
        # Refusals are worth counting ("how often does the policy bite?").
        _log_detection_best_effort(store, run, "seal_rejected", pixel_hash(prepared).hex())
        raise

    sealed, payload = seal_image(prepared, signer)
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
        ),
        run,  # same transaction as the seal: the verdict it was issued with is never lost
    )
    return sealed, payload, run


STATIC_DIR = Path(__file__).parent / "static"

# The UI is our own files only: no third-party scripts, nothing inline but
# CSS. If an attacker ever got text into the page (e.g. via an owner name),
# the browser still refuses to run it. The API key sits in that page, so
# this matters. img-src blob: is for previews of the user's own files.
UI_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' blob: data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
}


def create_app() -> FastAPI:
    # App factory: lets tests build a fresh app with different settings.
    settings = get_settings()
    app = FastAPI(title=settings.app_name, version=settings.version)
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    @app.get("/", include_in_schema=False)
    def ui() -> FileResponse:
        """The single-page customer UI. Same origin as the API: no CORS needed."""
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
        """Demo self-service sign-up: choose a free name, get an API key once.

        Disabled unless MINISEAL_OPEN_SIGNUP=true. In production a customer
        gets keys from a real account (email check, login, dashboard)."""
        if not settings.open_signup:
            # 404, as if the route didn't exist: nothing to probe when it's off.
            raise HTTPException(status.HTTP_404_NOT_FOUND, "sign-up is disabled")
        try:
            key_id, key = keys.signup(body.owner)
        except OwnerTakenError as exc:
            raise HTTPException(status.HTTP_409_CONFLICT, "this name is taken") from exc
        # The key is in this body: no browser or proxy may keep a copy.
        response.headers["Cache-Control"] = "no-store"
        return SignupResponse(id=key_id, owner=body.owner, key=key)

    @app.get("/health", tags=["ops"])
    def health() -> dict:
        """Liveness: the process is up and answering. Checks nothing else on
        purpose: a restart can't fix a missing key or a full disk, so this
        must not fail for those (an orchestrator would restart in a loop)."""
        return {"status": "ok", "version": settings.version}

    @app.get("/ready", tags=["ops"], responses={503: {"description": "Not ready; see checks"}})
    def ready(response: Response, settings: Settings = Depends(get_settings)) -> dict:
        """Readiness: can this instance actually serve seals right now?
        Load balancers route traffic only to ready instances. The answer
        names what failed, never secrets or file paths."""
        checks = {}
        try:
            checks["signing_key"] = f"ok ({load_signer(settings).key_id})"
        except SigningKeyError as exc:
            checks["signing_key"] = f"failed: {exc}"
        try:
            _store_for(settings.db_path).ping()
            _key_store_for(settings.db_path)
            checks["database"] = "ok"
        except Exception as exc:  # any failure means "don't send me traffic"
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
        # Decoding, hashing and PNG encoding are CPU-bound: run them off the
        # event loop so one large image doesn't stall every other request.
        sealed, payload, run = await run_in_threadpool(
            _seal_bytes, data, settings, signer, store, owner, detector
        )
        headers = {
            "Content-Disposition": f'attachment; filename="{sealed_filename(file.filename)}"',
            "X-Miniseal-Seal-Id": payload.seal_id,
            "X-Miniseal-Key-Id": payload.key_id,
        }
        if run.ok:  # the body is the image, so the verdict travels in headers
            headers["X-Miniseal-Detector-Label"] = run.label
            headers["X-Miniseal-Detector-Score"] = repr(run.score)
        return Response(content=sealed, media_type="image/png", headers=headers)

    @app.get("/me", tags=["account"])
    def me(owner: str = Depends(get_owner)) -> dict:
        """Who this API key belongs to. Lets the UI check a pasted key."""
        return {"owner": owner}

    @app.get("/seals", tags=["seal"], response_model=list[SealInfo])
    def my_seals(
        limit: int = Query(50, ge=1, le=200),
        store: SealStore = Depends(get_store),
        owner: str = Depends(get_owner),
    ) -> list[SealInfo]:
        """Your own seals, newest first. Never anyone else's."""
        return [SealInfo.from_record(r) for r in store.list_by_owner(owner, limit)]

    @app.get("/seals/{seal_id}", tags=["seal"], response_model=SealInfo)
    def get_seal(
        seal_id: str,
        store: SealStore = Depends(get_store),
        owner: str = Depends(get_owner),
    ) -> SealInfo:
        # Plain `def`: FastAPI runs it in the threadpool, so the blocking
        # SQLite read doesn't stall the event loop.
        record = store.get(seal_id)
        # Someone else's seal gets the SAME 404 as a missing one. A 403 would
        # confirm "this seal exists, it just isn't yours". Anyone holding the
        # image can still learn the owner through /verify: that's the point
        # of a seal, and it needs the image, not just an id.
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
        # Always 200 for a verdict, tampered included: the request succeeded,
        # the *image* failed. 4xx is kept for requests we couldn't evaluate.
        data = await read_upload(file, settings)

        def check():
            img = decode_upload(data, settings)  # decoded once, used by both checks
            digest = pixel_hash(img)  # hashed once, used by the seal check and the log
            result = verify_image(img, signer, store, digest=digest)
            run = run_detector(detector, img, settings.detector_threshold)
            # seal_id only when the seal is proven ours (result.record), so the
            # log never links a run to a seal_id an attacker merely claimed.
            seal_id = result.record.seal_id if result.record else None
            _log_detection_best_effort(store, run, "verify", digest.hex(), seal_id)
            return result, run

        # decode, hash and the model are CPU-bound: keep them off the event loop
        result, run = await run_in_threadpool(check)
        return VerifyResponse(
            status=result.status,
            reason=result.reason,
            seal=SealInfo.from_record(result.record) if result.record else None,
            detector=(
                DetectorInfo(model=run.model, score=run.score, label=run.label, latency_ms=run.latency_ms)
                if run.ok
                else None
            ),
        )

    return app


app = create_app()
