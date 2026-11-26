"""Content detector: does this image look generated or edited?

A different question from the seal. The seal says "we signed exactly these
pixels" (a cryptographic fact); the detector says "this looks real or fake"
(a model's guess). They are independent: an unsealed photo can still be
scored, and a sealed image can still look suspicious.

* Any class with a `name` and a `score(img)` method is a `Detector`.
* A detector returns a score only. The threshold that turns it into a label
  is a setting, because it depends on what a false alarm costs.
* `run_detector` never raises: a failed run is recorded and returned, so a
  model outage never hides the seal verdict.
"""

from __future__ import annotations

import hashlib
import logging
import math
import time
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

from PIL import Image

from app.crypto import pixel_hash

log = logging.getLogger(__name__)


class Label(StrEnum):
    LIKELY_REAL = "likely_real"
    SUSPICIOUS = "suspicious"


class Detector(Protocol):
    name: str

    def score(self, img: Image.Image) -> float:
        """Score in [0, 1]: 0 = looks real, 1 = looks fake."""
        ...


@dataclass(frozen=True)
class DetectorRun:
    """One call to a detector, successful or not."""

    model: str
    threshold: float  # kept so a stored label can be re-read if the threshold changes
    latency_ms: float
    score: float | None = None
    label: Label | None = None
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None

    @property
    def verdict(self) -> tuple[float, Label] | None:
        """(score, label) of a successful run, None for a failed one."""
        if self.score is None or self.label is None:
            return None
        return self.score, self.label


class DummyDetector:
    """Deterministic stand-in for a real model.

    The score comes from a hash of the pixels: the same image always gets the
    same score, and any pixel change gives an unrelated one. It knows nothing
    about content, which the model name says.
    """

    name = "dummy-hash-v1"
    _DOMAIN = b"miniseal/dummy-detector/v1"

    def score(self, img: Image.Image) -> float:
        h = hashlib.sha256(self._DOMAIN + pixel_hash(img)).digest()
        return int.from_bytes(h[:8], "big") / 2**64


def label_for(score: float, threshold: float) -> Label:
    """At or above the threshold is suspicious."""
    return Label.SUSPICIOUS if score >= threshold else Label.LIKELY_REAL


def _elapsed_ms(start: float) -> float:
    return round((time.perf_counter() - start) * 1000, 2)


def run_detector(detector: Detector, img: Image.Image, threshold: float) -> DetectorRun:
    """Score, time and label one image. Never raises: failures are recorded."""
    model = getattr(detector, "name", "unknown")
    start = time.perf_counter()
    try:
        score = float(detector.score(img))
    except Exception as exc:
        log.exception("detector %s failed", model)
        error = f"{type(exc).__name__}: {exc}"[:500]
        return DetectorRun(model, threshold, _elapsed_ms(start), error=error)
    latency_ms = _elapsed_ms(start)

    if not (0.0 <= score <= 1.0) or math.isnan(score):
        log.error("detector %s returned out-of-range score %r", model, score)
        return DetectorRun(model, threshold, latency_ms, error=f"score out of range: {score!r}")
    # Not rounded: a shown "0.5" labelled likely_real (really 0.49999) would look like a bug.
    return DetectorRun(model, threshold, latency_ms, score, label_for(score, threshold))
