"""Content detector: "does this image look synthetic or manipulated?"

This is a different question from the seal:
* the seal answers "did WE sign exactly these pixels?" (cryptography, yes/no);
* the detector answers "does the content look authentic?" (a model, a guess).
They are independent, so /verify runs the detector on every image, sealed or
not. An unsealed photo can still be scored, and a sealed image can still be
suspicious (we may have sealed a fake that a customer uploaded).

Design
------
* `Detector` is a Protocol: anything with a `name` and a `score(img)` method
  plugs in. Swapping the dummy for a real model is one new class plus one line
  in `get_detector`; the endpoint doesn't change.
* A detector returns a SCORE only (0 = looks real, 1 = looks fake). Turning
  that into a label is policy, not modelling: where to put the threshold
  depends on what a false alarm costs vs. a missed fake, so it lives in
  settings (MINISEAL_DETECTOR_THRESHOLD), not inside the model.
* Latency is measured here, around the call, so every detector is timed the
  same way and a slow model shows up in the response.
* A failing detector must not hide the seal verdict: `run_detector` returns
  None and logs, and /verify still answers.
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
        """Probability-like score in [0, 1]: 0 = looks real, 1 = looks fake."""
        ...


@dataclass(frozen=True)
class Detection:
    model: str
    score: float
    label: Label
    latency_ms: float


class DummyDetector:
    """Deterministic stand-in for a real model.

    The score is derived from a hash of the pixels, so:
    * the same image always gets the same score (stable tests, repeatable demo);
    * a lossless re-encode keeps the score (it hashes pixels, not file bytes);
    * any pixel change gives an unrelated score, like a real model might.
    It knows nothing about image content: the score is meaningless as a
    judgement, which the model name says out loud.
    """

    name = "dummy-hash-v1"
    _DOMAIN = b"miniseal/dummy-detector/v1"  # unrelated to the seal's hash

    def score(self, img: Image.Image) -> float:
        h = hashlib.sha256(self._DOMAIN + pixel_hash(img)).digest()
        return int.from_bytes(h[:8], "big") / 2**64  # uniform in [0, 1)


def label_for(score: float, threshold: float) -> Label:
    # At or above the threshold counts as suspicious: the threshold is the
    # lowest score we are not willing to call "likely real".
    return Label.SUSPICIOUS if score >= threshold else Label.LIKELY_REAL


def run_detector(detector: Detector, img: Image.Image, threshold: float) -> Detection | None:
    """Score, time and label one image. None if the detector fails or misbehaves."""
    start = time.perf_counter()
    try:
        score = float(detector.score(img))
    except Exception:  # a model crash must not take /verify down with it
        log.exception("detector %s failed", getattr(detector, "name", "?"))
        return None
    latency_ms = (time.perf_counter() - start) * 1000

    if not (0.0 <= score <= 1.0) or math.isnan(score):
        log.error("detector %s returned out-of-range score %r", detector.name, score)
        return None
    return Detection(
        model=detector.name,
        # Score not rounded: a displayed 0.5 labelled "likely_real" (because the
        # real value was 0.49999) would look like a bug to whoever reads it.
        score=score,
        label=label_for(score, threshold),
        latency_ms=round(latency_ms, 2),
    )
