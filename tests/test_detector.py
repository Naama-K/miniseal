"""The detector interface, the dummy, labelling policy, and /verify wiring."""

import io
import math

import pytest
from fastapi.testclient import TestClient
from PIL import Image
from pydantic import ValidationError

from app.config import Settings, get_settings
from app.crypto import generate_key_b64
from app.detector import DummyDetector, Label, label_for, run_detector
from app.main import create_app, get_detector
from tests.conftest import keyed_client


def photo(color=(10, 120, 200), mode="RGB", size=(16, 16)) -> Image.Image:
    return Image.new(mode, size, color)


def png(img: Image.Image, **kw) -> bytes:
    out = io.BytesIO()
    img.save(out, format="PNG", **kw)
    return out.getvalue()


class FixedDetector:
    """Any object with `name` and `score()` is a Detector: no base class needed."""

    def __init__(self, value, name="fixed"):
        self.value, self.name = value, name

    def score(self, img):
        return self.value


class CrashingDetector:
    name = "crashing"

    def score(self, img):
        raise RuntimeError("model server unreachable")


# ---------- the dummy ----------


def test_dummy_is_deterministic_and_in_range():
    d = DummyDetector()
    scores = {d.score(photo()) for _ in range(3)}
    assert len(scores) == 1
    assert 0.0 <= scores.pop() < 1.0


def test_dummy_depends_on_pixels_not_file_bytes():
    d = DummyDetector()
    a = Image.open(io.BytesIO(png(photo(), compress_level=0)))
    b = Image.open(io.BytesIO(png(photo(), compress_level=9)))
    assert d.score(a) == d.score(b)

    changed = photo()
    changed.putpixel((0, 0), (0, 0, 0))
    assert d.score(changed) != d.score(photo())


def test_dummy_spreads_scores_across_the_range():
    # Sanity check that it is not stuck on one label: 200 different images
    # should land on both sides of 0.5.
    d = DummyDetector()
    scores = [d.score(photo((i, 0, 0))) for i in range(200)]
    assert min(scores) < 0.5 < max(scores)


@pytest.mark.parametrize("mode, color", [("RGBA", (1, 2, 3, 4)), ("L", 7), ("I;16", 4000)])
def test_dummy_handles_other_modes(mode, color):
    assert 0.0 <= DummyDetector().score(photo(color, mode)) < 1.0


# ---------- labelling policy ----------


@pytest.mark.parametrize(
    "score, threshold, label",
    [
        (0.49, 0.5, Label.LIKELY_REAL),
        (0.5, 0.5, Label.SUSPICIOUS),  # the threshold itself is suspicious
        (0.51, 0.5, Label.SUSPICIOUS),
        (0.0, 0.0, Label.SUSPICIOUS),  # threshold 0: everything is flagged
        (0.99, 1.0, Label.LIKELY_REAL),  # threshold 1: only a certain fake
        (1.0, 1.0, Label.SUSPICIOUS),
    ],
)
def test_label_for(score, threshold, label):
    assert label_for(score, threshold) == label


@pytest.mark.parametrize("bad", [-0.1, 1.5])
def test_threshold_setting_must_be_in_range(bad):
    with pytest.raises(ValidationError):
        Settings(_env_file=None, detector_threshold=bad)


# ---------- run_detector ----------


def test_run_detector_reports_model_score_label_threshold_and_latency():
    det = run_detector(FixedDetector(0.8, name="m1"), photo(), threshold=0.5)
    assert det.ok and det.error is None
    assert (det.model, det.score, det.label, det.threshold) == ("m1", 0.8, Label.SUSPICIOUS, 0.5)
    assert det.latency_ms >= 0


def test_run_detector_measures_time_spent_in_the_model():
    import time

    class Slow(FixedDetector):
        def score(self, img):
            time.sleep(0.05)
            return 0.1

    assert run_detector(Slow(0.1), photo(), 0.5).latency_ms >= 45


def test_crashing_detector_is_a_failed_run_not_an_exception():
    det = run_detector(CrashingDetector(), photo(), 0.5)
    assert not det.ok
    assert det.error == "RuntimeError: model server unreachable"
    assert det.score is None and det.label is None
    assert det.model == "crashing" and det.threshold == 0.5 and det.latency_ms >= 0


@pytest.mark.parametrize("value", [-0.01, 1.01, math.nan, math.inf])
def test_out_of_range_score_is_a_failed_run(value):
    det = run_detector(FixedDetector(value), photo(), 0.5)
    assert not det.ok
    assert det.error.startswith("score out of range")
    assert det.score is None and det.label is None


# ---------- /verify ----------


def make_client(tmp_path, detector=None, **settings_kw):
    settings = Settings(
        _env_file=None, signing_key=generate_key_b64(), db_path=str(tmp_path / "d.db"), **settings_kw
    )
    app = create_app()
    app.dependency_overrides[get_settings] = lambda: settings
    if detector is not None:
        app.dependency_overrides[get_detector] = lambda: detector
    return keyed_client(app, settings.db_path)


def upload(client, path, data):
    return client.post(path, files={"file": ("x.png", data, "image/png")})


def test_verify_includes_detector_for_every_verdict(tmp_path):
    client = make_client(tmp_path)
    original = png(photo())
    sealed = upload(client, "/seal", original).content

    for data in (original, sealed):  # unsealed, sealed_intact
        det = upload(client, "/verify", data).json()["detector"]
        assert det["model"] == "dummy-hash-v1"
        assert 0 <= det["score"] < 1
        assert det["label"] in ("likely_real", "suspicious")
        assert det["latency_ms"] >= 0


def test_sealing_does_not_change_the_detector_score(tmp_path):
    # Sealing adds metadata only; the pixels the detector looks at are the same.
    client = make_client(tmp_path)
    original = png(photo())
    sealed = upload(client, "/seal", original).content
    score = lambda d: upload(client, "/verify", d).json()["detector"]["score"]
    assert score(original) == score(sealed)


@pytest.mark.parametrize("threshold, label", [(0.0, "suspicious"), (1.0, "likely_real")])
def test_threshold_setting_drives_the_label(tmp_path, threshold, label):
    client = make_client(tmp_path, detector_threshold=threshold)
    assert upload(client, "/verify", png(photo())).json()["detector"]["label"] == label


def test_detector_is_swappable(tmp_path):
    client = make_client(tmp_path, detector=FixedDetector(0.97, name="real-model-v3"))
    det = upload(client, "/verify", png(photo())).json()["detector"]
    assert det["model"] == "real-model-v3"
    assert det["score"] == 0.97
    assert det["label"] == "suspicious"


def test_detector_failure_keeps_the_seal_verdict(tmp_path):
    client = make_client(tmp_path, detector=CrashingDetector())
    sealed = upload(client, "/seal", png(photo())).content
    resp = upload(client, "/verify", sealed)
    assert resp.status_code == 200
    assert resp.json()["status"] == "sealed_intact"
    assert resp.json()["detector"] is None
