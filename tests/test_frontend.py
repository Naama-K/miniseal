"""The single-page UI is served, locked down, and talks to the API safely."""

from pathlib import Path

from fastapi.testclient import TestClient

from app.main import create_app

STATIC = Path(__file__).parents[1] / "app" / "static"


def test_ui_is_served_at_the_root_with_security_headers():
    resp = TestClient(create_app()).get("/")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/html")
    csp = resp.headers["content-security-policy"]
    # Only our own scripts may run: no inline script, no third-party code.
    assert "script-src 'self';" in csp and "unsafe-inline" not in csp.split("script-src")[1].split(";")[0]
    assert "frame-ancestors 'none'" in csp  # can't be framed (clickjacking)
    assert resp.headers["x-content-type-options"] == "nosniff"
    assert '<script src="/static/app.js">' in resp.text


def test_ui_script_is_served():
    resp = TestClient(create_app()).get("/static/app.js")
    assert resp.status_code == 200
    assert "javascript" in resp.headers["content-type"]


def test_ui_has_no_inline_scripts():
    html = (STATIC / "index.html").read_text(encoding="utf-8")
    assert html.count("<script") == 1 and "<script src=" in html  # the CSP would block inline ones


def test_ui_never_uses_innerhtml():
    # Server data (owner names, reasons) must only reach the page as text.
    js = (STATIC / "app.js").read_text(encoding="utf-8")
    assert "innerHTML" not in js and "outerHTML" not in js and "insertAdjacentHTML" not in js


def test_ui_is_not_in_the_api_docs():
    assert "/" not in TestClient(create_app()).get("/openapi.json").json()["paths"]
