"""Smoke test for a running MiniSeal: the core journey over real HTTP.

    python scripts/smoke_test.py [base_url]      (default http://localhost:8000)

Standard library only, so it runs anywhere (CI runner, laptop, a server)
without installing the app's dependencies. Needs MINISEAL_OPEN_SIGNUP=true
on the server (compose.yaml sets it). Exits non-zero on the first failure.
"""

import json
import struct
import sys
import time
import urllib.error
import urllib.request
import uuid
import zlib

BASE = (sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8000").rstrip("/")
# urllib also opens file:// and other schemes: accept only web URLs.
if not BASE.startswith(("http://", "https://")):
    sys.exit(f"base URL must start with http:// or https://, got {BASE!r}")


def png(width: int = 8, height: int = 8, rgb: tuple[int, int, int] = (40, 120, 200)) -> bytes:
    """A valid RGB PNG built by hand: no Pillow needed."""

    def chunk(kind: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))

    row = b"\x00" + bytes(rgb) * width  # filter byte 0, then the pixels
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    pixels = zlib.compress(row * height)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", pixels) + chunk(b"IEND", b"")


def request(method: str, path: str, *, body: bytes | None = None, headers: dict | None = None):
    # S310: the scheme is checked to be http(s) at the top of the file.
    req = urllib.request.Request(BASE + path, data=body, method=method, headers=headers or {})  # noqa: S310
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310
            return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as err:
        return err.code, dict(err.headers), err.read()


def upload(path: str, data: bytes, key: str | None = None):
    boundary = uuid.uuid4().hex
    body = (
        (
            f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="smoke.png"\r\n'
            f"Content-Type: image/png\r\n\r\n"
        ).encode()
        + data
        + f"\r\n--{boundary}--\r\n".encode()
    )
    headers = {"Content-Type": f"multipart/form-data; boundary={boundary}"}
    if key:
        headers["X-API-Key"] = key
    return request("POST", path, body=body, headers=headers)


def check(condition: bool, message: str) -> None:
    if not condition:
        print(f"FAIL  {message}")
        sys.exit(1)
    print(f"ok    {message}")


def main() -> None:
    deadline = time.monotonic() + 60
    while True:
        try:
            if request("GET", "/ready")[0] == 200:
                break
        except OSError:
            pass
        if time.monotonic() > deadline:
            check(False, "service became ready within 60 s")
        time.sleep(1)
    check(True, "service is ready (/ready = 200)")

    status, headers, body = request("GET", "/")
    check(
        status == 200 and "script-src 'self'" in headers.get("content-security-policy", ""),
        "UI served with a Content-Security-Policy",
    )

    owner = f"smoke-{uuid.uuid4().hex[:8]}"
    status, _, body = request(
        "POST",
        "/signup",
        body=json.dumps({"owner": owner}).encode(),
        headers={"Content-Type": "application/json"},
    )
    check(status == 201, f"sign-up works (got {status})")
    key = json.loads(body)["key"]

    check(upload("/seal", png())[0] == 401, "sealing without an API key is 401")

    status, headers, sealed = upload("/seal", png(), key)
    lower = {k.lower(): v for k, v in headers.items()}
    check(status == 200 and lower.get("content-type") == "image/png", f"seal returns a PNG (got {status})")
    seal_id = lower["x-miniseal-seal-id"]

    status, _, body = upload("/verify", sealed)
    result = json.loads(body)
    check(
        result["status"] == "sealed_intact" and result["seal"]["owner"] == owner,
        "verify: sealed image is intact, with its owner",
    )
    check(result["seal"]["seal_id"] == seal_id, "verify: the seal id matches")

    status, _, body = upload("/verify", png(rgb=(41, 120, 200)))
    check(json.loads(body)["status"] == "unsealed", "verify: an unsealed image is unsealed")
    print("smoke test passed")


if __name__ == "__main__":
    main()
