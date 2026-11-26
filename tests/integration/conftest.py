"""Harness: run the app as a real server process and talk to it over HTTP.

Why not TestClient here? It calls the app in-process, so it skips what a
real deployment goes through: config from environment variables, uvicorn's
HTTP parsing, a real socket, and a process that can be stopped and started
again against the same database file (what the Docker volume relies on).
"""

import io
import os
import socket
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

import httpx
import pytest
from PIL import Image, PngImagePlugin

from app.crypto import generate_key_b64
from app.embed import CHUNK_KEY

ROOT = Path(__file__).parents[2]


def pytest_collection_modifyitems(items):
    # Every test in this folder is an integration test: `-m "not integration"`
    # gives the fast in-process suite only.
    here = Path(__file__).parent
    for item in items:
        if here in Path(item.fspath).parents:
            item.add_marker(pytest.mark.integration)


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@dataclass
class Server:
    """One uvicorn process. Restartable: same files, maybe different settings."""

    workdir: Path
    env: dict = field(default_factory=dict)
    proc: subprocess.Popen | None = None
    url: str = ""
    log_file: object = None

    @property
    def db(self) -> Path:
        return Path(self.env["MINISEAL_DB_PATH"])

    def start(self, **env_overrides) -> Server:
        self.env.update({k: v for k, v in env_overrides.items() if v is not None})
        for k in [k for k, v in env_overrides.items() if v is None]:
            self.env.pop(k, None)  # None = unset this variable
        port = free_port()
        self.url = f"http://127.0.0.1:{port}"
        env = {**os.environ, **self.env, "PYTHONPATH": str(ROOT)}
        # Only MINISEAL_ settings we chose: drop any leaking from the shell.
        for k in list(env):
            if k.startswith("MINISEAL_") and k not in self.env:
                del env[k]
        # Server output goes to a file, not a pipe: a pipe nobody reads fills
        # up after a few tracebacks and the server then hangs on its next log line.
        # Kept open for the server's lifetime and closed in stop(), so no `with`.
        self.log_file = open(self.workdir / "server.log", "ab")  # noqa: SIM115
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "app.main:app", "--port", str(port), "--log-level", "warning"],
            cwd=self.workdir,  # a clean folder: no developer .env is read
            env=env,
            stdout=self.log_file,
            stderr=subprocess.STDOUT,
        )
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError("server exited:\n" + self.log())
            try:
                if httpx.get(self.url + "/health", timeout=0.5).status_code == 200:
                    return self
            except httpx.TransportError:
                time.sleep(0.1)
        self.stop()
        raise RuntimeError("server did not become healthy in time")

    def stop(self) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
        if self.log_file:
            self.log_file.close()
            self.log_file = None
        self.proc = None

    def log(self) -> str:
        """The server's output so far: for failure messages and log assertions."""
        return (self.workdir / "server.log").read_text(encoding="utf-8", errors="replace")

    def restart(self, **env_overrides) -> Server:
        self.stop()
        return self.start(**env_overrides)

    def client(self, key: str | None = None) -> httpx.Client:
        return httpx.Client(base_url=self.url, headers={"X-API-Key": key} if key else {}, timeout=30)

    def cli(self, *args: str) -> subprocess.CompletedProcess:
        """Run the admin CLI against this server's database, as an operator would."""
        return subprocess.run(
            [sys.executable, "-m", "app.auth", "--db", str(self.db), *args],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
        )


@pytest.fixture
def server(tmp_path):
    srv = Server(
        workdir=tmp_path,
        env={
            "MINISEAL_SIGNING_KEY": generate_key_b64(),
            "MINISEAL_DB_PATH": str(tmp_path / "data" / "miniseal.db"),  # folder doesn't exist yet
            "MINISEAL_OPEN_SIGNUP": "true",
        },
    ).start()
    yield srv
    srv.stop()


# ---------- helpers shared by the integration tests ----------


def image_bytes(fmt="PNG", size=(64, 48), color=(30, 120, 200), mode="RGB", **save_kw) -> bytes:
    out = io.BytesIO()
    Image.new(mode, size, color).save(out, format=fmt, **save_kw)
    return out.getvalue()


def signup(server: Server, owner: str) -> dict:
    resp = server.client().post("/signup", json={"owner": owner})
    assert resp.status_code == 201, resp.text
    return resp.json()


def seal(client: httpx.Client, data: bytes, name="photo.png", ctype="image/png") -> httpx.Response:
    return client.post("/seal", files={"file": (name, data, ctype)})


def verify(client: httpx.Client, data: bytes, name="x.png") -> dict:
    resp = client.post("/verify", files={"file": (name, data, "application/octet-stream")})
    assert resp.status_code == 200, resp.text
    return resp.json()


def tamper(sealed_png: bytes) -> bytes:
    """What an attacker does: change one pixel, put the original seal back."""
    img = Image.open(io.BytesIO(sealed_png))
    img.load()
    info = PngImagePlugin.PngInfo()
    info.add_itxt(CHUNK_KEY, img.text[CHUNK_KEY])
    p = img.getpixel((0, 0))
    img.putpixel((0, 0), tuple(255 - v for v in p) if isinstance(p, tuple) else 255 - p)
    out = io.BytesIO()
    img.save(out, format="PNG", pnginfo=info)
    return out.getvalue()


def reencode_as_jpeg(sealed_png: bytes) -> bytes:
    """What a social network does: decode and re-compress. Metadata is lost."""
    out = io.BytesIO()
    Image.open(io.BytesIO(sealed_png)).convert("RGB").save(out, format="JPEG", quality=85)
    return out.getvalue()


@pytest.fixture(scope="module")
def shared_server(tmp_path_factory):
    """One server for a whole module, for tests that never restart or reconfigure it."""
    tmp = tmp_path_factory.mktemp("shared")
    srv = Server(
        workdir=tmp,
        env={
            "MINISEAL_SIGNING_KEY": generate_key_b64(),
            "MINISEAL_DB_PATH": str(tmp / "miniseal.db"),
            "MINISEAL_OPEN_SIGNUP": "true",
        },
    ).start()
    yield srv
    srv.stop()
