"""Shared test helpers."""

from fastapi.testclient import TestClient

from app.auth import ApiKeyStore


def keyed_client(app, db_path, owner: str = "alice") -> TestClient:
    """A client that sends a real API key for `owner`, created in `db_path`.

    Tests go through the real key lookup instead of overriding get_owner,
    so authentication is exercised everywhere, not only in test_auth.py.
    """
    _, key = ApiKeyStore(db_path).create(owner)
    return TestClient(app, headers={"X-API-Key": key})
