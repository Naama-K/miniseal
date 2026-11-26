"""Whole customer journeys against a running server, start to finish."""
from tests.integration.conftest import image_bytes, reencode_as_jpeg, seal, signup, tamper, verify


def test_full_customer_journey(server):
    # 1. A newsroom signs up and gets a key.
    account = signup(server, "daily-news")
    newsroom = server.client(account["key"])
    assert newsroom.get("/me").json() == {"owner": "daily-news"}

    # 2. It seals a photo and gets a PNG back.
    resp = seal(newsroom, image_bytes("JPEG", quality=95), name="Protest Photo.jpg", ctype="image/jpeg")
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "image/png"
    assert 'filename="Protest_Photo.sealed.png"' in resp.headers["content-disposition"]
    sealed, seal_id = resp.content, resp.headers["x-miniseal-seal-id"]

    # 3. It appears in the newsroom's own list, with the verdict at sealing.
    (listed,) = newsroom.get("/seals").json()
    assert listed["seal_id"] == seal_id and listed["detector_at_seal"]["model"] == "dummy-hash-v1"

    # 4. A reader with no account verifies the file they received.
    reader = server.client()
    body = verify(reader, sealed)
    assert body["status"] == "sealed_intact"
    assert (body["seal"]["owner"], body["seal"]["seal_id"]) == ("daily-news", seal_id)
    assert body["detector"]["label"] in ("likely_real", "suspicious")

    # 5. Someone edits the picture and passes it on with the seal intact.
    body = verify(reader, tamper(sealed))
    assert (body["status"], body["reason"]) == ("sealed_tampered", "pixels_modified")
    assert body["seal"]["owner"] == "daily-news"  # whose original was altered

    # 6. A social network re-compresses it: the seal is gone, honestly reported.
    body = verify(reader, reencode_as_jpeg(sealed), name="x.jpg")
    assert (body["status"], body["seal"]) == ("unsealed", None)

    # 7. The key leaks; the operator revokes it with the admin CLI.
    done = server.cli("revoke", account["id"])
    assert done.returncode == 0, done.stderr
    assert seal(newsroom, image_bytes(color=(1, 2, 3))).status_code == 401  # at once, no restart
    assert newsroom.get("/seals").status_code == 401

    # 8. ...and everything sealed before still verifies: the service signed it.
    assert verify(reader, sealed)["status"] == "sealed_intact"


def test_two_customers_cannot_see_each_others_seals(server):
    alice = server.client(signup(server, "alice")["key"])
    bob = server.client(signup(server, "bob")["key"])

    a = seal(alice, image_bytes(color=(10, 10, 10)))
    b = seal(bob, image_bytes(color=(20, 20, 20)))
    a_id, b_id = a.headers["x-miniseal-seal-id"], b.headers["x-miniseal-seal-id"]

    assert [s["seal_id"] for s in alice.get("/seals").json()] == [a_id]
    assert [s["seal_id"] for s in bob.get("/seals").json()] == [b_id]
    assert alice.get(f"/seals/{b_id}").status_code == 404
    assert bob.get(f"/seals/{a_id}").status_code == 404
    # Holding the image is different: anyone can verify it and see who sealed it.
    assert verify(bob, a.content)["seal"]["owner"] == "alice"


def test_signup_cannot_take_over_an_account(server):
    signup(server, "alice")
    for name in ("alice", "ALICE"):
        assert server.client().post("/signup", json={"owner": name}).status_code == 409


def test_operator_issued_key_works_without_signup(server):
    # The production path: sign-up off, the company issues keys with the CLI.
    server.restart(MINISEAL_OPEN_SIGNUP=None)
    assert server.client().post("/signup", json={"owner": "x"}).status_code == 404

    out = server.cli("create", "partner-agency")
    assert out.returncode == 0, out.stderr
    key = next(line.split()[-1] for line in out.stdout.splitlines() if line.startswith("key:"))
    client = server.client(key)
    assert seal(client, image_bytes()).status_code == 200
    assert client.get("/me").json() == {"owner": "partner-agency"}
    assert key not in server.cli("list").stdout  # never shown again


def test_ui_and_docs_are_served(server):
    client = server.client()
    page = client.get("/")
    assert page.status_code == 200 and "script-src 'self'" in page.headers["content-security-policy"]
    assert client.get("/static/app.js").status_code == 200
    assert "/seal" in client.get("/openapi.json").json()["paths"]
