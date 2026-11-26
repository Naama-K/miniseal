"""Many customers at once against one real server process."""
import sqlite3
from concurrent.futures import ThreadPoolExecutor

from tests.integration.conftest import image_bytes, seal, signup, verify

CUSTOMERS, SEALS_EACH = 4, 8


def test_parallel_seals_and_verifies_stay_consistent(server):
    keys = {f"cust{i}": signup(server, f"cust{i}")["key"] for i in range(CUSTOMERS)}
    reference = seal(server.client(keys["cust0"]), image_bytes(color=(1, 1, 1))).content

    def seal_job(owner, n):
        resp = seal(server.client(keys[owner]), image_bytes(color=(n, len(owner), 77)))
        return owner, resp

    def verify_job(_):
        return verify(server.client(), reference)

    with ThreadPoolExecutor(max_workers=16) as pool:
        seal_futs = [pool.submit(seal_job, o, n) for o in keys for n in range(SEALS_EACH)]
        verify_futs = [pool.submit(verify_job, i) for i in range(CUSTOMERS * SEALS_EACH)]
        sealed = [f.result() for f in seal_futs]
        verified = [f.result() for f in verify_futs]

    assert all(r.status_code == 200 for _, r in sealed), {r.status_code for _, r in sealed}
    assert all(v["status"] == "sealed_intact" for v in verified)

    # Every image sealed under load verifies, with the right owner.
    for owner, resp in sealed:
        body = verify(server.client(), resp.content)
        assert (body["status"], body["seal"]["owner"]) == ("sealed_intact", owner)

    # Each customer sees exactly their own seals.
    for owner, key in keys.items():
        expected = SEALS_EACH + (1 if owner == "cust0" else 0)
        assert len(server.client(key).get("/seals").json()) == expected

    # The database agrees: no lost writes, no seal without its verdict.
    total_seals = CUSTOMERS * SEALS_EACH + 1
    with sqlite3.connect(server.db) as conn:
        q = lambda sql: conn.execute(sql).fetchone()[0]
        assert q("SELECT COUNT(*) FROM seals") == total_seals
        assert q("SELECT COUNT(*) FROM detections WHERE context = 'seal'") == total_seals
        assert q("SELECT COUNT(*) FROM seals s WHERE NOT EXISTS "
                 "(SELECT 1 FROM detections d WHERE d.seal_id = s.seal_id AND d.context = 'seal')") == 0
        # Every verify was logged and linked to its proven seal: the 32 run
        # under load plus the 32 checks of freshly sealed images above.
        verifies = len(verified) + len(sealed)
        assert q("SELECT COUNT(*) FROM detections WHERE context = 'verify'") == verifies
        assert q("SELECT COUNT(*) FROM detections WHERE context = 'verify' AND seal_id IS NULL") == 0
