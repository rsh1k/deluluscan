"""Iterable-IDOR scanner: canonical cross-tenant id corpus.

Unit-tests the pure `candidate_ids` corpus, then an integration test with a fake
client proving the scanner surfaces cross-tenant IDOR via a canonical LOW id
(tenant #1) even when the caller's own id is large and its neighbours are empty —
the case a neighbours-only probe misses.
"""
from __future__ import annotations
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from deluluscan.scanners.idor_iter_scanner import (
    IterableIdorScanner, candidate_ids, CANONICAL_CROSS_TENANT_IDS)
from deluluscan.models import RequestRecord, Endpoint, Identity, IdentityRole

_PASS = 0
_FAIL = 0
def check(name, cond, detail=""):
    global _PASS, _FAIL
    if cond:
        _PASS += 1; print(f"PASS  {name}")
    else:
        _FAIL += 1; print(f"FAIL  {name}  {detail}")


def test_candidate_ids():
    # large, sparse id space: neighbours + all canonical lows, capped at 8
    c = candidate_ids(849213)
    check("neighbours present", {849212, 849214, 849220} <= set(c), c)
    check("canonical lows present", set(CANONICAL_CROSS_TENANT_IDS) <= set(c), c)
    check("excludes base id", 849213 not in c)
    check("bounded to 8", len(c) == 8, len(c))
    check("no duplicates", len(c) == len(set(c)))
    check("no id < 1", all(n >= 1 for n in c), c)

    # small base: dedups against canonical, and base-1 could be 0 -> dropped
    c2 = candidate_ids(1)
    check("base=1 excludes 0 and 1", 0 not in c2 and 1 not in c2, c2)
    check("base=1 keeps 2,3,100,1000", {2, 3, 100, 1000} <= set(c2), c2)

    c3 = candidate_ids(2)
    check("base=2 dedups the shared neighbour/canonical 3", c3.count(3) == 1, c3)


# ---- integration: canonical low id finds cross-tenant IDOR ---------------
class FakeAuth:
    def headers_for(self, ident): return {"Authorization": "Bearer x"}

class FakeConfig:
    class _S: pass
    def __init__(self):
        self.scan = self._S(); self.scan.allow_state_changing = False
        self.base_url = "http://h"

class FakeClient:
    """Serves the caller's own object for a large id, an EMPTY 404 for its
    neighbours, and a DISTINCT real object only for canonical id 1 (another
    tenant). A neighbours-only scan would find nothing."""
    def __init__(self): self.seen_ids = []
    def request(self, method, path, *, identity_label=None, headers=None, **k):
        seg = path.rstrip("/").split("/")[-1].split("?")[0]
        try:
            n = int(seg)
        except ValueError:
            return None
        self.seen_ids.append(n)
        if n == 849213:      # the caller's own record
            body = '{"id":849213,"owner":"me","email":"me@acme.com","plan":"free"}'
            return RequestRecord("GET", "http://h"+path, "readonly", 200, 1.0, {}, "", {}, body, len(body))
        if n == 1:           # tenant #1 — someone else's real object
            body = '{"id":1,"owner":"globex","email":"root@globex.com","plan":"enterprise"}'
            return RequestRecord("GET", "http://h"+path, "readonly", 200, 1.0, {}, "", {}, body, len(body))
        body = '{"error":"not found"}'   # neighbours + other canon ids: empty
        return RequestRecord("GET", "http://h"+path, "readonly", 404, 1.0, {}, "", {}, body, len(body))


def _idents():
    return {"readonly": Identity(role=IdentityRole.READONLY, username="r", password="p"),
            "anonymous": Identity(role=IdentityRole.ANON)}


def test_canonical_low_id_finds_cross_tenant():
    client = FakeClient()
    sc = IterableIdorScanner(client, FakeAuth(), FakeConfig(), _idents())
    ep = Endpoint(method="GET", path="/api/v1/accounts/849213")
    findings = list(sc.run(ep))
    check("cross-tenant IDOR found via canonical low id", len(findings) == 1,
          [f.title for f in findings])
    if findings:
        ids_hit = findings[0].detail.get("accessed_ids", [])
        check("the accessed id is the canonical 1", 1 in ids_hit, ids_hit)
    check("scanner actually probed canonical id 1", 1 in client.seen_ids, client.seen_ids)
    check("scanner also probed neighbours", 849214 in client.seen_ids, client.seen_ids)


def run():
    for fn in (test_candidate_ids, test_canonical_low_id_finds_cross_tenant):
        fn()
    print(f"\n{_PASS} passed, {_FAIL} failed")
    return _FAIL == 0


if __name__ == "__main__":
    raise SystemExit(0 if run() else 1)
