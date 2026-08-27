"""Tests for the fuzzing / anomaly-detection lead generator."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from deluluscan.fuzzer import Fuzzer, FuzzConfig
from deluluscan.models import Endpoint, RequestRecord, Severity

_PASS = 0
_FAIL = 0


def check(name, cond, detail=""):
    global _PASS, _FAIL
    if cond:
        _PASS += 1; print(f"PASS  {name}")
    else:
        _FAIL += 1; print(f"FAIL  {name}  [{detail}]")


class Auth:
    def headers_for(self, i): return {}


class FakeClient:
    def __init__(self, rules): self.rules = rules

    def request(self, method, path, *, identity_label=None, headers=None, params=None,
                json_body=None, **k):
        val = None
        if params:
            val = list(params.values())[0]
        elif json_body:
            val = list(json_body.values())[0]
        out = self.rules(val)
        if out is None:
            raise ConnectionError("dropped")
        status, body, lat = out
        return RequestRecord(method=method, url="http://t" + path, identity=identity_label or "?",
                             status=status, elapsed_ms=lat, resp_headers={}, resp_body=body,
                             resp_len=len(body))


_IDS = {"anonymous": type("I", (), {"role": None})()}
_EP = Endpoint(method="GET", path="/api/item", query_params=[{"name": "id"}])


def _run(rules):
    return Fuzzer(FakeClient(rules), Auth(), None, _IDS, FuzzConfig(enabled=True)).run([_EP])


def test_new_server_error_flagged():
    def rules(val):
        if val in (None, "1", "test", "abc123"):
            return 200, "ok", 5.0
        if isinstance(val, str) and len(val) >= 5000:
            return 500, "internal error", 5.0
        return 200, "ok", 5.0
    kinds = {f.detail["kind"] for f in _run(rules)}
    check("new 5xx on mutation (not baseline) flagged", "new_server_error" in kinds, str(kinds))


def test_exception_surfaced_flagged():
    def rules(val):
        if val in (None, "1", "test", "abc123"):
            return 200, "normal", 5.0
        if val == "[]":
            return 200, "Traceback (most recent call last): File x", 5.0
        return 200, "normal", 5.0
    kinds = {f.detail["kind"] for f in _run(rules)}
    check("raw exception surfaced by mutation flagged", "exception_surfaced" in kinds, str(kinds))


def test_ssti_evaluation_flagged_high():
    # Rare arithmetic: an evaluated {{1337*1331}} returns 1779547 (payload gone).
    def rules(val):
        if val in (None, "1", "test", "abc123"):
            return 200, "hello", 5.0
        if val == "{{1337*1331}}":
            return 200, "value is 1779547", 5.0
        return 200, "hello", 5.0
    leads = _run(rules)
    ssti = [f for f in leads if f.detail["kind"] == "expression_evaluation"]
    check("expression evaluation (1337*1331->1779547) flagged HIGH",
          ssti and ssti[0].severity == Severity.HIGH, str([f.detail["kind"] for f in leads]))


def test_ssti_reflected_payload_not_flagged():
    # The payload reflected verbatim (NOT evaluated) must not be flagged, even if
    # a stray "1779547" appears — require payload-absent. Here the product never
    # appears and the payload echoes back: no SSTI.
    def rules(val):
        if val in (None, "1", "test", "abc123"):
            return 200, "hello", 5.0
        return 200, f"you sent {val}", 5.0     # reflects "{{1337*1331}}" verbatim
    leads = _run(rules)
    ssti = [f for f in leads if f.detail.get("kind") == "expression_evaluation"]
    check("expression eval: reflected-but-unevaluated payload NOT flagged", ssti == [],
          str([f.detail.get("kind") for f in leads]))


def test_ssti_bare_49_not_flagged():
    # A bare "49" (count/size/price/UUID hex) must NOT trigger SSTI now that the
    # signal is the rare product 1779547, not 49.
    def rules(val):
        return 200, '{"roles":[{"id":"6f9d5449-8f48-4c3b-9a10-abc123"}],"count":49}', 5.0
    leads = _run(rules)
    ssti = [f for f in leads if f.detail.get("kind") == "expression_evaluation"]
    check("expression eval: bare 49 in body NOT flagged as SSTI", ssti == [],
          str([f.detail.get("kind") for f in leads]))


def test_latency_outlier_flagged():
    def rules(val):
        if val in (None, "1", "test", "abc123"):
            return 200, "ok", 20.0
        if isinstance(val, str) and "A" * 100 in val:
            return 200, "ok", 9000.0
        return 200, "ok", 20.0
    kinds = {f.detail["kind"] for f in _run(rules)}
    check("latency spike flagged as outlier", "latency_outlier" in kinds, str(kinds))


def test_connection_drop_flagged():
    def rules(val):
        if val in (None, "1", "test", "abc123"):
            return 200, "ok", 5.0
        if val == "%00":
            return None      # simulate crash/drop
        return 200, "ok", 5.0
    kinds = {f.detail["kind"] for f in _run(rules)}
    check("connection drop on mutation flagged (possible crash)", "connection_dropped" in kinds, str(kinds))


def test_clean_endpoint_no_leads():
    # everything returns a normal 200 with a small body -> no anomalies
    def rules(val):
        return 200, "consistent ok", 10.0
    leads = _run(rules)
    check("well-behaved endpoint produces no leads (low false positives)", leads == [],
          str([f.detail.get("kind") for f in leads]))


def test_leads_are_unverified():
    def rules(val):
        if val in (None, "1", "test", "abc123"):
            return 200, "ok", 5.0
        if isinstance(val, str) and len(val) >= 5000:
            return 500, "err", 5.0
        return 200, "ok", 5.0
    leads = _run(rules)
    check("every lead is tentative/unverified (never confirmed)",
          leads and all(f.verdict == "unverified" and f.confidence == "tentative" for f in leads),
          "")


def test_disabled_yields_nothing():
    fz = Fuzzer(FakeClient(lambda v: (200, "x", 1.0)), Auth(), None, _IDS, FuzzConfig(enabled=False))
    check("disabled fuzzer yields no leads", fz.run([_EP]) == [], "")


if __name__ == "__main__":
    for fn in list(globals().values()):
        if callable(fn) and getattr(fn, "__name__", "").startswith("test_"):
            try:
                fn()
            except Exception as e:
                _FAIL += 1
                print(f"FAIL  {fn.__name__}  [exception: {e}]")
    print(f"\n{_PASS}/{_PASS + _FAIL} checks passed")
    sys.exit(1 if _FAIL else 0)
