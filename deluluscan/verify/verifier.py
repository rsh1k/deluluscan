"""Per-finding verification.

For each finding the verifier:
  * re-issues the primary evidence request to confirm it still reproduces;
  * sends a small, bounded number of *benign* corroboration/control probes that
    target the specific false-positive confounder for that vuln class;
  * inspects compensating controls (controls.py);
  * assigns a verdict (real vs FP), an exploitability rating (given the
    controls), a calibrated confidence, and a SAFE human reproduction step.

It never weaponizes. The control probes are: a benign value where the scanner
sent a metacharacter, a bogus object id where the scanner replayed a harvested
one, a fresh inert canary where the scanner sent one before, and repeated
timing/baseline measurements. All are the same class of request the scanners
already send against the authorized target.
"""
from __future__ import annotations

import random
import statistics
import string
from typing import Optional
from urllib.parse import urlparse, urlencode, parse_qsl, urlunparse

from ..models import Finding, Severity, VulnClass, RequestRecord
from . import controls as C
from . import evidence as E
from .models import Verification, ControlObservation


_RANK_TO_SEV = {0: Severity.INFO, 1: Severity.LOW, 2: Severity.MEDIUM,
                3: Severity.HIGH, 4: Severity.CRITICAL}


def _downgrade(sev: Severity, steps: int) -> Severity:
    return _RANK_TO_SEV[max(0, sev.rank - steps)]


def _rand(n: int = 8) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


class Verifier:
    """Attach a Verification to every finding. Detection-only."""

    def __init__(self, client, auth, identities, config=None, analyst=None):
        self.client = client
        self.auth = auth
        self.identities = identities
        self.config = config
        self.analyst = analyst   # optional AIAnalyst for root-cause analysis
        # probe budget per finding (keeps us polite; verification shouldn't
        # dwarf the scan itself).
        self.max_probes = 6
        if config is not None:
            self.max_probes = getattr(config.scan, "verify_max_probes", 6)

    # -- low-level re-issue helpers ----------------------------------------
    def _headers_for(self, identity_label: str) -> dict:
        ident = self.identities.get(identity_label)
        if not ident:
            return {}
        try:
            return self.auth.headers_for(ident)
        except Exception:
            return {}

    def _reissue(self, record: RequestRecord, *, set_param: Optional[str] = None,
                 value: Optional[str] = None,
                 replace_in_path: Optional[tuple[str, str]] = None) -> RequestRecord:
        """Re-send an evidence request, optionally overriding one query param
        or substituting a token in the URL path. Uses the recorded identity."""
        url = record.url
        if replace_in_path:
            old, new = replace_in_path
            url = url.replace(old, new)
        if set_param is not None:
            parts = urlparse(url)
            q = dict(parse_qsl(parts.query, keep_blank_values=True))
            q[set_param] = value if value is not None else ""
            url = urlunparse(parts._replace(query=urlencode(q)))
        return self._request_authed(record.method, url, record.identity)

    def _request_authed(self, method: str, url: str, identity_label: str) -> RequestRecord:
        """Issue a request as an identity, re-authenticating once if a
        CREDENTIALED identity gets an unexpected 401/403. A long scan (especially
        --allow-state-changing) can invalidate a session mid-run — a logout/
        state-changing probe, token rotation, or throttling — after which cached
        headers are stale. Without this, verification judges scan-damaged state
        and buries genuine findings as false positives (the anon/denied path).
        Retries only on a fresh denial for a non-anon identity, so it can't loop
        or mask a real access-control denial."""
        rec = self.client.request(method, url, identity_label=identity_label,
                                  headers=self._headers_for(identity_label))
        if rec.status in (401, 403) and identity_label not in (None, "anonymous"):
            ident = self.identities.get(identity_label)
            if ident is not None and hasattr(self.auth, "refresh"):
                try:
                    fresh = self.auth.refresh(ident)
                    retry = self.client.request(method, url,
                                                identity_label=identity_label, headers=fresh)
                    if retry.status not in (401, 403):
                        return retry
                except Exception:
                    pass
        return rec

    @staticmethod
    def _first_query_param(url: str) -> Optional[str]:
        q = parse_qsl(urlparse(url).query, keep_blank_values=True)
        return q[0][0] if q else None

    # -- public entrypoint --------------------------------------------------
    def verify_all(self, findings: list[Finding]) -> None:
        for f in findings:
            try:
                v = self._verify_one(f)
            except Exception as exc:  # never let verification crash a run
                v = Verification(verdict="inconclusive", exploitability="unknown",
                                 reasons=[f"verification error: {exc}"])
            self._apply(f, v)

    def _apply(self, f: Finding, v: Verification) -> None:
        f.detail["verification"] = v.to_dict()
        f.verdict = v.verdict
        f.exploitability = v.exploitability
        f.confidence = v.confidence_label()
        # Adjust severity conservatively — downgrade only, never inflate, and
        # never drop the finding (over-suppression hides true positives).
        if v.verdict == "false_positive":
            f.severity = Severity.INFO
        elif v.verdict == "likely_false_positive":
            f.severity = _downgrade(f.severity, 2)
        elif v.exploitability == "not_exploitable":
            f.severity = _downgrade(f.severity, 2)
        elif v.exploitability == "mitigated":
            f.severity = _downgrade(f.severity, 1)

    # -- dispatch -----------------------------------------------------------
    def _verify_one(self, f: Finding) -> Verification:
        cls = f.vuln_class
        detail = f.detail or {}
        # Version-based CVE inferences are not re-probable by an oracle — keep them
        # honest and tentative rather than letting generic logic relabel them.
        if detail.get("test") == "known_cve":
            kev = detail.get("kev")
            reason = ("Known CVE inferred from the fingerprinted version. This is not "
                      "confirmed exploitation: verify the running patch level (the build "
                      "may be back-patched or the banner inaccurate) before acting.")
            return Verification(
                verdict="unverified", exploitability="unknown",
                confidence_score=(0.5 if kev else 0.4),
                reasons=[reason],
                repro=(f"Confirm the exact version of {detail.get('tech')} and whether "
                       f"{detail.get('cve')} affects that build; reproduce the CVE's "
                       f"specific precondition before treating it as exploitable."))
        # An entitlement-spec violation is established by a DETERMINISTIC oracle:
        # the spec declares the privilege tier an operation requires, and the
        # scanner observed a sub-tier identity being served. A heuristic re-probe
        # (synthetic invalid id, response-shape guessing) cannot strengthen that
        # and routinely weakens it, so honor the spec verdict directly.
        ac = detail.get("auto_confirm") or {}
        # A scanner may present a finding as ALREADY PROVEN when it holds direct
        # evidence a heuristic re-probe cannot improve on — e.g. a deterministic
        # spec violation, or a cross-identity observation where the same request
        # demonstrably returned different data to different callers. Re-probing
        # such a finding with synthetic inputs only ever weakens it (observed
        # live: real violations downgraded to likely_false_positive).
        if ac.get("confirmed") and ac.get("kind") == "differential_observation":
            v = Verification(verdict="true_positive",
                             exploitability=ac.get("exploitability", "exploitable"),
                             confidence_score=0.9, probes=0)
            v.corroborations.append(
                f"observation-confirmed: {ac.get('reason', 'cross-identity difference observed')}")
            v.repro = ac.get("repro", "")
            return v
        if ac.get("confirmed") and ac.get("kind") == "entitlement_spec_violation":
            v = Verification(verdict="true_positive", exploitability="exploitable",
                             confidence_score=0.95, probes=0)
            v.corroborations.append(
                f"spec-confirmed: the authorization specification requires "
                f"{ac.get('required_tier')} privilege for this operation, but the "
                f"'{ac.get('violating_identity')}' identity ({ac.get('violating_tier')} "
                f"tier) was served HTTP {ac.get('status')}. Observed across identities: "
                f"{ac.get('status_by_identity')}.")
            v.repro = ac.get("repro", "")
            return v
        if cls is VulnClass.SUPPLY_CHAIN and detail.get("test") in ("sca", "sca_duplicate_artifacts"):
            # Manifest/classpath-derived: there is no live HTTP request behind this
            # evidence (dependency_scanner sets RequestRecord.status=0, method="SCA"
            # as a sentinel, not a real response) for the generic reissue-and-compare
            # verifier to re-probe. It was reissuing that sentinel as if it were an
            # HTTP request anyway, getting back an unrelated real status (e.g. 501 for
            # the literal method "SCA"), calling that a "status drift", and downgrading
            # EVERY shipped-dependency finding to likely_false_positive — discarding
            # the scanner's own shipped-vs-manifest-only grading in the process.
            # Honor that grading instead of reprobing evidence that was never HTTP.
            shipped = bool(detail.get("shipped"))
            v = Verification(
                verdict=f.verdict, exploitability=f.exploitability,
                confidence_score=0.7 if shipped else 0.4, probes=0)
            v.corroborations.append(
                "confirmed on the running target's classpath" if shipped
                else "declared in the build manifest only — presence on the running "
                     "classpath not confirmed")
            v.reasons.append(
                "Dependency/manifest finding: graded from manifest and classpath "
                "analysis (deluluscan/sca.py), not from a live HTTP probe — there is no "
                "endpoint response to re-test here.")
            return v
        if detail.get("active"):
            return self._verify_active(f)
        if cls is VulnClass.SQLI:
            if "signature" in detail:
                return self._verify_sqli_error(f)
            if "true_len" in detail or "false_len" in detail:
                return self._verify_sqli_boolean(f)
            if "sleep_s" in detail:
                return self._verify_sqli_time(f)
        if cls is VulnClass.XSS:
            return self._verify_xss(f)
        if cls is VulnClass.IDOR:
            return self._verify_idor(f)
        if cls is VulnClass.AUTHZ:
            if "permissive cors" in f.title.lower() or "cors" in f.title.lower():
                return self._verify_cors(f)
            return self._verify_authz(f)
        if cls is VulnClass.SSRF:
            return self._verify_ssrf(f)
        if cls is VulnClass.INFO_LEAK:
            return self._verify_info_leak(f)
        return self._verify_generic(f)

    # ======================================================================
    # Active findings (JWT / authz manipulations that were already exercised)
    # ======================================================================
    # Access-control findings are re-tested against an authorized oracle
    # (OWASP WSTG 4.5) rather than trusted from the scanner.
    _ACCESS_CONTROL_TESTS = {"missing_auth", "identity_swap", "bola_id_swap",
                             "authz_matrix_bypass"}

    def _verify_active(self, f: Finding) -> Verification:
        test = (f.detail or {}).get("test", "").split(":")[0]
        if test == "bfla_privileged_op":
            return self._verify_bfla(f)
        if test in self._ACCESS_CONTROL_TESTS:
            return self._verify_access_control(f)
        return self._verify_active_generic(f)

    def _verify_bfla(self, f: Finding) -> Verification:
        """Re-confirm a BFLA finding with the differential oracle: the endpoint
        must deny anonymous (auth IS enforced) while the low-priv user is not
        denied. A bare 400/404 with no anon-denial is treated as a false positive."""
        from . import evidence as E
        v = Verification()
        d = f.detail or {}
        # If the scanner already PROVED this by assigning a real object and reading
        # back the effect (then reverting), honor that — don't downgrade it with a
        # fresh invalid-id probe.
        ac = d.get("auto_confirm") or {}
        if ac.get("confirmed"):
            v.verdict = "true_positive"; v.exploitability = "exploitable"
            v.confidence_score = 0.95; v.probes = 1
            v.corroborations.append(
                f"auto-confirmed: the low-privilege user assigned a real admin layout "
                f"('{ac.get('layout_name')}', portlets {ac.get('portlets')}) and the grant "
                f"took effect; the scanner then reverted it "
                f"({'reverted OK' if ac.get('reverted') else 'REVERT FAILED — remove manually'}).")
            v.repro = ("As the low-privilege user: GET /api/roles/groups to find an admin "
                       "layout id, PUT /api/roles/{id}/members, then re-GET layouts to "
                       "see the grant. Revert with _removefromuser.")
            if ac.get("reverted") is False:
                v.reasons.append(ac.get("revert_warning", "auto-revert may have failed"))
            return v
        method = d.get("method", "GET"); path = d.get("op_path", "")
        low = self.identities.get("backend")
        anon = self.identities.get("anonymous")
        admin = self.identities.get("admin")

        def probe(ident):
            if ident is None:
                return None
            try:
                headers = dict(self.auth.headers_for(ident))
                if path.startswith("/dwr/"):
                    headers["Content-Type"] = "text/plain"
                    return self.client.request(method, path, identity_label=ident.label(),
                                               headers=headers, data="callCount=1\n")
                if path == "/api/plugins":
                    return self.client.request(method, path, identity_label=ident.label(),
                                               headers=headers,
                                               files={"file": ("none.txt", b"x", "text/plain")})
                if method in ("PUT", "POST", "PATCH"):
                    return self.client.request(method, path, identity_label=ident.label(),
                                               headers=headers, json_body={})
                return self.client.request(method, path, identity_label=ident.label(),
                                           headers=headers)
            except Exception:
                return None

        low_rec = probe(low); anon_rec = probe(anon); admin_rec = probe(admin)
        v.probes = sum(1 for r in (low_rec, anon_rec, admin_rec) if r is not None)
        if low_rec is None:
            v.verdict = "inconclusive"; v.exploitability = "unknown"
            v.confidence_score = 0.3
            v.reasons.append("Could not re-issue the low-privilege probe.")
            return v
        low_disp = E.classify_response(low_rec)
        anon_disp = E.classify_response(anon_rec) if anon_rec else "n/a"
        admin_disp = E.classify_response(admin_rec) if admin_rec else "n/a"

        if low_disp == E.DISPOSITION_DENIED:
            v.verdict = "false_positive"; v.exploitability = "not_exploitable"
            v.confidence_score = 0.1
            v.reasons.append(f"On re-test the low-privilege user is denied ({low_disp}); "
                             f"the endpoint enforces authorization. Not a BFLA.")
            return v
        if anon_disp != E.DISPOSITION_DENIED:
            v.verdict = "false_positive"; v.exploitability = "not_exploitable"
            v.confidence_score = 0.15
            v.confounders.append(f"anonymous is also not denied ({anon_disp}) — the endpoint "
                                 f"does not gate by identity here, so a low-priv non-denial is "
                                 f"not a privilege escalation (likely input validation or a "
                                 f"public/unauthenticated endpoint).")
            v.reasons.append("Bare 400/404 without an anonymous denial is not evidence of BFLA.")
            return v
        # anon denied, low-priv not denied => genuine differential
        executed = low_disp == E.DISPOSITION_CONTENT
        parity = admin_rec is not None and low_disp == admin_disp
        v.corroborations.append(f"anonymous={anon_disp} (denied), low-priv={low_disp}, "
                                f"admin={admin_disp}: the endpoint enforces auth yet the "
                                f"low-privilege user reaches the operation.")
        if executed:
            # the operation actually returned content for the low-priv user
            v.verdict = "true_positive"; v.exploitability = "exploitable"
            v.confidence_score = 0.85
            v.repro = ("As the low-privilege backend user, invoke the operation; it executed, "
                       "so function-level authorization is missing.")
        else:
            # low-priv only reached input validation (400/404). Auth was passed, but
            # the action was NOT completed — a bare 400 on an invalid id is not proof
            # of exploitation. Report as needing manual confirmation with a valid object.
            v.verdict = "likely_true_positive"; v.exploitability = "conditional"
            v.confidence_score = 0.5
            v.reasons.append("Anonymous is denied but the low-privilege user reached input "
                             "validation (HTTP 400/404 on the invalid test id). This strongly "
                             "suggests missing function-level authorization, but is NOT confirmed "
                             "exploitation — repeat with a VALID object id in a lab to confirm the "
                             "low-privilege user can actually complete the operation.")
            v.repro = ("Fetch a valid object id (e.g. an admin layout id from /api/roles/"
                       "layouts) and repeat the operation as the low-privilege user; a 2xx / "
                       "state change confirms the BFLA.")
        return v

    def _oracle_label(self) -> Optional[str]:
        """Highest-privilege identity available to serve as the authorized
        baseline (admin > backend > any credentialed identity)."""
        for lbl in ("admin", "backend"):
            ident = self.identities.get(lbl)
            if ident and (getattr(ident, "username", None) or
                          getattr(ident, "bearer_token", None)):
                return lbl
        for lbl, ident in self.identities.items():
            if lbl != "anonymous" and (getattr(ident, "username", None) or
                                       getattr(ident, "bearer_token", None)):
                return lbl
        return None

    def _fetch_as(self, url: str, method: str, identity_label: str) -> RequestRecord:
        # Uses the refresh-on-denial helper so a scan-degraded oracle/anon
        # session is re-authenticated rather than mistaken for enforced access.
        return self._request_authed(method, url, identity_label)

    def _verify_access_control(self, f: Finding) -> Verification:
        """The extra step NIST/OWASP require: actually re-test the access
        control. Re-fetch the resource anonymously AND as an authorized oracle,
        then confirm the anonymous caller receives the SAME protected data. If
        not (empty, denied, public-by-design, or different data), it is a false
        positive and we say so, downgrading rather than claiming 'confirmed'."""
        v = Verification()
        detail = f.detail or {}
        ev = f.evidence[0] if f.evidence else None
        url = getattr(ev, "url", "") if ev else ""
        method = getattr(ev, "method", "GET") if ev else "GET"
        v.controls.append(C.auth_required(None))

        if not url:
            v.verdict = "inconclusive"; v.exploitability = "unknown"
            v.confidence_score = 0.3
            v.reasons.append("no evidence URL to re-test")
            return v

        # 1) public-by-design endpoints (login/config/published content)
        if E.is_public_by_design(url):
            body = E._body(self._fetch_as(url, method, "anonymous"))
            sensitive = E.looks_sensitive_body(body)
            if not sensitive:
                v.verdict = "false_positive"; v.exploitability = "not_exploitable"
                v.confidence_score = 0.9; v.probes = 1
                v.reasons.append(
                    "endpoint is public by design (login/config/published "
                    "content); anonymous access is documented, intended behavior "
                    "and the body carries no sensitive properties")
                v.repro = ("Compare the anonymous and authenticated responses — "
                           "they are equivalent public data, so this is expected.")
                return v
            # public endpoint that DOES leak secrets -> keep it, escalate reason
            v.reasons.append(f"public endpoint but body exposes sensitive keys: "
                             f"{', '.join(sensitive)}")

        # 2) OWASP oracle: does anon get the same protected data as an authed user?
        anon = self._fetch_as(url, method, "anonymous")
        v.probes = 1
        oracle_label = None
        if detail.get("test", "").startswith("authz_matrix") and detail.get("reference"):
            oracle_label = detail["reference"]
        oracle_label = oracle_label or self._oracle_label()
        oracle = self._fetch_as(url, method, oracle_label) if oracle_label else None
        if oracle is not None:
            v.probes = 2

        res = E.served_protected_content(anon, oracle)

        # --- go the extra step: if the request was rejected as malformed (4xx),
        #     repair it (supply missing params/body/enum) and retest before
        #     concluding anything (RESTler-style error-guided repair).
        if (not res.served and (E.classify_response(anon) == E.DISPOSITION_BAD_REQUEST
                                or E.classify_response(oracle) == E.DISPOSITION_BAD_REQUEST)):
            fixed = self._repair_and_recompare(url, method, oracle_label)
            if fixed is not None:
                anon, oracle, note = fixed
                v.probes += 2
                res = E.served_protected_content(anon, oracle)
                v.reasons.append("original request was malformed (4xx); " + note)

        v.similarity = res.similarity
        v.controls.append(C.ControlObservation(
            "oracle_comparison", present=True,
            strength="strong" if oracle is not None else "weak",
            detail=res.reason))

        if res.served:
            v.verdict = "true_positive"; v.exploitability = "exploitable"
            v.confidence_score = 0.9
            v.corroborations.append(res.reason)
            v.reasons.append("confirmed by re-test: the unauthenticated request "
                             "returns the same protected data as an authorized "
                             "user (OWASP WSTG 4.5).")
            v.repro = ("Send the request with no credentials and again as an "
                       "authorized user; identical protected data in both "
                       "confirms the missing access control.")
        else:
            # not reproducible as a real bypass -> honest false positive
            disp = res.anon_disposition
            if disp == E.DISPOSITION_BAD_REQUEST:
                v.verdict = "false_positive"; v.confidence_score = 0.9
                v.repro = ("The request returns HTTP 4xx (malformed/missing input) "
                           "for every identity; it never reaches authorization, so "
                           "identical responses are meaningless. Supply the required "
                           "parameter/body and retest.")
            elif disp in (E.DISPOSITION_DENIED, E.DISPOSITION_NOT_FOUND):
                v.verdict = "false_positive"; v.confidence_score = 0.9
                v.repro = ("Re-fetch anonymously and as an authorized user; the "
                           "anonymous response is denied/not-found, so the control works.")
            elif disp == E.DISPOSITION_EMPTY:
                v.verdict = "false_positive"; v.confidence_score = 0.85
                v.repro = "Anonymous response is empty; no protected data was served."
            else:
                v.verdict = "likely_false_positive"; v.confidence_score = 0.6
                v.repro = "Could not reproduce a bypass on re-test."
            v.exploitability = "not_exploitable"
            v.confounders.append(res.reason)
            v.reasons.append("re-test did not reproduce a bypass: " + res.reason)

        self._ai_root_cause(f, v, anon, oracle)
        return v

    def _repair_and_recompare(self, url: str, method: str, oracle_label):
        """Repair a malformed (4xx) request and re-run the anon-vs-authed
        comparison so we test the resource, not the error path."""
        try:
            from ..active.repair import suggest_repairs
            from ..active.http_tools import RequestSpec, Repeater
        except Exception:
            return None
        rep = Repeater(self.client)
        anon_spec = RequestSpec(method=method, path=url,
                                headers=self._headers_for("anonymous"))
        oracle_spec = RequestSpec(method=method, path=url,
                                  headers=self._headers_for(oracle_label)) if oracle_label else None
        if oracle_spec is None:
            return None
        # drive repairs from whichever response carried the error message
        err_rec = self._fetch_as(url, method, oracle_label)
        o_variants = suggest_repairs(err_rec, oracle_spec)
        a_variants = suggest_repairs(err_rec, anon_spec)
        for ov, av in list(zip(o_variants, a_variants))[:4]:
            if not ov.spec:
                continue
            o_rec = rep.send(ov.spec, identity_label=oracle_label)
            if E.classify_response(o_rec) == E.DISPOSITION_BAD_REQUEST:
                continue  # still malformed, try next repair
            a_rec = rep.send(av.spec, identity_label="anonymous") if av.spec else \
                self._fetch_as(url, method, "anonymous")
            return a_rec, o_rec, f"repaired ({ov.what}) and retested against the resource"
        return None

    def _ai_root_cause(self, f: Finding, v: Verification, anon, oracle) -> None:
        """Optional full-AI analysis: ask the model to explain the responses and
        classify real-vs-artifact. Never overrides the deterministic verdict; it
        adds an explanation, and can downgrade confidence if it disagrees."""
        if not self.analyst or not getattr(self.analyst, "enabled", False):
            return
        try:
            ctx = {
                "title": f.title,
                "endpoint": f.endpoint,
                "test": (f.detail or {}).get("test"),
                "current_verdict": v.verdict,
                "anonymous_response": {"status": getattr(anon, "status", None),
                                       "body": (getattr(anon, "resp_body", "") or "")[:600]},
                "authorized_response": {"status": getattr(oracle, "status", None),
                                        "body": (getattr(oracle, "resp_body", "") or "")[:600]},
            }
            note = self.analyst.analyze_evidence(ctx)
            if note:
                v.ai_analysis = note.get("reason", "") if isinstance(note, dict) else str(note)
                if isinstance(note, dict) and note.get("is_real") is False and v.verdict == "true_positive":
                    v.confidence_score = min(v.confidence_score, 0.5)
                    v.reasons.append("AI review flags this as a likely artifact: "
                                     + note.get("reason", ""))
        except Exception:
            return

    def _verify_active_generic(self, f: Finding) -> Verification:
        """Active findings were confirmed by *exercising* the manipulation (the
        scanner compared the manipulated response against authorized/denied
        oracles). We don't re-judge them with the passive heuristics; we record
        the corroboration, rate exploitability by test type, and add a safe
        re-check. A light reachability re-issue guards against a stale endpoint."""
        v = Verification()
        test = (f.detail or {}).get("test", "")
        base = test.split(":")[0]

        _EXPL = {
            "alg_none": "exploitable", "strip_signature": "exploitable",
            "tamper_signature": "exploitable", "alg_confusion_rs_to_hs": "exploitable",
            "weak_secret": "exploitable", "claim_tamper": "exploitable",
            "missing_auth": "exploitable", "identity_swap": "exploitable",
            "bola_id_swap": "exploitable", "mass_assignment": "conditional",
            # v0.5 breadth
            "authz_matrix_bypass": "exploitable", "excessive_data": "exploitable",
            "graphql_introspection": "exploitable", "token_predictable": "exploitable",
            "token_weak": "conditional", "verbose_error": "conditional",
            "server_error": "conditional", "fail_open": "conditional",
            "no_rate_limit": "conditional", "no_pagination_cap": "conditional",
            # v0.6 advanced
            "verb_tamper": "exploitable", "race_condition": "conditional",
            "artifact_exposure": "exploitable", "shadow_endpoint": "conditional",
            "version_sprawl": "conditional", "graphql_batching": "conditional",
            "graphql_alias_amplification": "conditional", "graphql_no_depth_limit": "conditional",
            # v1.0 privilege escalation / BFLA
            "bfla_privileged_op": "exploitable",
        }
        _REPRO = {
            "alg_none": "Re-send the request with a token whose header alg is "
                        "'none' and an empty signature; a 200 confirms unsigned "
                        "tokens are trusted. Fix: enforce an algorithm allowlist.",
            "strip_signature": "Re-send with the signature segment removed; a 200 "
                               "confirms the signature isn't checked.",
            "tamper_signature": "Flip one character of the signature and re-send; "
                                "acceptance confirms the signature isn't verified.",
            "alg_confusion_rs_to_hs": "Re-sign the token with HS256 using the "
                                      "server's PUBLIC key as the HMAC secret; "
                                      "acceptance confirms RS/HS confusion.",
            "weak_secret": "Re-sign a token with the guessed secret and confirm "
                           "it's accepted. Fix: rotate to a strong random key.",
            "claim_tamper": "Change a role/privilege claim, re-sign via the "
                            "forging primitive, and confirm elevated access.",
            "missing_auth": "Re-send the request with no Authorization header/"
                            "cookie; a 200 with real content confirms missing auth.",
            "identity_swap": "Re-send with a lower-privilege identity's token and "
                             "confirm equivalent access.",
            "bola_id_swap": "As the lower-privilege identity, request another "
                            "principal's object id and confirm it's returned.",
            "mass_assignment": "Re-send the write with the elevated field, then "
                               "read the object back with a normal request to "
                               "confirm the privilege was actually PERSISTED, not "
                               "just echoed.",
            "authz_matrix_bypass": "Replay the reference request as the lower-"
                                   "privilege identity and confirm it returns the "
                                   "same protected resource.",
            "excessive_data": "Request the object as a low-privilege caller and "
                              "confirm the sensitive property is present in the JSON.",
            "graphql_introspection": "POST an introspection query to the GraphQL "
                                     "endpoint and confirm the full __schema is returned.",
            "bfla_privileged_op": "As the low-privilege backend user, send the admin "
                                  "operation; a non-403 response (even a 400 input error) "
                                  "proves function-level authorization is missing. Confirm "
                                  "the full impact in a lab with a throwaway user; do not "
                                  "escalate a real account or deploy code.",
            "token_predictable": "Collect several tokens and confirm they are "
                                 "sequential/colliding; a strong token must be "
                                 "unpredictable with >=128 bits of entropy.",
            "token_weak": "Collect several tokens and estimate entropy; increase "
                          "token length/randomness if below ~128 bits.",
            "verbose_error": "Send the malformed input again and confirm the "
                             "response body contains internal stack-trace detail.",
            "server_error": "Send the malformed input again and confirm an "
                            "unhandled 5xx instead of a validated 4xx.",
            "fail_open": "Send garbage/invalid auth and confirm the endpoint still "
                         "returns protected content.",
            "no_rate_limit": "Send a small bounded burst and confirm no 429/"
                             "throttling appears on the sensitive flow.",
            "no_pagination_cap": "Request a very large page size and confirm the "
                                 "response is not capped server-side.",
            "verb_tamper": "Re-send the request with the alternate method (or "
                           "method-override header) and confirm it returns the "
                           "protected resource the canonical method denied.",
            "race_condition": "Fire a small bounded burst of parallel identical "
                              "requests and confirm the action succeeds more than "
                              "once where only one should.",
            "artifact_exposure": "Fetch the path and confirm the sensitive file "
                                 "content is served; remove it from the web root.",
            "shadow_endpoint": "Fetch the undocumented path and confirm it responds "
                               "outside the documented API surface.",
            "version_sprawl": "Fetch each API version and confirm older versions "
                              "are still live and should be retired.",
            "graphql_batching": "POST a JSON array of queries and confirm all "
                                "resolve in one request.",
            "graphql_alias_amplification": "POST a query with many aliases of one "
                                           "field and confirm all resolve.",
            "graphql_no_depth_limit": "POST a deeply nested query and confirm it's "
                                      "accepted without a depth/complexity error.",
        }

        # light reachability re-issue (does not flip the verdict unless it errors)
        ev = f.evidence[0] if f.evidence else None
        if ev is not None:
            again = self._reissue(ev)
            v.probes = 1
            if again.status == 0:
                v.reasons.append("note: endpoint was unreachable on re-issue")

        v.corroborations.append("manipulation was exercised against the target "
                                "and the server accepted it (compared to "
                                "authorized/denied baselines)")
        v.controls.append(C.auth_required(None))

        if base == "mass_assignment":
            # echo != enforcement — be honest that this needs one more step.
            v.verdict = "likely_true_positive"
            v.exploitability = "conditional"
            v.confidence_score = 0.6
            v.reasons.append("The write accepted and reflected an unexpected "
                             "privileged field. Confirm the server actually "
                             "honors it (not just echoes it) before rating it "
                             "critical.")
        elif base == "param_tampering":
            # accepting an out-of-range value is NOT proof of impact, and it is not
            # an access-control bypass. It matters only if a harmful downstream
            # effect results — which we cannot see from a 200.
            v.verdict = "likely_true_positive"
            v.exploitability = "conditional"
            v.confidence_score = 0.45
            v.reasons.append("The server accepted an out-of-range value for this "
                             "parameter. This is only a business-logic vulnerability "
                             "if it produces a harmful downstream effect (a negative "
                             "charge/credit, a quota bypass, etc.). A 200 alone is not "
                             "proof — confirm the effect on the resulting order, "
                             "balance, or record. Note: on pagination-style params a "
                             "negative value often just means 'unbounded' and is "
                             "expected behavior, not a flaw.")
            # drop the generic 'compared to baselines' corroboration for this class
            v.corroborations = [c for c in v.corroborations
                                if "authorized/denied baselines" not in c]
        else:
            v.verdict = "true_positive"
            v.exploitability = _EXPL.get(base, "conditional")
            v.confidence_score = 0.9 if v.exploitability == "exploitable" else 0.7
            v.reasons.append("Access control was bypassed by manipulating the "
                             "request; this was confirmed by exercising it.")
        v.repro = _REPRO.get(base, "Re-run the manipulation and confirm the "
                             "server still grants access.")
        return v

    # ======================================================================
    # SQL injection
    # ======================================================================
    def _verify_sqli_error(self, f: Finding) -> Verification:
        import re as _re
        v = Verification()
        base = f.evidence[0] if f.evidence else None          # benign baseline
        payload_rec = f.evidence[1] if len(f.evidence) > 1 else None  # metachar payload
        param = (f.detail or {}).get("param")

        # A quote-induced *syntax* error is the specific injection tell: it means
        # the metacharacter broke out of the SQL token. A generic DB error (e.g.
        # "column X does not exist") can appear for benign values on endpoints that
        # concatenate the value as an identifier, so we must NOT treat "both
        # responses have a DB error" as a false positive. We compare error CLASS.
        _SYNTAX = _re.compile(r"(?i)syntax error|unterminated|unexpected token|"
                              r"quoted string not properly terminated|parse error|"
                              r"near \"|malformed")
        _DBERR = _re.compile(r"(?i)sqlexception|psqlexception|sqlsyntax|jdbc|"
                             r"does not exist|ORA-\d|SQLSTATE|hibernate|"
                             r"column .* does not exist|near \"")

        def bodies():
            # prefer re-issuing live for stability; fall back to captured evidence
            pbody = bbody = None
            if payload_rec is not None:
                try:
                    pbody = (self._reissue(payload_rec).resp_body or "")
                except Exception:
                    pbody = (payload_rec.resp_body or "")
            if base is not None and param:
                try:
                    # benign control: a plainly alphanumeric token (no metachars)
                    bbody = (self._reissue(base, set_param=param, value=f"z{_rand()}z").resp_body or "")
                except Exception:
                    bbody = (base.resp_body or "")
            elif base is not None:
                bbody = (base.resp_body or "")
            return (pbody if pbody is not None else (payload_rec.resp_body if payload_rec else "") or "",
                    bbody if bbody is not None else (base.resp_body if base else "") or "")

        payload_body, benign_body = bodies()
        v.probes = (1 if payload_rec is not None else 0) + (1 if (base is not None and param) else 0)

        p_syntax = bool(_SYNTAX.search(payload_body))
        b_syntax = bool(_SYNTAX.search(benign_body))
        p_dberr = bool(_DBERR.search(payload_body))
        b_dberr = bool(_DBERR.search(benign_body))

        waf = C.detect_waf([r for r in (base, payload_rec) if r])
        if waf.present:
            v.controls.append(waf)

        # Verbose-SQL disclosure = ground truth. the target (and similar stacks) echo
        # the CONSTRUCTED query in the error body, e.g.
        #   {"message":"ERROR: syntax error ... \"SQL\":[\"SELECT ... ORDER BY  ASC\"]"}
        # If the metacharacter payload triggers a syntax error AND the body echoes
        # a SQL statement, the value is provably concatenated unparameterized into
        # the query — a confirmed injection — EVEN WHEN a benign-but-invalid value
        # also errors (the ORDER BY / identifier case, where any invalid token
        # errors, defeating the plain benign-vs-payload error-class comparison).
        _ECHOED_SQL = _re.compile(r'(?is)"sql"\s*:\s*\[|\bselect\b.+\bfrom\b')
        if p_syntax and _ECHOED_SQL.search(payload_body):
            v.verdict = "true_positive"
            v.exploitability = "conditional" if waf.present else "exploitable"
            v.confidence_score = 0.85
            v.corroborations.append(
                "the error response echoes the CONSTRUCTED SQL query with a syntax break "
                "from the injected metacharacter — the parameter is concatenated "
                "unparameterized into the statement, confirming SQL injection")
            v.repro = (f"GET with {param}=<valid column> returns 200; {param}=<value>' (or a "
                       f"parenthesis) triggers a SQL *syntax error* whose body echoes the built "
                       f"query (e.g. ORDER BY ...), proving unparameterized interpolation. "
                       f"Confirm depth with the opt-in sqlmap integration (authenticated).")
            return v

        if p_syntax and not b_syntax:
            # the single quote specifically introduced a SQL syntax error that a
            # benign value does NOT produce -> unparameterized query. True positive
            # even if the benign value produced a *different* DB error.
            v.verdict = "true_positive"
            v.exploitability = "conditional" if waf.present else "exploitable"
            v.confidence_score = 0.8 if waf.present else 0.9
            v.corroborations.append("a single quote produces a SQL syntax error that a "
                                    "benign alphanumeric value does not — the value reaches "
                                    "an unparameterized query (e.g. concatenated into ORDER BY)")
            if b_dberr:
                v.corroborations.append("the benign value yields a different DB error "
                                        "(value used as an identifier), consistent with "
                                        "orderby/identifier injection")
            v.repro = (f"GET with {param}=title vs {param}=title' and diff: the quote alone "
                       f"turns a column/identifier error into a SQL *syntax* error, proving "
                       f"the value is concatenated into the query. Confirm depth with the "
                       f"opt-in sqlmap integration (authenticated).")
        elif p_dberr and not b_dberr and not b_syntax:
            v.verdict = "likely_true_positive"
            v.exploitability = "conditional"
            v.confidence_score = 0.6
            v.reasons.append("The metacharacter payload triggers a DB error absent for a "
                             "benign value; likely injection-driven but not a clean syntax "
                             "break — confirm with sqlmap.")
        elif b_dberr or b_syntax:
            # the benign value ALREADY errors with the same class and the quote
            # added no *new* syntax break -> generic error page / metacharacter-
            # insensitive -> not injection-driven.
            v.confounders.append("the same DB error appears for a benign value "
                                 "(metacharacter is not the discriminator)")
            v.verdict = "false_positive"
            v.exploitability = "not_exploitable"
            v.confidence_score = 0.15
            v.reasons.append("A benign value produces the same class of database error, so "
                             "the response is a generic verbose-error page rather than "
                             "injection-driven (still worth fixing the error handling).")
            v.repro = ("Diff the benign and payload responses: if both carry the same DB "
                       "error and the quote adds no syntax break, this is verbose error "
                       "handling, not SQLi.")
        else:
            v.verdict = "inconclusive"
            v.exploitability = "unknown"
            v.confidence_score = 0.35
            v.reasons.append("Could not distinguish an injection-driven error from baseline "
                             "behaviour; treat as a candidate pending manual/sqlmap check.")
        return v

    def _verify_sqli_boolean(self, f: Finding) -> Verification:
        v = Verification()
        if len(f.evidence) < 2:
            v.verdict = "inconclusive"; v.confidence_score = 0.3
            v.reasons.append("insufficient evidence to re-test")
            return v
        t_rec, fa_rec = f.evidence[0], f.evidence[1]
        # Repeat both sides twice to separate a real, stable boolean delta from
        # response jitter (a top boolean-SQLi false-positive source).
        t_lens, f_lens = [t_rec.resp_len], [fa_rec.resp_len]
        probes = 0
        for _ in range(2):
            if probes >= self.max_probes:
                break
            t2 = self._reissue(t_rec); f2 = self._reissue(fa_rec); probes += 2
            t_lens.append(t2.resp_len); f_lens.append(f2.resp_len)

        waf = C.detect_waf([t_rec, fa_rec])
        if waf.present or C.looks_like_block_page(t_rec) or C.looks_like_block_page(fa_rec):
            if waf.present:
                v.controls.append(waf)
            v.confounders.append("one branch looks like a WAF/edge block page")
            v.verdict = "likely_false_positive"
            v.exploitability = "conditional"
            v.confidence_score = 0.3
            v.reasons.append("The size difference is explained by a WAF blocking "
                             "one payload, not by the database evaluating the "
                             "condition.")
            v.probes = probes
            return v

        t_med, f_med = statistics.median(t_lens), statistics.median(f_lens)
        t_jit = (max(t_lens) - min(t_lens))
        f_jit = (max(f_lens) - min(f_lens))
        delta = abs(t_med - f_med)
        jitter = max(t_jit, f_jit)
        v.probes = probes
        v.confounders.append(f"response jitter measured at {jitter} bytes")
        if delta > max(64, 3 * jitter) and jitter < delta:
            v.corroborations.append(f"stable true/false size delta {delta:.0f}B "
                                    f"across repeats (jitter {jitter}B)")
            v.verdict = "true_positive"
            v.exploitability = "exploitable"
            v.confidence_score = 0.8
            v.reasons.append("The true/false-condition responses differ "
                             "repeatably and far beyond measured jitter — a "
                             "boolean-based injection indicator.")
            v.repro = ("Resend the true-condition and false-condition values a "
                       "few times; a consistent size/return delta that tracks "
                       "the boolean confirms it. Use sqlmap (opt-in) only to the "
                       "extent needed to confirm.")
        else:
            v.verdict = "likely_false_positive"
            v.exploitability = "unknown"
            v.confidence_score = 0.3
            v.reasons.append("The size difference is within, or not clearly "
                             "above, normal response jitter.")
        return v

    def _verify_sqli_time(self, f: Finding) -> Verification:
        v = Verification()
        base = f.evidence[0] if f.evidence else None
        delayed = f.evidence[1] if len(f.evidence) > 1 else None
        sleep_s = (f.detail or {}).get("sleep_s", 7)
        if not (base and delayed):
            v.verdict = "inconclusive"; v.confidence_score = 0.3
            v.reasons.append("insufficient evidence to re-time")
            return v
        # Re-measure baseline (median of a few) and re-run the sleep payload.
        base_samples = [base.elapsed_ms]
        probes = 0
        for _ in range(2):
            if probes >= self.max_probes:
                break
            b = self._reissue(base); probes += 1
            base_samples.append(b.elapsed_ms)
        d1 = self._reissue(delayed); probes += 1
        base_med = statistics.median(base_samples)
        threshold = base_med + sleep_s * 1000 * 0.7
        reproduced = d1.elapsed_ms > threshold
        v.probes = probes
        v.confounders.append(f"baseline latency median {base_med:.0f}ms "
                             f"(samples {', '.join(f'{x:.0f}' for x in base_samples)})")
        if reproduced:
            v.corroborations.append(f"sleep payload reproduced a "
                                    f"{d1.elapsed_ms:.0f}ms response vs "
                                    f"{base_med:.0f}ms baseline")
            v.verdict = "true_positive"
            v.exploitability = "exploitable"
            v.confidence_score = 0.82
            v.reasons.append("A modest, benign time delay reproduces well above "
                             "baseline latency — a strong time-based blind SQLi "
                             "indicator. No data was read or modified.")
            v.repro = ("Re-run the single pg_sleep probe two or three times; a "
                       "delay that consistently tracks the requested sleep "
                       "confirms injectability. Depth confirmation is sqlmap's "
                       "job (opt-in, authorized target only).")
        else:
            v.verdict = "likely_false_positive"
            v.exploitability = "unknown"
            v.confidence_score = 0.3
            v.reasons.append("The delay did not reproduce above baseline on "
                             "re-test — the original spike was likely transient "
                             "network/GC latency.")
        return v

    # ======================================================================
    # XSS  (verdict = is the reflection real; exploitability = do controls let it run)
    # ======================================================================
    def _verify_xss(self, f: Finding) -> Verification:
        v = Verification()
        detail = f.detail or {}
        rec = f.evidence[0] if f.evidence else None
        if rec is None:
            v.verdict = "inconclusive"; v.confidence_score = 0.3
            v.reasons.append("no evidence response to inspect")
            return v

        # Stored/profile variant: read back is evidence[1]
        stored = "givenName" in detail or "surname" in detail
        read_rec = f.evidence[1] if (stored and len(f.evidence) > 1) else rec

        # STORED / second-order XSS: the sink is a DIFFERENT surface (the admin
        # Users panel renders the name client-side), so the JSON read-back being
        # non-HTML does NOT make this safe. Confirm the vulnerability at the
        # STORAGE layer: did the dangerous markup survive the filter and persist?
        if stored:
            gv = detail.get("givenName", ""); sn = detail.get("surname", "")
            body = (read_rec.resp_body or "") if read_rec else ""
            survived = (gv and sn and gv in body and sn in body)
            v.probes = 1
            if survived:
                v.verdict = "true_positive"; v.exploitability = "conditional"
                v.confidence_score = 0.85
                v.corroborations.append("split payload survived the Xss.strip filter "
                                        "and persisted unescaped in stored profile fields")
                v.reasons.append("Stored/second-order XSS: the field-split bypass stores "
                                 "unescaped HTML that executes when an admin views the "
                                 "user row in the admin Users panel (a different sink "
                                 "than this API read-back).")
                v.repro = ("As a low-privilege backend user, set givenName='<img' and "
                           "surname='src=x onerror=...'; both pass the per-field filter and "
                           "persist. An admin viewing the user in Settings > Users renders "
                           "the combined markup. Confirm in the admin UI; do not weaponize.")
                v.controls.append(C.ControlObservation(
                    "output_encoding", present=False, strength="weak",
                    detail="dangerous markup stored without escaping (filter bypass)"))
            else:
                v.verdict = "likely_false_positive"; v.exploitability = "not_exploitable"
                v.confidence_score = 0.25
                v.confounders.append("split markers did not both survive storage on re-read")
            return v

        probes = 0
        input_driven = None
        param = detail.get("param")
        if param and not stored:
            # Control: does a FRESH unique value also get reflected? If yes, the
            # reflection tracks input (real). If a random value is NOT reflected,
            # the earlier 'reflection' may have been a coincidental static string.
            fresh = f"zz{_rand(10)}zz"
            ctrl = self._reissue(rec, set_param=param, value=f"<{fresh}>")
            probes += 1
            input_driven = fresh in (ctrl.resp_body or "")
            read_rec = ctrl if ctrl.status else read_rec

        # Compensating controls that decide EXECUTION.
        execable, ctx_reason = C.html_executable_context(read_rec)

        # Strongest confirmation: render the reflected payload in a real headless
        # browser and see whether it EXECUTES (not merely reflects).
        if param and not stored and self.config is not None and \
                getattr(self.config.scan, "enable_browser", True):
            from . import browser as B
            if B.playwright_available():
                token = f"tok{_rand(8)}"
                exec_rec = self._reissue(rec, set_param=param, value=B.exec_payload(token))
                probes += 1
                # only meaningful if our exec payload actually came back in the body
                if exec_rec and exec_rec.status and token in (exec_rec.resp_body or ""):
                    res = B.confirm_in_browser(exec_rec.resp_body or "", token)
                    v.controls.append(C.ControlObservation(
                        "browser_execution", present=True,
                        strength="strong", detail=res.detail))
                    if res.executed is True:
                        # set_content() doesn't enforce the response CSP header, so a
                        # strong CSP on the real response still mitigates execution.
                        csp_c = C.csp_control(exec_rec)
                        v.verdict = "true_positive"; v.probes = probes
                        v.corroborations.append("payload EXECUTED in a headless browser "
                                                "(sentinel fired) — reflection is live script")
                        if csp_c.present and csp_c.strength == "strong":
                            v.controls.append(csp_c)
                            v.exploitability = "mitigated"; v.confidence_score = 0.8
                            v.reasons.append("A strong Content-Security-Policy on the "
                                             "response blocks execution in a real browser "
                                             "navigation, mitigating the XSS.")
                            v.repro = ("Reflection executes without CSP; the response's CSP "
                                       "restricts script sources, so exploitation is blocked "
                                       "unless the CSP can be bypassed.")
                            return v
                        v.exploitability = "exploitable"; v.confidence_score = 0.97
                        v.repro = ("Load the URL with the reflected payload in a browser; "
                                   "the injected script runs in the page origin.")
                        return v
                    if res.executed is False:
                        v.verdict = "false_positive"; v.exploitability = "not_exploitable"
                        v.confidence_score = 0.15; v.probes = probes
                        v.confounders.append("headless browser rendered the response and the "
                                             "marker did NOT execute (escaped/non-rendered)")
                        v.reasons.append("Reflection is present but a real browser did not "
                                         "execute it, so it is not exploitable as XSS.")
                        return v
                    # executed is None -> inconclusive; fall through to heuristic

        csp = C.csp_control(read_rec)
        nosniff = C.nosniff_control(read_rec)
        cookies = C.cookie_flags_control(read_rec)
        v.controls.extend([csp, nosniff, cookies])
        v.probes = probes

        # Verdict: is the unescaped reflection real?
        if input_driven is False:
            v.verdict = "likely_false_positive"
            v.confidence_score = 0.25
            v.confounders.append("a fresh unique value was not reflected back")
            v.reasons.append("The marker may be a static string in the page "
                             "rather than a reflection of our input.")
            v.exploitability = "not_exploitable"
            return v

        v.corroborations.append("HTML metacharacters survive unescaped in the "
                                "response" + (" (input-driven confirmed)"
                                              if input_driven else ""))
        v.verdict = "true_positive" if input_driven else "likely_true_positive"

        # Exploitability from controls.
        if not execable:
            v.exploitability = "not_exploitable"
            v.confidence_score = 0.4
            v.reasons.append(ctx_reason + " — a reflection here will not execute "
                             "as script in a browser.")
            v.repro = ("Open the URL in a browser and confirm the response "
                       "Content-Type; a non-HTML type with nosniff will not run "
                       "injected markup.")
            return v

        if csp.present and csp.strength == "strong":
            v.exploitability = "mitigated"
            v.confidence_score = 0.6
            v.reasons.append(f"Reflection is real but a strong CSP ({csp.detail}) "
                             f"blocks inline script execution; impact is limited "
                             f"unless the CSP can be bypassed.")
        elif csp.present and csp.strength in ("moderate", "weak"):
            v.exploitability = "conditional"
            v.confidence_score = 0.7
            v.reasons.append(f"A CSP is present but {csp.strength} ({csp.detail}); "
                             f"execution may still be possible.")
        else:
            v.exploitability = "exploitable"
            v.confidence_score = 0.85
            v.reasons.append("Unescaped reflection in an HTML context with no "
                             "effective CSP — reflected XSS is likely executable.")
        if not cookies.present:
            v.reasons.append("Note: no HttpOnly cookie observed on this route; if "
                             "session cookies lack HttpOnly, XSS impact rises.")
        v.repro = ("In a browser, request the URL with an inert marker (e.g. a "
                   "unique string wrapped in angle brackets) and view source to "
                   "confirm it lands unescaped in an HTML/script context. Judge "
                   "real impact against the CSP shown above. Do not weaponize on "
                   "shared environments.")
        return v

    # ======================================================================
    # IDOR (horizontal) — the control probe is the key FP filter here
    # ======================================================================
    def _verify_idor(self, f: Finding) -> Verification:
        v = Verification()
        detail = f.detail or {}
        rec = f.evidence[0] if f.evidence else None
        obj_id = detail.get("object_id")
        if rec is None or not obj_id:
            v.verdict = "inconclusive"; v.confidence_score = 0.35
            v.reasons.append("missing evidence/object id to re-test")
            return v

        from ..semantic_diff import structural_similarity
        probes = 0
        # Confounder: does a BOGUS id also return a real object to the same
        # low-privilege identity? If yes, the endpoint hands data to anyone for
        # any id (broken, but not *object-scoped* IDOR — or it's a public list),
        # and the 'similarity' to admin proves nothing.
        bogus = "00000000-0000-0000-0000-0000000000ff" if "-" in obj_id \
            else ("f" * len(obj_id) if len(obj_id) in (32,) else "999999999")
        bogus_rec = self._reissue(rec, replace_in_path=(obj_id, bogus))
        probes += 1
        # "Real object" = body-aware CONTENT, not merely 200 + length > 64. A
        # 200-wrapped {"message":"No Permissions"} / error envelope is >64 bytes
        # and would otherwise count as a returned object (false positive).
        bogus_real = E.classify_response(bogus_rec) == E.DISPOSITION_CONTENT

        # Re-confirm the harvested id still returns a real object.
        again = self._reissue(rec)
        probes += 1
        harvested_real = E.classify_response(again) == E.DISPOSITION_CONTENT
        v.probes = probes

        if bogus_real:
            # A random id also works. If the two look structurally identical it's
            # likely a fixed page / list, not per-object leakage.
            sim = structural_similarity(bogus_rec.resp_body, again.resp_body)
            v.confounders.append(f"a bogus id also returned HTTP 200 "
                                 f"({bogus_rec.resp_len}B, {sim:.0%} similar to the "
                                 f"harvested-id response)")
            if sim >= 0.9:
                v.verdict = "likely_false_positive"
                v.confidence_score = 0.25
                v.exploitability = "not_exploitable"
                v.reasons.append("The endpoint returns the same structure for a "
                                 "non-existent id, so it is not exposing a "
                                 "specific object owned by someone else.")
            else:
                v.verdict = "likely_true_positive"
                v.confidence_score = 0.6
                v.exploitability = "conditional"
                v.reasons.append("Bogus and harvested ids both return data but "
                                 "differ — the endpoint may still expose real "
                                 "objects; verify ownership manually.")
            return v

        if harvested_real:
            v.corroborations.append("harvested id returns a real object while a "
                                    "bogus id does not (object-scoped access)")
            v.verdict = "true_positive"
            v.exploitability = "exploitable"
            v.confidence_score = 0.85
            v.reasons.append("A lower-privilege identity reads a specific object "
                             "(harvested from the admin oracle) that a "
                             "non-existent id does not return — consistent with "
                             "horizontal IDOR / BOLA.")
            v.repro = ("As the limited user, request the object id versus a "
                       "random id: the real id returns another principal's "
                       "object, the random id 404s. Confirm the object is not "
                       "owned by the test user before reporting.")
        else:
            v.verdict = "likely_false_positive"
            v.confidence_score = 0.3
            v.exploitability = "unknown"
            v.confounders.append("harvested id no longer returns a real object on "
                                 "re-test")
            v.reasons.append("Could not reproduce access to the object; may have "
                             "been transient or an already-authorized resource.")
        return v

    # ======================================================================
    # Vertical authz / missing-auth
    # ======================================================================
    def _verify_authz(self, f: Finding) -> Verification:
        v = Verification()
        rec = f.evidence[0] if f.evidence else None
        admin_rec = f.evidence[1] if len(f.evidence) > 1 else None
        if rec is None:
            v.verdict = "inconclusive"; v.confidence_score = 0.35
            v.reasons.append("no evidence to re-test"); return v

        again = self._reissue(rec)
        v.probes = 1
        # Body-aware gate (NIST 800-115 / OWASP WSTG 4.5): the low-privilege
        # re-test must return substantive CONTENT — not a 200-wrapped error
        # envelope ({"message":"No Permissions"}), a login page, a 4xx that
        # rejected the request before authz ran, a 5xx, or an empty result set.
        # Deciding on status==200 + resp_len>64 alone is the single biggest
        # false-positive source (an error body is >64 bytes and still a 200).
        disp = E.classify_response(again)
        login_page = _login_like(again.resp_body)
        if disp != E.DISPOSITION_CONTENT or login_page:
            if login_page and disp == E.DISPOSITION_CONTENT:
                v.verdict = "likely_false_positive"; v.confidence_score = 0.35
                v.confounders.append("re-test returned a login page, not privileged data")
            else:
                v.verdict = "false_positive" if disp in (
                    E.DISPOSITION_DENIED, E.DISPOSITION_BAD_REQUEST,
                    E.DISPOSITION_EMPTY, E.DISPOSITION_NOT_FOUND) else "likely_false_positive"
                v.confidence_score = 0.85 if v.verdict == "false_positive" else 0.4
                v.confounders.append(f"re-test disposition is '{disp}', not real content "
                                     f"(status {again.status}, {again.resp_len}B)")
            v.exploitability = "not_exploitable"
            v.reasons.append("The low-privilege identity does not actually receive "
                             "privileged content on re-test — the response is an "
                             "error/denial/empty/login page, so identical or similar "
                             "bodies across identities prove nothing.")
            return v

        role = (f.detail or {}).get("role", rec.identity)
        v.corroborations.append(f"{role} identity repeatedly receives substantive "
                                f"content ({again.resp_len}B, disposition '{disp}')")
        # Compare to the admin oracle by DATA VALUES, not structure: two responses
        # that share a schema but carry each caller's own data (self-scoped, e.g.
        # /users/current) are NOT the same protected object and must not confirm.
        if admin_rec is not None and E.classify_response(admin_rec) == E.DISPOSITION_CONTENT:
            res = E.served_protected_content(again, admin_rec)
            v.similarity = res.similarity
            if res.served:
                v.verdict = "true_positive"
                v.confidence_score = 0.85
                v.corroborations.append(res.reason)
            else:
                v.verdict = "likely_true_positive"
                v.confidence_score = 0.5
                v.confounders.append(res.reason)
                v.reasons.append("The identity reaches content, but it is not the "
                                 "same data the admin oracle returns — could be "
                                 "self-scoped/public data rather than a bypass.")
        else:
            v.verdict = "likely_true_positive"
            v.confidence_score = 0.55
        v.exploitability = "exploitable" if role == "anonymous" else "conditional"
        v.reasons.append("A privileged/id-bearing endpoint returns substantive "
                         f"content to a {role} identity that should not have access.")
        v.repro = (f"Repeat {rec.method} to this endpoint as {role} and as an "
                   f"admin; matching substantive data in both confirms the missing "
                   f"authorization check.")
        return v

    # ======================================================================
    # CORS / info leak / SSRF / generic
    # ======================================================================
    def _verify_cors(self, f: Finding) -> Verification:
        v = Verification()
        rec = f.evidence[0] if f.evidence else None
        if rec is None:
            v.verdict = "inconclusive"; v.confidence_score = 0.4; return v
        expl, reason = C.cors_assessment(rec)
        v.exploitability = expl
        v.reasons.append(reason)
        v.verdict = "true_positive" if expl != "unknown" else "inconclusive"
        v.confidence_score = 0.7 if expl != "unknown" else 0.4
        if expl == "not_exploitable":
            v.confidence_score = 0.75
            v.reasons.append("Header combination is real but browsers reject it, "
                             "so there is no cross-origin credentialed read as-is.")
        v.controls.append(ControlObservation("cors", present=True, strength="weak",
                                              detail=reason))
        v.repro = ("Issue a cross-origin credentialed fetch from a test origin "
                   "and observe whether the browser exposes the response; "
                   "wildcard+credentials will be blocked by the browser.")
        return v

    def _verify_info_leak(self, f: Finding) -> Verification:
        v = Verification()
        rec = f.evidence[0] if f.evidence else None
        if rec is None:
            v.verdict = "inconclusive"; v.confidence_score = 0.4; return v
        again = self._reissue(rec)
        v.probes = 1
        # Was it reachable anonymously? auth is the compensating control.
        anon_status = None
        if rec.identity == "anonymous":
            anon_status = again.status
        v.controls.append(C.auth_required(anon_status))
        body = again.resp_body or ""
        # Confirm the LEAK ITSELF reproduces — not merely that the status matches.
        # A reproduced 500 with a *different* body is not the same leak. Info-leak
        # findings legitimately live in error bodies (stack traces), so we do NOT
        # require DISPOSITION_CONTENT here; instead we require the concrete leaked
        # value(s) recorded in detail to still be present, falling back to body
        # similarity when the finding recorded no explicit indicator.
        _META = {"verification", "validation", "occurrences", "affected_endpoints",
                 "affected_count", "adjudication_reason", "test", "param",
                 "auth_required", "path_param_ignored", "always_returns"}
        indicators = [str(val) for k, val in (f.detail or {}).items()
                      if k not in _META and isinstance(val, (str, int, float))
                      and len(str(val)) >= 4]
        if indicators:
            present = [ind for ind in indicators if ind in body]
            reproduced = bool(present)
            note = (f"leaked value(s) still present: {', '.join(present[:3])}"
                    if present else "recorded sensitive values no longer present on re-test")
        else:
            from ..semantic_diff import structural_similarity
            sim = structural_similarity(rec.resp_body or "", body)
            reproduced = again.status == rec.status and len(body) > 0 and sim >= 0.6
            note = f"re-test body {sim:.0%} similar to captured evidence"
        if reproduced:
            v.verdict = "true_positive"
            v.confidence_score = 0.7
            v.exploitability = "exploitable" if rec.identity == "anonymous" else "conditional"
            v.corroborations.append("leak reproduces on re-test — " + note)
            v.reasons.append("The sensitive content reproduces on re-test.")
        else:
            v.verdict = "likely_false_positive"
            v.confidence_score = 0.35
            v.exploitability = "unknown"
            v.reasons.append("The sensitive content did not reproduce on re-test — " + note)
        v.repro = ("Re-request the URL and confirm the sensitive substring is "
                   "present; check whether it is reachable without credentials.")
        return v

    def _verify_ssrf(self, f: Finding) -> Verification:
        v = Verification()
        if f.confidence == "confirmed" or (f.detail or {}).get("interactions"):
            v.verdict = "true_positive"
            v.exploitability = "exploitable"
            v.confidence_score = 0.95
            v.corroborations.append("out-of-band callback observed (ground truth)")
            v.reasons.append("The server made an out-of-band request to the "
                             "collaborator — SSRF capability is confirmed. The "
                             "probe targeted only the collaborator.")
            v.repro = ("Re-supply a fresh collaborator canary and watch for the "
                       "inbound interaction. Do NOT point the parameter at cloud "
                       "metadata or internal ranges.")
        else:
            v.verdict = "inconclusive"
            v.exploitability = "unknown"
            v.confidence_score = 0.4
            v.reasons.append("URL-accepting parameter flagged, but no out-of-band "
                             "channel was configured to prove a server-side "
                             "request. Enable the Interactsh integration to "
                             "verify.")
            v.repro = ("Configure an out-of-band collaborator, submit its host in "
                       "the parameter, and check for an inbound DNS/HTTP hit.")
        return v

    def _verify_generic(self, f: Finding) -> Verification:
        v = Verification()
        rec = f.evidence[0] if f.evidence else None
        if rec is None:
            v.verdict = "inconclusive"; v.confidence_score = 0.4
            v.reasons.append("no evidence to re-test"); return v
        again = self._reissue(rec)
        v.probes = 1
        disp = E.classify_response(again)
        if again.status == rec.status:
            # A reproduced *error* (4xx/5xx/denied/empty) is not itself a finding —
            # only substantive or non-error behavior corroborates. This stops a
            # stable 400/500 from being reported as "behavior reproduces".
            if disp in (E.DISPOSITION_SERVER_ERROR, E.DISPOSITION_BAD_REQUEST,
                        E.DISPOSITION_DENIED, E.DISPOSITION_NOT_FOUND, E.DISPOSITION_EMPTY):
                v.verdict = "inconclusive"
                v.confidence_score = 0.4
                v.exploitability = "unknown"
                v.reasons.append(f"Behavior reproduces but the response is a '{disp}' "
                                 f"(error/denial/empty), which is not itself evidence "
                                 f"of a vulnerability.")
            else:
                v.verdict = "likely_true_positive"
                v.confidence_score = 0.55
                v.corroborations.append("primary evidence reproduces")
                v.reasons.append("The observed behavior reproduces on re-test.")
                v.exploitability = "conditional"
        else:
            v.verdict = "likely_false_positive"
            v.confidence_score = 0.35
            v.reasons.append(f"status drifted {rec.status}->{again.status} on "
                             f"re-test.")
            v.exploitability = "unknown"
        return v


def _login_like(body: str) -> bool:
    low = (body or "").lower()
    return ("login" in low and "password" in low) or "j_security_check" in low
