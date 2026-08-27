"""Generalised deep verification — researcher-grade depth for EVERY finding class.

The stored-XSS chain was the lesson; the principle generalises to all classes: a
finding is a *lead* until it has been (a) re-tested multiple ways, (b) checked for
what it can actually reach, and (c) reasoned about honestly. This layer runs after
the differential `Verifier` and attaches a `detail["deep"]` analysis block to each
finding, refining `exploitability` only when it has concrete evidence — it never
flips a live verdict on a hunch, and it never weaponises (read-only probes only).

Pluggable strategies, keyed by vuln class / endpoint shape:

  * IdentityMatrix — re-probe the finding's endpoint as EVERY configured identity
    and report who actually gets in (generalises BFLA/IDOR depth beyond one probe).
  * SessionRiding — probe the endpoint anon / session-cookie / Bearer / Basic AND
    read the session cookie flags, then decide whether an XSS/CSRF in a victim's
    session could drive it. This is the exact analysis that flipped #651 from
    "contained" to RCE — now applied to every privileged endpoint, not just XSS.
  * InjectionBypass — for injection classes, compute filter-evading mutations
    (field-split etc.) verified against the known filter, so "reflected/blocked"
    becomes "here is a bypass" or "genuinely filtered".

Every live probe is an injected seam on DeepContext, so strategies are unit-tested
against fakes with no server.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass, field
from typing import Callable, Optional

from ..models import Finding
from .exploitability import (ANON, BASIC, BEARER, COOKIE, AuthMatrix, CredentialSurface,
                             analyze_set_cookie, assess_privileged_action_via_xss)
from ..active.filter_bypass import (TARGET_XSS_REGEX, is_attr_unquoted_safe,
                                    marker_img, mutations)

# endpoints whose reachability implies a privileged capability worth the deep pass
_PRIVILEGED_HINTS = ("/plugin", "/roles", "/toolgroups", "/users", "/apps",
                     "/maintenance", "/configuration", "/apitoken", "/cluster",
                     "/system-table", "/esindex", "/portlet")
_AUTHZ_CLASSES = {"authz", "idor", "bopla", "misconfig", "info_leak"}
_INJECTION_CLASSES = {"xss", "sqli", "ssti", "graphql"}
# don't waste live probes re-testing things already ruled false
_CREDIBLE = {"true_positive", "likely_true_positive", "inconclusive", "unverified", "conditional"}


def split_endpoint(ep: str) -> tuple[str, str]:
    parts = (ep or "").split(None, 1)
    if len(parts) == 2:
        return parts[0].upper(), parts[1]
    return "GET", (ep or "")


def is_privileged_endpoint(path: str) -> bool:
    p = (path or "").lower()
    return any(h in p for h in _PRIVILEGED_HINTS)


class DeepContext:
    """Injected live-probe seams. Real implementation wraps the HttpClient; tests
    subclass and override the four probe methods."""

    def __init__(self, client=None, auth=None, config=None, identities=None):
        self.client = client
        self.auth = auth
        self.config = config
        self.identities = identities or {}
        self._auth_vectors_cache: dict[str, dict[str, int]] = {}
        self._cookie_cache: dict[str, list] = {}

    # -- identities ---------------------------------------------------------
    def victim_label(self) -> Optional[str]:
        """Highest-privilege identity whose session an attack would ride."""
        for label in ("admin", "publisher", "content_editor", "backend", "api_user"):
            i = self.identities.get(label)
            if i and (getattr(i, "password", None) or getattr(i, "bearer_token", None)):
                return label
        return None

    def sub_tier_labels(self) -> list[str]:
        return [l for l in self.identities if l != "admin"]

    def _basic(self, label) -> dict:
        i = self.identities.get(label)
        if not (i and getattr(i, "username", None) and getattr(i, "password", None)):
            return {}
        tok = base64.b64encode(f"{i.username}:{i.password}".encode()).decode()
        return {"Authorization": f"Basic {tok}"}

    # -- probe seams (override in tests) ------------------------------------
    def probe_as(self, label: str, method: str, path: str) -> int:
        """Status of `method path` issued as identity `label` (Basic auth)."""
        if self.client is None:
            return 0
        rec = self.client.request(method, path, identity_label=f"deep:{label}",
                                  headers=self._basic(label))
        return rec.status if rec else 0

    def _login(self, label) -> tuple[list[str], Optional[str]]:
        """One fresh login per victim, cached: returns (Set-Cookie lines, rme JWT).

        Use the SESSION rme JWT — what a real browser carries — for auth probing,
        not a minted API token. the target rotates tokens on each new login, so we log
        in ONCE and reuse the result across the whole deep pass; a token minted and
        used later can already be superseded (that is exactly the stale-token trap
        that produced false 401s during the manual #651 analysis)."""
        if label in self._cookie_cache:
            return self._cookie_cache[label]
        raw, jwt = [], None
        i = self.identities.get(label)
        if self.client is not None and i and getattr(i, "username", None):
            try:
                import requests
                s = requests.Session()
                r = s.post(self.client.url_for("/api/v1/authentication"),
                           json={"userId": i.username, "password": i.password, "rememberMe": True},
                           timeout=self.client.timeout, verify=self.client.verify,
                           allow_redirects=False)
                raw = (r.raw.headers.getlist("Set-Cookie")
                       if hasattr(r.raw.headers, "getlist") else [])
                jwt = next((c.value for c in s.cookies if c.name.lower() == "rme"), None)
            except Exception:
                raw, jwt = [], None
        self._cookie_cache[label] = (raw, jwt)
        return raw, jwt

    def auth_vectors(self, method: str, path: str, victim_label: str) -> dict[str, int]:
        """Probe one endpoint EVERY auth way, as the victim's credentials would
        arrive: nothing / session-cookie / Bearer header / Basic header. The cookie
        and Bearer vectors use the SAME fresh session rme JWT the browser holds."""
        key = f"{method} {path}"
        if key in self._auth_vectors_cache:
            return self._auth_vectors_cache[key]
        out = {ANON: 0, COOKIE: 0, BEARER: 0, BASIC: 0}
        if self.client is not None:
            _raw, jwt = self._login(victim_label)
            def _s(headers):
                rec = self.client.request(method, path, identity_label="deep:authvec",
                                          headers=headers)
                return rec.status if rec else 0
            out[ANON] = _s({})
            out[COOKIE] = _s({"Cookie": f"rme={jwt}"}) if jwt else 0
            out[BEARER] = _s({"Authorization": f"Bearer {jwt}"}) if jwt else 0
            out[BASIC] = _s(self._basic(victim_label))
        self._auth_vectors_cache[key] = out
        return out

    def cookie_facts(self, victim_label: str):
        """Set-Cookie flag facts for the victim's session (HttpOnly/Secure/JWT)."""
        raw, _jwt = self._login(victim_label)
        return analyze_set_cookie(raw)


@dataclass
class DeepResult:
    analysis: dict
    reasons: list[str] = field(default_factory=list)
    exploitability: Optional[str] = None   # refine only when there is evidence


# ---------------------------------------------------------------------------
# strategies
# ---------------------------------------------------------------------------
class DeepStrategy:
    name = "base"
    def applies(self, f: Finding) -> bool: return False
    def analyze(self, f: Finding, ctx: DeepContext) -> Optional[DeepResult]: return None


class IdentityMatrixStrategy(DeepStrategy):
    """Who *actually* gets in? Re-probe the endpoint as every identity."""
    name = "identity_matrix"

    def applies(self, f: Finding) -> bool:
        m, p = split_endpoint(f.endpoint)
        return (f.vuln_class.value in _AUTHZ_CLASSES
                and (f.verdict in _CREDIBLE)
                and p.startswith("/") and m == "GET")   # safe re-read only

    def analyze(self, f: Finding, ctx: DeepContext) -> Optional[DeepResult]:
        method, path = split_endpoint(f.endpoint)
        statuses = {label: ctx.probe_as(label, method, path) for label in ctx.identities}
        reachable = [l for l, s in statuses.items() if 200 <= s < 300]
        sub_tier_in = [l for l in reachable if l != "admin"]
        reasons = []
        if sub_tier_in:
            reasons.append(f"{method} {path} is reachable by sub-admin identities "
                           f"{sub_tier_in} (statuses {statuses}) — broken access control "
                           f"confirmed across identities, not just one probe.")
        return DeepResult(analysis={"statuses": statuses, "reachable": reachable,
                                    "sub_tier_reachable": sub_tier_in}, reasons=reasons)


class SessionRidingStrategy(DeepStrategy):
    """Can an XSS/CSRF in a victim session drive this endpoint? Probe it every auth
    way + read cookie flags, then grade weaponizable vs contained. This is the
    analysis that corrected #651 — now applied to every privileged endpoint."""
    name = "session_riding"

    def applies(self, f: Finding) -> bool:
        m, p = split_endpoint(f.endpoint)
        if f.verdict not in _CREDIBLE:
            return False
        return is_privileged_endpoint(p) or f.vuln_class.value in _AUTHZ_CLASSES

    def analyze(self, f: Finding, ctx: DeepContext) -> Optional[DeepResult]:
        victim = ctx.victim_label()
        if not victim:
            return None
        method, path = split_endpoint(f.endpoint)
        if not path.startswith("/"):
            return None
        # Probe AUTH with a side-effect-free GET on the same path, not the finding's
        # mutating verb: the question is "does this session authenticate to this
        # endpoint", which a GET answers cleanly (a POST with no body just yields
        # 400 and tells us nothing about auth). Same endpoint => same auth filter.
        vectors = ctx.auth_vectors("GET", path, victim)
        auth = AuthMatrix(endpoint=f"GET {path} (auth-probe for {method})", statuses=vectors)
        creds = CredentialSurface(cookies=ctx.cookie_facts(victim), storage_tokens=[])
        assessment = assess_privileged_action_via_xss(auth, creds)
        exploit = None
        # refine ONLY with concrete evidence, and never weaken a hard verdict blindly:
        if assessment.verdict == "weaponizable" and f.exploitability in (
                "unknown", "conditional", "not_exploitable"):
            exploit = "exploitable"
        elif assessment.verdict == "contained" and f.exploitability == "exploitable":
            exploit = "conditional"   # present, but the app's creds block the drive-by
        return DeepResult(
            analysis={"auth_matrix": vectors, "verdict": assessment.verdict,
                      "reasons": assessment.reasons},
            reasons=assessment.reasons, exploitability=exploit)


class InjectionBypassStrategy(DeepStrategy):
    """Turn 'reflected/blocked' into a concrete filter bypass (or 'genuinely
    filtered'). Pure analysis — computes field-split/encoding mutations and checks
    them against the known filter regex."""
    name = "injection_bypass"

    def applies(self, f: Finding) -> bool:
        return f.vuln_class.value in _INJECTION_CLASSES and f.verdict in _CREDIBLE

    def analyze(self, f: Finding, ctx: DeepContext) -> Optional[DeepResult]:
        # a representative payload for the class; XSS is the one with the field-split
        # filter, but the mutation engine is general.
        markup = marker_img("/rk-probe")
        muts = mutations(markup, max_fields=2, filter_regex=TARGET_XSS_REGEX)
        verified = [m for m in muts if m.get("evades_filter")]
        reasons = []
        if verified:
            top = verified[0]
            reasons.append(
                f"a {top['technique']} bypass beats the input filter "
                f"(fields={top.get('fields')}); attr-safe={is_attr_unquoted_safe(markup)}. "
                f"Surface 'filtered' verdicts on injection sinks should be re-tested "
                f"with this before being trusted.")
        return DeepResult(analysis={"bypasses": muts[:4], "verified_bypass": bool(verified)},
                          reasons=reasons)


DEFAULT_STRATEGIES: list[DeepStrategy] = [
    IdentityMatrixStrategy(), SessionRidingStrategy(), InjectionBypassStrategy(),
]


class DeepVerifier:
    def __init__(self, ctx: DeepContext, strategies: Optional[list[DeepStrategy]] = None):
        self.ctx = ctx
        self.strategies = strategies if strategies is not None else DEFAULT_STRATEGIES

    def run(self, findings: list[Finding]) -> dict:
        stats = {"analysed": 0, "enriched": 0, "exploitability_refined": 0}
        for f in findings:
            deep = f.detail.get("deep") or {}
            touched = False
            for strat in self.strategies:
                try:
                    if not strat.applies(f):
                        continue
                    res = strat.analyze(f, self.ctx)
                except Exception as exc:
                    deep[strat.name] = {"error": str(exc)[:160]}
                    continue
                if res is None:
                    continue
                touched = True
                entry = dict(res.analysis)
                if res.reasons:
                    entry["reasons"] = res.reasons
                deep[strat.name] = entry
                if res.exploitability and res.exploitability != f.exploitability:
                    entry["exploitability_change"] = f"{f.exploitability} -> {res.exploitability}"
                    f.exploitability = res.exploitability
                    stats["exploitability_refined"] += 1
                # thread deep reasons into the verification block so the report shows them
                if res.reasons:
                    v = f.detail.setdefault("verification", {})
                    v.setdefault("reasons", [])
                    v["reasons"].extend(f"[deep:{strat.name}] {r}" for r in res.reasons)
            if touched:
                f.detail["deep"] = deep
                stats["analysed"] += 1
                stats["enriched"] += 1
        return stats
