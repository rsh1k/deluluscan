"""Exploit-chain analysis — "combine low bugs into high chains".

Top red-teamers and bug-bounty hunters rarely report a lone low finding; they
ask "what does this unlock when combined with that?" This analyzer inspects the
whole finding set and, using a deterministic ruleset (optionally augmented by the
AI), emits *chain* findings that escalate severity when two or more issues
compose into a materially worse attack (e.g. SSRF + reachable cloud metadata =
credential theft; unrestricted upload + served content = stored XSS/RCE; open
redirect + OAuth = token theft; a GUID-leaking IDOR + a GUID-consuming IDOR =
full object access).

Chains are only built from *credible* constituents (not dismissed/false
positives), and they reference the contributing findings so a human can follow
the logic. This reasons about impact; it does not execute the chained attack.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional

from ..models import Finding, Severity, VulnClass


def _test(f: Finding) -> str:
    return (f.detail or {}).get("test", "")


def _credible(f: Finding) -> bool:
    return (f.verdict or "unverified") not in ("false_positive", "likely_false_positive") \
        and (f.detail or {}).get("validation", {}).get("state") != "dismissed"


# titles that denote an UNCONFIRMED candidate (surface flagged for manual review),
# which must never anchor an exploit chain
_UNCONFIRMED_TITLE = ("manual", "review", "candidate", "possible ", "flagged",
                      "unconfirmed", "worth manual")


def _chain_eligible(f: Finding) -> bool:
    """A constituent may only contribute to a chain if it is actually confirmed —
    not a false positive, not an inconclusive/unverified candidate, and not a
    'manual review' surface. This prevents chaining on unproven premises (e.g.
    a URL-ish parameter that was never shown to make a server-side request)."""
    if not _credible(f):
        return False
    if (f.verdict or "unverified") in ("inconclusive", "unverified"):
        return False
    if any(m in (f.title or "").lower() for m in _UNCONFIRMED_TITLE):
        return False
    return True


def _text(f: Finding) -> str:
    return f"{f.title} {f.description}".lower()


@dataclass
class ChainRule:
    name: str
    severity: Severity
    description: str
    # predicates: each must be satisfied by at least one credible finding
    needs: list[Callable[[Finding], bool]]


def _has_kw(*words):
    return lambda f: any(w in _text(f) for w in words)


def _is_test(*tests):
    return lambda f: _test(f) in tests


def _is_class(*classes):
    return lambda f: f.vuln_class in classes


_RULES = [
    ChainRule(
        "Low-privilege → CMS Administrator → RCE (BFLA + OSGi deploy)",
        Severity.CRITICAL,
        "A broken-function-level-authorization primitive (self-assigning an admin "
        "layout or granting a role via the DWR endpoint) that reaches the OSGi "
        "plugin-upload surface lets the lowest-privileged backend user escalate to "
        "CMS Administrator and deploy a plugin that executes OS commands — full "
        "remote code execution and system compromise.",
        [lambda f: _test(f) == "bfla_privileged_op" or "bfla" in _text(f),
         lambda f: "plugin" in _text(f) or "plugin/bundle upload" in _text(f) or "code-execution" in _text(f)]),
    ChainRule(
        "Stored XSS (profile field-split) → admin session → RCE",
        Severity.CRITICAL,
        "A low-privilege user stores a field-split XSS in their own profile name; "
        "when an administrator views the user in the admin Users panel the "
        "payload runs in the admin session and can deploy an OSGi plugin — turning "
        "self-editable profile fields into remote code execution.",
        [lambda f: f.vuln_class is VulnClass.XSS and ("profile" in _text(f) or "field-split" in _text(f)
                                                       or "givenname" in _text(f) or "stored" in _text(f)),
         lambda f: "plugin" in _text(f) or "plugin/bundle upload" in _text(f) or "code-execution" in _text(f)]),
    ChainRule(
        "SSRF → cloud metadata / internal service access (credential theft)",
        Severity.CRITICAL,
        "A confirmed SSRF combined with reachable internal/metadata surfaces lets "
        "an attacker read cloud credentials (169.254.169.254) or pivot to internal "
        "services — escalating an SSRF into full cloud/account compromise.",
        [_is_class(VulnClass.SSRF), _has_kw("metadata", "internal", "169.254", "admin", "actuator")]),
    ChainRule(
        "Unrestricted file upload → stored XSS / RCE",
        Severity.CRITICAL,
        "An accepted dangerous upload (SVG/HTML/JSP) that the app later serves or "
        "renders turns into stored XSS, or code execution if the runtime executes "
        "it — a classic low-to-critical chain.",
        [_is_test("file_upload"), _has_kw("served", "reflected", "xss", "download", "asset", "dA")]),
    ChainRule(
        "Open redirect → OAuth/token theft & phishing",
        Severity.HIGH,
        "An open redirect on a host that also runs an OAuth/login/token flow lets "
        "an attacker steal auth codes/tokens or run convincing phishing.",
        [_is_test("open_redirect"), _has_kw("oauth", "login", "authentication", "token", "sso", "jwt")]),
    ChainRule(
        "IDOR GUID amplification → full cross-object access",
        Severity.HIGH,
        "One endpoint leaks object identifiers (GUIDs) and another grants access by "
        "identifier without ownership checks; chained, an attacker enumerates and "
        "reads every object, removing the 'GUIDs are unguessable' mitigation.",
        [_has_kw("excessive data", "leak", "enumerat", "identifier", "guid", "listing"),
         lambda f: f.vuln_class in (VulnClass.IDOR,) or _test(f) in ("authz_matrix_bypass", "bola_id_swap")]),
    ChainRule(
        "XSS → session cookie theft (account takeover)",
        Severity.HIGH,
        "Reflected/stored XSS combined with a session cookie that lacks HttpOnly "
        "lets script read the cookie and hijack the session.",
        [_is_class(VulnClass.XSS), _has_kw("httponly", "cookie missing", "cookie flag")]),
    ChainRule(
        "Leaked secret/token → account takeover",
        Severity.HIGH,
        "A leaked token/secret (an actual secret VALUE in a response body or URL) "
        "plus an auth endpoint that accepts it enables direct impersonation / "
        "account takeover.",
        # anchor on an ACTUAL secret-material finding (value-based detector or a
        # confirmed excessive-data exposure) — NOT a mere 'token' keyword in a
        # path, which produced a false chain off an empty /apitoken/tokens list.
        [_is_test("secret_in_response", "excessive_data", "js_secret"),
         _has_kw("authentication", "login", "users/current", "jwt", "session")]),
    ChainRule(
        "Mass assignment → privilege escalation",
        Severity.HIGH,
        "A write that accepts role/isAdmin/roleId combined with self-service user "
        "creation or profile update lets a normal user grant themselves admin.",
        [_is_test("mass_assignment"), _has_kw("user", "profile", "register", "role", "account")]),
    ChainRule(
        "No rate limiting on auth → credential stuffing / brute force",
        Severity.HIGH,
        "A sensitive auth flow with no rate limiting enables large-scale credential "
        "stuffing, OTP brute force, or password spraying.",
        [_is_test("no_rate_limit"), _has_kw("login", "authentication", "password", "otp", "reset", "token")]),
    ChainRule(
        "Verbose errors → easier injection exploitation",
        Severity.MEDIUM,
        "Verbose stack traces/DB errors combined with an injection candidate give "
        "an attacker the feedback needed to weaponize it quickly.",
        [_is_test("verbose_error", "server_error"),
         lambda f: f.vuln_class is VulnClass.SQLI or _test(f) in ("traversal", "ssti", "nosql")]),
]


class ChainAnalyzer:
    def __init__(self, analyst=None):
        self.analyst = analyst

    def analyze(self, findings: list[Finding]) -> list[Finding]:
        credible = [f for f in findings if _chain_eligible(f)]
        chains: list[Finding] = []
        for rule in _RULES:
            matched: list[Finding] = []
            used: set[int] = set()
            ok = True
            for pred in rule.needs:
                # prefer a finding not already consumed by an earlier predicate,
                # so overlapping keywords don't collapse two roles onto one finding
                hit = next((f for f in credible if pred(f) and id(f) not in used), None)
                if hit is None:
                    hit = next((f for f in credible if pred(f)), None)  # fallback
                if hit is None:
                    ok = False
                    break
                used.add(id(hit))
                matched.append(hit)
            if not ok:
                continue
            # need genuinely distinct findings for a multi-part chain
            if len({id(m) for m in matched}) < 2 and len(rule.needs) >= 2:
                continue
            contributors = sorted({m.title for m in matched})
            chains.append(Finding(
                vuln_class=VulnClass.MISCONFIG, severity=rule.severity,
                title=f"Attack chain: {rule.name}", endpoint="(multiple)",
                description=(rule.description + "\n\nComposed from: " +
                             "; ".join(contributors)),
                evidence=[e for m in matched for e in (m.evidence or [])[:1]],
                detail={"test": "exploit_chain", "chain": rule.name,
                        "contributors": contributors, "active": True},
                confidence="firm"))
        # optional AI-discovered chains
        if self.analyst and getattr(self.analyst, "enabled", False) and credible:
            try:
                extra = self._ai_chains(credible)
                chains.extend(extra)
            except Exception:
                pass
        # chains are reasoned from credible constituents: mark them so they flow
        # through validation and render with a verdict.
        for c in chains:
            c.verdict = c.verdict if c.verdict != "unverified" else "likely_true_positive"
            c.exploitability = "conditional"
            c.detail.setdefault("verification", {
                "verdict": c.verdict, "exploitability": "conditional",
                "confidence_score": 0.65, "probes": 0,
                "reasons": ["composed from credible constituent findings"],
                "repro": "Reproduce each constituent finding, then perform them in "
                         "sequence to realize the combined impact."})
        return chains

    def _ai_chains(self, findings: list[Finding]) -> list[Finding]:
        summary = [{"title": f.title, "class": f.vuln_class.value,
                    "test": _test(f), "endpoint": f.endpoint,
                    "severity": f.severity.value} for f in findings[:40]]
        import json
        note = self.analyst.analyze_evidence({
            "task": "chain_analysis",
            "instruction": ("Given these confirmed/credible findings on ONE authorized "
                            "target, identify any ADDITIONAL exploit chains where two or "
                            "more combine into a materially worse attack (e.g. RCE, ATO, "
                            "data breach) beyond the known deterministic chains. Reply "
                            'JSON: {"chains":[{"name":..,"severity":"high|critical",'
                            '"why":..,"uses":[titles]}]}'),
            "findings": summary})
        out: list[Finding] = []
        chains = (note or {}).get("chains", []) if isinstance(note, dict) else []
        for c in chains[:6]:
            sev = Severity.CRITICAL if str(c.get("severity")).lower() == "critical" else Severity.HIGH
            out.append(Finding(
                vuln_class=VulnClass.MISCONFIG, severity=sev,
                title=f"Attack chain (AI): {c.get('name','composed attack')}",
                endpoint="(multiple)",
                description=f"{c.get('why','')}\n\nUses: {', '.join(c.get('uses', []))}",
                evidence=[], detail={"test": "exploit_chain", "ai": True,
                                     "chain": c.get("name"), "contributors": c.get("uses", []),
                                     "active": True}, confidence="tentative"))
        return out
