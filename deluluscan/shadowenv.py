"""Shadow-environment detection — the staging/sandbox that mirrors production
with weaker controls.

The recurring root cause behind a whole family of high-impact API breaches is not
a bug in production at all: it is a *non-production copy* of production — a
staging, sandbox, dev, qa or canary host — that serves the same data or the same
API but has quietly dropped a control. Signature validation off. Authentication
optional. GraphQL introspection left on. Security headers absent. The public
write-up that prompted this module (an AI-assisted sweep of Google's APIs) found
`*.sandbox.googleapis.com` staging endpoints pointed at production data with the
access checks removed — the same shape, again and again.

So this looks for it directly: derive the environment-variant hostnames of a
target, see which ones exist, and for the ones we are *authorized* to touch,
**diff their security posture against production** and report where the copy is
weaker than the original.

Two hard rules keep this inside the authorization boundary:

  1. A derived host is a DIFFERENT host from the target. We never send an HTTP
     request to one unless it is explicitly in scope (loopback/RFC1918, or named
     in `authorized_hosts` — e.g. from the Rules-of-Engagement). An out-of-scope
     candidate that merely resolves is reported as an INVENTORY lead ("this
     exists; authorize it to test"), never probed.
  2. Detection only. We observe status codes, headers and error bodies; we do not
     exploit the weaker control.

Injected `fetch` / `resolve` / scope make it fully offline-testable.
"""
from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass, field
from urllib.parse import urlparse

from .models import Finding, RequestRecord, Severity, VulnClass

# Environment names, most-conventional first. Kept deliberately short: every
# extra token multiplies the candidate host count, and these cover the vast
# majority of real deployments.
ENV_TOKENS = (
    "staging", "stage", "sandbox", "dev", "test", "qa", "uat",
    "canary", "preprod", "pre-prod", "beta", "internal", "demo", "int",
)

# Security headers whose ABSENCE in a copy that production sets is a real
# regression (the copy is weaker), keyed by the posture we record them under.
_SEC_HEADERS = ("content-security-policy", "strict-transport-security",
                "x-frame-options", "x-content-type-options")


def _host_port_scheme(base_url: str):
    u = urlparse(base_url if "://" in base_url else "https://" + base_url)
    return (u.hostname or "").lower(), u.port, (u.scheme or "https")


def _looks_like_env(label: str) -> bool:
    return any(label == t or label.startswith(t + "-") or label.endswith("-" + t)
              for t in ENV_TOKENS)


def derive_candidates(base_url: str) -> list[str]:
    """Environment-variant base URLs for a target, e.g. for https://api.example.com:
    staging.api.example.com, staging-api.example.com, staging.example.com, …

    Deduplicated, and never the target itself. IP-literal targets have no
    meaningful name variants, so they yield nothing.
    """
    host, port, scheme = _host_port_scheme(base_url)
    if not host:
        return []
    try:
        ipaddress.ip_address(host)
        return []                      # an IP literal has no env-variant names
    except ValueError:
        pass
    labels = host.split(".")
    apex = ".".join(labels[-2:]) if len(labels) >= 2 else host
    first = labels[0]
    seen: set[str] = set()
    out: list[str] = []
    portsuf = f":{port}" if port else ""
    for tok in ENV_TOKENS:
        variants = {
            f"{tok}.{host}",              # staging.api.example.com
            f"{tok}-{host}",              # staging-api.example.com (whole host)
            f"{tok}.{apex}",              # staging.example.com
        }
        # Rewrite the first label when it is not already an env token:
        if not _looks_like_env(first):
            rest = ".".join(labels[1:]) if len(labels) > 1 else ""
            if rest:
                variants.add(f"{first}-{tok}.{rest}")   # api-staging.example.com
                variants.add(f"{tok}-{first}.{rest}")   # staging-api.example.com
        for v in sorted(variants):
            if v == host or v in seen:
                continue
            seen.add(v)
            out.append(f"{scheme}://{v}{portsuf}")
    return out


@dataclass
class Posture:
    """What we could observe about one environment from a single root request."""
    reachable: bool = False
    status: int = 0
    auth_gated: bool = False           # a credential is demanded (401/403)
    sec_headers: set = field(default_factory=set)
    server: str = ""
    rec: RequestRecord = None          # evidence


def _default_fetch(url: str):
    import urllib.request
    req = urllib.request.Request(url, headers={"User-Agent": "deluluscan-shadowenv"})
    try:
        with urllib.request.urlopen(req, timeout=8) as r:
            return r.status, {k.lower(): v for k, v in dict(r.headers).items()}, \
                r.read(40_000).decode("utf-8", "replace")
    except Exception as e:  # HTTPError carries status; other errors -> unreachable
        code = getattr(e, "code", 0)
        hdrs = {}
        body = ""
        try:
            hdrs = {k.lower(): v for k, v in dict(e.headers or {}).items()}
            body = e.read(20_000).decode("utf-8", "replace") if getattr(e, "fp", None) else ""
        except Exception:
            pass
        return code, hdrs, body


def _default_resolve(host: str) -> bool:
    try:
        socket.getaddrinfo(host, None)
        return True
    except Exception:
        return False


def _is_private_host(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_loopback or ip.is_private
    except ValueError:
        return host in ("localhost",) or host.endswith(".localhost")


class ShadowEnvScan:
    """Detect weaker non-production copies of a target.

    fetch(url)   -> (status, headers, body)   — only ever called for in-scope hosts
    resolve(host)-> bool                       — does the name exist (cheap DNS)
    authorized_hosts: hosts the RoE authorizes active probing of (besides the
                      target itself and loopback/RFC1918).
    """

    def __init__(self, fetch=None, resolve=None, authorized_hosts=None,
                 in_scope=None, max_candidates: int = 60):
        self.fetch = fetch or _default_fetch
        self.resolve = resolve or _default_resolve
        self.authorized = {h.lower() for h in (authorized_hosts or ())}
        self._in_scope = in_scope
        self.max_candidates = max_candidates

    def in_scope(self, host: str) -> bool:
        if self._in_scope is not None:
            return bool(self._in_scope(host))
        return host in self.authorized or _is_private_host(host)

    def _posture(self, base_url: str) -> Posture:
        status, headers, body = self.fetch(base_url)
        headers = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
        p = Posture(reachable=status != 0, status=status,
                    auth_gated=status in (401, 403),
                    sec_headers={h for h in _SEC_HEADERS if h in headers},
                    server=headers.get("server", ""))
        u = urlparse(base_url)
        p.rec = RequestRecord(method="GET", url=base_url, identity="anon",
                              status=status, elapsed_ms=0.0,
                              resp_headers=headers, resp_body=(body or "")[:2000],
                              resp_len=len(body or ""))
        return p

    def scan(self, base_url: str) -> list[Finding]:
        target_host, _, _ = _host_port_scheme(base_url)
        prod = self._posture(base_url) if self.in_scope(target_host) else Posture(reachable=True)
        findings: list[Finding] = []

        for cand in derive_candidates(base_url)[: self.max_candidates]:
            host = urlparse(cand).hostname or ""
            if not self.resolve(host):
                continue                       # the name does not exist — skip
            if not self.in_scope(host):
                # Exists but out of scope: a lead, not a probe.
                findings.append(Finding(
                    vuln_class=VulnClass.INVENTORY, severity=Severity.INFO,
                    title=f"Shadow environment exists (unprobed): {host}",
                    endpoint=cand,
                    description=(f"A non-production variant of {target_host} resolves at "
                                 f"{host}. It was NOT probed — it is outside the authorized "
                                 "scope. Staging/sandbox copies routinely drop a control the "
                                 "production host enforces (auth, request signing, CSP, "
                                 "GraphQL introspection). Add it to scope to test it."),
                    evidence=[], confidence="tentative", verdict="inconclusive",
                    exploitability="unknown",
                    detail={"source": "shadowenv", "shadow_host": host,
                            "target_host": target_host, "probed": False}))
                continue

            shadow = self._posture(cand)
            if not shadow.reachable:
                continue
            findings.append(self._reachable_finding(target_host, host, cand, shadow))
            findings.extend(self._posture_diff(target_host, host, cand, prod, shadow))
        return findings

    def _reachable_finding(self, target_host, host, cand, shadow) -> Finding:
        return Finding(
            vuln_class=VulnClass.INVENTORY, severity=Severity.INFO,
            title=f"Shadow environment reachable: {host}",
            endpoint=cand,
            description=(f"A non-production variant of {target_host} answered at {host} "
                         f"(HTTP {shadow.status}). Treat it as its own attack surface — "
                         "it is a common place for weaker controls and pre-release code."),
            evidence=[shadow.rec], confidence="firm", verdict="true_positive",
            exploitability="n/a",
            detail={"source": "shadowenv", "shadow_host": host, "target_host": target_host,
                    "status": shadow.status, "server": shadow.server, "probed": True})

    def _posture_diff(self, target_host, host, cand, prod, shadow) -> list[Finding]:
        """Where the copy is weaker than the original."""
        out: list[Finding] = []
        base = {"source": "shadowenv", "shadow_host": host, "target_host": target_host}

        # 1) Authentication dropped: production demands a credential, the shadow does not.
        if prod.auth_gated and not shadow.auth_gated and 200 <= shadow.status < 300:
            out.append(Finding(
                vuln_class=VulnClass.AUTHZ, severity=Severity.HIGH,
                title=f"Shadow environment drops authentication: {host}",
                endpoint=cand,
                description=(f"{target_host} requires a credential at / (HTTP {prod.status}), "
                             f"but its {host} copy served HTTP {shadow.status} to the same "
                             "anonymous request. A staging host that mirrors production data "
                             "without production's auth is a direct access-control bypass — "
                             "the exact pattern behind several real cross-tenant breaches."),
                evidence=[shadow.rec], confidence="firm",
                verdict="likely_true_positive", exploitability="conditional",
                detail=dict(base, prod_status=prod.status, shadow_status=shadow.status,
                            remediation="Put the same authentication in front of every "
                                        "environment, or keep non-production off the public "
                                        "internet entirely.")))

        # 2) Security headers regressed: production sets them, the shadow doesn't.
        dropped = prod.sec_headers - shadow.sec_headers
        if dropped and shadow.reachable:
            out.append(Finding(
                vuln_class=VulnClass.MISCONFIG, severity=Severity.MEDIUM,
                title=f"Shadow environment weakens security headers: {host}",
                endpoint=cand,
                description=(f"{host} is missing security headers that {target_host} sets: "
                             f"{', '.join(sorted(dropped))}. A weaker non-production copy is "
                             "still reachable code and a softer target for XSS/clickjacking/"
                             "downgrade than the hardened original."),
                evidence=[shadow.rec], confidence="firm",
                verdict="likely_true_positive", exploitability="conditional",
                detail=dict(base, dropped_headers=sorted(dropped),
                            remediation="Apply the production security-header policy to "
                                        "every environment.")))
        return out


def scan(base_url: str, **kw) -> list[Finding]:
    """Convenience wrapper."""
    return ShadowEnvScan(**kw).scan(base_url)


def main(argv=None):
    import argparse
    import json as _json
    p = argparse.ArgumentParser(
        prog="deluluscan.shadowenv",
        description="Find staging/sandbox/dev copies of a target that are weaker than production.")
    p.add_argument("--url", required=True, help="the production target base URL")
    p.add_argument("--authorize", default="",
                   help="comma-separated shadow hostnames you ARE authorized to actively probe "
                        "(besides loopback/RFC1918). Without this, resolving shadow hosts are "
                        "reported as leads only, never probed.")
    p.add_argument("--list", action="store_true",
                   help="only print the candidate hostnames; make no network requests")
    p.add_argument("--json", action="store_true")
    a = p.parse_args(argv)

    if a.list:
        for c in derive_candidates(a.url):
            print(c)
        return 0

    authorized = [h.strip() for h in a.authorize.split(",") if h.strip()]
    findings = ShadowEnvScan(authorized_hosts=authorized).scan(a.url)
    if a.json:
        print(_json.dumps([{"severity": f.severity.value, "title": f.title,
                            "endpoint": f.endpoint, "detail": f.detail} for f in findings],
                          indent=2))
    else:
        print(f"[shadowenv] {a.url}: {len(findings)} finding(s)")
        for f in findings:
            print(f"  [{f.severity.value:8}] {f.title}")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
