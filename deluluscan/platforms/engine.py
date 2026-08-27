"""PlatformScan — identify the platform, then test what that platform exposes.

Two phases:
  1. identify(): probe each profile's fingerprint signals and score them. The
     best-scoring profile above threshold is the detected platform. This is how
     the tool learns the *system* it is looking at — its API base, auth model,
     and sensitive surface — instead of guessing.
  2. assess(): for the detected platform, run the high-signal, platform-specific
     checks that generic scanners miss: unauthenticated user enumeration
     (WordPress /wp-json/wp/v2/users, Drupal /jsonapi/user/user), version
     disclosure (CHANGELOG.txt, joomla.xml), and exposed control surfaces
     (xmlrpc.php, /administrator/). Detection only; each finding carries the
     exact request/response as evidence.

fetch is injected as fetch(url) -> (status, headers, body) so it runs offline in
tests and reuses the scanner's authorized HttpClient in production.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Callable, Optional

from ..models import Finding, RequestRecord, Severity, VulnClass
from .profiles import PROFILES, PlatformProfile, Signal

_META_GEN_RE = re.compile(
    r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', re.I)
_IDENTIFY_THRESHOLD = 3.0     # min cumulative weight to call a platform detected


@dataclass
class Detection:
    profile: PlatformProfile
    score: float
    matched: list = field(default_factory=list)   # human-readable signal hits

    @property
    def confidence(self) -> str:
        if self.score >= 6:
            return "confirmed"
        if self.score >= 4:
            return "firm"
        return "tentative"


class PlatformScan:
    def __init__(self, fetch: Optional[Callable] = None, timeout: int = 10):
        self.fetch = fetch or _default_fetch
        self.timeout = timeout
        self._cache: dict = {}

    # -- phase 1: identify -------------------------------------------------
    def _get(self, base_url: str, path: str):
        url = base_url.rstrip("/") + (path if path.startswith("/") else "/" + path)
        if url not in self._cache:
            try:
                self._cache[url] = self.fetch(url)
            except Exception as exc:          # fail-soft: unreachable signal
                self._cache[url] = (0, {}, f"__error__:{exc}")
        return self._cache[url]

    def _signal_hit(self, base_url: str, sig: Signal):
        # For path/api-json signals, `key` is the path to probe; for
        # header/body/meta-generator signals it names what to match, so probe root.
        probe_path = sig.key if sig.kind in ("path", "api-json") else "/"
        status, headers, body = self._get(base_url, probe_path or "/")
        headers = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
        body = body or ""
        if sig.kind == "path":
            ok = status in sig.statuses if sig.statuses else (200 <= status < 400)
            if ok and sig.pattern:
                ok = bool(re.search(sig.pattern, body))
            return (sig.weight, f"{sig.key} -> {status}") if ok else None
        if sig.kind == "header":
            val = headers.get(sig.key.lower(), "")
            if val and re.search(sig.pattern, val):
                return (sig.weight, f"header {sig.key}: {val[:60]}")
            return None
        if sig.kind == "meta-generator":
            m = _META_GEN_RE.search(body)
            if m and re.search(sig.pattern, m.group(1)):
                return (sig.weight, f"generator: {m.group(1)[:60]}")
            return None
        if sig.kind == "body":
            if re.search(sig.pattern, body):
                return (sig.weight, f"body ~ {sig.pattern}")
            return None
        if sig.kind == "api-json":
            if status == 200 and re.search(sig.pattern, body):
                return (sig.weight, f"{sig.key} JSON matched")
            return None
        return None

    def identify(self, base_url: str) -> Optional[Detection]:
        """Return the best-scoring platform above threshold, or None."""
        best: Optional[Detection] = None
        for profile in PROFILES:
            score, matched = 0.0, []
            for sig in profile.signals:
                hit = self._signal_hit(base_url, sig)
                if hit:
                    score += hit[0]
                    matched.append(hit[1])
            if score >= _IDENTIFY_THRESHOLD and (best is None or score > best.score):
                best = Detection(profile, score, matched)
        return best

    # -- phase 2: assess ---------------------------------------------------
    def _rec(self, base_url: str, path: str) -> RequestRecord:
        url = base_url.rstrip("/") + (path if path.startswith("/") else "/" + path)
        status, headers, body = self._get(base_url, path)
        return RequestRecord(method="GET", url=url, identity="anon", status=status,
                             elapsed_ms=0.0,
                             resp_headers={str(k).lower(): str(v) for k, v in (headers or {}).items()},
                             resp_body=(body or "")[:2000], resp_len=len(body or ""))

    def assess(self, base_url: str, detection: Detection) -> list:
        p = detection.profile
        findings: list = []

        # -- unauthenticated user enumeration --------------------------------
        if p.users_endpoint:
            rec = self._rec(base_url, p.users_endpoint)
            body = rec.resp_body or ""
            if rec.status == 200 and re.search(r'"(id|name|slug|username|display_name)"', body):
                names = re.findall(r'"(?:name|slug|username|display_name)"\s*:\s*"([^"]+)"', body)
                findings.append(Finding(
                    vuln_class=VulnClass.INFO_LEAK, severity=Severity.MEDIUM,
                    title=f"{p.name}: unauthenticated user enumeration",
                    endpoint=p.users_endpoint,
                    description=(f"The {p.name} API exposes user records to an anonymous "
                                 f"request at {p.users_endpoint}. This leaks valid usernames/"
                                 "slugs for credential-stuffing and targeted phishing."),
                    evidence=[rec], confidence="firm",
                    detail={"platform": p.name, "users_sample": names[:10],
                            "auth_methods": list(p.auth_methods),
                            "remediation": p.remediation}))

        # -- version disclosure ---------------------------------------------
        if p.version_path and p.version_regex:
            rec = self._rec(base_url, p.version_path)
            if rec.status == 200:
                m = re.search(p.version_regex, rec.resp_body or "")
                if m:
                    findings.append(Finding(
                        vuln_class=VulnClass.INFO_LEAK, severity=Severity.LOW,
                        title=f"{p.name}: version disclosure",
                        endpoint=p.version_path,
                        description=(f"{p.name} version {m.group(1)} is disclosed at "
                                     f"{p.version_path}, letting an attacker match the exact "
                                     "build to public CVEs."),
                        evidence=[rec], confidence="confirmed",
                        detail={"platform": p.name, "version": m.group(1),
                                "remediation": p.remediation}))
                    findings.extend(self._cve_findings(p, m.group(1), rec))

        # -- exposed control / RPC / admin surfaces (data-driven) -----------
        _sev = {"info": Severity.INFO, "low": Severity.LOW, "medium": Severity.MEDIUM,
                "high": Severity.HIGH, "critical": Severity.CRITICAL}
        for path, sev_name, note in p.exposed_checks:
            rec = self._rec(base_url, path)
            if rec.status in (200, 201, 301, 302):
                sev = _sev.get(sev_name, Severity.MEDIUM)
                findings.append(Finding(
                    vuln_class=VulnClass.MISCONFIG, severity=sev,
                    title=f"{p.name}: exposed surface {path}",
                    endpoint=path, description=f"{note} (reachable, HTTP {rec.status}).",
                    evidence=[rec], confidence="firm",
                    verdict="likely_true_positive", exploitability="conditional",
                    detail={"platform": p.name, "status": rec.status,
                            "remediation": p.remediation}))
            elif rec.status in (401, 403):
                findings.append(Finding(
                    vuln_class=VulnClass.MISCONFIG, severity=Severity.INFO,
                    title=f"{p.name}: control surface present {path}",
                    endpoint=path,
                    description=f"{note} Present but access-controlled (HTTP {rec.status}) — "
                                "still an attack surface (brute-force / auth-bypass target).",
                    evidence=[rec], confidence="tentative",
                    detail={"platform": p.name, "status": rec.status,
                            "remediation": p.remediation}))
        return findings

    def _cve_findings(self, p, version: str, ver_rec: RequestRecord) -> list:
        """Version-gated known-CVE findings (Nessus-plugin model). A version match
        is a LEAD, not proof: graded firm/likely_true_positive but exploitability
        stays 'unknown' — the report asserts the running version is in the affected
        range, never that the CVE is live-exploitable, until a probe confirms it."""
        from .cves import match_cves
        _sev = {"info": Severity.INFO, "low": Severity.LOW, "medium": Severity.MEDIUM,
                "high": Severity.HIGH, "critical": Severity.CRITICAL}
        out = []
        for r in match_cves(p.name, version):
            out.append(Finding(
                vuln_class=VulnClass.SUPPLY_CHAIN, severity=_sev.get(r.severity, Severity.HIGH),
                title=f"{p.name} {version} is in the affected range for {r.cve}",
                endpoint=p.version_path,
                description=(f"{r.summary} The fingerprinted version {version} falls in the "
                             f"affected range ({r.affected}). VERSION-INFERRED — confirm with a "
                             "live probe before asserting exploitability."),
                evidence=[ver_rec], confidence="firm",
                verdict="likely_true_positive", exploitability="unknown",
                detail={"platform": p.name, "version": version, "cve": r.cve,
                        "cwe": r.cwe, "affected": r.affected, "fixed_in": r.fixed_in,
                        "basis": "version_inference", "source": "platforms.cves",
                        "remediation": f"Upgrade to {r.fixed_in or 'a fixed release'}."}))
        return out

    def run(self, base_url: str):
        """Convenience: identify + assess. Returns (Detection|None, list[Finding])."""
        det = self.identify(base_url)
        if det is None:
            return None, []
        return det, self.assess(base_url, det)


def _default_fetch(url: str, method: str = "GET", timeout: int = 10):
    import urllib.request
    req = urllib.request.Request(url, method=method, headers={"User-Agent": "deluluscan-platform"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, dict(r.headers), r.read(200_000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers or {}), (e.read(50_000).decode("utf-8", "replace") if e.fp else "")
    except Exception:
        return 0, {}, ""
