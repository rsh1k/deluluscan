"""ReconEngine — build a picture of a web target before/while scanning it.

Three passes, producing one ReconProfile that the scanner (and a human) can act on:

  1. web fingerprint  — what the site is built with (server, framework, JS libs +
     versions) and which of those libraries are KNOWN-vulnerable.
  2. subdomains       — passive enumeration via Certificate Transparency (crt.sh),
     optionally resolved to see which are live.
  3. content discovery — high-signal files/dirs (.git, .env, actuator, swagger,
     admin, …) and a small directory wordlist.

Passive fingerprinting reads only what a normal client receives. Active passes
(content discovery, DNS resolution) send requests to the target, so the CLI gates
them behind the same loopback/RFC1918 authorization boundary as the rest of the
tool; CT-log lookups use public data. Detection only — no exploitation.

Everything is dependency-injected (`fetch`, `resolve`, `crt_fetch`) so it runs
fully offline in tests.
"""
from __future__ import annotations

import json
import re
import socket
from dataclasses import dataclass, field
from typing import Callable, Optional

from ..models import Finding, RequestRecord, Severity, VulnClass
from . import signatures as S

_SEV = {"low": Severity.LOW, "medium": Severity.MEDIUM, "high": Severity.HIGH,
        "critical": Severity.CRITICAL}
_SRC_RE = re.compile(r'<(?:script|link|img)[^>]+(?:src|href)\s*=\s*["\']([^"\']+)["\']', re.I)
_META_GEN_RE = re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', re.I)


@dataclass
class Tech:
    name: str
    category: str
    version: Optional[str] = None
    evidence: str = ""
    vulnerabilities: list = field(default_factory=list)  # list of {id, note, severity}


@dataclass
class ReconProfile:
    base_url: str
    techs: list = field(default_factory=list)          # list[Tech]
    subdomains: list = field(default_factory=list)     # list[{name, live}]
    paths: list = field(default_factory=list)          # list[{path, status, size}]
    exposures: list = field(default_factory=list)      # list[{path, status, note}]
    platform: Optional[dict] = None                    # detected platform intelligence
    platform_findings: list = field(default_factory=list)  # list[Finding]
    edges: list = field(default_factory=list)          # detected WAF/CDN/proxy (passive)
    js_endpoints: list = field(default_factory=list)   # list[{path, method, kind}] from JS
    takeover_findings: list = field(default_factory=list)  # subdomain-takeover Findings
    dns: Optional[dict] = None                          # DNS/email intelligence
    dns_findings: list = field(default_factory=list)    # SPF/DMARC/AXFR/email Findings

    def to_dict(self) -> dict:
        return {
            "base_url": self.base_url,
            "techs": [{"name": t.name, "category": t.category, "version": t.version,
                       "evidence": t.evidence, "vulnerabilities": t.vulnerabilities} for t in self.techs],
            "subdomains": self.subdomains,
            "paths": self.paths,
            "exposures": self.exposures,
            "platform": self.platform,
            "edges": self.edges,
            "js_endpoints": self.js_endpoints,
            "dns": self.dns,
        }

    def to_findings(self) -> list[Finding]:
        out: list[Finding] = []
        # 1) vulnerable client libraries -> supply chain
        for t in self.techs:
            for v in t.vulnerabilities:
                out.append(Finding(
                    vuln_class=VulnClass.SUPPLY_CHAIN,
                    severity=_SEV.get(v.get("severity", "medium"), Severity.MEDIUM),
                    title=f"Vulnerable component: {t.name} {t.version or ''}".strip(),
                    endpoint=self.base_url,
                    description=v.get("note", ""),
                    detail={"library": t.name, "version": t.version, "identifier": v.get("id"),
                            "source": "recon.web_fingerprint"},
                    confidence="firm", verdict="likely_true_positive", exploitability="conditional"))
        # 2) exposed sensitive files/surfaces
        for e in self.exposures:
            note = e.get("note", "")
            sensitive = any(k in e["path"] for k in (".git", ".env", ".aws", "backup", ".svn"))
            cls = VulnClass.INFO_LEAK if sensitive else VulnClass.MISCONFIG
            out.append(Finding(
                vuln_class=cls,
                severity=Severity.HIGH if sensitive else Severity.MEDIUM,
                title=f"Exposed: {e['path']}",
                endpoint=self.base_url.rstrip('/') + e["path"],
                description=note + f" (HTTP {e['status']})",
                detail={"path": e["path"], "status": e["status"], "note": note,
                        "source": "recon.content_discovery"},
                confidence="firm",
                verdict="true_positive" if sensitive else "likely_true_positive",
                exploitability="conditional"))
        # 3) platform-intelligence findings (user enum, version, exposed surfaces)
        out.extend(self.platform_findings)
        # 4a) subdomain takeover leads + DNS/email intelligence
        out.extend(self.takeover_findings)
        out.extend(self.dns_findings)
        # 4) shadow API surface recovered from client JS (OWASP API9 inventory)
        if self.js_endpoints:
            sample = ", ".join(sorted({e["path"] for e in self.js_endpoints})[:12])
            out.append(Finding(
                vuln_class=VulnClass.INVENTORY,
                severity=Severity.LOW,
                title=f"{len(self.js_endpoints)} API endpoint(s) discovered in client JavaScript",
                endpoint=self.base_url,
                description=("Static analysis of the site's JavaScript revealed API endpoints "
                             "the client calls. These often aren't in the OpenAPI spec — shadow/"
                             "undocumented surface (OWASP API9). Enumerate and test each for "
                             f"auth and object-level access. Sample: {sample}."),
                detail={"endpoints": self.js_endpoints, "count": len(self.js_endpoints),
                        "source": "recon.jsanalysis"},
                confidence="firm", verdict="true_positive", exploitability="conditional"))
        return out


# ---------------------------------------------------------------------------
def _default_fetch(url: str, method: str = "GET", timeout: int = 10):
    import requests
    try:
        r = requests.request(method, url, timeout=timeout, allow_redirects=False,
                             headers={"user-agent": "deluluscan-recon"})
        return r.status_code, {k.lower(): v for k, v in r.headers.items()}, r.text[:200000]
    except Exception:
        return 0, {}, ""


def _default_resolve(host: str) -> bool:
    try:
        socket.gethostbyname(host)
        return True
    except Exception:
        return False


def _default_crt_fetch(domain: str) -> list:
    import requests
    try:
        r = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=20,
                         headers={"user-agent": "deluluscan-recon"})
        rows = r.json()
        names = set()
        for row in rows:
            for n in str(row.get("name_value", "")).splitlines():
                n = n.strip().lstrip("*.").lower()
                if n.endswith(domain):
                    names.add(n)
        return sorted(names)
    except Exception:
        return []


class ReconEngine:
    def __init__(self, fetch: Optional[Callable] = None, resolve: Optional[Callable] = None,
                 crt_fetch: Optional[Callable] = None, max_paths: int = 60):
        self.fetch = fetch or _default_fetch
        self.resolve = resolve or _default_resolve
        self.crt_fetch = crt_fetch or _default_crt_fetch
        self.max_paths = max_paths

    # -- 1) web fingerprint -------------------------------------------------
    def web_fingerprint(self, base_url: str) -> list:
        status, headers, body = self.fetch(base_url)
        srcs = _SRC_RE.findall(body or "")
        meta_gen = _META_GEN_RE.search(body or "")
        meta_gen = meta_gen.group(1) if meta_gen else ""
        haystacks = {
            "body": body or "",
            "script-src": "\n".join(srcs),
            "meta-generator": meta_gen,
            "header-any": " ".join(f"{k}: {v}" for k, v in headers.items()),
            "cookie": headers.get("set-cookie", ""),
        }
        techs: list[Tech] = []
        for sig in S.TECH_SIGS:
            hit_ev = None
            for where, pat in sig.detectors:
                text = (headers.get(where.split(":", 1)[1], "") if where.startswith("header:")
                        else haystacks.get(where, ""))
                m = re.search(pat, text, re.I)
                if m:
                    hit_ev = f"{where}: {m.group(0)[:80]}"
                    break
            if not hit_ev:
                continue
            version = None
            if sig.version_re:
                vm = re.search(sig.version_re, (body or "") + "\n" + "\n".join(srcs) + "\n" +
                               " ".join(headers.values()), re.I)
                if vm:
                    version = vm.group(1)
            vulns = [{"id": r.identifier, "note": r.note, "severity": r.severity}
                     for r in S.lib_is_vulnerable(sig.name, version)]
            techs.append(Tech(sig.name, sig.category, version, hit_ev, vulns))
        return techs

    # -- 2) subdomains ------------------------------------------------------
    def enumerate_subdomains(self, domain: str, resolve: bool = True) -> list:
        names = self.crt_fetch(domain)
        out = []
        for n in names:
            live = self.resolve(n) if resolve else None
            out.append({"name": n, "live": live})
        return out

    # -- 3) content discovery ----------------------------------------------
    def content_discovery(self, base_url: str) -> tuple:
        base = base_url.rstrip("/")
        paths, exposures = [], []
        seen = 0
        interesting = {p: note for p, note in S.INTERESTING_PATHS}
        candidates = [p for p, _ in S.INTERESTING_PATHS] + ["/" + d for d in S.DIR_WORDLIST]
        candidates = list(dict.fromkeys(candidates))   # de-dup, preserve order
        for path in candidates:
            if seen >= self.max_paths:
                break
            seen += 1
            status, headers, body = self.fetch(base + path)
            if status in (200, 204, 301, 302, 307, 401, 403):
                entry = {"path": path, "status": status,
                         "size": len(body or "")}
                paths.append(entry)
                # a genuinely exposed sensitive file (200 with real content), or a
                # known-interesting surface reachable at all
                if path in interesting:
                    sensitive = any(k in path for k in (".git", ".env", ".aws", "backup", ".svn", ".DS_Store"))
                    if (sensitive and status == 200) or (not sensitive and status in (200, 401, 403)):
                        exposures.append({"path": path, "status": status, "note": interesting[path]})
        return paths, exposures

    # -- run everything -----------------------------------------------------
    def run(self, base_url: str, *, domain: Optional[str] = None,
            do_subdomains: bool = True, do_content: bool = True,
            resolve_subs: bool = True, do_platform: bool = True,
            do_edge: bool = True, do_js: bool = True, max_scripts: int = 8,
            do_dns: bool = True, dns_resolve=None, dns_axfr=None) -> ReconProfile:
        profile = ReconProfile(base_url=base_url)
        profile.techs = self.web_fingerprint(base_url)
        if do_content:
            profile.paths, profile.exposures = self.content_discovery(base_url)
        if do_subdomains and domain:
            profile.subdomains = self.enumerate_subdomains(domain, resolve=resolve_subs)
            self._check_takeovers(profile)
        if do_platform:
            self._detect_platform(profile)
        if do_edge:
            self._detect_edge(profile)
        if do_js:
            self._discover_js_endpoints(profile, max_scripts=max_scripts)
        if do_dns and domain:
            self._gather_dns(profile, domain, dns_resolve, dns_axfr)
        return profile

    def _gather_dns(self, profile: ReconProfile, domain: str, resolve=None, axfr=None) -> None:
        """Fold DNS/email intelligence (SPF/DMARC/AXFR/emails) into recon. Fail-soft."""
        try:
            from .dnsintel import DnsIntel
            body = ""
            try:
                _, _, body = self.fetch(profile.base_url)
            except Exception:
                body = ""
            di = DnsIntel(resolve=resolve, axfr=axfr)
            prof, finds = di.run(domain, page_body=body or "")
            profile.dns = prof.to_dict()
            profile.dns_findings = finds
        except Exception:
            pass

    def _check_takeovers(self, profile: ReconProfile) -> None:
        """Check enumerated subdomains for dangling-DNS takeover fingerprints.
        Reuses the recon fetch. Fail-soft."""
        try:
            from .takeover import check_subdomains
            def _fetch(url):
                return self.fetch(url)
            profile.takeover_findings = check_subdomains(_fetch, profile.subdomains)
        except Exception:
            pass

    def _discover_js_endpoints(self, profile: ReconProfile, *, max_scripts: int = 8) -> None:
        """Statically extract API endpoints from the home page's inline JS and its
        linked bundles (AJAX-spider payoff without a browser). Fail-soft."""
        try:
            from .jsanalysis import extract_endpoints
            from urllib.parse import urljoin
            status, headers, body = self.fetch(profile.base_url)
            body = body or ""
            found: dict = {}
            for e in extract_endpoints(body, source="inline"):
                found[(e.method, e.path)] = e
            # follow same-origin <script src> bundles (bounded)
            srcs = [s for s in _SRC_RE.findall(body) if s.endswith(".js") or ".js?" in s]
            for src in srcs[:max_scripts]:
                url = urljoin(profile.base_url, src)
                try:
                    st, _, js = self.fetch(url)
                except Exception:
                    continue
                for e in extract_endpoints(js or "", source=src):
                    found.setdefault((e.method, e.path), e)
            profile.js_endpoints = [
                {"path": e.path, "method": e.method, "kind": e.kind, "evidence": e.evidence}
                for e in found.values()]
        except Exception:
            pass

    def _detect_edge(self, profile: ReconProfile) -> None:
        """Fold PASSIVE WAF/CDN/proxy detection (header-only, no attack probe) into
        the recon profile. The active block-probe + port scan stay in the netscan
        CLI. Fail-soft."""
        try:
            from ..netscan.waf import WafScan
            edges = WafScan(fetch=self.fetch).detect(profile.base_url, active=False)
            profile.edges = [{"name": e.name, "kind": e.kind, "confidence": e.confidence,
                              "signals": e.signals} for e in edges]
        except Exception:
            pass

    def _detect_platform(self, profile: ReconProfile) -> None:
        """Fold platform intelligence into the recon profile. Fail-soft: any
        error leaves the recon result unchanged (black-box, as before)."""
        try:
            from ..platforms import PlatformScan
            scan = PlatformScan(fetch=self.fetch)
            det, findings = scan.run(profile.base_url)
            if det is not None:
                p = det.profile
                profile.platform = {
                    "name": p.name, "category": p.category,
                    "score": det.score, "confidence": det.confidence,
                    "matched": det.matched, "api_base": p.api_base,
                    "api_style": p.api_style, "auth_methods": list(p.auth_methods),
                    "users_endpoint": p.users_endpoint,
                    "sensitive_paths": list(p.sensitive_paths),
                    "relevant_classes": list(p.relevant_classes)}
                profile.platform_findings = findings
        except Exception:
            pass
