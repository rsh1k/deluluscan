"""Technology fingerprinting — the recon step that makes the scanner general.

A signature-based profiler (in the spirit of Wappalyzer/WhatWeb): it inspects
HTTP response headers, cookies, HTML body markers, script/asset paths and a few
well-known default files, matches them against a signature database, extracts
versions where possible, and returns the detected stack — server, language,
framework, CMS, API style, WAF/CDN — each with a confidence and the evidence that
justified it.

Crucially, the result drives *which* checks run: each technology maps to the vuln
classes and scanner "profiles" most relevant to it, so the tool audits a WordPress
site, a Django API, or a target instance with the checks that matter for each,
instead of being wired to one product.

This module is passive: it reasons over responses the caller already fetched (root
page, a few probes). It does not exploit anything.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable, Optional


# --------------------------------------------------------------------------- #
# Signature model
# --------------------------------------------------------------------------- #
@dataclass
class Signature:
    tech: str                      # canonical name, e.g. "WordPress"
    category: str                  # server|language|framework|cms|api|waf|analytics
    # any-of matchers; each is (where, regex). where in:
    #   header:<name>  cookie:<name>  body  script  path  meta-generator  header-any
    patterns: list[tuple[str, str]] = field(default_factory=list)
    # optional version extractor (where, regex-with-group1)
    version: Optional[tuple[str, str]] = None
    # vuln classes / scanner profiles most relevant when this tech is present
    relevant: tuple[str, ...] = ()
    # default files whose presence (200) strongly implies the tech
    default_files: tuple[str, ...] = ()


# The signature DB. Intentionally compact but real; extend freely. Ordering does
# not matter — all are evaluated and results merged.
_SIGNATURES: list[Signature] = [
    # ---- web servers -----------------------------------------------------
    Signature("nginx", "server", [("header:server", r"(?i)nginx")],
              version=("header:server", r"(?i)nginx/([\d.]+)"),
              relevant=("misconfig", "ssrf")),
    Signature("Apache httpd", "server", [("header:server", r"(?i)apache")],
              version=("header:server", r"(?i)apache/([\d.]+)"),
              relevant=("misconfig",)),
    Signature("Microsoft IIS", "server", [("header:server", r"(?i)microsoft-iis")],
              version=("header:server", r"(?i)iis/([\d.]+)"),
              relevant=("misconfig",)),
    Signature("Apache Tomcat", "server",
              [("header:server", r"(?i)tomcat|coyote"),
               ("body", r"(?i)apache tomcat"), ("path", r"/manager/html")],
              version=("body", r"(?i)tomcat/([\d.]+)"),
              relevant=("misconfig", "fileupload"),
              default_files=("/manager/html", "/host-manager/html")),
    Signature("Jetty", "server", [("header:server", r"(?i)jetty")],
              version=("header:server", r"(?i)jetty\(([\d.]+)")),
    # ---- languages / runtimes -------------------------------------------
    Signature("Java", "language",
              [("cookie:JSESSIONID", r".+"), ("header:x-powered-by", r"(?i)servlet|jsp")],
              relevant=("sqli", "injection", "supply_chain")),
    # ---- API styles ------------------------------------------------------
    Signature("GraphQL", "api",
              [("path", r"/graphql"), ("body", r"(?i)\"data\":\s*\{.*__typename|graphiql")],
              relevant=("graphql",)),
    Signature("OpenAPI / Swagger", "api",
              [("path", r"/openapi\.json|/swagger|/api-docs"),
               ("body", r"(?i)\"openapi\"\s*:|\"swagger\"\s*:")],
              relevant=("idor", "authz", "bopla", "injection")),
    Signature("REST API (JSON)", "api",
              [("header:content-type", r"(?i)application/json")],
              relevant=("idor", "authz", "bopla")),
    # ---- WAF / CDN -------------------------------------------------------
    Signature("Cloudflare", "waf",
              [("header:server", r"(?i)cloudflare"), ("header:cf-ray", r".+"),
               ("cookie:__cf_bm", r".+")], relevant=()),
    Signature("Akamai", "waf", [("header-any", r"(?i)akamai|x-akamai")], relevant=()),
    Signature("AWS (ALB/CloudFront)", "waf",
              [("header:server", r"(?i)awselb|cloudfront"), ("header:x-amz-cf-id", r".+")],
              relevant=()),
    Signature("ModSecurity", "waf", [("header-any", r"(?i)mod_security|modsecurity")], relevant=()),
]


@dataclass
class Detection:
    tech: str
    category: str
    version: Optional[str]
    confidence: float          # 0-1
    evidence: list[str]        # human-readable matched signals
    relevant: tuple[str, ...]


@dataclass
class Fingerprint:
    detections: list[Detection] = field(default_factory=list)

    def techs(self) -> list[str]:
        return [d.tech for d in self.detections]

    def by_category(self, cat: str) -> list[Detection]:
        return [d for d in self.detections if d.category == cat]

    def relevant_scanners(self) -> set[str]:
        out: set[str] = set()
        for d in self.detections:
            out.update(d.relevant)
        return out

    def to_dict(self) -> dict:
        return {"detections": [
            {"tech": d.tech, "category": d.category, "version": d.version,
             "confidence": round(d.confidence, 2), "evidence": d.evidence[:4],
             "relevant": list(d.relevant)} for d in self.detections]}


def _headers_lower(headers: dict) -> dict:
    return {(k or "").lower(): (v or "") for k, v in (headers or {}).items()}


def _cookie_names(headers: dict) -> dict:
    """Return {cookie_name: value} from any Set-Cookie headers."""
    out = {}
    for k, v in (headers or {}).items():
        if (k or "").lower() == "set-cookie":
            for part in (v if isinstance(v, list) else [v]):
                m = re.match(r"\s*([^=;]+)=([^;]*)", part or "")
                if m:
                    out[m.group(1).strip()] = m.group(2).strip()
    return out


def _meta_generator(body: str) -> str:
    m = re.search(r'(?i)<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', body or "")
    return m.group(1) if m else ""


def _match(sig: Signature, ctx: dict) -> tuple[bool, list[str]]:
    """Evaluate a signature's any-of patterns against the context. Returns
    (matched, evidence)."""
    hl = ctx["headers"]; cookies = ctx["cookies"]; body = ctx["body"]
    paths = ctx["paths"]; gen = ctx["generator"]
    ev = []
    for where, pat in sig.patterns:
        rx = re.compile(pat)
        if where.startswith("header:"):
            name = where.split(":", 1)[1].lower()
            val = hl.get(name, "")
            if val and rx.search(val):
                ev.append(f"header {name}: {val[:60]}")
        elif where == "header-any":
            for k, v in hl.items():
                if rx.search(f"{k}: {v}"):
                    ev.append(f"header {k}: {v[:50]}"); break
        elif where.startswith("cookie:"):
            name = where.split(":", 1)[1]
            for cn, cv in cookies.items():
                if cn.lower() == name.lower() and rx.search(cv or " " or ""):
                    ev.append(f"cookie {cn}"); break
                if cn.lower() == name.lower():
                    ev.append(f"cookie {cn}"); break
        elif where == "body":
            if body and rx.search(body):
                ev.append("body marker")
        elif where == "script":
            if body and rx.search(body):
                ev.append("script path")
        elif where == "meta-generator":
            if gen and rx.search(gen):
                ev.append(f"meta generator: {gen[:50]}")
        elif where == "path":
            for p in paths:
                if rx.search(p):
                    ev.append(f"path {p}"); break
    return (len(ev) > 0, ev)


def _extract_version(sig: Signature, ctx: dict) -> Optional[str]:
    if not sig.version:
        return None
    where, pat = sig.version
    rx = re.compile(pat)
    hl = ctx["headers"]
    if where.startswith("header:"):
        m = rx.search(hl.get(where.split(":", 1)[1].lower(), ""))
        return m.group(1) if m else None
    if where == "meta-generator":
        m = rx.search(ctx["generator"])
        return m.group(1) if m else None
    if where == "body":
        m = rx.search(ctx["body"] or "")
        return m.group(1) if m else None
    return None


def fingerprint(records: Iterable, extra_paths: Optional[list[str]] = None) -> Fingerprint:
    """Fingerprint from one or more RequestRecords (root page + any probes).

    `records` are objects with .resp_headers, .resp_body, .url. `extra_paths` are
    additional known paths (e.g. from discovery) that strengthen path-based
    signatures.
    """
    headers: dict = {}
    cookies: dict = {}
    body_parts: list[str] = []
    paths: list[str] = list(extra_paths or [])
    for rec in records:
        if rec is None:
            continue
        for k, v in (getattr(rec, "resp_headers", {}) or {}).items():
            headers.setdefault(k, v)
        cookies.update(_cookie_names(getattr(rec, "resp_headers", {}) or {}))
        b = getattr(rec, "resp_body", "") or ""
        if b:
            body_parts.append(b[:20000])
        u = getattr(rec, "url", "") or ""
        if u:
            paths.append(u)
    body = "\n".join(body_parts)
    ctx = {"headers": _headers_lower(headers), "cookies": cookies, "body": body,
           "paths": paths, "generator": _meta_generator(body)}

    fp = Fingerprint()
    for sig in _SIGNATURES:
        matched, ev = _match(sig, ctx)
        if not matched:
            continue
        strong = [e for e in ev if e.startswith(("header", "cookie", "meta"))]
        pathish = [e for e in ev if e.startswith("path")]
        # High-stakes categories (which drive technology profiles) must NOT be
        # asserted from a lone body/script substring — that's what produced
        # WordPress/the target/PHP false positives on unrelated sites. Require a strong
        # signal, or a path plus at least one more independent signal.
        if sig.category in ("cms", "framework", "language"):
            if not strong and not (pathish and len(ev) >= 2):
                continue
        conf = min(0.55 + 0.2 * (len(ev) - 1), 0.98)
        if strong:
            conf = min(conf + 0.15, 0.98)
        elif not pathish:
            conf = min(conf, 0.5)          # body-only evidence stays low-confidence
        fp.detections.append(Detection(
            tech=sig.tech, category=sig.category,
            version=_extract_version(sig, ctx), confidence=round(conf, 2),
            evidence=ev, relevant=sig.relevant))
    # sort: higher confidence first, servers/cms before generic api
    order = {"cms": 0, "framework": 1, "language": 2, "server": 3, "api": 4, "waf": 5}
    fp.detections.sort(key=lambda d: (order.get(d.category, 9), -d.confidence))
    return fp


def default_file_probes() -> list[tuple[str, str]]:
    """(-tech, path) pairs the caller can GET to strengthen detection. Returns a
    de-duplicated list across all signatures."""
    seen = set(); out = []
    for sig in _SIGNATURES:
        for df in sig.default_files:
            if df not in seen:
                seen.add(df); out.append((sig.tech, df))
    return out
