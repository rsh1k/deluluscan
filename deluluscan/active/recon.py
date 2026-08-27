"""Recon / discovery analyzers (v0.6) — Burp Param Miner + content-discovery
parity, plus API9 (improper inventory) and A03/A08:2025 (supply chain / integrity)
exposure checks.

All probes are benign GETs against the authorized target (the HttpClient safety
gate + rate limiter apply), and every wordlist is small and bounded — this is
recon, not a crawler flood.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, Optional

# ---- bounded wordlists ------------------------------------------------------
# Common hidden/undocumented parameters (Param Miner style, trimmed & bounded).
_PARAM_WORDS = [
    "debug", "test", "admin", "id", "user", "userId", "role", "roleId", "token",
    "access_token", "api_key", "apiKey", "format", "callback", "redirect",
    "redirect_uri", "url", "next", "return", "returnUrl", "file", "path", "page",
    "limit", "offset", "sort", "order", "fields", "include", "expand", "filter",
    "q", "search", "lang", "locale", "preview", "draft", "internal", "raw",
]
# Common shadow/undocumented API paths (bounded).
_CONTENT_WORDS = [
    "/api", "/api/v1", "/api/v2", "/api/v3", "/api/internal", "/api/admin",
    "/api/debug", "/api/test", "/api/private", "/api/beta", "/api/legacy",
    "/api/openapi.json", "/api/swagger.json", "/swagger-ui.html", "/openapi.json",
    "/actuator", "/actuator/health", "/actuator/env", "/metrics", "/health",
    "/graphql", "/api/graphql", "/.well-known/security.txt", "/robots.txt",
    "/api/system/info", "/admin/maintenance", "/console", "/status",
]
# Sensitive artifacts that should never be web-exposed (supply chain / integrity).
_SUPPLY_PATHS = [
    "/.git/config", "/.git/HEAD", "/.env", "/.env.local", "/package.json",
    "/package-lock.json", "/yarn.lock", "/composer.json", "/composer.lock",
    "/pom.xml", "/build.gradle", "/requirements.txt", "/Gemfile.lock",
    "/sbom.json", "/bom.json", "/.dockerenv", "/Dockerfile", "/docker-compose.yml",
    "/.npmrc", "/.aws/credentials", "/config.json", "/appsettings.json",
    "/WEB-INF/web.xml", "/.svn/entries", "/backup.zip", "/dump.sql",
]
# Version-bearing path patterns for API9 enumeration.
_VERSION_RE = re.compile(r"/v(\d+)(/|$)")


def _looks_present(rec) -> bool:
    return rec is not None and getattr(rec, "status", 0) not in (0, 404, 400) \
        and getattr(rec, "resp_len", 0) > 0


import math as _math
import os as _os


def _bucket(n: int) -> int:
    return int(_math.log(max(n, 1)) * 8) if n > 0 else 0


def _norm_len(rec) -> int:
    """Body length with the reflected request path/query stripped, so a catch-all
    that echoes the URL still buckets consistently."""
    body = getattr(rec, "resp_body", "") or ""
    url = getattr(rec, "url", "") or ""
    from urllib.parse import urlparse, unquote
    pu = urlparse(url)
    for frag in (pu.path, unquote(pu.path), pu.query, unquote(pu.query)):
        if frag:
            body = body.replace(frag, "")
    return len(body)


class Calibrator:
    """Learns a server's not-found / catch-all behaviour so soft-404 sites (which
    return a 'present' status for every path, and may echo any query string) cannot
    manufacture phantom findings. Real scanners call this 'auto-calibration'."""

    def __init__(self):
        self.notfound_sigs: set = set()     # {(status, length_bucket)} for junk paths
        self.catch_all = False
        self.reflects_junk = False          # server reflects an arbitrary param value
        self.junk_status = None
        self.junk_len = None

    def learn_paths(self, send_path, exts=("", ".php", ".json", ".zip", ".env", ".xml")):
        present = {200, 201, 202, 204, 301, 302, 307, 308, 401, 403, 405}
        for ext in exts:
            rand = "zz" + _os.urandom(8).hex() + "notreal" + ext
            rec = send_path("/" + rand)
            if rec is None:
                continue
            st = getattr(rec, "status", 0)
            if st in present:
                self.catch_all = True
                self.notfound_sigs.add((st, _bucket(_norm_len(rec))))
                self.junk_status = st
                self.junk_len = _norm_len(rec)

    def learn_reflection(self, send_with_param):
        marker = "zzcal" + _os.urandom(4).hex()
        rec = send_with_param("zzjunk" + _os.urandom(3).hex(), marker)
        if rec is not None:
            body = getattr(rec, "resp_body", "") or ""
            if marker in body:
                self.reflects_junk = True
            self.junk_status = getattr(rec, "status", self.junk_status)
            self.junk_len = getattr(rec, "resp_len", self.junk_len)

    def is_notfound(self, rec) -> bool:
        if rec is None:
            return True
        return (getattr(rec, "status", 0), _bucket(_norm_len(rec))) in self.notfound_sigs


# ===========================================================================
# Param Miner — discover hidden/undocumented parameters
# ===========================================================================
@dataclass
class DiscoveredParam:
    name: str
    signal: str        # "reflected" | "status_change" | "size_change"
    detail: str


class ParamMiner:
    """Send a bounded wordlist of parameter names; flag any that change the
    response (reflected value, status change, or notable size delta)."""

    def __init__(self, words: Optional[list[str]] = None):
        self.words = (words or _PARAM_WORDS)[:64]

    def mine(self, send_with_param: Callable, baseline) -> list[DiscoveredParam]:
        found: list[DiscoveredParam] = []
        base_status = getattr(baseline, "status", 0)
        base_len = getattr(baseline, "resp_len", 0)
        # calibrate: if an arbitrary junk parameter is also reflected / changes the
        # response the same way, the signal is worthless on this endpoint.
        cal = Calibrator()
        cal.learn_reflection(send_with_param)
        for w in self.words:
            marker = f"dfz{abs(hash(w)) % 99999}"
            rec = send_with_param(w, marker)
            if rec is None:
                continue
            body = rec.resp_body or ""
            if marker in body and not cal.reflects_junk:
                found.append(DiscoveredParam(w, "reflected",
                             f"parameter '{w}' is reflected in the response"))
            elif rec.status != base_status and rec.status != cal.junk_status:
                found.append(DiscoveredParam(w, "status_change",
                             f"parameter '{w}' changed status {base_status}->{rec.status}"))
            elif (base_len and abs(rec.resp_len - base_len) > max(64, int(0.25 * base_len))
                  and rec.resp_len != cal.junk_len):
                found.append(DiscoveredParam(w, "size_change",
                             f"parameter '{w}' changed response size "
                             f"{base_len}->{rec.resp_len}"))
        return found


# ===========================================================================
# Content discovery — find shadow / undocumented endpoints
# ===========================================================================
@dataclass
class DiscoveredPath:
    path: str
    status: int
    detail: str


class ContentDiscovery:
    def __init__(self, words: Optional[list[str]] = None):
        self.words = (words or _CONTENT_WORDS)[:64]

    def discover(self, send_path: Callable) -> list[DiscoveredPath]:
        out: list[DiscoveredPath] = []
        cal = Calibrator()
        cal.learn_paths(send_path)
        for p in self.words:
            rec = send_path(p)
            if _looks_present(rec) and not cal.is_notfound(rec):
                out.append(DiscoveredPath(p, rec.status,
                           f"undocumented path '{p}' responded {rec.status}"))
        return out


# ===========================================================================
# API version enumeration — API9 improper inventory (shadow/deprecated versions)
# ===========================================================================
@dataclass
class VersionFinding:
    live_versions: list[int]
    detail: str


class VersionEnumerator:
    """Given a versioned path (…/vN/…), probe neighbouring versions and flag when
    multiple are live (older versions are often unpatched/deprecated)."""

    def enumerate(self, path: str, send_path: Callable, max_version: int = 4) -> Optional[VersionFinding]:
        m = _VERSION_RE.search(path)
        if not m:
            return None
        cal = Calibrator()
        cal.learn_paths(send_path)
        live = []
        for v in range(1, max_version + 1):
            candidate = _VERSION_RE.sub(f"/v{v}\\2", path, count=1)
            rec = send_path(candidate)
            if _looks_present(rec) and not cal.is_notfound(rec):
                live.append(v)
        if len(live) > 1:
            return VersionFinding(live,
                f"multiple API versions are live ({', '.join('v'+str(v) for v in live)}); "
                f"older versions are frequently unpatched — retire deprecated versions")
        return None


# ===========================================================================
# Supply-chain / integrity exposure — A03 / A08:2025
# ===========================================================================
@dataclass
class ExposureFinding:
    path: str
    kind: str          # "vcs" | "secrets" | "manifest" | "config" | "backup" | "actuator"
    detail: str
    status: int


_KIND_BY_HINT = [
    (("/.git", "/.svn"), "vcs", "version-control metadata is web-exposed"),
    (("/.env", "credentials", ".npmrc", "appsettings", "config.json"), "secrets",
     "a secrets/config file is web-exposed"),
    (("package.json", "composer", "pom.xml", "requirements", "gradle", "Gemfile",
      "yarn.lock", "sbom", "bom.json"), "manifest",
     "a dependency manifest is exposed (fingerprints your supply chain)"),
    (("backup", "dump.sql", ".zip"), "backup", "a backup/dump artifact is exposed"),
    (("actuator", "metrics"), "actuator", "a management/actuator endpoint is exposed"),
    (("Dockerfile", "docker-compose", ".dockerenv", "web.xml"), "config",
     "a build/deploy config file is exposed"),
]


class SupplyChainProbe:
    def __init__(self, paths: Optional[list[str]] = None):
        self.paths = (paths or _SUPPLY_PATHS)[:48]

    @staticmethod
    def _classify(path: str) -> tuple[str, str]:
        for hints, kind, detail in _KIND_BY_HINT:
            if any(h in path for h in hints):
                return kind, detail
        return "config", "a sensitive file is web-exposed"

    def scan(self, send_path: Callable) -> list[ExposureFinding]:
        out: list[ExposureFinding] = []
        cal = Calibrator()
        cal.learn_paths(send_path)
        for p in self.paths:
            rec = send_path(p)
            if not _looks_present(rec) or cal.is_notfound(rec):
                continue
            body = (rec.resp_body or "")[:200].lower()
            # avoid flagging SPA/soft-404 catch-all 200s that return HTML for a file
            if "<!doctype html" in body and p.endswith((".json", ".xml", ".lock", ".sql",
                                                         ".env", ".zip", ".gradle", ".txt")):
                continue
            kind, detail = self._classify(p)
            out.append(ExposureFinding(p, kind, detail, rec.status))
        return out
