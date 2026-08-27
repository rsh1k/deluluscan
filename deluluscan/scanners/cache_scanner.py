"""Web cache poisoning + web cache deception detection.

Two of the highest-value modern classes (PortSwigger/Kettle cache poisoning,
Gil/Mirheidari cache deception, 2024 URL-parser-confusion WCD). Detection is
observational and safe — we look for the *signals* (an unkeyed header reflected
into a cacheable response; a private endpoint served under a static-looking path
with cache indicators). We do NOT persistently poison a shared cache for other
users; confirming end-to-end impact is a manual step.
"""
from __future__ import annotations

from typing import Iterable, Optional

from .base import Scanner
from ..models import Endpoint, Finding, IdentityRole, Severity, VulnClass

_CANARY = "deluluscan-cache-canary.example"
_UNKEYED_HEADERS = ["X-Forwarded-Host", "X-Forwarded-Scheme", "X-Host",
                    "X-Forwarded-Server", "X-HTTP-Host-Override", "Forwarded"]
_CACHE_HDRS = ("x-cache", "cf-cache-status", "x-cache-hits", "age", "x-served-by",
               "x-drupal-cache", "x-varnish", "cdn-cache")


def _h(headers: dict, name: str):
    for k, v in (headers or {}).items():
        if k.lower() == name.lower():
            return v
    return None


def is_cacheable(rec) -> bool:
    cc = (_h(rec.resp_headers, "cache-control") or "").lower()
    if "no-store" in cc or "private" in cc:
        return False
    if "public" in cc or "max-age" in cc or "s-maxage" in cc:
        return True
    # presence of a CDN/cache status header suggests a caching layer is in play
    return any(_h(rec.resp_headers, h) is not None for h in _CACHE_HDRS)


def cache_hit(rec) -> bool:
    for h in _CACHE_HDRS:
        val = (_h(rec.resp_headers, h) or "").lower()
        if val and ("hit" in val or (h == "age" and val.strip().isdigit() and int(val) > 0)):
            return True
    return False


class CacheScanner(Scanner):
    name = "cache"
    vuln_classes = [VulnClass.MISCONFIG.value]

    def applies_to(self, e: Endpoint) -> bool:
        return e.method.upper() == "GET"

    def run(self, endpoint: Endpoint) -> Iterable[Finding]:
        anon = self.identities.get(IdentityRole.ANON.value) or \
            next(iter(self.identities.values()), None)
        if anon is None:
            return
        path = self.concrete_path(endpoint)
        base = self.client.request("GET", path, identity_label="anonymous",
                                   headers=self.auth.headers_for(anon))
        if base is None or base.status == 0:
            return

        # 1) web cache poisoning: unkeyed header reflected into a cacheable body
        if is_cacheable(base):
            for hdr in _UNKEYED_HEADERS:
                rec = self.client.request("GET", path, identity_label="anonymous",
                                          headers={**self.auth.headers_for(anon), hdr: _CANARY})
                if rec is None:
                    continue
                if _CANARY in (rec.resp_body or "") or _CANARY in str(rec.resp_headers):
                    yield Finding(
                        vuln_class=VulnClass.MISCONFIG, severity=Severity.HIGH,
                        title=f"Web cache poisoning: unkeyed '{hdr}' reflected",
                        endpoint=endpoint.key,
                        description=(f"The '{hdr}' request header is reflected into a "
                                     f"cacheable response but is not part of the cache key. "
                                     f"An attacker can poison the shared cache so other users "
                                     f"receive attacker-controlled content (redirects, script "
                                     f"src, etc.). Add the header to the cache key or stop "
                                     f"reflecting it. (Detected via a unique canary; not "
                                     f"persisted.)"),
                        evidence=[base, rec],
                        detail={"test": "cache_poisoning", "active": True, "header": hdr},
                        confidence="firm")
                    return

        # 2) web cache deception: private content served under a static-looking path
        authed = self.identities.get(IdentityRole.BACKEND.value) or \
            self.identities.get(IdentityRole.ADMIN.value)
        if authed and "/api/" in path:
            real = self.client.request("GET", path, identity_label=authed.label(),
                                       headers=self.auth.headers_for(authed))
            from ..verify import evidence as E
            if real and E.classify_response(real) == E.DISPOSITION_CONTENT:
                for suffix in ("/nonexistent.css", ";.css", "/x.js", "%2fx.css"):
                    trick = self.client.request("GET", path + suffix, identity_label=authed.label(),
                                                headers=self.auth.headers_for(authed))
                    if trick is None or trick.status >= 400:
                        continue
                    if (E.classify_response(trick) == E.DISPOSITION_CONTENT
                            and is_cacheable(trick) and not is_cacheable(real)):
                        yield Finding(
                            vuln_class=VulnClass.MISCONFIG, severity=Severity.HIGH,
                            title="Web cache deception: private content cacheable via static suffix",
                            endpoint=endpoint.key,
                            description=(f"Appending '{suffix}' makes a private API response "
                                         f"cacheable (the caching layer treats it as a static "
                                         f"asset by extension). An attacker who lures a victim "
                                         f"to the suffixed URL can then read the victim's cached "
                                         f"private response. Ensure caching keys on content-type/"
                                         f"auth, not just extension."),
                            evidence=[real, trick],
                            detail={"test": "cache_deception", "active": True, "suffix": suffix},
                            confidence="firm")
                        return
