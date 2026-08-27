"""Memory-disclosure / diagnostics-surface detector (Phase 2).

A JVM app that exposes a heap dump, thread dump, or a diagnostics console
(Spring Boot actuator, Jolokia/JMX, Tomcat manager) hands an attacker the
contents of process memory — tokens, passwords, session state — or a live view
of internals. This scanner probes a fixed, bounded set of well-known surfaces
for reachability by an ANONYMOUS caller.

False-positive discipline: a bare 200 is NOT proof. the target/dotusage-style SPAs
answer 200 with index.html for unknown paths, so every probe must match a
CONTENT marker specific to the artifact (hprof magic / octet-stream for a heap
dump, actuator's `_links`, a thread-state dump, `propertySources` for env, …) and
must NOT be text/html. A 401/403 means the surface exists but is gated — recorded
at low severity, not as an open leak.

Runs once per scan (not per endpoint); it targets fixed paths, not the discovered
surface.
"""
from __future__ import annotations

from typing import Iterable

from ..models import Endpoint, Finding, RequestRecord, Severity, VulnClass
from .base import Scanner


class MemoryDisclosureScanner(Scanner):
    name = "memory_disclosure"
    vuln_classes = [VulnClass.MEMORY_DISCLOSURE.value]

    # (path, family, severity_if_open). Bounded and generic; the target runs on
    # Tomcat/Spring so actuator + manager + jolokia are the realistic surfaces.
    _PROBES = [
        ("/actuator/heapdump", "heapdump", Severity.HIGH),
        ("/heapdump", "heapdump", Severity.HIGH),
        ("/actuator/threaddump", "threaddump", Severity.HIGH),
        ("/threaddump", "threaddump", Severity.HIGH),
        ("/actuator/env", "env", Severity.HIGH),
        ("/actuator", "actuator", Severity.MEDIUM),
        ("/actuator/metrics", "metrics", Severity.MEDIUM),
        ("/actuator/mappings", "actuator", Severity.MEDIUM),
        ("/jolokia/list", "jolokia", Severity.HIGH),
        ("/jolokia", "jolokia", Severity.MEDIUM),
        ("/manager/status", "tomcat_manager", Severity.MEDIUM),
    ]

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self._done = False

    def applies_to(self, endpoint: Endpoint) -> bool:
        return not self._done

    @staticmethod
    def _confirms(family: str, ct: str, body: str, headers: dict) -> bool:
        """True only if the response body/headers actually carry the artifact —
        never on a generic 200 (SPA index) or an error page."""
        low = (body or "").lower()
        cd = " ".join(f"{k}:{v}" for k, v in (headers or {}).items()).lower()
        if "text/html" in ct and family not in ("tomcat_manager",):
            return False
        if family == "heapdump":
            return ("octet-stream" in ct or ".hprof" in cd
                    or body.startswith("JAVA PROFILE") or "\x89hprof" in low[:16]
                    or "hprof" in cd)
        if family == "threaddump":
            return ('"threads"' in low or "java.lang.thread.state" in low
                    or '"threadname"' in low)
        if family == "env":
            return '"propertysources"' in low or '"activeprofiles"' in low
        if family == "metrics":
            return ('"names"' in low or "jvm_memory_used_bytes" in low
                    or '"measurements"' in low)
        if family == "actuator":
            return '"_links"' in low and "actuator" in low
        if family == "jolokia":
            return ('"agent"' in low or ('"request"' in low and '"value"' in low)
                    or '"mbean"' in low)
        if family == "tomcat_manager":
            return "tomcat" in low and ("status" in low or "server status" in low)
        return False

    def run(self, endpoint: Endpoint) -> Iterable[Finding]:
        self._done = True
        anon = self.identities.get("anonymous")
        headers = dict(self.auth.headers_for(anon)) if anon else {}
        for path, family, sev in self._PROBES:
            try:
                rec = self.client.status_probe("GET", path, identity_label="anonymous",
                                               headers=headers, read_timeout=5.0,
                                               max_bytes=4096)
            except Exception:
                continue
            if rec is None or rec.status == 0:
                continue
            ct = (rec.resp_headers or {}).get("Content-Type", "") or \
                 (rec.resp_headers or {}).get("content-type", "")
            if rec.status in (401, 403):
                # Present but gated — worth noting, not an open leak.
                yield Finding(
                    vuln_class=VulnClass.MEMORY_DISCLOSURE, severity=Severity.LOW,
                    title=f"Diagnostics surface present but access-gated: {path}",
                    endpoint=f"GET {path}",
                    description=(f"{path} exists ({rec.status}) — a {family} diagnostics "
                                 f"surface that is currently authenticated. Confirm the gate "
                                 f"holds for every identity and consider removing it in prod."),
                    evidence=[rec], detail={"test": "memory_disclosure", "family": family,
                                            "state": "gated"},
                    verdict="likely_true_positive", exploitability="mitigated",
                    confidence="firm")
                continue
            if 200 <= rec.status < 300 and self._confirms(family, ct, rec.resp_body or "",
                                                          rec.resp_headers or {}):
                yield Finding(
                    vuln_class=VulnClass.MEMORY_DISCLOSURE, severity=sev,
                    title=f"Exposed {family.replace('_', ' ')} reachable anonymously: {path}",
                    endpoint=f"GET {path}",
                    description=(f"{path} is reachable by an ANONYMOUS caller and returns a "
                                 f"{family} artifact (content-type '{ct or 'n/a'}'). A heap/thread "
                                 f"dump or diagnostics console leaks in-memory secrets and "
                                 f"internals. Disable it or put it behind authentication in "
                                 f"production."),
                    evidence=[rec], detail={"test": "memory_disclosure", "family": family,
                                            "content_type": ct, "state": "open"},
                    verdict="true_positive", exploitability="exploitable",
                    confidence="firm")
