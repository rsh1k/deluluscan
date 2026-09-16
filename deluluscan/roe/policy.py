"""Rules-of-Engagement policy — machine-enforceable engagement constraints.

A pentest RoE says what is in scope, what is explicitly OUT, when testing is
allowed, which test types are prohibited, and the rate ceiling. This turns that
document into an object the tool enforces: it strengthens Deluluscan's
authorization boundary (in-scope + allow_remote authorizes a non-loopback target;
out-of-scope always wins) and lets a scan honour prohibited-test and window
constraints. Governance, not weaponization — the boundary is a feature.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime, time as _time
from typing import Optional
from urllib.parse import urlparse


def _host_of(target: str) -> str:
    t = target.strip()
    if "://" in t:
        return (urlparse(t).hostname or "").lower()
    # bare host[:port] or CIDR
    return t.split("/")[0].split(":")[0].lower()


def _as_network(entry: str):
    try:
        return ipaddress.ip_network(entry, strict=False)
    except ValueError:
        return None


def _as_ip(s: str):
    try:
        return ipaddress.ip_address(s)
    except ValueError:
        return None


def _domain_match(host: str, pattern: str) -> bool:
    p = pattern.lower().lstrip("*.").strip(".")
    h = host.lower().strip(".")
    return bool(h) and (h == p or h.endswith("." + p))


@dataclass
class RoEPolicy:
    in_scope: list = field(default_factory=list)       # hosts / domains / CIDRs
    out_of_scope: list = field(default_factory=list)   # exclusions (take precedence)
    excluded_tests: set = field(default_factory=set)   # scanner/test names not permitted
    window_start: Optional[str] = None                 # "HH:MM" (24h, local)
    window_end: Optional[str] = None
    max_requests: Optional[int] = None
    rate_limit_rps: Optional[float] = None
    allow_destructive: bool = False
    allow_remote: bool = False                          # authorize non-loopback in-scope targets
    notes: str = ""

    # ---- scope ----
    def _matches(self, target: str, entry: str) -> bool:
        entry = entry.strip()
        if not entry:
            return False
        host = _host_of(target)
        net = _as_network(entry)
        if net is not None:
            ip = _as_ip(host)
            if ip is not None:
                try:
                    return ip in net
                except TypeError:
                    return False
            return False
        # domain / host / wildcard
        return _domain_match(host, entry)

    def target_in_scope(self, target: str) -> tuple:
        """Return (allowed: bool, reason: str). out_of_scope always wins."""
        host = _host_of(target)
        if not host:
            return False, "no host in target"
        for ex in self.out_of_scope:
            if self._matches(target, ex):
                return False, f"explicitly out of scope ({ex})"
        if not self.in_scope:
            return False, "no in-scope entries defined"
        for inc in self.in_scope:
            if self._matches(target, inc):
                return True, f"in scope ({inc})"
        return False, "not listed in scope"

    # ---- test-type constraints ----
    def scanner_allowed(self, name: str) -> bool:
        n = (name or "").lower()
        return not any(n == e or e in n for e in self.excluded_tests)

    # ---- time window ----
    def within_window(self, now: Optional[datetime] = None) -> bool:
        if not self.window_start or not self.window_end:
            return True
        now = now or datetime.now()
        try:
            sh, sm = map(int, self.window_start.split(":"))
            eh, em = map(int, self.window_end.split(":"))
        except Exception:
            return True
        start, end, cur = _time(sh, sm), _time(eh, em), now.time()
        if start <= end:
            return start <= cur <= end
        return cur >= start or cur <= end        # window crosses midnight

    def to_dict(self) -> dict:
        return {"in_scope": self.in_scope, "out_of_scope": self.out_of_scope,
                "excluded_tests": sorted(self.excluded_tests),
                "window": [self.window_start, self.window_end] if self.window_start else None,
                "max_requests": self.max_requests, "rate_limit_rps": self.rate_limit_rps,
                "allow_destructive": self.allow_destructive, "allow_remote": self.allow_remote,
                "notes": self.notes}
