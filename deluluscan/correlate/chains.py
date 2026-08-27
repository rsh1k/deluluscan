"""Attack-chain correlation rules — combine individual findings into higher-impact
chains, and hand the agentic engine a concrete objective to PROVE.

A chain is a *hypothesis derived from the findings this scan actually produced*
(never invented): each rule fires only when every one of its member predicates
matches a real finding. The output is a suggestion + a suggested objective for
`deluluscan.agentic.ExploitChainAgent` — it is not asserted as proven until the
agent demonstrates it.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable

from ..models import Finding, Severity, VulnClass

_SEV_RANK = {Severity.INFO: 0, Severity.LOW: 1, Severity.MEDIUM: 2,
             Severity.HIGH: 3, Severity.CRITICAL: 4}


# -- predicate helpers -------------------------------------------------------
def cls(*vcs):
    want = set(vcs)
    return lambda f: f.vuln_class in want


def kw(*words):
    rx = re.compile("|".join(re.escape(w) for w in words), re.I)
    return lambda f: bool(rx.search(f.title + " " + f.description + " " + str(f.detail)))


def all_of(*preds):
    return lambda f: all(p(f) for p in preds)


@dataclass
class ChainRule:
    id: str
    name: str
    members: list                    # list[predicate]; each must match >=1 finding
    severity: Severity
    objective: str                   # objective for the agentic engine
    rationale: str
    remediation: str = ""


CHAIN_RULES = [
    ChainRule(
        "ssrf-to-cloud-creds", "SSRF → cloud credential theft",
        [cls(VulnClass.SSRF), all_of(kw("metadata", "IMDS", "credential", "169.254"))],
        Severity.CRITICAL,
        "Chain the SSRF into the instance metadata service to read cloud role credentials.",
        "An SSRF plus reachable instance metadata means the SSRF can read the cloud role's "
        "temporary credentials — full account pivot.",
        "Fix the SSRF (allowlist egress) AND enforce IMDSv2 / block 169.254.169.254."),
    ChainRule(
        "idor-to-privesc", "IDOR/BOLA → privilege escalation",
        [cls(VulnClass.IDOR, VulnClass.BOPLA), all_of(cls(VulnClass.AUTHZ), kw("admin", "role", "privilege", "escalat"))],
        Severity.HIGH,
        "Use the object-level access flaw to reach an admin/privileged operation.",
        "An object-level access-control flaw next to a broken function-level control lets a "
        "low-privileged user reach privileged actions.",
        "Enforce per-object AND per-function authorization server-side."),
    ChainRule(
        "xss-to-session-hijack", "XSS → session hijack",
        [cls(VulnClass.XSS), all_of(cls(VulnClass.MISCONFIG), kw("HttpOnly", "cookie"))],
        Severity.HIGH,
        "Use the XSS to read the session cookie (missing HttpOnly) and hijack the session.",
        "A stored/reflected XSS combined with a session cookie that lacks HttpOnly means the "
        "XSS can exfiltrate the session token.",
        "Fix the XSS and set HttpOnly + SameSite on session cookies."),
    ChainRule(
        "secret-to-access", "Leaked credential → authenticated access",
        [all_of(cls(VulnClass.INFO_LEAK), kw("secret", "key", "token", "credential")), cls(VulnClass.AUTHZ)],
        Severity.HIGH,
        "Replay the leaked credential against the authenticated surface.",
        "A credential exposed in responses/JS/config, next to an authenticated API, invites "
        "credential replay for direct access.",
        "Rotate the exposed secret and move it out of the client-reachable surface."),
    ChainRule(
        "sqli-to-exfil", "SQL injection → data exfiltration",
        [cls(VulnClass.SQLI), all_of(cls(VulnClass.INFO_LEAK), kw("data", "PII", "user", "bucket"))],
        Severity.CRITICAL,
        "Demonstrate data extraction via the SQL injection against the exposed data surface.",
        "A confirmed SQLi alongside exposed data multiplies impact to bulk exfiltration.",
        "Parameterize queries; restrict DB permissions."),
    ChainRule(
        "graphql-mass-abuse", "GraphQL surface → unauthorized mutations",
        [all_of(cls(VulnClass.INVENTORY, VulnClass.GRAPHQL), kw("mutation", "introspection")),
         cls(VulnClass.AUTHZ)],
        Severity.HIGH,
        "Invoke the high-impact GraphQL mutations as an unauthorized identity.",
        "An introspected GraphQL surface with dangerous mutations next to a broken authz control "
        "is a prioritized mass-abuse path.",
        "Disable introspection in prod; enforce authorization per mutation."),
]
