"""Core data models shared across the whole toolkit.

Everything that moves between the discovery layer, the scanners, the AI
analyst and the reporting layer is one of the dataclasses defined here. Keeping
them in one place means the JSON that lands in a report is the same shape the
web UI consumes.
"""
from __future__ import annotations

import enum
import hashlib
import time
import uuid
from dataclasses import dataclass, field, asdict
from typing import Any, Optional


class Severity(str, enum.Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}[self.value]


class VulnClass(str, enum.Enum):
    IDOR = "idor"
    XSS = "xss"
    SQLI = "sqli"
    SSTI = "ssti"            # server-side template injection
    SSRF = "ssrf"
    AUTHZ = "authz"          # broken access control / missing auth (API1/API5, A01)
    INFO_LEAK = "info_leak"
    # OWASP API 2023 / OWASP 2025 breadth
    BOPLA = "bopla"          # broken object property level authz: mass assign + excessive data (API3)
    RATE_LIMIT = "rate_limit"      # unrestricted resource consumption (API4, A02/A06)
    BUSINESS_LOGIC = "business_logic"  # unrestricted access to sensitive business flows (API6)
    MISCONFIG = "misconfig"        # security misconfiguration (API8, A02:2025)
    INVENTORY = "inventory"        # improper inventory mgmt / shadow & deprecated APIs (API9)
    SUPPLY_CHAIN = "supply_chain"  # software supply chain / integrity (API10, A03/A08:2025)
    CRYPTO = "crypto"              # cryptographic failures / weak tokens (A04:2025)
    ERROR_HANDLING = "error_handling"  # mishandling of exceptional conditions (A10:2025)
    GRAPHQL = "graphql"            # graphql-specific exposure
    AI_LLM = "ai_llm"              # AI/LLM feature weaknesses: prompt injection, system-prompt leak (OWASP LLM Top 10)
    # Grey-box / observability classes: surfaced by correlating live probes with
    # the target's OWN telemetry (logs, memory/CPU) during the scan. See
    # deluluscan/telemetry/ — these need the target's runtime observed, which is why
    # they only appear on an --observe run.
    LOGGING_FAILURE = "logging_failure"      # exploit leaves no log/audit trail (A09:2025)
    LOG_INJECTION = "log_injection"          # CRLF/forged log lines (CWE-117)
    MEMORY_DISCLOSURE = "memory_disclosure"  # heap/thread dumps / debug surfaces leak memory (CWE-215)


class IdentityRole(str, enum.Enum):
    """Trust levels compared during a scan.

    ANON           - no credentials at all.
    BACKEND        - authenticated CMS back-end user with limited rights.
    ADMIN          - CMS Administrator (ground-truth oracle).
    CONTENT_EDITOR - back-end user with content editing permissions.
    READONLY       - authenticated user with read-only / minimal permissions.
    API_USER       - user created specifically for API / token-based access.
    """
    ANON = "anonymous"
    FRONT_END_USER = "frontend_user"   # logged-in site user, NO back-end/API access
    BACKEND = "backend"
    ADMIN = "admin"
    READONLY = "readonly"              # back-end + view-only
    CONTENT_EDITOR = "content_editor"  # back-end + edit content
    PUBLISHER = "publisher"            # back-end + publish content
    API_USER = "api_user"


@dataclass
class Identity:
    role: IdentityRole
    # Exactly one auth strategy is used per identity.
    username: Optional[str] = None
    password: Optional[str] = None
    bearer_token: Optional[str] = None      # API access token (JWT)
    # Populated after a successful login so we can reuse the session JWT.
    session_jwt: Optional[str] = None
    extra_headers: dict[str, str] = field(default_factory=dict)

    def label(self) -> str:
        return self.role.value


@dataclass
class Endpoint:
    """A single (method, path) operation, normally sourced from openapi.json."""
    method: str
    path: str                                # templated, e.g. /api/v1/users/{userId}
    summary: str = ""
    tags: list[str] = field(default_factory=list)
    path_params: list[str] = field(default_factory=list)
    query_params: list[dict[str, Any]] = field(default_factory=list)
    request_body_schema: dict[str, Any] = field(default_factory=dict)
    # Heuristic flag: does this op take an opaque object id / inode that another
    # user might own? Those are the prime IDOR candidates.
    id_bearing: bool = False
    source: str = "openapi"                  # openapi | seed | crawl

    @property
    def key(self) -> str:
        return f"{self.method.upper()} {self.path}"

    def __hash__(self) -> int:
        return hash(self.key)


@dataclass
class RequestRecord:
    """An immutable record of one HTTP exchange, used as evidence."""
    method: str
    url: str
    identity: str
    status: int
    elapsed_ms: float
    req_headers: dict[str, str] = field(default_factory=dict)
    req_body: Optional[str] = None
    resp_headers: dict[str, str] = field(default_factory=dict)
    resp_body: str = ""
    resp_len: int = 0
    error: Optional[str] = None

    def body_fingerprint(self) -> str:
        """Length-bucketed hash so near-identical responses compare equal even
        when they carry a per-request token or timestamp."""
        normalized = self.resp_body.strip()
        return hashlib.sha1(
            f"{self.status}:{len(normalized)//32}".encode()
        ).hexdigest()[:12]


@dataclass
class Finding:
    vuln_class: VulnClass
    severity: Severity
    title: str
    endpoint: str
    description: str
    evidence: list[RequestRecord] = field(default_factory=list)
    # Free-form, scanner-specific detail (payload used, timing delta, etc.)
    detail: dict[str, Any] = field(default_factory=dict)
    confidence: str = "tentative"            # tentative | firm | confirmed
    # Populated by the verification layer (deluluscan.verify):
    verdict: str = "unverified"              # true_positive | likely_true_positive | inconclusive | likely_false_positive | false_positive | unverified
    exploitability: str = "unknown"          # exploitable | conditional | mitigated | not_exploitable | unknown
    ai_notes: str = ""
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:10])
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["vuln_class"] = self.vuln_class.value
        d["severity"] = self.severity.value
        return d
