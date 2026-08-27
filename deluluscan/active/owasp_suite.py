"""OWASP-coverage analyzers (v0.5) — breadth across the OWASP API Top 10 (2023)
and OWASP Top 10 (2025), grounded in current research and Burp Suite parity.

Each analyzer is deliberately written as pure, testable logic that operates over
the shared HttpClient (so the authorized-target safety gate, rate limiter and
redaction still apply). Nothing here weaponizes: probes are benign, bursts are
hard-capped (this is not a DoS tool), and confirmation stops at proving the flaw.

Analyzers:
  AuthorizationMatrix  Autorize/AuthMatrix-style access-control matrix — replays
                       each request as every identity and flags unexpected grants
                       (API1 BOLA, API5 BFLA, A01:2025). Equixly's R×P approach.
  PropertyMiner        BOPLA (API3): excessive-data-exposure detection + read-only
                       property overwrite (mass assignment), per Corradini et al.
  TokenSequencer       Burp Sequencer parity — entropy/predictability of session
                       tokens/ids (weak auth / A04 cryptographic failures).
  FaultProbe           A10:2025 mishandling of exceptional conditions — malformed
                       input -> verbose stack traces (info leak) or fail-open.
  FlowProbe            API4 unrestricted resource consumption + API6 business-flow
                       abuse — bounded rate-limit and pagination-cap checks.
  GraphQLProbe         GraphQL introspection / field-suggestion exposure.
"""
from __future__ import annotations

import json
import math
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from ..semantic_diff import structural_similarity
from ..verify import evidence as E

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------
def _looks_denied(rec) -> bool:
    return E.classify_response(rec) != E.DISPOSITION_CONTENT


def _login_like(body: str) -> bool:
    low = (body or "").lower()
    return ("login" in low and "password" in low) or "j_security_check" in low


# Framework / language error signatures -> verbose error handling (A10, info leak)
_STACK_SIGS = [
    r"traceback \(most recent call last\)", r"at [\w\.$]+\([\w]+\.java:\d+\)",
    r"org\.apache\.", r"com\.target\.", r"com\.example\.",
    r"javax\.servlet", r"jakarta\.servlet", r"caused by:",
    r"nullpointerexception", r"sqlexception", r"stacktrace",
    r"exception in thread", r"panic:", r"goroutine \d+",
    r"system\.\w+\.\w+exception", r"\.rb:\d+:in ", r"node_modules",
    r"line \d+, in ", r"\bhibernate\b", r"unhandled exception",
]
_STACK_RE = re.compile("|".join(_STACK_SIGS), re.I)

# Property names that usually shouldn't be client-writable (mass assignment) ...
_READONLY_HINTS = {
    "id", "inode", "identifier", "iduser", "userid", "owner", "createdate",
    "moddate", "moduser", "lastmodified", "created", "updated", "version",
    "isadmin", "admin", "roleid", "roles", "role", "active", "approved",
    "emailverified", "permissions", "balance", "price", "credits", "verified",
}
# ... and names that usually shouldn't be *readable* by a low-priv caller (excessive data)
_SENSITIVE_READ_HINTS = {
    "password", "passwordhash", "hash", "salt", "token", "accesstoken",
    "refreshtoken", "secret", "apikey", "api_key", "privatekey", "ssn",
    "creditcard", "cardnumber", "cvv", "pin", "securityquestion",
    "resettoken", "totp", "mfasecret", "sessionid",
}


# ===========================================================================
# API1 / API5 / A01:2025 — Authorization matrix (Autorize / AuthMatrix parity)
# ===========================================================================
@dataclass
class MatrixCell:
    identity: str
    status: int
    granted: bool
    similarity_to_ref: Optional[float] = None


@dataclass
class MatrixResult:
    endpoint_key: str
    reference_identity: str        # the identity legitimately expected to have access
    cells: list[MatrixCell]
    bypass_identities: list[str]   # lower-priv identities that also got in
    detail: str = ""


class AuthorizationMatrix:
    """Replays one request as every identity and reports who got access.

    ``send(endpoint, identity_label, headers) -> record``. ``rank`` maps an
    identity label to a privilege rank (higher = more privilege); a *bypass* is a
    lower-ranked identity obtaining an equivalent response to the reference."""

    def __init__(self, send: Callable, rank: dict[str, int], similarity_gate: float = 0.85):
        self.send = send
        self.rank = rank
        self.gate = similarity_gate

    def test(self, endpoint_key: str, identities: dict[str, dict]) -> Optional[MatrixResult]:
        # public-by-design endpoints legitimately return the same data to all
        if E.is_public_by_design(endpoint_key):
            return None
        # identities: label -> headers
        recs = {label: self.send(endpoint_key, label, headers)
                for label, headers in identities.items()}
        granted = {label: (E.classify_response(r) == E.DISPOSITION_CONTENT)
                   for label, r in recs.items()}
        # reference = highest-privilege identity that legitimately got real content
        holders = [l for l, g in granted.items() if g]
        if not holders:
            return None
        ref = max(holders, key=lambda l: self.rank.get(l, 0))
        ref_rank = self.rank.get(ref, 0)
        ref_rec = recs[ref]

        cells, bypass = [], []
        for label, r in recs.items():
            sim = None
            is_bypass = False
            if label != ref and self.rank.get(label, 0) < ref_rank and granted[label]:
                # OWASP WSTG 4.5 oracle: same protected data as the reference?
                res = E.served_protected_content(r, ref_rec, similarity_gate=self.gate)
                sim = res.similarity
                is_bypass = res.served
            cells.append(MatrixCell(label, getattr(r, "status", 0), granted[label], sim))
            if is_bypass:
                bypass.append(label)
        if not bypass:
            return None
        return MatrixResult(endpoint_key, ref, cells, bypass,
                            detail=(f"{', '.join(bypass)} received the same protected "
                                    f"data as '{ref}' — access control is not enforced "
                                    f"by role (confirmed by content comparison)."))


# ===========================================================================
# API3 / BOPLA — excessive data exposure + mass assignment (Corradini et al.)
# ===========================================================================
@dataclass
class PropertyFinding:
    kind: str                 # "excessive_data" | "mass_assignment"
    field: str
    detail: str
    evidence_status: Optional[int] = None


def _flatten_keys(obj, prefix="") -> set[str]:
    out: set[str] = set()
    if isinstance(obj, dict):
        for k, v in obj.items():
            out.add(k.lower())
            out |= _flatten_keys(v, k)
    elif isinstance(obj, list):
        for v in obj[:5]:
            out |= _flatten_keys(v, prefix)
    return out


def _flatten_items(obj):
    """Yield (lowercased-key, value) pairs across nested dicts/lists."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, (dict, list)):
                yield from _flatten_items(v)
            else:
                yield (k.lower(), v)
    elif isinstance(obj, list):
        for v in obj[:5]:
            yield from _flatten_items(v)


def _is_masked_value(v) -> bool:
    """True if a value is null/empty/masked/placeholder — i.e. NOT a real leak."""
    if v is None or isinstance(v, bool):
        return True
    if isinstance(v, (int, float)):
        return True  # numeric flags/ids aren't 'secret material' on their own
    s = str(v).strip()
    if len(s) < 6:
        return True
    low = s.lower()
    if low in ("null", "none", "false", "true", "redacted", "changeme"):
        return True
    if any(t in low for t in ("redacted", "masked", "hidden", "example", "placeholder",
                              "dummy", "xxxx", "your_", "<", "changeit", "*****")):
        return True
    if sum(c in "*•.\u2022x " for c in s) / max(1, len(s)) > 0.6:
        return True
    return False


class PropertyMiner:
    """Runtime BOPLA testing.

    Excessive data: sensitive-looking fields present in a response returned to a
    caller who probably shouldn't see them. Mass assignment: attempt to overwrite
    read-only-looking fields on a write and see if the server accepts/reflects."""

    def __init__(self, send_write: Optional[Callable] = None):
        # send_write(field, value) -> record ; used for the mass-assignment probe
        self.send_write = send_write

    def check_excessive_data(self, response_body: str, status: int) -> list[PropertyFinding]:
        try:
            obj = json.loads(response_body)
        except Exception:
            return []
        # walk (key, value) pairs; only flag a sensitive-looking key when it
        # actually carries a real, non-masked value — a field named "apiKey" with
        # null/""/"REDACTED"/"****" is NOT a data exposure.
        out: list[PropertyFinding] = []
        for k, v in _flatten_items(obj):
            if k in _SENSITIVE_READ_HINTS and not _is_masked_value(v):
                out.append(PropertyFinding("excessive_data", k,
                           f"response exposes sensitive property '{k}' with a real value",
                           status))
        # de-dup by field
        seen = set(); uniq = []
        for pf in out:
            if pf.field not in seen:
                seen.add(pf.field); uniq.append(pf)
        return uniq

    def check_mass_assignment(self, readable_fields: set[str]) -> list[PropertyFinding]:
        if not self.send_write:
            return []
        out: list[PropertyFinding] = []
        # target read-only-looking fields that appear readable but shouldn't be set
        candidates = sorted((readable_fields & _READONLY_HINTS) | {"isAdmin", "roleId"})
        for fieldname in candidates:
            value = True if fieldname.lower() in ("isadmin", "admin", "active",
                                                  "approved", "verified") else "deluluscan"
            rec = self.send_write(fieldname, value)
            if rec is None or rec.status >= 400:
                continue
            body = (rec.resp_body or "").lower()
            if f'"{fieldname.lower()}"' in body and str(value).lower() in body:
                out.append(PropertyFinding("mass_assignment", fieldname,
                           f"write accepted and reflected read-only property "
                           f"'{fieldname}'={value}", rec.status))
                break   # one confirmed field is enough
        return out


# ===========================================================================
# Broken auth / A04 crypto — token entropy (Burp Sequencer parity)
# ===========================================================================
@dataclass
class SequencerReport:
    n: int
    mean_bits_per_char: float
    total_bits_estimate: float
    unique_ratio: float
    looks_sequential: bool
    verdict: str          # "strong" | "weak" | "predictable"
    detail: str


def _shannon(sample: str) -> float:
    if not sample:
        return 0.0
    counts = Counter(sample)
    n = len(sample)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


class TokenSequencer:
    def analyze(self, tokens: list[str]) -> Optional[SequencerReport]:
        tokens = [t for t in tokens if t]
        if len(tokens) < 3:
            return None
        per_char = [_shannon(t) for t in tokens]
        mean_bits = sum(per_char) / len(per_char)
        avg_len = sum(len(t) for t in tokens) / len(tokens)
        total_bits = mean_bits * avg_len
        unique_ratio = len(set(tokens)) / len(tokens)
        # sequential detection: many tokens numeric and monotonically increasing
        nums = [int(t) for t in tokens if t.isdigit()]
        looks_seq = len(nums) >= 3 and all(
            b - a == nums[1] - nums[0] for a, b in zip(nums, nums[1:]))
        if looks_seq or unique_ratio < 1.0:
            verdict, detail = "predictable", (
                "tokens are sequential/colliding — trivially guessable")
        elif total_bits < 64:
            verdict, detail = "weak", (
                f"~{total_bits:.0f} bits of entropy is below a safe threshold "
                f"(>=128 recommended for session tokens)")
        else:
            verdict, detail = "strong", f"~{total_bits:.0f} bits of estimated entropy"
        return SequencerReport(len(tokens), round(mean_bits, 2), round(total_bits, 1),
                               round(unique_ratio, 3), looks_seq, verdict, detail)


# ===========================================================================
# A10:2025 — mishandling of exceptional conditions (verbose errors / fail-open)
# ===========================================================================
@dataclass
class FaultFinding:
    kind: str            # "verbose_error" | "server_error" | "fail_open"
    probe: str
    detail: str
    status: int


# Benign malformed inputs — designed to trip error paths, not to harm.
def malformed_probes() -> list[tuple[str, Any]]:
    return [
        ("broken_json", '{"a": '),
        ("wrong_type", {"id": {"$nested": [1, 2, 3]}}),
        ("huge_number", {"id": 10 ** 40}),
        ("negative", {"id": -1, "limit": -1}),
        ("null_byte", {"q": "a\x00b"}),
        ("deep_array", {"q": [[[[[[[[["x"]]]]]]]]]}),
    ]


class FaultProbe:
    """Send benign malformed inputs; detect verbose stack traces (info leak) and
    fail-open behavior (an auth-required endpoint returning success on garbage)."""

    def classify(self, probe_name: str, rec, auth_required: bool) -> list[FaultFinding]:
        if rec is None:
            return []
        out: list[FaultFinding] = []
        body = rec.resp_body or ""
        if _STACK_RE.search(body):
            out.append(FaultFinding("verbose_error", probe_name,
                       "malformed input produced a stack trace / internal error "
                       "detail in the response (information disclosure)", rec.status))
        elif rec.status >= 500:
            out.append(FaultFinding("server_error", probe_name,
                       "malformed input caused an unhandled 5xx (should be a "
                       "validated 4xx)", rec.status))
        if auth_required and rec.status == 200 and not _login_like(body) and rec.resp_len > 8:
            out.append(FaultFinding("fail_open", probe_name,
                       "endpoint returned success on malformed/garbage input where "
                       "a rejection was expected (possible fail-open)", rec.status))
        return out


# ===========================================================================
# API4 / API6 — unrestricted resource consumption + business-flow abuse
# ===========================================================================
@dataclass
class FlowFinding:
    kind: str            # "no_rate_limit" | "no_pagination_cap"
    detail: str
    detail_data: dict = field(default_factory=dict)


class FlowProbe:
    """Bounded, SAFE checks. This is not a load generator: bursts are hard-capped
    and exist only to observe whether *any* throttling appears."""

    HARD_CAP = 20

    def check_rate_limit(self, send_once: Callable, burst: int = 12) -> Optional[FlowFinding]:
        burst = min(burst, self.HARD_CAP)
        statuses = []
        for _ in range(burst):
            r = send_once()
            statuses.append(getattr(r, "status", 0))
            if getattr(r, "status", 0) == 429:
                return None  # throttling present -> good, stop immediately
        if 429 not in statuses:
            return FlowFinding("no_rate_limit",
                               f"{burst} rapid requests to a sensitive flow drew no "
                               f"429/throttling response — missing rate limiting / "
                               f"anti-automation", {"burst": burst, "statuses": statuses[:5]})
        return None

    def check_pagination_cap(self, send_with_limit: Callable, huge: int = 100000) -> Optional[FlowFinding]:
        baseline = send_with_limit(10)
        big = send_with_limit(huge)
        if baseline is None or big is None:
            return None
        # if a huge limit yields a much larger response, the cap isn't enforced
        if big.status == 200 and baseline.resp_len and big.resp_len > baseline.resp_len * 5:
            return FlowFinding("no_pagination_cap",
                               f"limit={huge} returned a {big.resp_len}B response vs "
                               f"{baseline.resp_len}B at limit=10 — no server-side "
                               f"page-size cap (resource-consumption risk)",
                               {"baseline_len": baseline.resp_len, "big_len": big.resp_len})
        return None


# ===========================================================================
# GraphQL introspection / field suggestion
# ===========================================================================
_INTROSPECTION_QUERY = '{"query":"query{__schema{queryType{name}}}"}'


@dataclass
class GraphQLFinding:
    kind: str            # "introspection" | "field_suggestion"
    detail: str
    status: int


class GraphQLProbe:
    def classify_introspection(self, rec) -> Optional[GraphQLFinding]:
        if rec is None or rec.status != 200:
            return None
        body = rec.resp_body or ""
        if "__schema" in body and "queryType" in body:
            return GraphQLFinding("introspection",
                                  "GraphQL introspection is enabled — the full schema "
                                  "is disclosed to unauthenticated callers", rec.status)
        return None

    @staticmethod
    def introspection_query() -> str:
        return _INTROSPECTION_QUERY
