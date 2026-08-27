"""Signatures that turn raw target telemetry into security signal.

The grey-box uplift lives here. Three kinds of signature:

  * TRACE_SIGNATURES — server exception / stack-trace patterns a probe can
    provoke, each mapped to the vulnerability class it CONFIRMS. A bare HTTP 500
    is noise; the same request producing
    `org.postgresql.util.PSQLException: ERROR: unterminated quoted string` in the
    log line is *confirmation* of SQL injection even when the response body was a
    generic error page. This is what makes observation worth wiring in.

  * SECRET_PATTERNS — credential / session / key shapes that must never sit in a
    log (CWE-532). Every log line is run through `redact_secrets()` BEFORE it is
    retained as evidence, so Deluluscan's own telemetry store can never become a
    secondary leak of the target's secrets.

  * OOM / resource markers — memory-pressure signals in the log stream.

Everything here is pure/deterministic and unit-tested offline (tests/test_telemetry.py):
no telemetry source, no Docker, no live target is required to exercise it.
"""
from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class TraceSignature:
    """A server-side error pattern that confirms a vulnerability class."""
    label: str            # human name, e.g. "PostgreSQL error"
    vuln_class: str       # VulnClass.value it confirms
    severity: str         # Severity.value hint (final rating is the analyzer's)
    pattern: re.Pattern


def _rx(p: str) -> re.Pattern:
    return re.compile(p, re.IGNORECASE)


# Ordered most-specific first: classify_trace returns the FIRST match, so a
# PostgreSQL error (which also contains the word "exception") is attributed to
# SQLi, not to the generic exception bucket.
TRACE_SIGNATURES: list[TraceSignature] = [
    # --- SQL injection -----------------------------------------------------
    TraceSignature("PostgreSQL error", "sqli", "high",
                   _rx(r"org\.postgresql\.util\.PSQLException|ERROR:\s+syntax error at or near|unterminated quoted string|column .* does not exist")),
    TraceSignature("SQL grammar error", "sqli", "high",
                   _rx(r"SQLGrammarException|BadSqlGrammarException|java\.sql\.SQLException|BatchUpdateException|SQLSyntaxErrorException")),
    # --- Server-side template injection (the target: Velocity/Freemarker) ------
    TraceSignature("Freemarker template error", "ssti", "high",
                   _rx(r"freemarker\.core\.|freemarker\.template\.|InvalidReferenceException")),
    TraceSignature("Velocity template error", "ssti", "high",
                   _rx(r"org\.apache\.velocity|MethodInvocationException|ParseErrorException|VelocityException")),
    # --- Injection family: path traversal / XXE / command ------------------
    TraceSignature("Path/file access error", "injection", "medium",
                   _rx(r"java\.io\.FileNotFoundException|java\.nio\.file\.(NoSuchFileException|AccessDeniedException)|InvalidPathException")),
    TraceSignature("XML/XXE parser error", "injection", "high",
                   _rx(r"org\.xml\.sax\.SAXParseException|DOCTYPE is disallowed|external entity|XMLStreamException")),
    # --- Unsafe deserialization -------------------------------------------
    TraceSignature("Java deserialization error", "supply_chain", "high",
                   _rx(r"java\.io\.(InvalidClassException|StreamCorruptedException|OptionalDataException)|cannot be cast to|readObject")),
    # --- Resource exhaustion (memory) -------------------------------------
    TraceSignature("Out of memory", "rate_limit", "high",
                   _rx(r"java\.lang\.OutOfMemoryError|GC overhead limit exceeded|Java heap space|unable to create new native thread")),
    TraceSignature("Stack overflow", "rate_limit", "medium",
                   _rx(r"java\.lang\.StackOverflowError")),
    # --- Generic uncaught exception (weakest; last) ------------------------
    TraceSignature("Uncaught NullPointerException", "error_handling", "low",
                   _rx(r"java\.lang\.NullPointerException")),
    TraceSignature("Uncaught server exception", "error_handling", "low",
                   _rx(r"\bException\b.*\bat [\w.$]+\(|Caused by:|Exception in thread")),
]


def classify_trace(line: str):
    """Return the first TraceSignature matching `line`, or None."""
    if not line:
        return None
    for sig in TRACE_SIGNATURES:
        if sig.pattern.search(line):
            return sig
    return None


# --- secret / credential redaction ----------------------------------------
# (kind, pattern). The pattern's group(1), if present, is the sensitive span to
# mask; otherwise the whole match is masked. `severity` classifies impact so the
# analyzer can rate a leak proportionally.
@dataclass(frozen=True)
class SecretPattern:
    kind: str
    severity: str
    pattern: re.Pattern


SECRET_PATTERNS: list[SecretPattern] = [
    SecretPattern("jwt", "high",
                  re.compile(r"eyJ[A-Za-z0-9_-]{4,}\.eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}")),
    SecretPattern("private_key", "high",
                  re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    SecretPattern("aws_access_key", "high", re.compile(r"AKIA[0-9A-Z]{16}")),
    SecretPattern("db_url_credentials", "high",
                  re.compile(r"(?:jdbc:)?(?:postgres(?:ql)?|mysql|mongodb)://[^:@\s/]+:([^@\s/]+)@", re.IGNORECASE)),
    SecretPattern("password", "high",
                  re.compile(r"(?i)(?:password|passwd|pwd)\s*[=:]\s*([^\s,;&\"']{3,})")),
    SecretPattern("bearer_token", "medium",
                  re.compile(r"(?i)bearer\s+([A-Za-z0-9._~+/-]{12,}=*)")),
    SecretPattern("session_id", "medium",
                  re.compile(r"(?i)(JSESSIONID|SESSIONID|sid)=([A-Za-z0-9]{12,})")),
    SecretPattern("api_key", "medium",
                  re.compile(r"(?i)(?:api[_-]?key|secret[_-]?key|access[_-]?token)\s*[=:]\s*([A-Za-z0-9._-]{12,})")),
]


def redact_secrets(line: str) -> tuple[str, list[str]]:
    """Return (redacted_line, kinds_found). The sensitive span of each match is
    replaced with `<redacted:KIND>` while surrounding context (so the line stays
    legible as evidence) is preserved. Idempotent enough to run on every log line."""
    if not line:
        return line, []
    kinds: list[str] = []
    out = line
    for sp in SECRET_PATTERNS:
        def _sub(m: re.Match) -> str:
            # Mask the credential span (last populated group) but keep any label
            # prefix the pattern captured before it.
            whole = m.group(0)
            secret = None
            if m.groups():
                # choose the last non-None group as the sensitive span
                for g in reversed(m.groups()):
                    if g:
                        secret = g
                        break
            token = f"<redacted:{sp.kind}>"
            if secret and secret in whole:
                return whole.replace(secret, token)
            return token
        new = sp.pattern.sub(_sub, out)
        if new != out:
            kinds.append(sp.kind)
            out = new
    # de-dup preserving order
    seen: set[str] = set()
    uniq = [k for k in kinds if not (k in seen or seen.add(k))]
    return out, uniq


def secret_severity(kinds: list[str]) -> str:
    """Worst severity across the kinds present in a line."""
    rank = {"low": 1, "medium": 2, "high": 3}
    worst = 0
    for sp in SECRET_PATTERNS:
        if sp.kind in kinds:
            worst = max(worst, rank.get(sp.severity, 1))
    return {0: "low", 1: "low", 2: "medium", 3: "high"}[worst]


# --- log-injection detection ----------------------------------------------
def forged_line_present(lines: list[str], forged_marker: str) -> bool:
    """True if `forged_marker` begins its OWN log line — i.e. an injected newline
    successfully split the log (a forged entry), not merely appeared inline within
    an escaped field of a legitimate line."""
    if not forged_marker:
        return False
    for ln in lines:
        # tolerate a leading docker/log timestamp or level before the marker only
        # if the marker still starts a logical line; the strict signal is a line
        # whose (stripped) content STARTS with the marker.
        if ln.lstrip().startswith(forged_marker):
            return True
    return False
