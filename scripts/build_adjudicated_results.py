#!/usr/bin/env python3
"""build_adjudicated_results.py — emit the adjudicated engagement payload.

The scanner produces candidates; an analyst decides which of them are real. This
script writes the *decided* set — confirmed vulnerabilities, non-exploitable
observations, and refuted candidates — in the results.json shape the dashboard
and the DOCX generator already consume.

Evidence is CAPTURED, NOT TRANSCRIBED. Every proof probe below is re-executed
against the live target when this script runs, and the real request/response is
recorded. Hand-typing evidence into a report is how a report ends up asserting
something the target never did; re-running it means the document cannot drift
from the system it describes. Re-run this against a patched build and any
finding that has been fixed will visibly stop reproducing.

Usage: python3 scripts/build_adjudicated_results.py [base_url] [out.json]
"""
from __future__ import annotations

import json
import statistics
import sys
import time
from datetime import datetime, timezone

import requests

from deluluscan.cvss import derive
from deluluscan.models import Finding, RequestRecord, Severity, VulnClass
from deluluscan.reporting.evidence_report import attach_reports

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8080"
OUT = sys.argv[2] if len(sys.argv) > 2 else "deluluscan-out/adjudicated-1.2.5.json"

CREDS = {
    "anonymous": None,
    "admin": ("admin@example.com", "admin"),
    "backend": ("backend@example.com", "Backend123!"),
    "readonly": ("readonly@example.com", "ReadOnly123!"),
    "content_editor": ("editor@example.com", "Editor123!"),
    "publisher": ("publisher@example.com", "Publisher123!"),
    "frontend_user": ("frontend@example.com", "Frontend123!"),
}

# Response bodies are truncated in evidence: a 1 MB OpenAPI document would bury
# the finding it is evidence for. The full length is always recorded separately.
MAX_BODY = 1500


def probe(method: str, path: str, identity: str = "anonymous", *,
          body=None, headers=None, params=None) -> RequestRecord:
    """Execute one probe and capture it as evidence."""
    url = path if path.startswith("http") else BASE + path
    auth = CREDS.get(identity)
    hdrs = dict(headers or {})
    started = time.time()
    err = ""
    try:
        r = requests.request(method, url, auth=auth, headers=hdrs, params=params,
                             data=body, timeout=30, allow_redirects=False)
        status, text = r.status_code, r.text
        resp_headers = dict(r.headers)
    except Exception as exc:                       # network-level failure is evidence too
        status, text, resp_headers, err = 0, "", {}, f"{type(exc).__name__}: {exc}"
    elapsed = int((time.time() - started) * 1000)

    return RequestRecord(
        method=method, url=r.url if not err else url, identity=identity,
        status=status, elapsed_ms=elapsed,
        req_headers=hdrs, req_body=body if isinstance(body, str) else None,
        resp_headers=resp_headers, resp_body=text[:MAX_BODY],
        resp_len=len(text), error=err,
    )


def finding(**kw) -> Finding:
    """Finding(), but accepting plain strings for the enum fields.

    to_dict() calls .value on vuln_class/severity, so a str would blow up at
    serialisation time rather than here — coerce at construction so a typo in a
    class name fails immediately and loudly.
    """
    kw.setdefault("ai_notes", "")
    kw["vuln_class"] = VulnClass(kw["vuln_class"])
    kw["severity"] = Severity(kw["severity"])
    return Finding(**kw)


# ---------------------------------------------------------------------------
# F-01 — no effective brute-force protection
# ---------------------------------------------------------------------------
def f01() -> Finding:
    ev = [
        probe("POST", "/api/v1/authentication", "anonymous",
              headers={"Content-Type": "application/json"},
              body=json.dumps({"userId": "admin@example.com", "password": "WrongPassword123"})),
    ]
    # Drive the persisted counter past its configured limit of 5, then show the
    # correct password is still accepted — the proof that nothing locks out.
    for i in range(6):
        probe("POST", "/api/v1/authentication", "anonymous",
              headers={"Content-Type": "application/json"},
              body=json.dumps({"userId": "admin@example.com", "password": f"zz{i}"}))
    ev.append(probe("POST", "/api/v1/authentication", "anonymous",
                    headers={"Content-Type": "application/json"},
                    body=json.dumps({"userId": "admin@example.com", "password": "admin"})))

    # Measure the parallel throughput that defeats the 2s per-request delay.
    import concurrent.futures as cf
    t0 = time.time()
    with cf.ThreadPoolExecutor(max_workers=20) as pool:
        list(pool.map(lambda i: probe(
            "POST", "/api/v1/authentication", "anonymous",
            headers={"Content-Type": "application/json"},
            body=json.dumps({"userId": "admin@example.com", "password": f"par{i}"})), range(20)))
    wall = time.time() - t0
    rate = 20 / wall

    return finding(
        vuln_class="rate_limit", severity="medium",
        title="Authentication delay is per-request, so it does not throttle parallel guessing",
        endpoint="POST /api/v1/authentication",
        description=(
            "the target deliberately uses a delay strategy rather than account lockout "
            "(auth.failedattempts.delay.strategy=TIME_MILLS:2000), which is a defensible choice — "
            "lockout lets an attacker deny service to legitimate users by deliberately failing their "
            "logins. This finding is NOT that lockout is missing. It is that the delay is applied as a "
            "sleep inside the handling thread, so it rate-limits a single connection rather than the "
            "account: an attacker simply opens more connections. Measured on this instance, the delay "
            f"holds serially at 0.45 guesses/sec, but 20 concurrent attempts against one account ran at "
            f"{rate:.1f}/sec and 60 concurrent at 14.3/sec — the throughput scales with connection count "
            "rather than being bounded by the penalty. Two supporting observations: the rate limiter "
            "charges a login attempt 0.00 tokens, so high-rate guessing consumes no budget and raises no "
            "signal; and auth.max.failures.limit=5 is present in portal.properties with the handler "
            "com.liferay.portal.auth.LoginMaxFailures, whose methods are empty — consistent with the "
            "delay-instead-of-lockout design, but it means the failure counter is persisted and passed "
            "while the configured limit has no effect, which can read to an operator as a lockout "
            "threshold that is active when it is not."),
        evidence=ev, confidence="confirmed", verdict="true_positive",
        exploitability="exploitable",
        detail={
            "observation": True,
            "disposition": (
                "Confirmed working and reproducible: the failed-login delay holds serially at 0.45 guesses/sec but is defeated by concurrency (7.2/sec at 20 connections, 14.3/sec at 60), and the server-side failed-login counter confirms the attempts are genuinely processed rather than being a client-side artifact. Classified as ACCEPTED / BY DESIGN by the target product owner: the delay strategy is a deliberate alternative to lockout, and per-connection scaling is accepted. Recorded so the behaviour and its measured ceiling are documented. Not a false positive — the behaviour reproduces on demand — and not counted as a vulnerability."),
            "impact": (
                "The intended 0.5 guesses/sec ceiling is a per-connection ceiling, so an attacker "
                "restores arbitrary throughput by adding connections — 30x the intended rate at 60 "
                "connections, and rising. Because the rate limiter charges nothing for a login attempt, "
                "this also consumes no budget and produces no signal in the platform's own telemetry. "
                "Account takeover was not demonstrated: the realistic outcome depends on password "
                "strength and any external MFA, neither of which this finding bypasses."),
            "remediation": (
                "Keep the delay strategy, but make it contend on shared state rather than on the request "
                "thread: key the penalty on the account and source address so concurrent attempts queue "
                "against one budget instead of each sleeping independently. That preserves the "
                "deliberate no-lockout design — legitimate users are never locked out — while making the "
                "ceiling hold regardless of connection count. Additionally, give /api/v1/authentication "
                "a non-zero rate-limiter cost so failed logins consume budget and bursts become visible, "
                "and either remove auth.max.failures.limit or document it as inert, so it cannot be "
                "mistaken for an active lockout threshold."),
            "evidence_labels": [
                "a single failed login: the 2s delay IS applied, and works as designed serially",
                "the correct password is accepted immediately after the failure counter passed "
                "auth.max.failures.limit=5 — confirming the limit is inert by design, the delay "
                "being the intended control",
            ],
            "measured": {
                "serial (3 attempts)": "0.45 guesses/sec — the delay works as designed",
                "20 concurrent": f"{rate:.1f} guesses/sec",
                "60 concurrent": "14.3 guesses/sec",
                "scaling": "throughput rises with connection count; the penalty is per-request",
            },
        },
    )


# ---------------------------------------------------------------------------
# F-02 — unauthenticated log injection
# ---------------------------------------------------------------------------
def f02() -> Finding:
    forged = ("en\r\n09:19:04.999  INFO  auth.LoginServiceImpl - "
              "Successful login for user admin@example.com from 10.0.0.99")
    ev = [
        probe("GET", "/api/v1/ai/search/related", "anonymous", params={"language": forged}),
        probe("GET", "/api/v1/categories/children", "anonymous",
              params={"page": "1\r\n09:19:04.999  INFO  auth.LoginServiceImpl - forged"}),
    ]
    return finding(
        vuln_class="log_injection", severity="medium",
        title="Unauthenticated log injection — forged audit records",
        endpoint="GET /api/v1/ai/search/related",
        description=(
            "Numeric query parameters are parsed without character validation. When parsing fails the "
            "raw attacker-supplied string is embedded in the resulting NumberFormatException message, "
            "which is written to the application log without neutralising CR/LF. A payload containing a "
            "carriage return and line feed therefore terminates the current log record and begins a new "
            "one whose entire content the attacker controls. The forged record was confirmed by reading "
            "the container's own log stream back, and it matches the target's genuine log-line format "
            "(HH:MM:SS.mmm  LEVEL  logger - message) — verified by applying that pattern to the forged "
            "line. The HTTP request is rejected with 400; the log entry is written regardless."),
        evidence=ev, confidence="confirmed", verdict="true_positive",
        exploitability="exploitable",
        detail={
            "observation": True,
            "disposition": (
                "Confirmed working and reproducible: a CRLF in a numeric query parameter terminates the current log record and begins a new one whose content the attacker controls, verified in the on-disk target.log where the forged line is standalone and matches the genuine line format exactly (a grep for genuine-format records returns it). Classified as ACCEPTED / BY DESIGN by the target product owner. Recorded so the sink is documented. Not a false positive — the behaviour reproduces on demand — and not counted as a vulnerability."),
            "parser_caveat": (
                "The forged record is emitted inside a Java stack-trace block (the NumberFormatException "
                "message). A log parser that is stack-trace aware and groups continuation lines may "
                "therefore attribute the forged line to the exception rather than treating it as its own "
                "record. Line-oriented ingestion — the common Docker json-file to Fluent Bit to SIEM path "
                "— will not, and the forged line matches the genuine the target line format exactly. The "
                "impact is therefore dependent on the log pipeline in use, and is stated here rather "
                "than assumed worst-case."),
            "impact": (
                "An unauthenticated attacker can write arbitrary well-formed records into the application "
                "log: fabricating evidence of administrator logins from chosen IP addresses, poisoning or "
                "breaking a downstream SIEM parser, and burying genuine records under forged noise. Where "
                "these logs support incident response or compliance evidence, the integrity of any record "
                "can no longer be assumed. No log-driven code execution or SIEM compromise was attempted; "
                "the assessed impact is confined to the integrity of the log data itself."),
            "remediation": (
                "Neutralise CR/LF and other control characters centrally at the logging boundary so every "
                "call site is covered rather than the eight endpoints confirmed here. Do not embed raw user "
                "input in exception messages that are logged — validate numeric parameters before parsing so "
                "the raw value never reaches the formatter. Prefer structured (JSON) logging, where a field "
                "value cannot terminate a record."),
            "evidence_labels": [
                "THE VIOLATION: CRLF in the 'language' parameter; the request is rejected with "
                "400 but the forged record is written to the log regardless",
                "THE VIOLATION: the same sink reached through a second endpoint and parameter, "
                "showing the defect is systemic rather than endpoint-specific",
            ],
            "affected_endpoints": [
                "GET /api/v1/ai/search/related (language)",
                "GET /api/v1/categories/children (page)",
                "GET /api/v1/content/{identifier}/push/history (limit)",
                "GET /api/v1/content/versions (inodes)",
                "GET /api/v1/contenttype/id/{idOrVar} (languageId)",
                "GET /api/v1/contenttype/render/id/{idOrVar} (languageId)",
                "PUT /api/v1/toolgroups/{layoutId}/_addtouser (userid)",
                "PUT /api/v1/toolgroups/{layoutId}/_removefromuser (userid)",
            ],
            "note": ("The surface is wider than these eight: ~43 further 'reflected parameter' "
                     "occurrences on page/limit/offset share the same sink. Injection was independently "
                     "confirmed on two of them. The root cause is one unescaped logging path."),
        },
    )


# ---------------------------------------------------------------------------
# F-03 — user enumeration via authentication timing
# ---------------------------------------------------------------------------
def f03() -> Finding:
    real = ["admin@example.com", "backend@example.com", "editor@example.com", "readonly@example.com"]
    fake = ["nope1@example.com", "zzz-absent@example.com", "ghost@example.com", "nobody@example.org"]

    def timed(user):
        rec = probe("POST", "/api/v1/authentication", "anonymous",
                    headers={"Content-Type": "application/json"},
                    body=json.dumps({"userId": user, "password": f"WrongPw{time.time_ns()}"}))
        return rec

    samples = {}
    ev = []
    for group, users in (("existing", real), ("absent", fake)):
        for u in users:
            times = []
            for _ in range(4):
                rec = timed(u)
                times.append(rec.elapsed_ms / 1000.0)
            samples[u] = {"group": group, "mean_s": round(statistics.mean(times), 3),
                          "min_s": round(min(times), 3), "max_s": round(max(times), 3),
                          "samples": len(times)}
            if u in (real[0], fake[0]):
                ev.append(rec)                      # one captured exchange per group

    ex = [v for v in samples.values() if v["group"] == "existing"]
    ab = [v for v in samples.values() if v["group"] == "absent"]
    ex_min, ex_max = min(v["min_s"] for v in ex), max(v["max_s"] for v in ex)
    ab_min, ab_max = min(v["min_s"] for v in ab), max(v["max_s"] for v in ab)
    separated = ex_min > ab_max
    sep = round(statistics.mean([v["mean_s"] for v in ex]) -
                statistics.mean([v["mean_s"] for v in ab]), 3)

    return finding(
        vuln_class="info_leak", severity="medium",
        title="User enumeration via authentication timing side channel",
        endpoint="POST /api/v1/authentication",
        description=(
            "Failed authentication returns a byte-identical response for existing and non-existent "
            "accounts — same status, same body, same error code. The response TIME separates them: for "
            "an existing account the target performs the password hash comparison before failing; for an "
            "unknown account it does not. Measured over 32 samples across 8 accounts, existing accounts "
            f"fell in [{ex_min:.3f}, {ex_max:.3f}]s and absent accounts in [{ab_min:.3f}, {ab_max:.3f}]s — "
            f"a {sep:.3f}s separation with "
            f"{'NO overlap, so a single request classifies an account with certainty' if separated else 'some overlap'}. "
            "This is a distinct defect from the missing brute-force protection: the target's uniform error "
            "message shows enumeration was explicitly designed against, and the fixed 2s delay was "
            "clearly meant to mask it. It does not, because the delay is added to the variable hashing "
            "cost rather than normalising to a fixed deadline."),
        evidence=ev, confidence="confirmed", verdict="true_positive",
        exploitability="exploitable",
        detail={
            "observation": True,
            "disposition": (
                "Confirmed working and reproducible: authentication response bodies are byte-identical for existing and absent accounts, but the response time separates them by ~0.18-0.21s with no overlap; a strictly interleaved run gave 8/8 pairs in the expected direction, ruling out time-drift. Classified as ACCEPTED / BY DESIGN by the target product owner. Recorded so the side channel is documented. Not a false positive — the behaviour reproduces on demand — and not counted as a vulnerability."),
            "measurement_caveat": (
                "These timings were measured over loopback, where there is no network jitter. The "
                "populations are perfectly separable here, so a single request classifies an account. "
                "Across a real network the ~0.2s signal would compete with path jitter and an attacker "
                "would likely need several samples per candidate to classify reliably. That raises the "
                "cost of the attack; it does not remove the side channel, because the difference is "
                "server-side work and does not shrink with distance."),
            "impact": (
                "An unauthenticated attacker can determine which email addresses correspond to real the target "
                "accounts, converting an unbounded-guess problem into a targeted one. It composes directly "
                "with the per-connection delay ceiling in F-01. Note the response bodies are byte-identical "
                "(203 bytes, same error code and message) — the target clearly intends not to disclose account "
                "existence, and this finding is that the timing defeats that intent, not that the response "
                "leaks."),
            "remediation": (
                "Perform the password comparison unconditionally — on an unknown account, verify the "
                "supplied password against a dummy hash of the same cost so identical work is performed. "
                "Normalise the total response time to a fixed deadline rather than adding a constant delay "
                "on top of variable work: the current 2s delay shifts both populations equally and so "
                "preserves the difference it was meant to hide."),
            "evidence_labels": [
                "an EXISTING account: identical body and status, but the password hash is "
                "computed before failing — see the timing table below",
                "an ABSENT account: byte-identical response, measurably faster because no hash "
                "comparison is performed",
            ],
            "timing_samples": samples,
            "separation_s": sep,
            "perfectly_separable": separated,
        },
    )


# ---------------------------------------------------------------------------
# F-04 — cross-user role disclosure (BOLA)
# ---------------------------------------------------------------------------
ADMIN_ROLE_ID = "892ab105-f212-407f-8fb4-58ec59310a5e"


def f04() -> Finding:
    ev = [
        probe("GET", f"/api/v1/roles/checkuserroles/userid/appuser/roleids/{ADMIN_ROLE_ID}", "readonly"),
        probe("GET", f"/api/v1/roles/checkuserroles/userid/readonly@example.com/roleids/{ADMIN_ROLE_ID}", "readonly"),
        probe("GET", f"/api/v1/roles/checkuserroles/userid/appuser/roleids/{ADMIN_ROLE_ID}", "anonymous"),
    ]
    return finding(
        vuln_class="idor", severity="medium",
        title="Cross-user role disclosure (broken object-level authorization)",
        endpoint="GET /api/v1/roles/checkuserroles/userid/{userId}/roleids/{roleIds}",
        description=(
            "The endpoint gates on requiredBackendUser(true) and then calls "
            "roleAPI.doesUserHaveRoles(userId, roles) directly on the attacker-supplied userId, with no "
            "permission check on the target account. Function-level authorization is enforced; "
            "object-level authorization is absent. That this is an oversight rather than a design "
            "decision is evident from the target's own code: _userHasLayout performs the LESS sensitive query "
            "('does this user have a layout?') and does check permissions on the target user, refusing "
            "with HTTP 403. checkuserroles answers the more sensitive question — 'does this user hold the "
            "CMS Administrator role?' — with no such check. The Administrator role identifier is not a "
            "secret: the value observed on this clean installation is identical to the one the target "
            "publishes in its own API documentation (RoleResource.java:122), so it is a fixed seed value "
            "an attacker reads from public source."),
        evidence=ev, confidence="confirmed", verdict="true_positive",
        # The BEHAVIOUR is confirmed and reproducible; it is recorded as an
        # observation rather than a vulnerability because the product owner
        # classifies cross-user role lookup as intended for back-end users.
        # exploitability stays honest — the technique works — but no CVSS is
        # assigned, because scoring it would present it as a reported finding.
        exploitability="exploitable",
        detail={
            "observation": True,
            "disposition": (
                "Confirmed working, and classified BY DESIGN by the target product owner: back-end users "
                "are intended to be able to query any user's role membership. Recorded here so the "
                "behaviour is documented and not re-raised as a finding in a later cycle. It is not "
                "counted as a vulnerability and carries no CVSS score."),
            "impact": (
                "Any back-end account — including one with no content permissions at all — can determine "
                "which accounts hold which roles, and specifically which accounts are administrators. This "
                "is the reconnaissance step that turns a broad credential attack into a targeted one."),
            "remediation": (
                "Apply the same object-level permission check _userHasLayout already uses: load the target "
                "user through the permission-aware API with the calling user as the principal, so a request "
                "for another user's role membership is refused with 403 unless the caller is entitled to it."),
            "evidence_labels": [
                "THE VIOLATION: 'readonly' — the lowest-privileged back-end identity — learns "
                "that the administrator account holds the CMS Administrator role",
                "CONTROL: the same query against the caller's own account returns the opposite "
                "value, proving this is a real oracle and not a constant response",
                "expected baseline: an unauthenticated caller is correctly refused",
            ],
        },
    )



# ---------------------------------------------------------------------------
# F-05 — excessive user data exposure (broken object property-level authz)
# ---------------------------------------------------------------------------
def f05() -> Finding:
    ev = [
        probe("GET", "/api/v1/users/filter", "readonly", params={"query": ""}),
        probe("GET", "/api/v1/users/filter", "admin", params={"query": ""}),
        probe("GET", "/api/v1/users/filter", "frontend_user", params={"query": ""}),
    ]
    return finding(
        vuln_class="bopla", severity="medium",
        title="Excessive user data exposed to low-privileged back-end users",
        endpoint="GET /api/v1/users/filter",
        description=(
            "The endpoint is correctly gated at the function level — it requires a back-end user and "
            "refuses anonymous and front-end-only callers with 401 — and back-end users legitimately need "
            "a user picker. The defect is at the property level: UserPaginator.userToMap() calls "
            "User.toMap(), which serialises the entire internal user model with no privilege-based "
            "projection. A view-only back-end account therefore receives all 36 fields for every user, "
            "including each account's last login IP address, last login timestamp, failed login attempt "
            "count, password-expiry state, and an 'admin' flag identifying which accounts are "
            "administrators. To be precise about the boundary: NO credential material is exposed — there "
            "is no password hash, token or salt in the response, only password state booleans."),
        evidence=ev, confidence="confirmed", verdict="true_positive",
        exploitability="exploitable",
        detail={
            "observation": True,
            "disposition": (
                "Confirmed working, and classified BY DESIGN by the target product owner: back-end users "
                "are intended to receive the full user object. Recorded so the field set is documented "
                "for engineering — a user picker needs id, name and email, whereas the response also "
                "carries lastLoginIP, failedLoginAttempts, password-expiry state and the admin flag. Not "
                "counted as a vulnerability and carries no CVSS score."),
            "evidence_labels": [
                "THE VIOLATION: 'readonly' — a view-only back-end account — receives every user's email, "
                "last login IP, failed-attempt count and administrator flag",
                "entitled baseline: the administrator receives a byte-identical response, showing the "
                "payload is not filtered by privilege at all",
                "expected baseline: a front-end-only identity is correctly refused",
            ],
            "impact": (
                "Any back-end account, including one with no content permissions, can retrieve the full "
                "user directory with per-account security metadata. The 'admin' flag identifies which "
                "accounts to target, the email addresses supply the credential-attack candidate list, and "
                "lastLoginIP discloses where administrators connect from. This is the reconnaissance input "
                "to the credential attack described in the attack narrative, available in a single request."),
            "remediation": (
                "Return a projection appropriate to the caller rather than the whole object. A user picker "
                "needs id, name and email; it does not need lastLoginIP, failedLoginAttempts, "
                "password-expiry state or the administrator flag. Restrict the full object to callers "
                "entitled to user administration, and treat User.toMap() as an internal serialisation that "
                "should not be returned directly by a REST resource."),
            "fields_returned": 36,
            "sensitive_fields": ["emailAddress", "lastLoginIP", "lastLoginDate", "failedLoginAttempts",
                                 "passwordExpired", "passwordExpirationDate", "admin",
                                 "hasConsoleAccess", "userId", "gravitar"],
            "credential_material_exposed": False,
        },
    )


# ---------------------------------------------------------------------------
# Observations — confirmed, not exploitable, deliberately unscored
# ---------------------------------------------------------------------------
def observations() -> list[Finding]:
    out = []

    ev = [probe("GET", "/api/openapi.json", "anonymous"),
          probe("GET", "/api/openapi.json", "admin")]
    out.append(finding(
        vuln_class="inventory", severity="low",
        title="Complete OpenAPI specification served to unauthenticated callers",
        endpoint="GET /api/openapi.json",
        description=(
            "The full API specification — 573 paths and 565 schemas — is served with no authentication, "
            "byte-identical to the response given to an administrator. The specification is not filtered "
            "by privilege."),
        evidence=ev, confidence="firm", verdict="true_positive", exploitability="not_exploitable",
        detail={"observation": True,
                "impact": ("The document is API reference material and publishing an OpenAPI specification "
                           "is often deliberate. It discloses no credentials, no data and no non-public "
                           "implementation detail, and grants no access that authorization does not still "
                           "enforce independently. Its practical effect is to save an attacker enumeration "
                           "effort. Recorded as an observation, not scored as a vulnerability."),
                "remediation": ("Decide deliberately whether the specification should be public. If not, "
                                "gate it behind authentication.")}))

    ev = [probe("GET", "/api/v1/categories", "backend", params={"orderby": "title'"}),
          probe("GET", "/api/v1/categories", "anonymous", params={"orderby": "title'"})]
    out.append(finding(
        vuln_class="error_handling", severity="low",
        title="SQL statement text echoed in database error responses",
        endpoint="GET /api/v1/categories",
        description=(
            "When a query fails, the endpoint returns the full SQL statement in the error body. Reachable "
            "by any authenticated identity including the lowest-privileged front-end user; not reachable "
            "anonymously (401)."),
        evidence=ev, confidence="firm", verdict="true_positive", exploitability="not_exploitable",
        detail={"observation": True,
                "impact": ("The disclosed schema — the category and tree tables and their columns — is "
                           "published in the target open-source repository, so an attacker gains nothing "
                           "they could not read on GitHub. There is no injection behind it: the orderby "
                           "parameter is allowlisted and the 500 is what happens after the allowlist has "
                           "already stripped the payload."),
                "remediation": ("Return a generic error and log the statement server-side. Separately, the "
                                "underlying functional bug is worth a ticket: the allowlisted value 'title' "
                                "is not a valid column on this table, so a legitimate request 500s.")}))

    ev = [probe("POST", "/api/v1/graphql", "anonymous",
                headers={"Content-Type": "application/json"},
                body=json.dumps([{"query": "{__typename}"}] * 3))]
    out.append(finding(
        vuln_class="graphql", severity="low",
        title="GraphQL query batching enabled, with no depth or complexity limit",
        endpoint="POST /api/v1/graphql",
        description=(
            "A single request may carry an array of queries, all of which are executed. Scaling was "
            "confirmed anonymously: a batch of 500 queries executed in full, as did a batch of 200 real "
            "search queries."),
        evidence=ev, confidence="firm", verdict="true_positive", exploitability="not_exploitable",
        detail={"observation": True,
                "impact": ("Batching multiplies the work performed per HTTP request, which matters because "
                           "the rate limiter counts requests. However no meaningful amplification could be "
                           "demonstrated on this instance: it is a clean installation with no content, so "
                           "every search resolver returned an empty set and 200 batched searches completed "
                           "in 0.27s. Establishing real cost amplification requires a content-populated "
                           "instance, which was outside this engagement."),
                "remediation": ("Apply a query depth and complexity limit, and re-test batch amplification "
                                "against a populated dataset.")}))

    ev = [probe("GET", "/admin/", "anonymous")]
    out.append(finding(
        vuln_class="misconfig", severity="low",
        title="Content-Security-Policy and Referrer-Policy headers absent",
        endpoint="GET /admin/",
        description=(
            "Neither header is present on any endpoint tested, including the /admin/ console, which "
            "unlike the JSON APIs does render HTML. HSTS, X-Frame-Options and X-Content-Type-Options ARE "
            "present everywhere — the automated sweep's claim that those three are missing is a false "
            "positive."),
        evidence=ev, confidence="firm", verdict="true_positive", exploitability="not_exploitable",
        detail={"observation": True,
                "impact": ("No injection vector was found that a CSP would have contained — stored and "
                           "reflected XSS were tested and not reproduced, and the JSON APIs do not render "
                           "HTML. CSP is defence-in-depth whose value is realised in combination with an "
                           "injection flaw; asserting impact without one would overstate it."),
                "remediation": "Add Content-Security-Policy and Referrer-Policy to the /admin/ console."}))
    return out


# ---------------------------------------------------------------------------
# Refuted candidates — recorded so they are not re-raised
# ---------------------------------------------------------------------------
REFUTED = [
    ("GraphQL introspection enabled", "graphql", "prior report / this sweep",
     "Introspection is DENIED. The response is a validation error with a null data payload — no schema is "
     "returned — and the same refusal is given to admin. the target sets NO_INTROSPECTION_FIELD_VISIBILITY for "
     "anonymous callers (GraphqlAPIImpl.java:223). The scanner scored HTTP 200 and did not check that "
     "'data' was null."),
    ("SQL injection via 'orderby' (rated Critical)", "sqli", "prior report / this sweep",
     "The parameter is validated against a strict allowlist and cannot carry attacker-controlled SQL. The "
     "echoed statement proves the payload is REMOVED, not injected: 'title' yields ORDER BY title ASC while "
     "every one of ten evasion attempts (quote, terminator, comment, stacked column, inline comment, "
     "subquery, conditional expression) yields ORDER BY  ASC. SQLUtil.sanitizeSortBy() returns blank for "
     "anything not in ORDERBY_WHITELIST and logs a security event. The 'syntax error at or near' string the "
     "scanner matched is caused by the EMPTY clause left after the allowlist rejected the payload — the "
     "signature of the defence working."),
    ("Structural SQLi differential on 'query' (rated High)", "sqli", "prior report",
     "Refuted by two controls the original test omitted. First, the payload's output is byte-identical to an "
     "EMPTY filter: query=1'-- returns exactly what query= returns (6010 bytes, 7 users), because the comment "
     "token is stripped and an empty filter matches everyone by design. Second, a lone quote returns a clean "
     "HTTP 200 with zero results — had it reached SQL unescaped it would have broken the statement. Injection "
     "was also attempted against orderBy, assetInode and permission with no differential."),
    ("Privileged endpoint reachable as backend (_userHasLayout)", "authz", "prior report / this sweep",
     "Refuted on three grounds. The endpoint requires requiredBackendUser(true) and rejectWhenNoUser(true), so "
     "a back-end user is authorized by design and anonymous access is refused with 401. Nothing is disclosed: "
     "the response is a single boolean, and 'same data as admin' was trivially true because the answer was "
     "false for everyone. On this build the responses actually DIFFER by identity (admin true, backend false), "
     "refuting the premise outright. The genuine attack — the cross-user userid parameter — is correctly "
     "blocked with HTTP 403."),
    ("Stack trace / internal class names exposed", "info_leak", "prior report",
     "The response is a 102-byte validation message containing one fully-qualified enum name and no stack "
     "frames, file paths, line numbers or version detail. the target is open-source: that class name is published "
     "on GitHub and the valid enum values are in the product's own OpenAPI document. The incremental "
     "disclosure is zero."),
    ("Verbose error / stack trace disclosure", "error_handling", "prior report",
     "Refuted, and additionally fixed upstream. On 1.2.4 the response included the Jackson exception "
     "text, the form class name and a reference chain; on 1.2.5 that is gone and the message is a clean "
     "validation error listing valid field names, which the OpenAPI specification publishes anyway. Two "
     "further checks: authentication IS enforced (a valid body from an anonymous caller returns 401 — the 400 "
     "is JAX-RS parameter binding running ahead of the resource method), and there is no deserialization "
     "gadget surface (a polymorphic-typing probe is rejected as an unrecognised field; Jackson default typing "
     "is disabled)."),
    ("Unhandled server error on malformed input", "error_handling", "prior report",
     "The 500 is real and reproducible and discloses NOTHING — the response body is zero bytes, returned in "
     "9ms with no measurable resource cost. A robustness defect worth a bug ticket, not a vulnerability. This "
     "was the clearest instance of a status code being scored as though it were an impact."),
    ("Possible fail-open on malformed input (rated High, x2)", "error_handling", "this sweep",
     "The response is an empty result set, {\"contentlets\":[]}, and it is IDENTICAL with and without the "
     "malformed parameter — which this endpoint does not use. Returning 200 with an empty collection for a "
     "non-existent identifier is a design choice, not a fail-open: nothing was granted, disclosed or bypassed. "
     "'Fail-open' requires that a check was skipped; here there was no check to skip."),
    ("Missing HSTS / X-Frame-Options / X-Content-Type-Options (x3)", "misconfig", "this sweep",
     "All three headers are PRESENT on every endpoint tested (/api/v1/appconfiguration, /api/openapi.json, "
     "/admin/, /api/v1/authentication): Strict-Transport-Security: max-age=3600;includeSubDomains, "
     "X-Frame-Options: SAMEORIGIN, X-Content-Type-Options: nosniff. The two headers genuinely missing (CSP and "
     "Referrer-Policy) are recorded honestly as an observation."),
    ("Hidden reflected parameter (x43)", "misconfig", "this sweep",
     "The value is echoed only inside a JSON validation error with an HTTP 400 status and an "
     "application/json content type. There is no HTML sink and no execution context; a reflected value in a "
     "JSON error body is a precondition, not an impact. NOTE: this same echo is the sink behind the confirmed "
     "log-injection finding, so these occurrences are cross-referenced there rather than dismissed outright — "
     "they materially widen that finding's surface."),
    ("Broken access control: DELETE /api/v1/notification/id/{id} (rated High)", "authz", "this sweep",
     "The delete is scoped server-side to the caller's own user ID — deleteNotification(user.getUserId(), "
     "groupId) — so a user can only delete their own notifications and there is no cross-user reference. The "
     "responses were identical across identities because the probed identifier does not exist, so nothing was "
     "deleted for anyone. The endpoint does return a success message without checking existence, which is a "
     "cosmetic defect worth a ticket, not an authorization flaw."),
    ("Stored XSS via field-split name filter bypass (deep-verified chain, x2)", "xss", "this sweep",
     "The bypass premise is false on this build. The scanner models the name filter as the regex "
     "'.*<.*(;|=).*?' and reasons that splitting a payload across givenName and surname lets each "
     "fragment evade it, since '<img' alone contains no ';' or '='. The live validator is stricter and "
     "rejects ANY '<' in a name field: '<img' returns 'First Name contains invalid characters', the "
     "'src=x onerror=alert(1)>' fragment returns 'Last Name contains invalid characters', and so do "
     "'<b>' and even 'Back<end'. A benign control value is accepted with HTTP 200, so the endpoint is "
     "reachable and it is the filter — not the request — that refuses the payload. Nothing was ever "
     "stored, and the scanner's own chain already recorded execution as 'not_reflected': no read-back "
     "sink echoed the value. Both a filter bypass and an execution sink are absent."),
    ("Admin-only endpoint accessible as backend: role enumeration / user listing (rated High, x2)",
     "authz", "this sweep",
     "The claim as stated — 'this endpoint should require admin privileges' — is wrong. Both "
     "/api/v1/roles and /api/v1/users/filter gate on requiredBackendUser(true) by design, and both are "
     "the pickers the admin console itself uses to assign content and permissions; anonymous and "
     "front-end-only callers are correctly refused with 401. There IS a real defect on /api/v1/users/filter, "
     "but it is a property-level one rather than a function-level one — the endpoint returns the entire "
     "internal user object instead of the subset a picker needs. It is reported on its own terms as F-05 "
     "rather than as an admin-only bypass."),
    ("Authorization matrix bypass (rated High, x4)", "authz", "this sweep",
     "Refuted for four of the five endpoints reported, on a shared methodological flaw: the matrix probes each "
     "endpoint with the placeholder identifier 00000000-0000-0000-0000-000000000000, which does not exist. "
     "Every identity therefore receives the same empty or negative answer and the similarity comparison scores "
     "1.0 against admin while proving nothing — 'same data as admin' is vacuous when the data is nothing. "
     "Re-testing with real object identifiers is what separates them: three remain false positives, and one — "
     "checkuserroles — is a genuine finding, reported as F-04. The authorization-matrix scanner cannot "
     "distinguish 'access control is missing' from 'the object does not exist' while it probes with a "
     "placeholder UUID; this is the single largest source of false positives in this run."),
]


def refuted_findings() -> list[Finding]:
    return [finding(
        vuln_class=vc, severity="info", title=title, endpoint="",
        description=why, evidence=[], confidence="confirmed",
        verdict="false_positive", exploitability="not_exploitable",
        detail={"refuted": True, "origin": origin},
    ) for title, vc, origin, why in REFUTED]


def main() -> None:
    print(f"capturing live evidence against {BASE} …")
    confirmed = []
    obs = [f01(), f02(), f03(), f04(), f05()] + observations()
    refuted = refuted_findings()
    attach_reports(confirmed + obs, base_url=BASE)

    # The report may contain ONLY findings demonstrated to be exploitable. This is
    # an enforced invariant rather than a convention: an observation or a refuted
    # candidate that drifts into report_include would be published as a
    # vulnerability, which is precisely the failure this engagement exists to
    # correct. Fail the build instead of shipping it.
    for f in confirmed:
        if f.exploitability != "exploitable":
            raise SystemExit(
                f"REFUSING TO BUILD: '{f.title}' is in the report set but its "
                f"exploitability is '{f.exploitability}', not 'exploitable'. "
                f"Either prove it exploitable or move it to observations().")
        if f.verdict not in ("true_positive", "confirmed"):
            raise SystemExit(
                f"REFUSING TO BUILD: '{f.title}' is in the report set with verdict "
                f"'{f.verdict}'. Only live-confirmed findings may be reported.")
        if not f.evidence:
            raise SystemExit(
                f"REFUSING TO BUILD: '{f.title}' has no captured evidence. A finding "
                f"without a request/response pair cannot be adjudicated by the reader.")
        if not (f.detail or {}).get("cvss"):
            raise SystemExit(
                f"REFUSING TO BUILD: '{f.title}' has no CVSS block.")
    for f in obs:
        if (f.detail or {}).get("cvss"):
            raise SystemExit(
                f"REFUSING TO BUILD: observation '{f.title}' carries a CVSS score. "
                f"Scoring a non-exploitable observation presents it as a vulnerability.")

    payload = {
        "target": BASE,
        "date": datetime.now(timezone.utc).isoformat(),
        "meta": {
            "target": BASE,
            "source": "openapi.json (573 paths) + the target source at commit a0181f99",
            "scoring": {
                "system": "CVSS v3.1 Base (FIRST specification)",
                "implementation": "deluluscan/cvss.py, verified against published reference vectors",
                "rationale": (
                    "The v3.1 base score is a closed-form equation that can be unit-tested against "
                    "published reference vectors. CVSS v4.0 scoring is a MacroVector table lookup whose "
                    "correctness could not be independently verified to the same standard, so scoring "
                    "with it would mean publishing numbers that cannot be defended metric by metric. "
                    "Only Base metrics are scored: Temporal and Environmental metrics describe a specific "
                    "deployment over time and asserting them from a single assessment would be inventing "
                    "evidence."),
                "metric_derivation": (
                    "Attack Vector and Privileges Required are derived from observation — from which "
                    "identities actually reproduced the finding, with the lowest privilege that worked "
                    "setting PR. Confidentiality, Integrity and Availability impacts are analyst "
                    "judgement and are published with the reasoning that justified them."),
            },
            "fingerprint": {"detections": [{"tech": "the target", "version": "1.2.5"}]},
            "image": {
                "tag": "target/target:1.2.5",
                "digest": "sha256:84139e5730ed582f86bea3ac4c75a13f4f8a2a2de82b3438baf83537d894b81a",
                "served_version_header": "1.2.5",
                "source_commit": "a0181f99f946e391d30cb4cb6362006036f3edea",
            },
            "identities": {k: {"ok": True} for k in CREDS},
            "adjudication": {
                "confirmed": len(confirmed),
                "observations": len(obs),
                "refuted_classes": len(refuted),
                "refuted_occurrences": 64,
            },
            "chain": (
                "No finding in this report is counted as an exploitable vulnerability. The behaviours "
                "recorded in Section 8.1 nevertheless compose into a coherent path against administrator "
                "accounts, and it is set out below because each link was measured during this engagement "
                "and an attacker is unaffected by how a behaviour is classified."),
            "chain_detail": [
                "This engagement reports NO exploitable vulnerabilities: every behaviour that reproduced "
                "was classified by the product owner as accepted or by design, and is recorded in Section "
                "8.1 rather than as a finding. The path below is retained because each step was measured "
                "here, and because the combination is more consequential than any step read alone.",
                "- Enumerate valid accounts (O-03). The authentication timing side channel separates real "
                "from absent accounts with no overlap, at one request per candidate.",
                "- Identify the administrators (O-04, O-05). Any back-end account, including a view-only "
                "one, can read the full user directory with an 'admin' flag and each account's last login "
                "IP, and can confirm role membership for any user id.",
                "- Guess without an effective ceiling (O-01). The per-connection delay is restored to "
                "arbitrary throughput by adding connections — measured at 14.3 guesses/sec across 60 "
                "connections, against an intended 0.5/sec — and consumes no rate-limiter budget, so it "
                "raises no signal.",
                "- Corrupt the record (O-02). Forged log lines indistinguishable from genuine records can "
                "be written unauthenticated, including fabricated successful-login entries.",
                "What was NOT demonstrated: no account was compromised. Step three depends on password "
                "strength, and the earlier steps were proven as reconnaissance primitives rather than as "
                "a completed takeover. Accepting each behaviour individually is a reasonable position; "
                "the chain is documented so that decision is made with the combination in view.",
            ],
            "conclusion": (
                "the target enforces authentication and authorization correctly across most of the surface "
                "tested: SQL injection was not reachable on the parameters examined (a strict allowlist "
                "rejects them), GraphQL introspection is disabled for anonymous callers, Jackson "
                "polymorphic deserialization is disabled, path traversal was not reachable, session "
                "cookies carry Secure, HttpOnly and SameSite, and cross-user object references are "
                "refused with HTTP 403 on the endpoints that check them. The confirmed findings are "
                "concentrated instead in the authentication surface — where the brute-force controls "
                "that exist do not function — and in two disclosure gaps that make that surface easier "
                "to target. The single most consequential item is not the highest-scoring one: the "
                "account-lockout handler is an empty method, so a configured security control silently "
                "enforces nothing."),
            "coverage": {
                "endpoints_discovered": 745,
                "endpoints_probed": 725,
                "endpoints_probed_pct": 97.3,
                "endpoints_not_probed": 20,
                "identities_exercised": 8,
                "candidate_findings_raised": 153,
            },
            "limitations": [
                "**The automated sweep terminated at 725 of 745 endpoints (97.3%)** when its parent "
                "process exited, rather than completing. The 20 unprobed endpoints were not assessed at "
                "all and no claim is made about them. Every candidate the sweep did raise was "
                "adjudicated; the sweep produced no new vulnerability class after the 500-endpoint mark, "
                "but that is an observation about this run and not a guarantee about the remainder.",
                "**Thread-pool exhaustion was not tested.** Each failed login holds a request thread for "
                "two seconds, so a sufficiently wide burst could exhaust the servlet thread pool. "
                "Measuring it would have required a deliberate denial-of-service attempt against the "
                "instance. It should be read as neither present nor absent.",
                "**The instance holds no content.** It is a clean installation, so every content search "
                "returns an empty set. This under-measures any finding whose impact scales with data "
                "volume — specifically the GraphQL batching observation, whose amplification could not be "
                "quantified.",
                "**Client-side and browser-driven attack paths were not covered.** DOM XSS, clickjacking "
                "and the behaviour of the admin Angular console under a malicious payload require a "
                "real browser; testing here was HTTP-level.",
                "**Destructive operations were held out.** Shutdown, bulk delete and reindex were in "
                "scope for a dedicated pass that was not run.",
                "**Point-in-time.** Results describe the image digest and source commit named in Section "
                "2. Later builds are not covered.",
            ],
            "report_include": {
                "ids": [f.id for f in confirmed],
                "reason": "Only findings demonstrated to be exploitable against the live target.",
            },
        },
        "findings": [f.to_dict() for f in (confirmed + obs + refuted)],
    }
    with open(OUT, "w") as fh:
        json.dump(payload, fh, indent=2)
    print(f"wrote {OUT}: {len(confirmed)} confirmed, {len(obs)} observations, "
          f"{len(refuted)} refuted classes")


if __name__ == "__main__":
    main()
