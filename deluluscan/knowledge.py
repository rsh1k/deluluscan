"""Deluluscan security knowledge base — per-class testing & verification methodology.

Two complementary stores make Deluluscan "learn":
  * deluluscan/memory.py       — WHAT we found on a target (per-target, cross-scan).
  * deluluscan/knowledge.py    — HOW each vulnerability class is tested, deeply
                            VERIFIED, and remediated (standing methodology).

This is Deluluscan's equivalent of an operator's skill set, distilled from OWASP Top
10:2025, the OWASP API Security Top 10, and the deep-verification discipline the
tool already enforces in code (deluluscan/verify/). It is wired in two ways:

  1. build_report() pulls `verify` + `remediation` + taxonomy from here so every
     finding's report carries consistent, current, independently-runnable
     verification steps and a class-level fix — never a blank or a hand-authored
     one-off.
  2. The deluluscan-audit skill references it so a human/Claude-driven audit applies
     the full playbook per class.

Design rule mirrored from the deep-verification layer: a reflected/echoed value
is a LEAD, not a finding. Every `verify` list encodes how to turn a lead into
proof for that class — the same discipline as deluluscan/verify/deep.py.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ClassKnowledge:
    summary: str                       # what the class is, in one line
    how_tested: str                    # how Deluluscan exercises it
    verify: list[str]                  # deep-verification discipline: lead -> proof
    remediation: str                   # class-level fix (not instance-level)
    owasp_2025: str = ""               # A0X:2025
    api_top10: str = ""                # APIX
    cwe: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)


# Keyed by VulnClass.value. Covers the security classes Deluluscan actually emits;
# identity roles (anon/admin/…) are not vulnerability classes and are omitted.
METHODOLOGY: dict[str, ClassKnowledge] = {
    "authz": ClassKnowledge(
        summary="Broken function-level access control (BFLA) / missing authorization — a privileged operation reachable by an under-privileged or anonymous identity.",
        how_tested="Differential replay: every endpoint is sent as each configured identity and any success below its required tier is flagged; verb tampering backs it up.",
        verify=[
            "Re-probe the endpoint as EVERY identity (anon/session-cookie/Bearer/Basic) with FRESH credentials — the target rotates the rme JWT and a stale token yields false 401s.",
            "Confirm the response carries privileged DATA or performs the privileged ACTION — a 200 with an empty list or a public stub is not a disclosure.",
            "If a lower tier can grant itself a role/layout, MEASURE what it unlocks: grant -> re-probe capability surface as the same identity -> diff -> revert. Do not assume.",
        ],
        remediation="Enforce an explicit role/permission check on the operation at the data layer — never rely on menu/UI visibility or route obscurity.",
        owasp_2025="A01:2025", api_top10="API5", cwe=["CWE-862", "CWE-285"]),

    "idor": ClassKnowledge(
        summary="Broken object-level authorization (BOLA/IDOR) — an object reference the client supplies is trusted as proof of ownership.",
        how_tested="Object identifiers are requested across identities and ownership boundaries; iterable-id enumeration probes sequential/guessable references.",
        verify=[
            "Use TWO identities you control: create/own an object as A, request it as B. A 200 returning A's data is the finding; B's own data is not.",
            "Confirm cross-tenant/cross-user impact, not just a 200 — inspect the body for the OTHER identity's records.",
            "Enumerate a few adjacent IDs to show it is systemic, but never exfiltrate real third-party data — proof is a count/sample, then stop.",
        ],
        remediation="Enforce per-object ownership at the data layer; never treat a client-supplied identifier as authorization.",
        owasp_2025="A01:2025", api_top10="API1", cwe=["CWE-639", "CWE-284"]),

    "bopla": ClassKnowledge(
        summary="Broken object property-level authorization — mass-assignment of privileged fields, or excessive data returned.",
        how_tested="Response property mining for over-broad fields plus mass-assignment probes on writes (e.g. role, isAdmin, ownerId).",
        verify=[
            "Send the privileged field on a write and re-read the object to confirm it was ACCEPTED and persisted — not silently dropped.",
            "For excessive data, confirm the extra fields are sensitive and returned to an identity that should not see them.",
        ],
        remediation="Bind request bodies through explicit allow-listed DTOs; serialize responses through per-role field allow-lists.",
        owasp_2025="A01:2025", api_top10="API3", cwe=["CWE-915", "CWE-213"]),

    "sqli": ClassKnowledge(
        summary="SQL injection — request-controlled input reaches query construction.",
        how_tested="Differential, error-based, and time-based probing of parameters reaching query/orderby construction; optional sqlmap confirmation.",
        verify=[
            "A database error string is a LEAD, not proof — demonstrate data-dependent behaviour: differential (true vs false condition) or reliable time-delay (n>=5 repeats vs baseline to beat jitter).",
            "For time-based, confirm the delay tracks the injected sleep length, not network noise.",
            "Never dump data to 'prove' it — retrieve a version string or a single benign row, then stop.",
        ],
        remediation="Parameterized queries / prepared statements. Escaping is not a fix; allow-list identifiers used in ORDER BY / column positions.",
        owasp_2025="A05:2025", cwe=["CWE-89"]),

    "ssti": ClassKnowledge(
        summary="Server-side template injection — user input evaluated as a template (e.g. Velocity/Freemarker/Jinja/Twig/Freemarker).",
        how_tested="Template-expression evaluation probes on request-controlled input; stored template-expression probe for the content sink.",
        verify=[
            "Evaluation (e.g. arithmetic returning the product) is confirmation, not the finding — escalate to the engine's code-execution gadget to establish real impact.",
            "Read the stored value back through every render surface; a raw value in a JSON API is a precondition, only an evaluated render executes.",
            "Confirm to proof (a benign marker / id), never a live weaponized payload.",
        ],
        remediation="Never build templates from request data; use a sandboxed context and pass user input as data, not template source.",
        owasp_2025="A05:2025", cwe=["CWE-1336", "CWE-94"]),

    "xss": ClassKnowledge(
        summary="Cross-site scripting — user input rendered without contextual output encoding.",
        how_tested="Canary reflection with render-context classification, then deep field-split filter-bypass + read-back across every sink (deluluscan/verify/readback.py).",
        verify=[
            "A reflected/echoed value is a LEAD. A raw value in a JSON API is a PRECONDITION; only a raw render in an HTML sink executes — classify the context before asserting.",
            "Try filter BYPASSES (field-split so each fragment evades a per-field blocklist), verified against the real filter regex, before concluding 'mitigated'.",
            "For stored XSS, decide drivability from the credential surface: HttpOnly hides a cookie from JS but the browser still sends it, so a same-origin XSS can ride a cookie-authed privileged endpoint. Grade served_raw_api + session-ridable as conditional pending one browser-render confirmation, not a hard exploitable.",
        ],
        remediation="Contextual output encoding at the sink; a tuned CSP (no unsafe-inline) as defence in depth; validate on input, encode on output.",
        owasp_2025="A05:2025", cwe=["CWE-79", "CWE-80"]),

    "ssrf": ClassKnowledge(
        summary="Server-side request forgery — the server makes a request to a destination the client controls. (Folded into A01 in OWASP 2025.)",
        how_tested="Loopback/link-local/callback destination probing on URL-accepting parameters, with an out-of-band (OAST) collaborator when available.",
        verify=[
            "Confirm the server actually initiated the request — an OOB callback received, or a timing/response difference between reachable and unreachable destinations.",
            "For blind SSRF, use the local OAST listener (loopback targets) or interactsh; absence of visible output does not mean it failed.",
            "Escalate carefully toward cloud metadata (169.254.169.254) only to prove reachability — never harvest live credentials.",
        ],
        remediation="Allow-list destination hosts, resolve-then-check to defeat DNS rebinding, block link-local/metadata ranges, and egress-filter the app tier.",
        owasp_2025="A01:2025", api_top10="API7", cwe=["CWE-918"]),

    "injection": ClassKnowledge(
        summary="Command/OS/LDAP/path/XXE and other injection where input reaches an interpreter or resolver.",
        how_tested="Class-specific payloads on parameters reaching a shell, path, parser, or command sink, with OOB confirmation for blind cases.",
        verify=[
            "Prove interpreter execution, not reflection: OOB callback, time delay, or a benign command marker in the response.",
            "For path traversal, confirm access to a file outside the intended root; for XXE, confirm entity resolution (OOB or error).",
        ],
        remediation="Avoid passing untrusted input to interpreters; use safe APIs, parameterization, allow-listed paths, and disable external entities.",
        owasp_2025="A05:2025", cwe=["CWE-77", "CWE-78", "CWE-22", "CWE-611"]),

    "crypto": ClassKnowledge(
        summary="Cryptographic failures / weak tokens — predictable, unsigned, over-long-lived, or weakly-verified secrets and JWTs.",
        how_tested="JWT algorithm/signature handling (alg:none, RS256->HS256 confusion), token entropy/sequencing, and lifetime review.",
        verify=[
            "Forge or tamper the token and confirm the SERVER accepts it (a 200 on a privileged endpoint) — client-side acceptance is not proof.",
            "For weak entropy, collect a sample and demonstrate predictability/collision, not just short length.",
        ],
        remediation="Pin the algorithm server-side, verify signature and exp, keep lifetimes short, rotate on privilege change, and use a CSPRNG for tokens.",
        owasp_2025="A04:2025", api_top10="API2", cwe=["CWE-347", "CWE-330"]),

    "misconfig": ClassKnowledge(
        summary="Security misconfiguration — permissive CORS, verbose errors, missing hardening headers, exposed management surfaces, cache issues.",
        how_tested="CORS, cache, verb tampering, error-handling and exposed-admin-surface probes across the discovered surface.",
        verify=[
            "For CORS, confirm the origin is REFLECTED with credentials allowed (Access-Control-Allow-Credentials: true) — a wildcard without credentials is lower impact.",
            "Rate by reachable impact: a missing header alone is usually low; tie it to a demonstrated consequence.",
        ],
        remediation="Hardened baseline config as code; allow-list exact CORS origins; suppress verbose errors in prod; disable unused endpoints.",
        owasp_2025="A02:2025", api_top10="API8", cwe=["CWE-16", "CWE-942"]),

    "info_leak": ClassKnowledge(
        summary="Sensitive information exposure — server internals, secrets, or over-broad data returned to an under-privileged identity.",
        how_tested="Response inspection for server internals/secrets, SPA/JS secret mining, and over-broad data detection.",
        verify=[
            "Confirm the leaked value is genuinely sensitive AND reachable by an identity that should not see it (or anonymously).",
            "For a secret in client JS, confirm it is live/usable, not a placeholder — then rate by what it authorizes.",
        ],
        remediation="Move secrets server-side and rotate any exposed; scope responses to the caller; strip internal detail from errors and headers.",
        owasp_2025="A01:2025", api_top10="API3", cwe=["CWE-200", "CWE-215"]),

    "supply_chain": ClassKnowledge(
        summary="Software supply-chain / integrity failures — vulnerable/outdated components and unsafe deserialization of untrusted data.",
        how_tested="Dependency inventory (manifests + the running target's actual classpath) checked against an advisory database (deluluscan/sca.py), source-informed targeting, and deserialization-sink probing.",
        verify=[
            "A vulnerable version is a LEAD, not a finding. Walk all five steps below before asserting anything — 'old version, therefore vulnerable' is the single biggest source of worthless SCA output.",
            "1. CONFIRM THE VERSION IS IN RANGE. Read the advisory's affected ranges rather than trusting a name match, and remember backports break version inference.",
            "2. CONFIRM IT ACTUALLY SHIPS. Check the RUNNING target's classpath, not just the manifest: an upgrade often leaves the old vulnerable jar loadable beside the new one (e.g. 32 artifacts present at two versions at once), while other manifest entries never ship at all.",
            "3. READ THE ADVISORY FOR THE SPECIFIC VECTOR, then test THAT vector. 'DoS via introspection queries' is not the same surface as 'the library is old'.",
            "4. LOOK FOR A COMPENSATING CONTROL that neutralises the vector, and re-derive the CVSS for THIS deployment — e.g. an app that disables GraphQL introspection for anonymous users turns a PR:N advisory into PR:L at best.",
            "5. MEASURE, do not assume. For a resource-exhaustion CVE, scale the input and watch the amplification ratio: a ratio that stays FLAT is linear cost, not a DoS. Only a ratio that climbs (or memory that does not recover) demonstrates the vulnerability.",
            "Presence without a caller is not reachability: if neither the application nor a shipped library invokes the vulnerable API, say so rather than rating it high.",
            "For deserialization, confirm the sink processes attacker-controlled serialized data (rO0 / gadget marker) and reaches execution to proof, not just an accepted blob.",
        ],
        remediation="Maintain an SBOM and patch on exploitability rather than on version age; exclude superseded artifacts from the build so an upgrade cannot leave the vulnerable copy on the classpath; never native-deserialize untrusted input; sign artifacts.",
        owasp_2025="A03:2025", api_top10="API10", cwe=["CWE-1104", "CWE-502", "CWE-1395"],
        references=["OWASP A03 Software Supply Chain Failures",
                    "CWE-1395 Dependency on Vulnerable Third-Party Component"]),

    "rate_limit": ClassKnowledge(
        summary="Unrestricted resource consumption — no rate limiting on authentication or expensive operations.",
        how_tested="Bounded burst probing of auth and expensive endpoints against a baseline.",
        verify=[
            "Confirm requests SUCCEED past the expected threshold (no 429), using a bounded burst — never a real DoS.",
        ],
        remediation="Rate-limit and quota expensive/auth operations; add lockout/backoff on authentication.",
        owasp_2025="A02:2025", api_top10="API4", cwe=["CWE-770", "CWE-307"]),

    "business_logic": ClassKnowledge(
        summary="Unrestricted access to sensitive business flows / workflow abuse — state machine accepts illegal transitions or replays.",
        how_tested="Workflow ordering, step-skipping, and replay probes on multi-step flows.",
        verify=[
            "Demonstrate the illegal state transition or duplicated effect actually persisted (re-read the resource), not just an accepted request.",
        ],
        remediation="Enforce server-side workflow invariants and idempotency; validate state transitions, not just individual requests.",
        owasp_2025="A04:2025", api_top10="API6", cwe=["CWE-840", "CWE-841"]),

    "inventory": ClassKnowledge(
        summary="Improper inventory management — shadow, deprecated, or older API versions lacking current fixes.",
        how_tested="Discovery of parallel versions (/v1 vs /v2), undocumented and deprecated routes, spec exposure.",
        verify=[
            "Confirm the shadow/old endpoint is live AND lacks a control present on the current one (e.g., the auth check).",
        ],
        remediation="Inventory and retire deprecated APIs; apply the same controls across all live versions; restrict spec exposure.",
        owasp_2025="A02:2025", api_top10="API9", cwe=["CWE-1059"]),

    "error_handling": ClassKnowledge(
        summary="Mishandling of exceptional conditions — fail-open logic, swallowed exceptions, error paths that skip authorization. (New in OWASP 2025.)",
        how_tested="Malformed/oversized/truncated input and wrong content types, watching for fail-open behaviour and authz bypass on error paths.",
        verify=[
            "Confirm the error path FAILS OPEN: a malformed request is allowed through where a well-formed one is denied (e.g. 200 for a malformed auth header vs 401 for none).",
            "Confirm a stack trace / internal detail leaks, or an exception skips a control — a plain 500 alone is low impact.",
        ],
        remediation="Fail closed; handle exceptions explicitly; never let an error path bypass authorization; suppress internal detail.",
        owasp_2025="A10:2025", cwe=["CWE-755", "CWE-703"]),

    "graphql": ClassKnowledge(
        summary="GraphQL-specific exposure — introspection, deep nesting/aliasing resource abuse, and field-level authorization gaps.",
        how_tested="Introspection probing, aliased/nested query cost probes, and per-field authorization differentials.",
        verify=[
            "Confirm introspection returns the schema to an unauthorized caller, or that a nested/aliased query is actually processed (cost/latency), not rejected.",
            "For field authz, confirm a lower tier retrieves a field it should not via a crafted query.",
        ],
        remediation="Disable introspection in prod, enforce query depth/cost limits, and apply per-field authorization.",
        owasp_2025="A01:2025", api_top10="API1", cwe=["CWE-770", "CWE-285"]),

    "ai_llm": ClassKnowledge(
        summary="AI/LLM feature weaknesses — prompt injection, system-prompt leakage, and improper handling of model output in the app's AI endpoints.",
        how_tested="Benign-marker probes against the AI endpoints (direct and, where content is stored/retrieved, indirect injection), plus system-prompt-extraction and output-handling checks.",
        verify=[
            "Prove injection with a BENIGN unmistakable marker (e.g. get the model to emit INJECTION-OK-<n>), not a harmful payload; repeat n>=3 because models are stochastic.",
            "For system-prompt leakage, confirm the extracted text is the real system prompt (contains config/instructions), not a hallucination.",
            "For improper output handling, trace where the model's output goes — rendered as HTML (XSS via the model) or passed to a sink — reflection in JSON is a precondition, not execution.",
        ],
        remediation="Treat model output as untrusted input and validate it outside the model; least-privilege tool/agency; keep no secrets in the system prompt; pre-retrieval tenant/ACL filtering for RAG.",
        owasp_2025="A03:2025", cwe=["CWE-77", "CWE-1426"],
        references=["OWASP Top 10 for LLM Applications 2025: LLM01 Prompt Injection (direct/indirect, jailbreaks, multi-turn crescendo), LLM02 Sensitive Information Disclosure, LLM05 Improper Output Handling, LLM06 Excessive Agency, LLM07 System Prompt Leakage; OWASP Top 10 for Agentic Applications", "Reference tooling: NVIDIA garak, Microsoft PyRIT, Promptfoo, DeepTeam"]),

    # ---- grey-box / observability classes (deluluscan/telemetry) ----------------
    "logging_failure": ClassKnowledge(
        summary="Security logging & monitoring failure — a security-relevant action (auth bypass, injection, state change) produces no server log or audit entry, so the attack is invisible to defenders.",
        how_tested="Grey-box: each probe is time-windowed and correlated against the target's own log stream (docker logs). A security-relevant operation whose window contains NO correlated log line is flagged as a detection gap.",
        verify=[
            "Confirm the operation actually SUCCEEDED (2xx / effect persisted) before calling its silence a gap — an unlogged 404 is not a finding.",
            "Confirm the log SINK you observed is the one that should record it — a distinct audit sink you did not tap could still hold the record; state the observation window and sink honestly.",
            "Repeat the operation and confirm the absence is consistent, not a dropped/rate-limited line.",
        ],
        remediation="Log and alert on authentication, authorization decisions, and state-changing operations with enough context to trace them; ship logs to tamper-evident storage and monitor for the events an attacker would trigger.",
        owasp_2025="A09:2025", cwe=["CWE-778", "CWE-223"],
        references=["OWASP A09 Security Logging and Monitoring Failures"]),

    "log_injection": ClassKnowledge(
        summary="Log injection / forging — unsanitized input containing CR/LF or control characters is written to logs, letting an attacker forge log lines, break parsers, or poison a SIEM.",
        how_tested="Grey-box: inputs carrying a benign canary with an embedded newline + forged-line marker are sent, then the log stream is read back to see whether the marker appears at the START of its own line (a forged entry).",
        verify=[
            "Confirm the injected newline actually SPLIT the log — the forged marker must begin its own line, not sit inline within one escaped field.",
            "A raw value appearing inline in a log is a precondition; a value that creates a new, parser-valid line is the finding.",
            "Use only a benign marker (e.g. a fake INFO line with a canary id) — never inject content that would trigger downstream automation.",
        ],
        remediation="Neutralize CR/LF and control characters before logging (or use a structured/JSON logger that encodes them); never interpolate raw request data into a log message.",
        owasp_2025="A05:2025", cwe=["CWE-117"],
        references=["OWASP A05 Injection", "CWE-117 Improper Output Neutralization for Logs"]),

    "memory_disclosure": ClassKnowledge(
        summary="Memory disclosure / debug-surface exposure — an exposed heap dump, thread dump, or diagnostics endpoint (JMX/actuator/Jolokia) leaks in-memory secrets, or a probe drives runaway memory/CPU consumption.",
        how_tested="Reachability probes for heap/thread-dump and diagnostics endpoints, plus grey-box correlation of docker-stats memory/CPU deltas with probes (and OutOfMemoryError in the log stream).",
        verify=[
            "For a dump/diagnostics surface, confirm it is reachable by an under-privileged/anonymous identity AND actually returns memory contents — a 200 stub is not a leak.",
            "For a heap dump, confirm it carries recoverable secrets (tokens/passwords) rather than merely existing — prove impact, do not exfiltrate at scale.",
            "For consumption, MEASURE the memory/CPU delta against baseline and confirm it does not recover (leak) — a transient spike under load is not proof; escalate via the destructive resource pass, restarting between probes.",
        ],
        remediation="Disable or authenticate heap/thread-dump and diagnostics endpoints in production; bound request-driven allocation (pagination caps, entity-expansion limits, query depth/cost) and cap upload/decompression sizes.",
        owasp_2025="A02:2025", api_top10="API8", cwe=["CWE-215", "CWE-200", "CWE-538"],
        references=["OWASP A02 Security Misconfiguration", "CWE-215 Insertion of Sensitive Information Into Debugging Code"]),
}



# Canonical OWASP Top 10:2025 category names.
#
# This lives here, next to the mappings that use it, because it was previously
# duplicated in two renderers and BOTH copies held the 2021 list — so a finding
# classified A02:2025 (Security Misconfiguration) rendered as "Cryptographic
# Failures", which is the 2021 meaning of that code. A wrong category in a
# pentest report is a factual error about the finding, so the codes and their
# names must come from one place.
OWASP_2025_NAME: dict[str, str] = {
    "A01:2025": "Broken Access Control",
    "A02:2025": "Security Misconfiguration",
    "A03:2025": "Software Supply Chain Failures",
    "A04:2025": "Cryptographic Failures",
    "A05:2025": "Injection",
    "A06:2025": "Insecure Design",
    "A07:2025": "Authentication Failures",
    "A08:2025": "Software and Data Integrity Failures",
    "A09:2025": "Security Logging and Monitoring Failures",
    "A10:2025": "Mishandling of Exceptional Conditions",
}


def owasp_2025_label(code: str) -> str:
    """'A02:2025' -> 'A02:2025 Security Misconfiguration'.

    Returns the bare code when the name is unknown rather than guessing — an
    unlabelled code is honest; a wrongly-labelled one is not.
    """
    if not code:
        return ""
    name = OWASP_2025_NAME.get(code.strip())
    return f"{code} {name}" if name else code

def methodology_for(vuln_class) -> Optional[ClassKnowledge]:
    """Return the standing methodology for a VulnClass (or its .value / a str)."""
    key = getattr(vuln_class, "value", vuln_class)
    return METHODOLOGY.get(key)


def verification_steps(vuln_class) -> list[str]:
    k = methodology_for(vuln_class)
    return list(k.verify) if k else []


def remediation_for(vuln_class) -> str:
    k = methodology_for(vuln_class)
    return k.remediation if k else ""


def taxonomy_for(vuln_class) -> dict:
    """OWASP-2025 / API-Top-10 / CWE mapping for a class, for report references."""
    k = methodology_for(vuln_class)
    if not k:
        return {}
    return {"owasp_2025": k.owasp_2025, "api_top10": k.api_top10, "cwe": list(k.cwe)}


def describe() -> str:
    lines = [f"Deluluscan knowledge base: {len(METHODOLOGY)} vulnerability classes", ""]
    for key, k in sorted(METHODOLOGY.items()):
        tax = " · ".join(x for x in [k.owasp_2025, k.api_top10] if x)
        lines.append(f"■ {key}  ({tax})")
        lines.append(f"    {k.summary}")
        for v in k.verify:
            lines.append(f"    - verify: {v[:100]}")
    return "\n".join(lines)


def main(argv=None) -> int:
    print(describe())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
