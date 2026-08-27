"""SQL injection detector.

Detection-only, four complementary signals, all benign:

1. **Error-based:** inject a single quote / SQL metacharacter and look for
   database error fingerprints in the response (Postgres, MySQL, H2, Oracle...).
   the target ships on Postgres, so the Postgres signatures matter most.

2. **Boolean differential:** compare a "true" payload (e.g. `' OR '1'='1`) vs a
   "false" payload (`' AND '1'='2`) appended to a parameter; a meaningful
   difference in response size/status hints at injection.

3. **Time-based:** append a database sleep and measure the latency delta against
   a baseline. We use a single, modest sleep (configurable, default 7s) and only
   flag when the delayed request is clearly slower than baseline. No stacked
   queries, no data exfiltration -- this just answers "is the parameter
   injectable?". Confirmation/exploitation is delegated to sqlmap (opt-in) under
   the integrations module, pointed only at your authorized localhost target.

4. **Body-field injection (POST/PUT/PATCH):** build a minimal seed body from the
   endpoint's request_body_schema (or target-specific heuristics), then run the
   same error-based and boolean-differential probes on each string field. Uses the
   ADMIN identity so that authentication walls don't block the test.

5. **Path-parameter injection:** the target uses path params such as
   /api/items/{var}/fields where {var} is a variable name (string), not
   a UUID. For each non-UUID path param we run error-based, boolean-differential,
   and time-based probes.
"""
from __future__ import annotations

import re
import time
from typing import Any, Iterable

from .base import Scanner, sample_value_for_param
from ..models import (Endpoint, Finding, IdentityRole, Severity, VulnClass)

# ---------------------------------------------------------------------------
# DB error fingerprints
# ---------------------------------------------------------------------------
_DB_ERRORS = re.compile(
    r"(org\.postgresql\.util\.PSQLException|PSQLException|"
    r"syntax error at or near|unterminated quoted string|"
    r"You have an error in your SQL syntax|com\.mysql\.jdbc|"
    r"ORA-\d{5}|org\.h2\.jdbc|JdbcSQLException|"
    r"SQLGrammarException|DotDataException.*SQL)",
    re.IGNORECASE)

# ---------------------------------------------------------------------------
# Payloads
# ---------------------------------------------------------------------------
_ERR_PAYLOADS = ["'", "\"", "')", "';"]
_BOOL_TRUE  = "' OR '1'='1"
_BOOL_FALSE = "' AND '1'='2"

# UUID pattern — path params that match this are skipped for injection.
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Seed-body builder (mirrors bodyinject._seed_from_schema so sqli.py stays
# self-contained and avoids a circular import)
# ---------------------------------------------------------------------------
_TARGET_BODY_SEEDS: list[tuple[re.Pattern[str], dict[str, Any]]] = [
    (re.compile(r"/api/v1/users", re.IGNORECASE),
     {"userId": "test@test.com", "email": "test@test.com",
      "firstName": "test", "lastName": "test"}),
    (re.compile(r"/api/items", re.IGNORECASE),
     {"name": "test", "variable": "testVar",
      "clazz": "com.example.model.type.SimpleType"}),
    (re.compile(r"/api/v1/workflow", re.IGNORECASE),
     {"name": "test", "description": "test"}),
    (re.compile(r"/api/content", re.IGNORECASE),
     {"stName": "webPageContent", "title": "test"}),
]


def _seed_from_schema(schema: dict[str, Any]) -> dict[str, Any] | None:
    """Generate a minimal valid body from a JSON Schema *object* definition."""
    if not schema:
        return None
    props = schema.get("properties")
    if not props:
        for key in ("allOf", "anyOf", "oneOf"):
            for candidate in schema.get(key, []):
                props = candidate.get("properties")
                if props:
                    break
        if not props:
            return None

    body: dict[str, Any] = {}
    for field_name, field_schema in props.items():
        ftype = field_schema.get("type", "string")
        if isinstance(ftype, list):
            ftype = ftype[0]
        if ftype == "string":
            fmt = field_schema.get("format", "")
            if fmt == "email":
                body[field_name] = "test@test.com"
            elif fmt == "uuid":
                body[field_name] = "00000000-0000-0000-0000-000000000000"
            elif fmt in ("date", "date-time"):
                body[field_name] = "2024-01-01"
            else:
                body[field_name] = "test"
        elif ftype in ("integer", "number"):
            body[field_name] = 1
        elif ftype == "boolean":
            body[field_name] = True
        elif ftype == "array":
            body[field_name] = []
        elif ftype == "object":
            body[field_name] = {}
    return body if body else None


def _seed_body_for_endpoint(endpoint: Endpoint) -> dict[str, Any] | None:
    """Return a minimal seed body for the endpoint, or None if unavailable."""
    if endpoint.request_body_schema:
        seed = _seed_from_schema(endpoint.request_body_schema)
        if seed:
            return seed
    for pattern, template in _TARGET_BODY_SEEDS:
        if pattern.search(endpoint.path):
            return dict(template)
    return None


def _string_fields(body: dict[str, Any]) -> list[str]:
    """Keys whose seed values are plain strings (injectable candidates)."""
    return [k for k, v in body.items() if isinstance(v, str)]


def _is_uuid(value: str) -> bool:
    return bool(_UUID_RE.fullmatch(value))


def _param_looks_injectable(param_name: str, seed_value: str) -> bool:
    """Return True if this path param is worth injecting into.

    We skip params whose seed value is a UUID (they are opaque identifiers
    the backend typically looks up by exact match, not SQL LIKE / ORDER BY).
    Variable-name-style params (e.g. contentType variable, workflow step name)
    are worth testing.
    """
    return not _is_uuid(seed_value)


# ===========================================================================
class SqliScanner(Scanner):
    name = "sqli"
    vuln_classes = [VulnClass.SQLI.value]

    def applies_to(self, endpoint: Endpoint) -> bool:
        if endpoint.query_params:
            return True
        if endpoint.method.upper() in ("POST", "PUT", "PATCH"):
            return True
        if endpoint.path_params:
            return True
        return False

    def run(self, endpoint: Endpoint) -> Iterable[Finding]:
        # --- identity resolution -------------------------------------------
        # Query/path param probes: prefer backend, fall back to anon.
        identity = (self.identities.get(IdentityRole.BACKEND.value)
                    or self.identities.get(IdentityRole.ANON.value))
        # Body probes: prefer admin so auth walls don't hide the body processing.
        admin_identity = (self.identities.get(IdentityRole.ADMIN.value)
                          or self.identities.get(IdentityRole.BACKEND.value)
                          or identity)

        # --- query parameters ----------------------------------------------
        for qp in endpoint.query_params[:6]:
            name = qp.get("name")
            if not name:
                continue
            schema = qp.get("schema", {}) or {}
            # Skip boolean params: any SQL payload is treated as `false` by the
            # server, producing a legitimate size differential that looks like SQLi.
            if schema.get("type") == "boolean":
                continue
            # Skip enum-only params: only allowed values are accepted.
            if schema.get("enum"):
                continue
            # Use the OpenAPI schema default/example/enum as the seed value
            # so we probe with a value the server actually accepts, not "1".
            seed = (schema.get("example") or schema.get("default")
                    or (schema.get("enum") or [None])[0])
            # Normalise Python True/False to lowercase for URL params.
            if isinstance(seed, bool):
                seed = str(seed).lower()
            seed_str = str(seed) if seed is not None else "1"
            yield from self._probe_param(endpoint, identity, name, seed=seed_str)

        # --- JSON body fields (POST/PUT/PATCH) -----------------------------
        if endpoint.method.upper() in ("POST", "PUT", "PATCH"):
            yield from self._probe_body_fields(endpoint, admin_identity)

        # --- path parameters -----------------------------------------------
        for param_name in endpoint.path_params:
            seed_val = sample_value_for_param(param_name)
            if _param_looks_injectable(param_name, seed_val):
                yield from self._probe_path_param(endpoint, identity, param_name)

    # -----------------------------------------------------------------------
    # Query-parameter probes (original logic, unchanged)
    # -----------------------------------------------------------------------

    def _probe_param(self, endpoint, identity, param, seed: str = "1") -> Iterable[Finding]:
        # baseline — use the OpenAPI-derived seed so the endpoint responds
        base = self.fetch(endpoint, identity, params={param: seed})

        # A database error alone does NOT mean injection. A sanitizer that BLANKS a
        # rejected value can make the caller build invalid SQL, producing an error
        # that has nothing to do with our payload's content. Observed live on
        # the target: GET /api/categories?orderby=<anything non-allowlisted> yields
        # the IDENTICAL "syntax error at or near \"ASC\"" at the SAME position for
        # a quote, a space, a semicolon or a subquery, because sanitizeSortBy
        # returned blank and the caller emitted `ORDER BY  ASC`. pg_sleep payloads
        # had zero timing effect. Two CRITICAL false positives came from trusting
        # the signature alone.
        #
        # Control: a value that is certainly rejected but contains no SQL syntax.
        # If our payload produces the SAME error as this control, the input was
        # normalised away and we have learned nothing about injection.
        _ctl = self.fetch(endpoint, identity,
                          params={param: "deluluscanNeutralRejectedValue"})
        _ctl_err = _DB_ERRORS.search(_ctl.resp_body or "")
        _ctl_sig = (_ctl_err.group(0)[:120] if _ctl_err else None)

        # 1) error-based
        for payload in _ERR_PAYLOADS:
            rec = self.fetch(endpoint, identity, params={param: f"{seed}{payload}"})
            m = _DB_ERRORS.search(rec.resp_body)
            if m and _ctl_sig and m.group(0)[:120] == _ctl_sig:
                # Same error as a payload-free rejected value => sanitizer
                # normalisation, not injection. Report the real defect instead.
                yield Finding(
                    vuln_class=VulnClass.ERROR_HANDLING, severity=Severity.MEDIUM,
                    title=f"Rejected '{param}' value produces HTTP {rec.status} and may "
                          f"disclose the SQL statement",
                    endpoint=endpoint.key,
                    description=(
                        f"A non-allowlisted '{param}' value causes a database error, but this "
                        f"is NOT injection: a payload-free control value produces the identical "
                        f"error ({_ctl_sig[:60]}...), which means the input was normalised or "
                        f"blanked before reaching SQL rather than being interpolated into it. "
                        f"The real defect is that the rejected value is concatenated with no "
                        f"fallback, so the request fails with a server error"
                        + (" and the response discloses the SQL statement."
                           if '"SQL"' in (rec.resp_body or "") or "SELECT" in (rec.resp_body or "")
                           else ".")),
                    evidence=[base, _ctl, rec],
                    detail={"param": param, "payload": payload,
                            "signature": m.group(0)[:120],
                            "control_signature": _ctl_sig,
                            "why_not_injection": ("payload and payload-free control produce the "
                                                  "same database error, so payload content never "
                                                  "reached the statement"),
                            "remediation": ("Fall back to a safe default when the sort/filter "
                                            "value is rejected, and never serialise the SQL "
                                            "statement into an error response."),
                            "cwe": "CWE-209"},
                    confidence="firm", verdict="true_positive",
                    exploitability="not_exploitable")
                return
            if m:
                yield Finding(
                    vuln_class=VulnClass.SQLI, severity=Severity.CRITICAL,
                    title=f"SQL error triggered by query param '{param}'",
                    endpoint=endpoint.key,
                    description=(
                        f"Injecting {payload!r} into query parameter '{param}' "
                        f"produced a database error signature "
                        f"({m.group(0)[:60]}...). This strongly indicates SQL "
                        f"injection. Confirm with the sqlmap integration against "
                        f"your localhost target."),
                    evidence=[base, rec],
                    detail={"param": param, "payload": payload,
                            "signature": m.group(0)[:120]},
                    confidence="firm")
                return

        # 2) boolean differential
        t = self.fetch(endpoint, identity, params={param: f"{seed}{_BOOL_TRUE}"})
        f = self.fetch(endpoint, identity, params={param: f"{seed}{_BOOL_FALSE}"})
        if (t.status == 200 and f.status == 200 and
                abs(t.resp_len - f.resp_len) > max(64, int(0.2 * (base.resp_len + 1)))):
            yield Finding(
                vuln_class=VulnClass.SQLI, severity=Severity.HIGH,
                title=f"Boolean-differential response on query param '{param}'",
                endpoint=endpoint.key,
                description=(
                    f"A true-condition payload and a false-condition payload on "
                    f"query parameter '{param}' produced materially different "
                    f"response sizes ({t.resp_len} vs {f.resp_len} bytes). This "
                    f"is a boolean-based SQLi indicator. Verify with sqlmap."),
                evidence=[t, f],
                detail={"param": param, "true_len": t.resp_len,
                        "false_len": f.resp_len},
                confidence="tentative")
            return

        # 3) structural differential — tests SQL terminator + comment injection
        # that rewrites a clause without producing an error (e.g. ORDER BY param).
        # Confirmed in the target /api/items?orderby=name'-- which reduces
        # response from ~52KB to ~44KB by commenting out part of the ORDER BY.
        threshold = max(512, int(0.05 * (base.resp_len + 1)))
        for struct_payload in ("'--", "' --", "';--"):
            struct_rec = self.fetch(endpoint, identity,
                                    params={param: f"{seed}{struct_payload}"})
            # Control: a benign suffix of similar length with NO SQL meaning. If
            # this ALSO shifts the response size by a comparable amount, the
            # endpoint is simply search/filter-term sensitive (the param narrows
            # a result set), and the size delta is NOT evidence of SQL-structural
            # rewriting. Appending "'--" to a LIKE search changes the matches too,
            # which is the dominant structural-SQLi false positive.
            ctrl_rec = self.fetch(endpoint, identity, params={param: f"{seed}zqx9"})
            sql_delta = abs(struct_rec.resp_len - base.resp_len)
            ctrl_delta = abs(ctrl_rec.resp_len - base.resp_len)
            if (struct_rec.status == 200 and base.status == 200
                    and sql_delta > threshold
                    and sql_delta > 3 * max(ctrl_delta, 1)):
                yield Finding(
                    vuln_class=VulnClass.SQLI, severity=Severity.HIGH,
                    title=f"Structural SQLi differential on query param '{param}'",
                    endpoint=endpoint.key,
                    description=(
                        f"A SQL terminator+comment payload ('{struct_payload}') "
                        f"on query parameter '{param}' caused a {sql_delta} byte "
                        f"response size change ({base.resp_len} → "
                        f"{struct_rec.resp_len} bytes), while a benign suffix of "
                        f"similar length changed it only {ctrl_delta} bytes. Because "
                        f"the SQL-comment payload shifts the response far more than a "
                        f"non-SQL change to the same parameter, the value is "
                        f"interpolated into a SQL clause (e.g. ORDER BY) without "
                        f"quoting, allowing structural rewriting. Verify with sqlmap."),
                    evidence=[base, struct_rec, ctrl_rec],
                    detail={"param": param, "payload": struct_payload,
                            "baseline_len": base.resp_len,
                            "injected_len": struct_rec.resp_len,
                            "control_len": ctrl_rec.resp_len,
                            "control_delta": ctrl_delta},
                    confidence="tentative")
                return

        # 4) time-based blind. A SINGLE sleep probe marked "firm" is unreliable:
        # a GC pause, cold cache, or slow query trips the threshold once. Require
        # the delay to REPRODUCE across two probes AND a pg_sleep(0) control (same
        # query shape, no delay) to stay fast — that separates real injectable
        # latency from ambient jitter. Only both-delayed + fast-control is "firm".
        sleep = self.config.scan.sqli_sleep_s
        baseline_ms = base.elapsed_ms
        threshold = baseline_ms + sleep * 1000 * 0.7
        payload = f"{seed}' AND (SELECT 1 FROM pg_sleep({sleep}))--"
        zero_payload = f"{seed}' AND (SELECT 1 FROM pg_sleep(0))--"
        delays = []
        rec = None
        for _ in range(2):
            rec = self.fetch(endpoint, identity, params={param: payload})
            delays.append(rec.elapsed_ms)
        ctrl = self.fetch(endpoint, identity, params={param: zero_payload})
        hits = sum(1 for d in delays if d > threshold)
        control_fast = ctrl.elapsed_ms <= threshold
        if hits >= 1 and control_fast:
            conf = "firm" if hits == 2 else "tentative"
            yield Finding(
                vuln_class=VulnClass.SQLI, severity=Severity.HIGH,
                title=f"Time-based delay on query param '{param}'",
                endpoint=endpoint.key,
                description=(
                    f"A pg_sleep({sleep}) payload on query parameter '{param}' "
                    f"delayed the response ({'/'.join(f'{d:.0f}' for d in delays)}ms "
                    f"across {hits}/2 probes) vs a {baseline_ms:.0f}ms baseline, "
                    f"while a pg_sleep(0) control returned in {ctrl.elapsed_ms:.0f}ms "
                    f"(below threshold). The delay tracks the requested sleep and "
                    f"not ambient latency — a time-based blind SQLi indicator. "
                    f"Confirm with sqlmap; the scanner used only benign sleeps and "
                    f"did not read or modify any data."),
                evidence=[base, rec, ctrl],
                detail={"param": param, "baseline_ms": baseline_ms,
                        "delayed_ms": delays, "control_ms": ctrl.elapsed_ms,
                        "sleep_s": sleep, "reproductions": hits},
                confidence=conf)

    # -----------------------------------------------------------------------
    # JSON body field probes
    # -----------------------------------------------------------------------

    def _probe_body_fields(self, endpoint: Endpoint, identity) -> Iterable[Finding]:
        """Run error-based and boolean-differential SQLi on each string field
        of the request body.  Uses *admin* identity so auth walls don't
        prevent the body from being processed by the application."""
        seed = _seed_body_for_endpoint(endpoint)
        if not seed:
            return
        string_fields = _string_fields(seed)
        if not string_fields:
            return

        # Baseline: does the endpoint respond at all to a valid body?
        baseline = self.fetch(endpoint, identity, json_body=seed)
        if baseline.status == 0:
            return  # network error — skip

        # We continue even on 4xx: some endpoints return 400 for our dummy
        # seed but still reflect DB error text in the response body.
        for field_name in string_fields[:8]:
            finding = self._probe_body_field(
                endpoint, identity, seed, field_name, baseline)
            if finding:
                yield finding
                return  # one confirmed body-injection finding per endpoint is enough

    def _probe_body_field(self, endpoint: Endpoint, identity,
                          seed: dict[str, Any], field_name: str,
                          baseline) -> Finding | None:
        """Test a single body string field for SQL injection.

        1. Error-based: inject SQL metacharacters, scan response for DB errors.
        2. Boolean differential: compare true/false condition response sizes.

        Returns the first Finding encountered, or None.
        """
        original_value = seed[field_name]

        # --- 1. Error-based ---
        for payload in _ERR_PAYLOADS:
            body = dict(seed)
            body[field_name] = original_value + payload
            rec = self.fetch(endpoint, identity, json_body=body)
            m = _DB_ERRORS.search(rec.resp_body)
            if m:
                return Finding(
                    vuln_class=VulnClass.SQLI,
                    severity=Severity.CRITICAL,
                    title=(f"SQL error via body field '{field_name}' on "
                           f"{endpoint.key}"),
                    endpoint=endpoint.key,
                    description=(
                        f"Injecting {payload!r} into JSON body field "
                        f"'{field_name}' produced a database error signature: "
                        f"{m.group(0)[:80]}. This strongly indicates SQL "
                        f"injection via the request body. The probe was sent "
                        f"with admin credentials to bypass auth walls. Confirm "
                        f"with sqlmap against your localhost target."),
                    evidence=[baseline, rec],
                    detail={"field": field_name, "payload": payload,
                            "signature": m.group(0)[:120],
                            "identity": identity.label()},
                    confidence="firm",
                )

        # --- 2. Boolean differential ---
        body_true = dict(seed)
        body_true[field_name] = original_value + _BOOL_TRUE
        body_false = dict(seed)
        body_false[field_name] = original_value + _BOOL_FALSE

        rec_true  = self.fetch(endpoint, identity, json_body=body_true)
        rec_false = self.fetch(endpoint, identity, json_body=body_false)

        if (rec_true.status == 200 and rec_false.status == 200
                and abs(rec_true.resp_len - rec_false.resp_len)
                > max(64, int(0.2 * (baseline.resp_len + 1)))):
            return Finding(
                vuln_class=VulnClass.SQLI,
                severity=Severity.HIGH,
                title=(f"Boolean-differential SQLi in body field "
                       f"'{field_name}' on {endpoint.key}"),
                endpoint=endpoint.key,
                description=(
                    f"True-condition and false-condition payloads in JSON "
                    f"body field '{field_name}' produced materially different "
                    f"response sizes ({rec_true.resp_len} vs "
                    f"{rec_false.resp_len} bytes). Boolean-based SQLi "
                    f"indicator via the request body. Verify with sqlmap."),
                evidence=[rec_true, rec_false],
                detail={"field": field_name,
                        "true_len": rec_true.resp_len,
                        "false_len": rec_false.resp_len,
                        "identity": identity.label()},
                confidence="tentative",
            )

        return None

    # -----------------------------------------------------------------------
    # Path-parameter probes
    # -----------------------------------------------------------------------

    def _probe_path_param(self, endpoint: Endpoint, identity,
                          param_name: str) -> Iterable[Finding]:
        """Probe a path parameter for SQL injection (error-based, boolean-
        differential, and time-based).

        the target uses path params such as /api/items/{var}/fields
        where {var} is a variable name (arbitrary string), not a UUID.
        Those string-type params feed directly into HQL/SQL queries in some
        endpoints and are worth testing.
        """
        seed_val = sample_value_for_param(param_name)

        # baseline — other path params keep their seed values
        base = self.fetch(endpoint, identity,
                          path_overrides={param_name: seed_val})

        # --- 1. Error-based ---
        for payload in _ERR_PAYLOADS:
            injected = seed_val + payload
            rec = self.fetch(endpoint, identity,
                             path_overrides={param_name: injected})
            m = _DB_ERRORS.search(rec.resp_body)
            if m:
                yield Finding(
                    vuln_class=VulnClass.SQLI,
                    severity=Severity.CRITICAL,
                    title=f"SQL error triggered by path param '{{{param_name}}}'",
                    endpoint=endpoint.key,
                    description=(
                        f"Injecting {payload!r} into path parameter "
                        f"'{{{param_name}}}' produced a database error "
                        f"signature ({m.group(0)[:60]}...). the target's endpoints "
                        f"that accept variable names / string identifiers in "
                        f"the path can pass them unsanitised to HQL or SQL. "
                        f"Confirm with sqlmap against your localhost target."),
                    evidence=[base, rec],
                    detail={"path_param": param_name, "payload": payload,
                            "signature": m.group(0)[:120]},
                    confidence="firm",
                )
                return

        # --- 2. Boolean differential ---
        inj_true  = seed_val + _BOOL_TRUE
        inj_false = seed_val + _BOOL_FALSE
        rec_true  = self.fetch(endpoint, identity,
                               path_overrides={param_name: inj_true})
        rec_false = self.fetch(endpoint, identity,
                               path_overrides={param_name: inj_false})
        if (rec_true.status == 200 and rec_false.status == 200
                and abs(rec_true.resp_len - rec_false.resp_len)
                > max(64, int(0.2 * (base.resp_len + 1)))):
            yield Finding(
                vuln_class=VulnClass.SQLI,
                severity=Severity.HIGH,
                title=(f"Boolean-differential response on path param "
                       f"'{{{param_name}}}'"),
                endpoint=endpoint.key,
                description=(
                    f"True-condition and false-condition payloads in path "
                    f"parameter '{{{param_name}}}' produced materially "
                    f"different response sizes ({rec_true.resp_len} vs "
                    f"{rec_false.resp_len} bytes). Boolean-based SQLi "
                    f"indicator via path parameter. Verify with sqlmap."),
                evidence=[rec_true, rec_false],
                detail={"path_param": param_name,
                        "true_len": rec_true.resp_len,
                        "false_len": rec_false.resp_len},
                confidence="tentative",
            )
            return

        # --- 3. Time-based (multi-probe + pg_sleep(0) control; see query-param
        # path for rationale — a single sleep probe is unreliable jitter). ---
        sleep = self.config.scan.sqli_sleep_s
        baseline_ms = base.elapsed_ms
        threshold = baseline_ms + sleep * 1000 * 0.7
        time_payload = seed_val + f"' AND (SELECT 1 FROM pg_sleep({sleep}))--"
        zero_payload = seed_val + "' AND (SELECT 1 FROM pg_sleep(0))--"
        delays = []
        rec = None
        for _ in range(2):
            rec = self.fetch(endpoint, identity,
                             path_overrides={param_name: time_payload})
            delays.append(rec.elapsed_ms)
        ctrl = self.fetch(endpoint, identity, path_overrides={param_name: zero_payload})
        hits = sum(1 for d in delays if d > threshold)
        if hits >= 1 and ctrl.elapsed_ms <= threshold:
            yield Finding(
                vuln_class=VulnClass.SQLI,
                severity=Severity.HIGH,
                title=f"Time-based delay on path param '{{{param_name}}}'",
                endpoint=endpoint.key,
                description=(
                    f"A pg_sleep({sleep}) payload in path parameter "
                    f"'{{{param_name}}}' delayed the response "
                    f"({'/'.join(f'{d:.0f}' for d in delays)}ms across {hits}/2 probes) "
                    f"vs a {baseline_ms:.0f}ms baseline, while a pg_sleep(0) control "
                    f"returned in {ctrl.elapsed_ms:.0f}ms. Time-based blind SQLi "
                    f"indicator via path parameter. Confirm with sqlmap; the scanner "
                    f"used only benign sleeps and did not read or modify any data."),
                evidence=[base, rec, ctrl],
                detail={"path_param": param_name,
                        "baseline_ms": baseline_ms,
                        "delayed_ms": delays,
                        "control_ms": ctrl.elapsed_ms,
                        "sleep_s": sleep,
                        "reproductions": hits},
                confidence="firm" if hits == 2 else "tentative",
            )
