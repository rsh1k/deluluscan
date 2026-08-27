"""deluluscan.templates — declarative YAML detection templates.

Adding a check to Deluluscan means writing a Python scanner. That is right for
anything needing real logic (differential authz, deep verification, telemetry
correlation), and overkill for the large class of checks that are just
"request these paths, look for these markers". This module makes that second
kind declarative, so a target-specific check can be added by dropping a YAML
file in `templates/` with no Python and no redeploy.

The format is deliberately close to Nuclei's, because that is the format
security engineers already know:

    id: target-example
    info:
      name: Example exposure
      severity: medium
      description: what this detects
      vuln_class: info_leak          # optional; maps into Deluluscan's taxonomy
    http:
      - method: GET
        path:
          - "{{BaseURL}}/api/v1/example"
        matchers-condition: and       # and | or   (default: and)
        matchers:
          - type: status
            status: [200]
          - type: word
            words: ["secret", "token"]
            condition: or             # or | and   (default: or)
            part: body                # body | header | all
          - type: regex
            regex: ["v[0-9]+\\.[0-9]+"]
          - type: dsl
            dsl: ["len(body) > 100"]

Two deliberate departures from Nuclei, both following house rules:

* **Detection only.** There is no template action that writes, deletes or
  executes. A template describes a request and what a response must look like;
  it cannot be used to weaponise anything. Templates that request a
  state-changing method are gated behind the same `--allow-state-changing`
  policy as everything else, via HttpClient.
* **A match is a lead, not a verdict.** Template findings enter the pipeline
  with `confidence="tentative"` and `verdict="unverified"`, so they go through
  the same live re-test and deep verification as any scanner hit. A YAML file
  cannot promote itself to a confirmed finding — which is exactly the failure
  mode that produced the false positives this codebase keeps refuting.

The `dsl` matcher is intentionally NOT a Python eval: it is a tiny expression
grammar over a fixed set of names. Templates are data, and data must not be
able to execute arbitrary code just because it was dropped in a directory.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Any, Iterable

from .models import Endpoint, Finding, Severity, VulnClass
from .scanners.base import Scanner

try:                                                # PyYAML is already a dep
    import yaml
except ImportError:                                 # pragma: no cover
    yaml = None

DEFAULT_TEMPLATE_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "templates")

_VALID_MATCHERS = {"status", "word", "regex", "dsl", "size"}
_VALID_PARTS = {"body", "header", "all"}
# Only these methods are permitted from a template. A template is a detection
# artefact; anything that mutates state belongs in a reviewed Python scanner.
_SAFE_METHODS = {"GET", "HEAD", "OPTIONS", "POST"}


class TemplateError(ValueError):
    """A template is malformed. Raised at load time, never at match time."""


@dataclass
class Matcher:
    type: str
    condition: str = "or"
    part: str = "body"
    negative: bool = False
    status: list[int] = field(default_factory=list)
    words: list[str] = field(default_factory=list)
    regex: list[str] = field(default_factory=list)
    dsl: list[str] = field(default_factory=list)
    size: list[int] = field(default_factory=list)
    case_insensitive: bool = False
    _compiled: list[re.Pattern] = field(default_factory=list, repr=False)

    def haystack(self, body: str, headers: dict[str, str]) -> str:
        if self.part == "header":
            return "\n".join(f"{k}: {v}" for k, v in (headers or {}).items())
        if self.part == "all":
            return "\n".join(f"{k}: {v}" for k, v in (headers or {}).items()) + "\n" + body
        return body

    def matches(self, *, status: int, body: str, headers: dict[str, str]) -> bool:
        result = self._matches(status=status, body=body, headers=headers)
        return (not result) if self.negative else result

    def _matches(self, *, status: int, body: str, headers: dict[str, str]) -> bool:
        if self.type == "status":
            return status in self.status
        if self.type == "size":
            return len(body or "") in self.size

        text = self.haystack(body or "", headers or {})
        if self.case_insensitive:
            text = text.lower()

        if self.type == "word":
            needles = [w.lower() if self.case_insensitive else w for w in self.words]
            hits = [n in text for n in needles]
        elif self.type == "regex":
            hits = [bool(p.search(text)) for p in self._compiled]
        elif self.type == "dsl":
            hits = [evaluate_dsl(expr, status=status, body=body or "",
                                 headers=headers or {}) for expr in self.dsl]
        else:                                        # unreachable: validated on load
            return False
        return all(hits) if self.condition == "and" else any(hits)


@dataclass
class Request:
    method: str = "GET"
    paths: list[str] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)
    body: str | None = None
    matchers: list[Matcher] = field(default_factory=list)
    matchers_condition: str = "and"

    def evaluate(self, *, status: int, body: str, headers: dict[str, str]) -> bool:
        if not self.matchers:
            return False                             # a template that matches everything is a bug
        results = [m.matches(status=status, body=body, headers=headers)
                   for m in self.matchers]
        return all(results) if self.matchers_condition == "and" else any(results)


@dataclass
class Template:
    id: str
    name: str
    severity: str = "info"
    description: str = ""
    vuln_class: str = "misconfig"
    tags: list[str] = field(default_factory=list)
    reference: list[str] = field(default_factory=list)
    remediation: str = ""
    requests: list[Request] = field(default_factory=list)
    source_path: str = ""


# --------------------------------------------------------------------------
# A deliberately small DSL
# --------------------------------------------------------------------------
# Nuclei's DSL is large. Deluluscan supports the handful of predicates that actually
# earn their place, evaluated by a parser rather than by eval(): a template is
# untrusted data, and `eval` on data dropped into a directory is a code
# execution primitive, not a feature.
# The right-hand side is deliberately narrow: a quoted string (which may
# contain spaces), or a bare token with no whitespace and no parentheses. A
# permissive ".+" would accept "0 and __import__('x')" — inert, because nothing
# is ever evaluated, but it would load silently and then never match, which
# hides the author's mistake instead of reporting it.
_DSL_RE = re.compile(
    r"""^\s*
        (?P<lhs>len\(body\)|len\(headers\)|status|body|headers)
        \s*(?P<op><=|>=|==|!=|<|>|\bcontains\b)\s*
        (?P<rhs>"[^"]*"|'[^']*'|[^\s()]+)
    \s*$""", re.X | re.I)


def evaluate_dsl(expr: str, *, status: int, body: str, headers: dict[str, str]) -> bool:
    """Evaluate one DSL expression. Unparseable expressions are False, not errors.

    Returning False rather than raising is deliberate: a malformed expression
    must never cause a template to *match*, and must never take down a scan.
    Malformed expressions are rejected at load time anyway (see `_parse_matcher`).
    """
    m = _DSL_RE.match(expr or "")
    if not m:
        return False
    lhs_name, op, rhs_raw = m.group("lhs").lower(), m.group("op").lower(), m.group("rhs").strip()
    rhs_raw = rhs_raw.strip("\"'")

    if lhs_name == "len(body)":
        lhs: Any = len(body)
    elif lhs_name == "len(headers)":
        lhs = len(headers)
    elif lhs_name == "status":
        lhs = status
    elif lhs_name == "body":
        lhs = body
    else:
        lhs = "\n".join(f"{k}: {v}" for k, v in headers.items())

    if op == "contains":
        return rhs_raw in str(lhs)
    if isinstance(lhs, int):
        try:
            rhs: Any = int(rhs_raw)
        except ValueError:
            return False
    else:
        rhs = rhs_raw
    try:
        return {"<": lhs < rhs, ">": lhs > rhs, "<=": lhs <= rhs,
                ">=": lhs >= rhs, "==": lhs == rhs, "!=": lhs != rhs}[op]
    except TypeError:
        return False


def _parse_matcher(raw: dict, tpl_id: str) -> Matcher:
    if not isinstance(raw, dict):
        raise TemplateError(f"{tpl_id}: each matcher must be a mapping")
    mtype = str(raw.get("type", "")).lower().strip()
    if mtype not in _VALID_MATCHERS:
        raise TemplateError(
            f"{tpl_id}: unknown matcher type {mtype!r}; known: {sorted(_VALID_MATCHERS)}")
    part = str(raw.get("part", "body")).lower().strip()
    if part not in _VALID_PARTS:
        raise TemplateError(f"{tpl_id}: matcher part must be one of {sorted(_VALID_PARTS)}")
    condition = str(raw.get("condition", "or")).lower().strip()
    if condition not in {"and", "or"}:
        raise TemplateError(f"{tpl_id}: matcher condition must be 'and' or 'or'")

    m = Matcher(
        type=mtype, condition=condition, part=part,
        negative=bool(raw.get("negative", False)),
        status=[int(s) for s in raw.get("status", []) or []],
        words=[str(w) for w in raw.get("words", []) or []],
        regex=[str(r) for r in raw.get("regex", []) or []],
        dsl=[str(d) for d in raw.get("dsl", []) or []],
        size=[int(s) for s in raw.get("size", []) or []],
        case_insensitive=bool(raw.get("case-insensitive", raw.get("case_insensitive", False))),
    )
    required = {"status": m.status, "word": m.words, "regex": m.regex,
                "dsl": m.dsl, "size": m.size}[mtype]
    if not required:
        raise TemplateError(f"{tpl_id}: matcher of type '{mtype}' has no values")
    if mtype == "regex":
        for pattern in m.regex:
            try:
                m._compiled.append(re.compile(pattern, re.I if m.case_insensitive else 0))
            except re.error as exc:
                raise TemplateError(f"{tpl_id}: invalid regex {pattern!r}: {exc}") from exc
    if mtype == "dsl":
        for expr in m.dsl:
            if not _DSL_RE.match(expr):
                raise TemplateError(
                    f"{tpl_id}: unsupported DSL expression {expr!r}. Supported: "
                    "len(body)/len(headers)/status/body/headers with "
                    "< <= > >= == != contains")
    return m


def parse_template(raw: dict, source_path: str = "") -> Template:
    """Validate and build a Template from parsed YAML. Raises TemplateError."""
    if not isinstance(raw, dict):
        raise TemplateError(f"{source_path or '<template>'}: top level must be a mapping")
    tpl_id = str(raw.get("id") or "").strip()
    if not tpl_id:
        raise TemplateError(f"{source_path or '<template>'}: missing 'id'")
    if not re.fullmatch(r"[a-z0-9][a-z0-9._-]*", tpl_id):
        raise TemplateError(f"{tpl_id}: id must be lowercase alphanumeric with . _ -")

    info = raw.get("info") or {}
    if not isinstance(info, dict):
        raise TemplateError(f"{tpl_id}: 'info' must be a mapping")
    severity = str(info.get("severity", "info")).lower().strip()
    valid_sev = {s.value for s in Severity}
    if severity not in valid_sev:
        raise TemplateError(f"{tpl_id}: severity {severity!r} not in {sorted(valid_sev)}")
    vuln_class = str(info.get("vuln_class", "misconfig")).lower().strip()
    valid_vc = {v.value for v in VulnClass}
    if vuln_class not in valid_vc:
        raise TemplateError(f"{tpl_id}: vuln_class {vuln_class!r} not in {sorted(valid_vc)}")

    http_blocks = raw.get("http") or raw.get("requests") or []
    if not isinstance(http_blocks, list) or not http_blocks:
        raise TemplateError(f"{tpl_id}: needs at least one 'http' request block")

    requests: list[Request] = []
    for block in http_blocks:
        if not isinstance(block, dict):
            raise TemplateError(f"{tpl_id}: each http block must be a mapping")
        method = str(block.get("method", "GET")).upper().strip()
        if method not in _SAFE_METHODS:
            raise TemplateError(
                f"{tpl_id}: method {method!r} is not permitted in a template. "
                f"Templates are detection-only; allowed: {sorted(_SAFE_METHODS)}. "
                "A state-changing check belongs in a reviewed Python scanner.")
        paths = block.get("path") or block.get("paths") or []
        if isinstance(paths, str):
            paths = [paths]
        paths = [str(p) for p in paths]
        if not paths:
            raise TemplateError(f"{tpl_id}: http block has no 'path'")
        cond = str(block.get("matchers-condition",
                             block.get("matchers_condition", "and"))).lower().strip()
        if cond not in {"and", "or"}:
            raise TemplateError(f"{tpl_id}: matchers-condition must be 'and' or 'or'")
        matchers = [_parse_matcher(m, tpl_id) for m in (block.get("matchers") or [])]
        if not matchers:
            raise TemplateError(
                f"{tpl_id}: http block has no matchers — a template that matches "
                "every response would report every endpoint as a finding")
        requests.append(Request(
            method=method, paths=paths,
            headers={str(k): str(v) for k, v in (block.get("headers") or {}).items()},
            body=block.get("body"), matchers=matchers, matchers_condition=cond))

    return Template(
        id=tpl_id, name=str(info.get("name") or tpl_id), severity=severity,
        description=str(info.get("description") or ""), vuln_class=vuln_class,
        tags=[str(t) for t in (info.get("tags") or [])],
        reference=[str(r) for r in (info.get("reference") or [])],
        remediation=str(info.get("remediation") or ""),
        requests=requests, source_path=source_path)


def load_template_file(path: str) -> Template:
    if yaml is None:                                 # pragma: no cover
        raise TemplateError("PyYAML is required to load templates")
    with open(path, encoding="utf-8") as fh:
        raw = yaml.safe_load(fh)                     # safe_load: never construct objects
    return parse_template(raw, source_path=path)


def load_templates(directory: str | None = None) -> tuple[list[Template], list[str]]:
    """Load every template under `directory`.

    Returns (templates, errors). A broken template is reported and skipped
    rather than aborting the load: one bad file must not disable every check.
    """
    directory = directory or DEFAULT_TEMPLATE_DIR
    templates: list[Template] = []
    errors: list[str] = []
    if not os.path.isdir(directory):
        return templates, errors
    seen: dict[str, str] = {}
    for root, _dirs, files in os.walk(directory):
        for name in sorted(files):
            if not name.endswith((".yaml", ".yml")):
                continue
            path = os.path.join(root, name)
            try:
                tpl = load_template_file(path)
            except (TemplateError, Exception) as exc:   # yaml errors included
                errors.append(f"{path}: {exc}")
                continue
            if tpl.id in seen:
                errors.append(f"{path}: duplicate template id {tpl.id!r} "
                              f"(already defined in {seen[tpl.id]})")
                continue
            seen[tpl.id] = path
            templates.append(tpl)
    return templates, errors


def render_path(path_expr: str, base_url: str) -> str:
    """Resolve {{BaseURL}} in a template path."""
    return path_expr.replace("{{BaseURL}}", base_url.rstrip("/"))


class TemplateScanner(Scanner):
    """Runs YAML templates as a normal Deluluscan scanner.

    Templates are host-level rather than per-endpoint: each declares its own
    absolute paths. The scanner therefore fires once per scan, on the first
    endpoint it is offered, and remembers that it has run.
    """

    name = "templates"
    vuln_classes = ["misconfig", "info_leak", "inventory"]

    def __init__(self, *args, template_dir: str | None = None, **kwargs):
        super().__init__(*args, **kwargs)
        self.templates, self.load_errors = load_templates(template_dir)
        self._ran = False

    def applies_to(self, endpoint: Endpoint) -> bool:
        return bool(self.templates) and not self._ran

    def run(self, endpoint: Endpoint) -> Iterable[Finding]:
        if self._ran:
            return
        self._ran = True
        base_url = getattr(self.config, "base_url", "").rstrip("/")

        for tpl in self.templates:
            for req in tpl.requests:
                for path_expr in req.paths:
                    url = render_path(path_expr, base_url)
                    try:
                        resp = self.client.request(
                            req.method, url, headers=req.headers or None,
                            data=req.body, identity=None)
                    except Exception:
                        continue                      # unreachable path is not a finding
                    if resp is None:
                        continue
                    status = getattr(resp, "status_code", getattr(resp, "status", 0)) or 0
                    body = getattr(resp, "text", "") or ""
                    headers = dict(getattr(resp, "headers", {}) or {})
                    if not req.evaluate(status=status, body=body, headers=headers):
                        continue
                    yield Finding(
                        vuln_class=VulnClass(tpl.vuln_class),
                        severity=Severity(tpl.severity),
                        title=tpl.name,
                        endpoint=f"{req.method} {url}",
                        description=(tpl.description or
                                     f"Template '{tpl.id}' matched this response."),
                        evidence=[],
                        # A template match is a LEAD. It enters the pipeline
                        # unverified so the same live re-test and deep
                        # verification apply as to any other scanner hit.
                        confidence="tentative",
                        verdict="unverified",
                        exploitability="unknown",
                        detail={
                            "test": f"template:{tpl.id}",
                            "template_id": tpl.id,
                            "template_source": tpl.source_path,
                            "tags": tpl.tags,
                            "references": tpl.reference,
                            "remediation": tpl.remediation,
                            "matched_url": url,
                        })


def describe(directory: str | None = None) -> str:
    templates, errors = load_templates(directory)
    lines = [f"Deluluscan templates ({len(templates)} loaded from "
             f"{directory or DEFAULT_TEMPLATE_DIR})", "=" * 66]
    for t in sorted(templates, key=lambda x: (x.severity, x.id)):
        lines.append(f"  [{t.severity:8}] {t.id:34} {t.name}")
        for r in t.requests:
            for p in r.paths:
                lines.append(f"               {r.method} {p}")
    if errors:
        lines += ["", f"{len(errors)} template(s) failed to load:"]
        lines += [f"  ! {e}" for e in errors]
    return "\n".join(lines)


if __name__ == "__main__":
    import sys
    print(describe(sys.argv[1] if len(sys.argv) > 1 else None))
