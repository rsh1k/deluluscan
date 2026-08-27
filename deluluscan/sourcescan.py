"""Source-informed scanning.

The target source is open (github.com/the target source). Rather than probe blindly, we
read the code, find *concrete* dangerous patterns keyed to real the target shapes, map
each one to the REST endpoint + parameter it sits behind, and emit a targeted live
probe. The source tells us WHERE and WHAT to test; the dynamic check confirms
whether it is real on the running instance.

Boundary: this module only READS source (local clone preferred, else raw.github
fetch of specific files) and turns findings into *probes* that the existing,
safety-gated scanners execute. It never executes code from the repo, never clones
via arbitrary shell, and adds no new request path outside HttpClient.

Design (approved with the user):
  - source access: prefer a local clone, fall back to fetching specific files
  - analysis: static grep for known-dangerous patterns + optional AI review of the
    surrounding snippet to drop false leads
  - output: auto-generate a live probe (SourceCandidate) per surviving pattern,
    ranked by severity
"""
from __future__ import annotations

import glob
import json
import os
import re
from dataclasses import dataclass, field
from typing import Callable, Iterable, Optional

from .models import Severity, VulnClass


# --------------------------------------------------------------------------- #
# Pattern library — each entry encodes a real target-specific danger signal.
# `regex` matches the dangerous shape; `sink`/`guard` refine it; `vuln_class`,
# `severity`, and `probe` describe how to confirm it live.
# --------------------------------------------------------------------------- #
@dataclass
class SourcePattern:
    id: str
    vuln_class: str
    severity: Severity
    description: str
    # regex that flags a suspicious line/block (compiled case-insensitively)
    regex: re.Pattern
    # if this guard token appears in the same method body, the danger is mitigated
    # (e.g. orderBy that IS passed through sanitizeSortBy) -> not a candidate
    guard: Optional[re.Pattern] = None
    # Look for `guard` in the classes this method DELEGATES to, not just in the
    # method itself. the target consistently sanitizes one layer down (the resource
    # hands orderBy to a Paginator/Factory and THAT calls SQLUtil.sanitizeSortBy),
    # so a method-local check reports every such endpoint as a critical SQLi.
    # Measured on the target source @94c5c8cf: 14/14 orderby_sqli candidates were false
    # positives for exactly this reason.
    check_downstream: bool = False
    # how to turn a match into a live probe: which param to fuzz + payloads
    probe_param_hint: tuple[str, ...] = ()
    probe_kind: str = ""            # sqli | authz | rce | ssti | deserialize
    # only consider files whose path contains one of these (keeps it targeted)
    path_hint: tuple[str, ...] = ("/rest/", "Resource.java")


_PATTERNS: list[SourcePattern] = [
    # 1) orderBy SQL injection: the confirmed class. the target's intended defense is
    #    SQLUtil.sanitizeSortBy / ORDERBY_WHITELIST (see issue #19500). A resource
    #    that takes an orderby param and reaches pagination WITHOUT that guard is a
    #    candidate.
    SourcePattern(
        id="orderby_sqli",
        vuln_class=VulnClass.SQLI.value,
        severity=Severity.CRITICAL,
        description=("An 'orderBy'/'orderby' request parameter reaches a query or "
                     "PaginationUtil without passing through SQLUtil.sanitizeSortBy / "
                     "ORDERBY_WHITELIST — the same unsanitized-sort class as the "
                     "/api/v1/containers and /api/v1/categories orderby SQLi."),
        regex=re.compile(r"(?i)@QueryParam\(\s*\"orderby\"|String\s+orderBy\b|"
                         r"orderBy\s*=|\"orderby\""),
        guard=re.compile(r"(?i)sanitizeSortBy|ORDERBY_WHITELIST|sanitizeParameter"),
        probe_param_hint=("orderby", "orderBy", "direction"),
        probe_kind="sqli",
        check_downstream=True,
    ),
    # 2) generic string-built SQL: concatenation / String.format into a SQL string,
    #    or DotConnect.setSQL with '+' — classic injection sink.
    SourcePattern(
        id="concat_sql",
        vuln_class=VulnClass.SQLI.value,
        severity=Severity.HIGH,
        description=("A SQL string appears to be built with concatenation or "
                     "String.format from request-derived values (DotConnect/"
                     "setSQL/addParam missing), risking SQL injection."),
        regex=re.compile(r"(?i)(setSQL|dc\.setSQL|new\s+DotConnect\(\)).{0,80}"
                         r"(\+\s*\w+|String\.format)"),
        guard=re.compile(r"(?i)addParam|\?\s*,|PreparedStatement"),
        probe_param_hint=("filter", "query", "sites", "id"),
        probe_kind="sqli",
        path_hint=("/rest/", "Resource.java", "API.java", "Factory.java"),
        check_downstream=True,
    ),
    # 3) missing function-level authz on a state-changing resource method: a
    #    @PUT/@POST/@DELETE handler with NO permission/role/user check in scope.
    #    This is the _addtouser / BFLA class.
    SourcePattern(
        id="missing_authz",
        vuln_class=VulnClass.AUTHZ.value,
        severity=Severity.HIGH,
        description=("A state-changing REST method (@PUT/@POST/@DELETE) has no "
                     "visible authorization check (no WebResource.init / "
                     "requiredBackendUser / requiredPortlet / permission / role "
                     "guard), so a low-privilege user may reach an admin operation "
                     "(BFLA)."),
        regex=re.compile(r"(?i)@(PUT|POST|DELETE)\b"),
        # the target authorizes via a WebResource.InitBuilder chain (often multi-line,
        # ending in .init()) and/or explicit permission/role checks. Any of these
        # in the method body means the endpoint IS gated. Matched against
        # comment-stripped code with DOTALL so multi-line chains are seen.
        guard=re.compile(
            r"(?is)"
            r"webresource\s*\.\s*init|"
            r"new\s+webresource\.initbuilder|"
            r"\.init\s*\(\s*(req|request)[^)]*\)|"
            r"requiredbackenduser|requiredportlet|requiredfrontenduser|"
            r"rejectwhennouser|requiredroles?|requireduser\b|"
            r"requirepermission|checkpermission|doesuserhavepermission|"
            r"doesuserhaverole|iscmsadmin|loadcmsadminrole|hasrole|"
            r"@requiresrole|@permissionsutil|permissionapi|"
            r"initdataobject"),
        probe_param_hint=(),
        probe_kind="authz",
    ),
    # 4) Velocity / VTL evaluation of request input -> template injection / RCE.
    SourcePattern(
        id="velocity_ssti",
        vuln_class=VulnClass.SUPPLY_CHAIN.value,
        severity=Severity.CRITICAL,
        description=("Request-controlled input is evaluated by the Velocity engine "
                     "(evaluate/mergeTemplate/VelocityUtil), a server-side template "
                     "injection -> code-execution surface."),
        regex=re.compile(r"(?i)(velocity[\w.]*\.(eval|evaluate|merge)\w*|"
                         r"mergeTemplate|evalVelocity|VelocityEval|\.evaluateVTL)"),
        guard=None,
        probe_param_hint=("velocity", "code", "script", "body"),
        probe_kind="ssti",
        path_hint=("/rest/", "Resource.java", "VTL", "Velocity"),
    ),
    # 5) Java deserialization of request data -> RCE.
    SourcePattern(
        id="deserialize",
        vuln_class=VulnClass.SUPPLY_CHAIN.value,
        severity=Severity.HIGH,
        description=("Untrusted input appears to be deserialized "
                     "(ObjectInputStream/readObject/XStream/SerializationUtils), a "
                     "remote code-execution risk."),
        regex=re.compile(r"(?i)(ObjectInputStream|\.readObject\(|XStream\(|"
                         r"SerializationUtils\.deserialize)"),
        guard=re.compile(r"(?i)validateClass|ClassFilter|allowTypes|resolveClass"),
        probe_param_hint=("body",),
        probe_kind="deserialize",
        path_hint=("/rest/", "Resource.java"),
    ),
]


# --------------------------------------------------------------------------- #
# Source candidate + provider
# --------------------------------------------------------------------------- #
@dataclass
class SourceCandidate:
    pattern_id: str
    vuln_class: str
    severity: Severity
    description: str
    file_path: str
    line_no: int
    snippet: str
    endpoint_path: Optional[str] = None   # e.g. /api/v1/categories
    http_methods: tuple[str, ...] = ()
    probe_params: tuple[str, ...] = ()
    probe_kind: str = ""
    ai_verdict: str = ""                  # confirmed | unlikely | "" (not reviewed)
    ai_reason: str = ""
    source: str = "sourcescan"            # sourcescan (regex pattern) | mantis
    # Mantis calibration + triage carried through so the live pass can act on the
    # work Mantis's 16-stage funnel already did (see load_mantis_findings).
    risk_score: float = 0.0               # Mantis mantis_risk_score 0.1-10.0 (0 = unknown)
    identity_hint: str = ""               # identity to probe as, from privileges_required
    provenance: dict = field(default_factory=dict)   # status/repro/commit/signature


class SourceProvider:
    """Prefer a local clone; fall back to fetching specific files from GitHub raw.

    `fetch_url(url)` is injected (the orchestrator passes an HttpClient-backed
    fetcher) so that all network egress still goes through one controlled place.
    """

    RAW_BASE = "https://raw.githubusercontent.com/the target source/main/"
    # the source subtree that holds the REST resources
    REST_ROOT = "./app-src/main/java/com/example/rest/"

    def __init__(self, local_root: Optional[str], fetch_text: Optional[Callable[[str], Optional[str]]] = None):
        self.local_root = local_root if local_root and os.path.isdir(local_root) else None
        self.fetch_text = fetch_text
        # a small curated file list to fetch when there is no local clone (keeps
        # the GitHub path fast + deterministic). Extended by discovered endpoints.
        self.seed_files = [
            "./app-src/main/java/com/example/rest/api/v1/categories/CategoryResource.java",
            "./app-src/main/java/com/example/rest/api/v1/container/ContainerResource.java",
            "./app-src/main/java/com/example/rest/api/v1/template/TemplateResource.java",
            "./app-src/main/java/com/example/rest/api/v1/role/RoleResource.java",
            "./app-src/main/java/com/example/rest/api/v1/user/UserResource.java",
            "./app-src/main/java/com/example/rest/api/v1/authentication/AuthenticationResource.java",
            "./app-src/main/java/com/example/rest/api/v1/template/VTLResource.java",
            "./app-src/main/java/com/example/rest/api/v1/system/AppContextInitResource.java",
        ]

    def iter_source_files(self, max_files: int = 60,
                          accept=None) -> Iterable[tuple[str, str]]:
        """Yield (path, text) for candidate source files.

        By default this walks ONLY `*Resource.java` under the REST tree — 125 of
        the target's 7,779 java files. That default is a real blind spot: an XXE in
        bundle import, an unsafe YAML constructor, or a reachable script engine
        lives outside `rest/` and was therefore invisible to every pattern, no
        matter how well written. Pass `accept(path)->bool` to widen the walk to
        the whole clone (the analyzer derives one from the active patterns'
        path_hints), still bounded by max_files.
        """
        if self.local_root:
            broad = accept is not None
            root = self.local_root if broad else os.path.join(self.local_root, self.REST_ROOT)
            if not os.path.isdir(root):
                root = self.local_root  # user pointed directly at the rest dir
            count = 0
            for dirpath, _dirs, files in os.walk(root):
                for fn in files:
                    if not fn.endswith(".java"):
                        continue
                    fp = os.path.join(dirpath, fn)
                    if broad:
                        if not accept(fp):
                            continue
                    elif not fn.endswith("Resource.java"):
                        continue
                    try:
                        with open(fp, "r", encoding="utf-8", errors="replace") as fh:
                            yield (fp, fh.read())
                        count += 1
                        if count >= max_files:
                            return
                    except OSError:
                        continue
            return
        # no local clone -> fetch the seed files from GitHub raw
        if self.fetch_text is None:
            return
        for rel in self.seed_files[:max_files]:
            txt = self.fetch_text(self.RAW_BASE + rel)
            if txt:
                yield (rel, txt)


# --------------------------------------------------------------------------- #
# Analyzer
# --------------------------------------------------------------------------- #
_PATH_RE = re.compile(r'@Path\s*\(\s*"(/?[^"]+)"\s*\)')
_METHOD_ANNOT = re.compile(r"@(GET|POST|PUT|DELETE|PATCH)\b")


class SourceAnalyzer:
    def __init__(self, provider: SourceProvider, analyst=None, use_ai: bool = False):
        self.provider = provider
        self.analyst = analyst
        self.use_ai = use_ai and analyst is not None

    def analyze(self, max_files: int = 60, broad: bool = False) -> list[SourceCandidate]:
        """`broad=True` walks the whole clone, keeping any file whose path matches
        some active pattern's path_hint. Needed for patterns that target code
        OUTSIDE the REST layer (XML/bundle import, script engines, publishing) —
        the default REST-only walk makes those patterns silently unmatchable."""
        candidates: list[SourceCandidate] = []
        analyzer_skipped.clear()
        analyzer_skipped.update({"in_comment": 0, "guarded_downstream": 0})
        accept = None
        if broad:
            hints = tuple({h for pat in _PATTERNS for h in pat.path_hint})

            def accept(fp: str, _h=hints) -> bool:
                return any(h in fp for h in _h)

        for path, text in self.provider.iter_source_files(max_files=max_files,
                                                          accept=accept):
            class_path = self._class_path(text)          # @Path on the resource class
            # Match against a comment-MASKED copy (same length, so every offset and
            # line number still lines up with `text`). Previously the pattern ran
            # over raw text, so javadoc like
            #   * api/v1/categories?orderby=order-field-name
            # was reported as a critical SQLi. Measured on the target source @94c5c8cf:
            # 5/316 candidates were doc comments, including /api/v1/categories.
            masked = self._mask_comments(text)
            file_code = self._strip_comments(text)
            for pat in _PATTERNS:
                if not any(h in path for h in pat.path_hint):
                    continue
                for m in pat.regex.finditer(masked):
                    block, line_no = self._method_block(text, m.start())
                    code = self._strip_comments(block)
                    # guard present in the enclosing method CODE (not comments) ->
                    # mitigated, skip
                    if pat.guard is not None and pat.guard.search(code):
                        continue
                    # ...or present in a class this method delegates to. the target
                    # sanitizes in the Paginator/Factory layer, not the resource,
                    # so a method-local check calls every such endpoint critical.
                    # DOWNGRADE rather than drop: the live probe still runs, but it
                    # no longer leads the report as a critical SQLi.
                    severity = pat.severity
                    description = pat.description
                    if pat.check_downstream and pat.guard is not None:
                        guarded_by = self._downstream_guard(file_code, pat.guard)
                        if guarded_by:
                            analyzer_skipped["guarded_downstream"] += 1
                            severity = Severity.LOW
                            description = (
                                f"{pat.description} NOTE: the sanitizer appears to be applied "
                                f"downstream in {guarded_by}, so this is most likely already "
                                f"mitigated — retained at LOW for live confirmation only.")
                    ep = self._resolve_endpoint(text, m.start(), class_path, block)
                    block_verbs = set(_METHOD_ANNOT.findall(block))
                    if pat.id == "missing_authz":
                        # the match IS the @VERB annotation; seed from it directly
                        mv = re.match(r"@(PUT|POST|DELETE|PATCH|GET)", m.group(0), re.I)
                        if mv:
                            block_verbs.add(mv.group(1).upper())
                        # only a BFLA candidate if it actually changes state
                        state_verbs = block_verbs & {"PUT", "POST", "DELETE", "PATCH"}
                        if not state_verbs:
                            continue
                        methods = tuple(sorted(state_verbs))
                    else:
                        methods = tuple(sorted(block_verbs))
                    candidates.append(SourceCandidate(
                        pattern_id=pat.id, vuln_class=pat.vuln_class,
                        severity=severity, description=description,
                        file_path=path, line_no=line_no,
                        snippet=self._trim(block),
                        endpoint_path=ep, http_methods=methods,
                        probe_params=pat.probe_param_hint, probe_kind=pat.probe_kind))
        candidates = self._dedup(candidates)
        if self.use_ai:
            candidates = [c for c in (self._ai_review(c) for c in candidates)
                          if c.ai_verdict != "unlikely"]
        candidates.sort(key=lambda c: c.severity.rank, reverse=True)
        return candidates

    # --- helpers ---------------------------------------------------------- #
    @staticmethod
    def _mask_comments(text: str) -> str:
        """Blank out // and /* */ comments, replacing them with spaces so the
        result is the SAME LENGTH as the input. Length preservation is the point:
        every match offset still maps to the correct line in the original text."""
        out = list(text)
        i, n = 0, len(text)
        while i < n:
            if text.startswith("//", i):
                j = text.find("\n", i)
                j = n if j == -1 else j
                for k in range(i, j):
                    out[k] = " "
                i = j
            elif text.startswith("/*", i):
                j = text.find("*/", i + 2)
                j = n if j == -1 else j + 2
                for k in range(i, j):
                    if out[k] != "\n":          # keep newlines: line numbers matter
                        out[k] = " "
                i = j
            elif text[i] == '"':                # skip string literals verbatim
                i += 1
                while i < n and text[i] != '"':
                    i += 2 if text[i] == "\\" else 1
                i += 1
            else:
                i += 1
        return "".join(out)

    def _file_index(self) -> dict:
        """basename -> absolute path, built once per analyzer over the local clone.
        Only available with a local checkout; the raw-fetch path cannot walk
        downstream classes, so the check simply no-ops there."""
        idx = getattr(self, "_fidx", None)
        if idx is not None:
            return idx
        idx = {}
        root = getattr(self.provider, "local_root", None)
        if root:
            for dirpath, _dirs, files in os.walk(root):
                for fn in files:
                    if not fn.endswith(".java"):
                        continue
                    # basename -> ALL paths. Class names collide in a tree this
                    # size (the target has two PaginationUtil.java), and keeping only
                    # one meant the walk could read the wrong class and miss the
                    # guard entirely. Check every candidate instead of guessing.
                    idx.setdefault(fn, []).append(os.path.join(dirpath, fn))
        self._fidx = idx
        return idx

    # Any CamelCase identifier is a delegate candidate; only names that resolve to
    # a real file in the clone are followed, so this stays grounded.
    _DELEGATE_RE = re.compile(r"\b([A-Z][A-Za-z0-9_]{2,})\b")

    def _downstream_guard(self, code: str, guard: re.Pattern,
                          max_depth: int = 3, max_files: int = 40) -> Optional[str]:
        """Walk the delegation chain looking for `guard`; return the class that
        applies it, or None.

        Transitive because the target's sanitizer can sit several hops down — e.g.
        ContentReportResource -> ContentReportPaginator -> SiteContentReport ->
        ContentTypeFactoryImpl.sanitizeSortBy. Bounded by depth and file count so
        it stays cheap over a 7.7k-file tree.

        NOTE the caller DOWNGRADES on a hit, it does not suppress: this is a
        heuristic, and silently dropping a candidate because some class in its
        neighbourhood mentions the guard could hide a real bug. Deluluscan's rule is
        that only a live probe settles it.
        """
        idx = self._file_index()
        if not idx:
            return None
        frontier = [n for n in dict.fromkeys(self._DELEGATE_RE.findall(code))]
        visited: set[str] = set()
        budget = max_files
        for _depth in range(max_depth):
            nxt: list[str] = []
            for name in frontier:
                if name in visited or budget <= 0:
                    continue
                visited.add(name)
                for cand in (f"{name}.java", f"{name}Impl.java"):
                    for fp in idx.get(cand, ()):
                        if budget <= 0:
                            break
                        budget -= 1
                        try:
                            with open(fp, "r", encoding="utf-8", errors="replace") as fh:
                                body = self._strip_comments(fh.read())
                        except OSError:
                            continue
                        if guard.search(body):
                            return cand[:-5]        # drop ".java"
                        nxt.extend(self._DELEGATE_RE.findall(body)[:60])
            frontier = nxt
        return None

    @staticmethod
    def _class_path(text: str) -> Optional[str]:
        m = _PATH_RE.search(text)
        return m.group(1) if m else None

    @staticmethod
    def _method_block(text: str, pos: int) -> tuple[str, int]:
        """Return the enclosing method (signature + full body) around `pos`, using
        brace matching so multi-line auth chains (WebResource.InitBuilder ...
        .init()) and permission checks anywhere in the body are captured."""
        # start just after the previous method's close / class open brace
        prev = max(text.rfind("}", 0, pos), text.rfind("{", 0, pos))
        start = prev + 1 if prev >= 0 else max(0, pos - 200)
        # Extend the block backwards over the method's OWN signature and
        # annotations. They sit above the opening brace, so a block anchored at
        # the brace excludes them and the method's @Path becomes invisible —
        # which previously forced a backwards scan through the whole file that
        # picked up a SIBLING method's @Path instead (UserResource.create() was
        # mapped to /users/loginAsData). Including only the contiguous annotation
        # lines keeps a neighbour's annotations out.
        _ls = text.rfind("\n", 0, start) + 1          # start of the signature line
        _probe = _ls
        while _probe > 0:
            _pl = text.rfind("\n", 0, _probe - 1) + 1  # start of the line above
            _line = text[_pl:_probe].strip()
            if _line.startswith("@"):
                _probe = _pl
                continue
            break
        if _probe < start:
            start = _probe
        line_no = text.count("\n", 0, pos) + 1
        # forward: find the method body's opening brace, then balance to its close.
        # Skip braces inside string/char literals and // or /* */ comments so path
        # annotations like @Path("/{id}/grant") don't corrupt the count.
        cap = min(len(text), pos + 8000)
        i = pos
        depth = 0
        started = False
        end = cap
        in_line_comment = False
        in_block_comment = False
        in_str = None  # '"' or "'"
        while i < cap:
            c = text[i]
            nxt = text[i + 1] if i + 1 < cap else ""
            if in_line_comment:
                if c == "\n":
                    in_line_comment = False
            elif in_block_comment:
                if c == "*" and nxt == "/":
                    in_block_comment = False; i += 1
            elif in_str is not None:
                if c == "\\":
                    i += 1  # skip escaped char
                elif c == in_str:
                    in_str = None
            elif c == "/" and nxt == "/":
                in_line_comment = True; i += 1
            elif c == "/" and nxt == "*":
                in_block_comment = True; i += 1
            elif c in ('"', "'"):
                in_str = c
            elif c == "{":
                depth += 1; started = True
            elif c == "}":
                depth -= 1
                if started and depth == 0:
                    end = i + 1
                    break
            i += 1
        if not started:
            end = min(len(text), pos + 400)
        return text[start:end], line_no

    @staticmethod
    def _strip_comments(block: str) -> str:
        b = re.sub(r"/\*.*?\*/", " ", block, flags=re.S)   # block comments
        b = re.sub(r"//[^\n]*", " ", b)                     # line comments
        return b

    @staticmethod
    def _resolve_endpoint(text: str, pos: int, class_path: Optional[str],
                          block: str = "") -> Optional[str]:
        # method-level @Path: within the block, prefer a @Path that appears AFTER
        # the first HTTP-verb annotation (that's the method's own @Path; the first
        # @Path in the block is usually the class-level one). Fall back to nearest
        # above the match, then to the class path.
        method_path = None
        if block:
            verb = _METHOD_ANNOT.search(block)
            search_from = verb.start() if verb else 0
            after = list(_PATH_RE.finditer(block, search_from))
            if after:
                method_path = after[0].group(1)
            else:
                allp = list(_PATH_RE.finditer(block))
                # last @Path that isn't the class path
                for pm in reversed(allp):
                    if pm.group(1) != (class_path or ""):
                        method_path = pm.group(1); break
        if method_path is None:
            # Deliberately DO NOT scan backwards through the file here. A method
            # without its own @Path is served at the class path; taking the
            # nearest preceding @Path silently attributes the finding to a
            # different endpoint, which sends probes at the wrong target — worse
            # than leaving it unresolved.
            method_path = None
        base = class_path or ""
        if method_path and method_path != base:
            joined = (base.rstrip("/") + "/" + method_path.lstrip("/")) if base else method_path
        else:
            joined = base
        if not joined:
            return None
        # normalise to the live API prefix. the target mounts REST under /api, and the
        # class @Path usually already includes the version (e.g. /v1/categories),
        # so prepend only /api in that case — avoid producing /api/v1/v1/...
        joined = re.sub(r"//+", "/", joined)
        if joined.startswith("/api"):
            pass
        elif re.match(r"^/v\d+/", joined):
            joined = "/api" + joined
        elif joined.startswith("/"):
            joined = "/api/v1" + joined
        else:
            joined = "/api/v1/" + joined
        # collapse JAX-RS path params {id: regex} -> {id}
        joined = re.sub(r"\{(\w+)\s*:[^}]+\}", r"{\1}", joined)
        return joined

    @staticmethod
    def _trim(block: str, limit: int = 600) -> str:
        b = block.strip()
        return b if len(b) <= limit else b[:limit] + " ..."

    @staticmethod
    def _dedup(cands: list[SourceCandidate]) -> list[SourceCandidate]:
        seen = set(); out = []
        for c in cands:
            key = (c.pattern_id, c.endpoint_path, c.http_methods)
            if key in seen:
                continue
            seen.add(key); out.append(c)
        return out

    def _ai_review(self, c: SourceCandidate) -> SourceCandidate:
        """Ask the AI whether the snippet is a real, reachable danger. Conservative:
        only DROP a candidate on a clear 'unlikely'; anything else is kept."""
        try:
            ctx = {
                "task": "source_vuln_review",
                "pattern": c.pattern_id,
                "vuln_class": c.vuln_class,
                "endpoint": c.endpoint_path,
                "methods": list(c.http_methods),
                "snippet": c.snippet,
                "instructions": (
                    "You are reviewing a target Java source snippet flagged by a static "
                    "pattern. Decide if it is a plausibly REAL, reachable vulnerability of "
                    "the stated class in this snippet, or a false lead (guarded elsewhere, "
                    "not request-reachable, framework-handled). Reply strict JSON: "
                    '{"verdict":"confirmed|unlikely","reason":"<=200 chars"}'),
            }
            raw = self.analyst.analyze_evidence(ctx) if hasattr(self.analyst, "analyze_evidence") else {}
            verdict = str(raw.get("verdict", "")).lower()
            if verdict in ("confirmed", "unlikely"):
                c.ai_verdict = verdict
                c.ai_reason = str(raw.get("reason", ""))[:200]
        except Exception:
            pass  # AI is advisory only; never block on it
        return c


def candidates_to_probe_plan(cands: list[SourceCandidate]) -> list[dict]:
    """Translate source candidates into a probe plan the orchestrator/scanners can
    consume: which concrete endpoint + method + params to actively test, and with
    which scanner family."""
    plan = []
    for c in cands:
        if not c.endpoint_path:
            continue
        plan.append({
            "source": c.source,
            "pattern_id": c.pattern_id,
            "vuln_class": c.vuln_class,
            "severity": c.severity.value,
            "endpoint_path": c.endpoint_path,
            "methods": list(c.http_methods) or ["GET"],
            "params": list(c.probe_params),
            "probe_kind": c.probe_kind,
            "why": c.description,
            "evidence_file": f"{c.file_path}:{c.line_no}",
            "ai_verdict": c.ai_verdict,
            "risk_score": c.risk_score,
            "identity_hint": c.identity_hint,
            "provenance": c.provenance,
        })
    return plan


# --------------------------------------------------------------------------- #
# Mantis integration — ingest findings from a Mantis code-scan campaign
# (google/mantis skills, run separately via the deluluscan-codescan skill against a
# local the target source clone) and turn each into the same SourceCandidate shape
# the regex patterns above produce, so the orchestrator queues an identical
# live probe. This module never invokes Mantis or an LLM here — it only reads
# whatever workspace/findings/*.json a prior Mantis pass already wrote.
# --------------------------------------------------------------------------- #

# CWE -> (vuln_class, probe_kind, probe_params). Checked before the keyword
# fallback since Mantis findings usually carry a CWE.
_CWE_MAP: dict[str, tuple[str, str, tuple[str, ...]]] = {
    "CWE-89": (VulnClass.SQLI.value, "sqli", ("id", "filter", "orderby", "query")),
    "CWE-943": (VulnClass.SQLI.value, "sqli", ("id", "filter", "orderby", "query")),
    "CWE-79": (VulnClass.XSS.value, "xss", ("body", "name", "title")),
    "CWE-352": (VulnClass.AUTHZ.value, "authz", ()),
    "CWE-862": (VulnClass.AUTHZ.value, "authz", ()),
    "CWE-863": (VulnClass.AUTHZ.value, "authz", ()),
    "CWE-284": (VulnClass.AUTHZ.value, "authz", ()),
    "CWE-639": (VulnClass.IDOR.value, "authz", ("id",)),
    "CWE-918": (VulnClass.SSRF.value, "ssrf", ("url", "uri", "href")),
    "CWE-611": (VulnClass.SSRF.value, "ssrf", ("url", "xml", "body")),
    "CWE-502": (VulnClass.SUPPLY_CHAIN.value, "deserialize", ("body",)),
    "CWE-94": (VulnClass.SSTI.value, "ssti", ("velocity", "code", "script", "body")),
    "CWE-1336": (VulnClass.SSTI.value, "ssti", ("velocity", "code", "script", "body")),
    "CWE-22": (VulnClass.INFO_LEAK.value, "authz", ("path", "file", "name")),
    "CWE-434": (VulnClass.SUPPLY_CHAIN.value, "authz", ("file", "body")),
    "CWE-798": (VulnClass.CRYPTO.value, "authz", ()),
    "CWE-321": (VulnClass.CRYPTO.value, "authz", ()),
}

# Free-text fallback when there's no CWE or it isn't in the map above.
_KEYWORD_MAP: tuple[tuple[re.Pattern, tuple[str, str, tuple[str, ...]]], ...] = (
    (re.compile(r"(?i)sql\s*inject|order\s*by|unsanitized sort"),
     (VulnClass.SQLI.value, "sqli", ("id", "filter", "orderby", "query"))),
    (re.compile(r"(?i)deserializ|xstream|objectinputstream"),
     (VulnClass.SUPPLY_CHAIN.value, "deserialize", ("body",))),
    (re.compile(r"(?i)template injection|\bssti\b|velocity"),
     (VulnClass.SSTI.value, "ssti", ("velocity", "code", "script", "body"))),
    (re.compile(r"(?i)ssrf|server-side request forgery"),
     (VulnClass.SSRF.value, "ssrf", ("url", "uri", "href"))),
    (re.compile(r"(?i)cross-site scripting|\bxss\b"),
     (VulnClass.XSS.value, "xss", ("body", "name", "title"))),
    (re.compile(r"(?i)idor|insecure direct object|object[- ]level authz"),
     (VulnClass.IDOR.value, "authz", ("id",))),
    (re.compile(r"(?i)authoriz|access control|privilege|\bbfla\b|\bbola\b|missing (auth|permission)"),
     (VulnClass.AUTHZ.value, "authz", ())),
    (re.compile(r"(?i)path traversal|directory traversal|\.\./"),
     (VulnClass.INFO_LEAK.value, "authz", ("path", "file", "name"))),
    (re.compile(r"(?i)mass assign|excessive data exposure|\bbopla\b"),
     (VulnClass.BOPLA.value, "authz", ())),
)

# --- Mantis triage vocabulary (google/mantis schema.json) ------------------
# Mantis's own funnel decides these; honouring them is the difference between
# using its output and merely reading its files.
_MANTIS_DEAD_STATUS = {"FALSE_POSITIVE", "DUPLICATE"}
_MANTIS_DEAD_VIABILITY = {"NON_VIABLE", "SAMPLE_OR_TEST"}
# Positions Deluluscan (an HTTP scanner) cannot testify to either way.
_MANTIS_UNREACHABLE_POSITION = {"LOCAL", "HOST_SYSTEM",
                                "PHYSICAL_TEMPORARY", "PHYSICAL_LONG_TERM"}
# privileges_required -> the identity the live probe should run as. This is the
# natural bridge from Mantis's model to Deluluscan's identity matrix.
_MANTIS_IDENTITY = {"NONE": "anonymous", "LOW": "backend", "HIGH": "admin"}

# Populated by the most recent load_mantis_findings() call so the orchestrator
# can report what the corpus contributed AND what it withheld — an ignored
# finding must be visible, never silently absent.
candidates_skipped: dict = {}

# What the static analyzer itself withheld this run (comment matches, and
# candidates proven guarded one layer downstream). Surfaced rather than silent:
# suppression that nobody can see is indistinguishable from a scanner that
# simply missed something.
analyzer_skipped: dict = {}


def _mantis_verdict(status: str, repro_status: str) -> str:
    """Map Mantis's triage to Deluluscan's ai_verdict vocabulary.

    'confirmed' here means "Mantis concluded this is real in the code" — it is
    NOT a live verdict, and never overrides one. A finding still under research
    stays unreviewed rather than being promoted.
    """
    if repro_status == "reproduced":
        return "confirmed"          # Mantis built and ran a working PoC
    if status == "VALID":
        return "confirmed"          # passed the 13 negative filters + critic
    if status in ("PROVISIONALLY_VALID", "NEEDS_RESEARCH"):
        return ""                   # a lead; do not overstate it
    return ""


_SEVERITY_MAP = {"CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH,
                 "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW}


def _classify_mantis_finding(finding: dict) -> tuple[str, str, tuple[str, ...]]:
    """Map a Mantis finding's CWE (preferred) or free text to
    (vuln_class, probe_kind, probe_params). Defaults to a generic authz probe
    when nothing matches — still worth a live look, never dropped silently."""
    cwe = ""
    if finding.get("cwe"):
        cwe = str(finding["cwe"]).split()[0].upper()
    if cwe in _CWE_MAP:
        return _CWE_MAP[cwe]
    text = " ".join(str(finding.get(k, "") or "") for k in ("title", "description", "impact"))
    for pattern, mapped in _KEYWORD_MAP:
        if pattern.search(text):
            return mapped
    return (VulnClass.AUTHZ.value, "authz", ())


def _iter_mantis_finding_files(findings_root: str) -> list[str]:
    """All finding JSON files for a Mantis pass, campaign-wide: the active
    queue plus everything archived by prior passes (mirrors mantis-report's
    own "campaign-wide view" so a finding a later pass stopped retrying
    doesn't silently vanish from what deluluscan tests). Active findings/ win over
    an archived duplicate with the same id."""
    by_id: dict[str, str] = {}
    for pat in (os.path.join(findings_root, "archive", "findings_pass_*", "*.json"),
                os.path.join(findings_root, "archive", "loop*_findings", "*.json")):
        for fp in glob.glob(pat):
            by_id[os.path.splitext(os.path.basename(fp))[0]] = fp
    for fp in glob.glob(os.path.join(findings_root, "findings", "*.json")):
        by_id[os.path.splitext(os.path.basename(fp))[0]] = fp
    return list(by_id.values())


def load_mantis_findings(findings_root: str, source_root: Optional[str]) -> list[SourceCandidate]:
    """Read a prior Mantis code-scan pass's findings and turn each into a
    SourceCandidate with a resolved target REST endpoint, the same shape the
    regex patterns above produce, so the orchestrator queues an identical live
    probe. Deterministic — never invokes Mantis or an LLM.

    `source_root` must be the SAME the target source clone Mantis analyzed (its
    `code_paths` are relative to that CODE_ROOT); without it, or if a file has
    moved/been renamed since the scan, that finding is skipped rather than
    guessed at.
    """
    candidates: list[SourceCandidate] = []
    skipped = {"triaged_out": 0, "not_production": 0, "not_remotely_testable": 0}
    candidates_skipped.clear()
    if not findings_root or not os.path.isdir(findings_root):
        return candidates
    for fp in _iter_mantis_finding_files(findings_root):
        try:
            with open(fp, "r", encoding="utf-8", errors="replace") as fh:
                finding = json.load(fh)
        except (OSError, json.JSONDecodeError):
            continue
        # Mantis spends 16 stages triaging: /mantis-review applies 13 negative
        # filters, /mantis-critic decides production viability, /mantis-calibrate
        # scores risk. Ingesting the raw finding set throws all of that away and
        # queues live probes for findings Mantis itself already rejected.
        status = str(finding.get("status", "") or "").upper()
        if status in _MANTIS_DEAD_STATUS:
            skipped["triaged_out"] += 1
            continue
        viability = str(finding.get("production_viability", "") or "").upper()
        if viability in _MANTIS_DEAD_VIABILITY:
            skipped["not_production"] += 1
            continue
        position = str(finding.get("attacker_position", "") or "").upper()
        if position in _MANTIS_UNREACHABLE_POSITION:
            # Real, but not reachable over HTTP — Deluluscan cannot testify to it, and
            # a probe would be theatre. Counted, never silently dropped.
            skipped["not_remotely_testable"] += 1
            continue

        code_paths = finding.get("code_paths") or []
        if not code_paths or not source_root:
            continue  # no locator, or no clone to re-read it against

        # code_paths is the data-flow PATH (source -> ... -> sink), not one point.
        # The REST resource is often not the first entry, so try each until one
        # resolves to an endpoint; fall back to the first readable location.
        resolved = None
        fallback = None
        for locator in code_paths[:8]:
            m = re.match(r"^(.*):(\d+)$", str(locator))
            if not m:
                continue
            rel_path, line_no = m.group(1), int(m.group(2))
            try:
                with open(os.path.join(source_root, rel_path), "r",
                          encoding="utf-8", errors="replace") as fh:
                    text = fh.read()
            except OSError:
                continue  # file moved/renamed since the scan — don't fabricate
            lines = text.split("\n")
            if line_no < 1 or line_no > len(lines):
                continue
            pos = sum(len(l) + 1 for l in lines[:line_no - 1])
            class_path = SourceAnalyzer._class_path(text)
            block, _ = SourceAnalyzer._method_block(text, pos)
            ep = SourceAnalyzer._resolve_endpoint(text, pos, class_path, block)
            hit = (rel_path, line_no, text, pos, block, ep)
            if fallback is None:
                fallback = hit
            if ep:
                resolved = hit
                break
        if resolved is None and fallback is None:
            continue
        rel_path, line_no, text, pos, block, ep = resolved or fallback
        methods = tuple(sorted(set(_METHOD_ANNOT.findall(block)))) or ("GET",)
        sev = _SEVERITY_MAP.get(str(finding.get("severity", "")).upper(), Severity.MEDIUM)
        vuln_class, probe_kind, probe_params = _classify_mantis_finding(finding)
        title = str(finding.get("title", "") or "").strip()
        desc = str(finding.get("description", "") or "").strip()
        why = f"{title} — {desc}" if title and desc else (title or desc or "Mantis code-scan finding")
        fid = str(finding.get("id") or os.path.splitext(os.path.basename(fp))[0])
        repro = str(finding.get("repro_status", "") or "").lower()
        try:
            risk = float(finding.get("mantis_risk_score") or 0.0)
        except (TypeError, ValueError):
            risk = 0.0
        candidates.append(SourceCandidate(
            pattern_id=f"mantis:{fid}",
            vuln_class=vuln_class, severity=sev, description=why[:400],
            file_path=rel_path, line_no=line_no, snippet=SourceAnalyzer._trim(block),
            endpoint_path=ep, http_methods=methods, probe_params=probe_params,
            probe_kind=probe_kind,
            # Derive the verdict from what Mantis ACTUALLY concluded rather than
            # stamping every finding "confirmed". A reproduced PoC is the strong
            # case; VALID is Mantis's own triage passing it; anything still under
            # research stays unreviewed so the report cannot overstate it.
            ai_verdict=_mantis_verdict(status, repro),
            ai_reason=str(finding.get("mitigation", "") or "")[:200],
            source="mantis",
            risk_score=risk,
            identity_hint=_MANTIS_IDENTITY.get(
                str(finding.get("privileges_required", "") or "").upper(), ""),
            provenance={
                "status": status or None,
                "production_viability": viability or None,
                "attacker_position": position or None,
                "privileges_required": str(finding.get("privileges_required", "") or "") or None,
                "repro_status": repro or None,
                "inferred_exposure": str(finding.get("inferred_exposure", "") or "") or None,
                "mantis_risk_score": risk or None,
                "discovery_commit": str(finding.get("discovery_commit", "") or "") or None,
                "signature": str(finding.get("signature", "") or "") or None,
                "code_paths": [str(p) for p in code_paths[:8]],
            }))
    # Mantis's calibrated risk score beats a bare severity label when present:
    # it already folds in impact x likelihood x exposure with 27 sanity caps.
    candidates.sort(key=lambda c: (c.risk_score, c.severity.rank), reverse=True)
    if any(skipped.values()):
        candidates_skipped.update(skipped)
    return candidates
