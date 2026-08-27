"""Analogical vulnerability research — bug patterns transferred between products.

Products that solve the same problem make the same mistakes. A peer Java CMS's
CVE history is therefore a distilled list of *domain-specific* mistake classes,
written by people who already did the hard analysis — and most of those classes
were never hunted in the target, because the CVE was filed against someone else.

This module turns that corpus into machine-usable patterns:

    fetch_nvd("liferay")      -> [Advisory, ...]        public CVE corpus
    cluster(advisories)       -> [AdvisoryCluster, ...] one cluster per mistake CLASS
    distill(cluster, ask)     -> BugPattern             abstract shape + how to probe
    to_source_patterns([...]) -> [SourcePattern, ...]   feeds the existing pipeline

The output deliberately targets `sourcescan.SourcePattern`, so everything
downstream — endpoint resolution, live probing, telemetry correlation, recheck —
works unchanged. Deluluscan's 5 hand-written patterns are this technique done by hand;
`orderby_sqli` abstracts a real order-by SQL-injection class into a search shape.

DISCIPLINE. A transferred pattern is a HYPOTHESIS about someone else's code:
  * every pattern carries `provenance` — the CVEs it was derived from — so a
    finding can always be traced back to the bug that motivated the search;
  * patterns are search heuristics, never findings. Nothing here asserts a
    vulnerability. The existing verify chain (live probe -> telemetry -> recheck)
    is what decides, and that step is the whole difference between research and
    the automated bug-bounty spam this technique is currently producing at scale.
"""
from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

from .models import Severity, VulnClass

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Peer products whose CVE history transfers usefully onto a Java CMS.
PEER_PRODUCTS = ("liferay", "magnolia cms", "alfresco", "opencms",
                 "adobe experience manager", "hippo cms")


@dataclass
class Advisory:
    id: str                                  # CVE-YYYY-NNNNN
    product: str
    description: str
    cwe: list[str] = field(default_factory=list)
    severity: str = "UNKNOWN"
    published: str = ""

    def text(self) -> str:
        return f"{self.id} {self.description}"


@dataclass
class AdvisoryCluster:
    """Several advisories describing the SAME mistake class. Distilling per
    cluster rather than per CVE is what yields a pattern instead of 300 of them."""
    key: str                                 # cwe or keyword bucket
    advisories: list[Advisory] = field(default_factory=list)

    @property
    def cves(self) -> list[str]:
        return [a.id for a in self.advisories]


@dataclass
class BugPattern:
    """A mistake class, abstracted into something searchable in another codebase."""
    id: str
    vuln_class: str
    severity: Severity
    description: str
    regex: str                               # code shape to look for
    guard: Optional[str] = None              # shape that means it is mitigated
    probe_kind: str = ""
    probe_params: tuple[str, ...] = ()
    path_hint: tuple[str, ...] = ("/rest/", "Resource.java")
    check_downstream: bool = False
    provenance: list[str] = field(default_factory=list)   # the CVEs behind it

    def to_dict(self) -> dict:
        d = dict(self.__dict__)
        d["severity"] = self.severity.value
        d["probe_params"] = list(self.probe_params)
        d["path_hint"] = list(self.path_hint)
        return d

    @staticmethod
    def from_dict(d: dict) -> "BugPattern":
        d = dict(d)
        d["severity"] = Severity(d.get("severity", "medium"))
        d["probe_params"] = tuple(d.get("probe_params") or ())
        d["path_hint"] = tuple(d.get("path_hint") or ("/rest/", "Resource.java"))
        return BugPattern(**d)


# --------------------------------------------------------------------------- #
# 1. corpus
# --------------------------------------------------------------------------- #
def fetch_nvd(keyword: str, *, max_results: int = 200,
              fetch: Optional[Callable] = None, pause_s: float = 6.0) -> list[Advisory]:
    """Public CVEs for a product. NVD's anonymous limit is ~5 requests/30s, hence
    the pause; `fetch` is injected so tests never touch the network."""
    if fetch is None:
        fetch = _http_json
    out: list[Advisory] = []
    start = 0
    while start < max_results:
        page = min(100, max_results - start)
        url = (f"{NVD_API}?keywordSearch={keyword.replace(' ', '%20')}"
               f"&resultsPerPage={page}&startIndex={start}")
        try:
            doc = fetch(url)
        except Exception:
            break
        items = doc.get("vulnerabilities") or []
        if not items:
            break
        for it in items:
            c = it.get("cve") or {}
            desc = next((d.get("value", "") for d in c.get("descriptions") or []
                         if d.get("lang") == "en"), "")
            cwes = []
            for w in c.get("weaknesses") or []:
                for d in w.get("description") or []:
                    v = d.get("value", "")
                    if v.startswith("CWE-"):
                        cwes.append(v)
            sev = "UNKNOWN"
            metrics = c.get("metrics") or {}
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if metrics.get(key):
                    sev = (metrics[key][0].get("cvssData", {}).get("baseSeverity")
                           or metrics[key][0].get("baseSeverity") or "UNKNOWN")
                    break
            out.append(Advisory(id=c.get("id", ""), product=keyword, description=desc,
                                cwe=sorted(set(cwes)), severity=str(sev).upper(),
                                published=(c.get("published") or "")[:10]))
        start += page
        if len(items) < page:
            break
        time.sleep(pause_s)
    return out


# --------------------------------------------------------------------------- #
# 2. cluster (one mistake CLASS, not 300 instances)
# --------------------------------------------------------------------------- #
# Keyword buckets for advisories NVD left without a usable CWE.
_BUCKETS: list[tuple[str, re.Pattern]] = [
    ("ssti", re.compile(r"(?i)template injection|freemarker|velocity|expression language|\bEL\b injection")),
    ("deserialization", re.compile(r"(?i)deseriali|readObject|gadget chain")),
    ("xxe", re.compile(r"(?i)XML external entity|\bXXE\b|DOCTYPE")),
    ("path_traversal", re.compile(r"(?i)path traversal|directory traversal|\.\./|zip slip")),
    ("authz_bypass", re.compile(r"(?i)authoriz|access control|permission check|privilege escalat|bypass authentication")),
    ("sqli", re.compile(r"(?i)SQL injection|SQLi")),
    ("ssrf", re.compile(r"(?i)server-side request forgery|\bSSRF\b")),
    ("upload_rce", re.compile(r"(?i)(unrestricted|arbitrary) file upload|upload .* (webshell|jsp|executable)")),
    ("info_disclosure", re.compile(r"(?i)information (disclosure|exposure)|sensitive information")),
    ("xss", re.compile(r"(?i)cross-site scripting|\bXSS\b")),
]


def cluster(advisories: list[Advisory], min_size: int = 2) -> list[AdvisoryCluster]:
    """Group advisories by mistake class. CWE when NVD gives a usable one,
    otherwise a keyword bucket over the description."""
    groups: dict[str, AdvisoryCluster] = {}
    for a in advisories:
        keys = [c for c in a.cwe if c not in ("NVD-CWE-noinfo", "NVD-CWE-Other")]
        if not keys:
            keys = [name for name, rx in _BUCKETS if rx.search(a.description)]
        for k in keys or ["unclassified"]:
            groups.setdefault(k, AdvisoryCluster(key=k)).advisories.append(a)
    out = [c for c in groups.values()
           if len(c.advisories) >= min_size and c.key != "unclassified"]
    out.sort(key=lambda c: len(c.advisories), reverse=True)
    return out


# --------------------------------------------------------------------------- #
# 3. distil
# --------------------------------------------------------------------------- #
DISTILL_PROMPT = """You are doing analogical vulnerability research.

Below are real CVEs against {product} — a product in the same category as the
TARGET codebase ({target}). They describe a recurring class of mistake.

Your job: abstract them into ONE searchable pattern for the TARGET's source, not
a summary of the CVEs. Return STRICT JSON only:

{{"id": "snake_case_id",
  "vuln_class": "one of: sqli|ssti|ssrf|xss|authz|idor|injection|supply_chain|info_leak|misconfig",
  "severity": "critical|high|medium|low",
  "description": "what the mistake is and why it is dangerous, one or two sentences",
  "regex": "Python regex matching the DANGEROUS code shape in {lang}",
  "guard": "Python regex matching the shape that MITIGATES it, or null",
  "probe_kind": "sqli|authz|ssti|ssrf|deserialize|traversal|upload",
  "probe_params": ["request parameter names worth fuzzing"],
  "path_hint": ["path substrings worth restricting the search to"]}}

Rules:
- The regex must match a CODE SHAPE, not a product name or a CVE id.
- Prefer a shape that is specific enough to be actionable and general enough to
  survive different naming. Assume it will run over {lang} source.
- The guard is what makes it a false positive; get it right or the pattern is noise.

CVEs:
{cves}
"""


def distill(c: AdvisoryCluster, ask: Callable[[str], str], *,
            product: str = "peer CMS", target: str = "the target (Java, JAX-RS)",
            lang: str = "Java", max_cves: int = 12) -> Optional[BugPattern]:
    """Abstract a cluster into a BugPattern. `ask(prompt)->str` is the LLM."""
    sample = c.advisories[:max_cves]
    body = "\n".join(f"- {a.id} [{a.severity}] {a.description[:300]}" for a in sample)
    prompt = DISTILL_PROMPT.format(product=product, target=target, lang=lang, cves=body)
    try:
        raw = ask(prompt) or ""
    except Exception:
        return None
    m = re.search(r"\{.*\}", raw, re.S)
    if not m:
        return None
    try:
        d = json.loads(m.group(0))
    except json.JSONDecodeError:
        return None
    try:
        return BugPattern(
            id=str(d["id"]), vuln_class=str(d["vuln_class"]),
            severity=Severity(str(d.get("severity", "medium")).lower()),
            description=str(d.get("description", ""))[:400],
            regex=str(d["regex"]), guard=(d.get("guard") or None),
            probe_kind=str(d.get("probe_kind", "")),
            probe_params=tuple(d.get("probe_params") or ()),
            path_hint=tuple(d.get("path_hint") or ("/rest/", "Resource.java")),
            provenance=[a.id for a in sample])
    except (KeyError, ValueError):
        return None


# --------------------------------------------------------------------------- #
# 4. hand back to the existing pipeline
# --------------------------------------------------------------------------- #
def to_source_patterns(patterns: list[BugPattern]) -> list:
    """Compile BugPatterns into sourcescan.SourcePattern objects.

    A pattern whose regex does not compile is dropped rather than crashing the
    scan — generated input is never trusted to be well-formed.
    """
    from .sourcescan import SourcePattern

    out = []
    for p in patterns:
        try:
            rx = re.compile(p.regex, re.I)
            guard = re.compile(p.guard, re.I | re.S) if p.guard else None
        except re.error:
            continue
        out.append(SourcePattern(
            id=f"analogy:{p.id}", vuln_class=p.vuln_class, severity=p.severity,
            description=f"{p.description} [transferred from {', '.join(p.provenance[:3])}]",
            regex=rx, guard=guard, probe_param_hint=p.probe_params,
            probe_kind=p.probe_kind, path_hint=p.path_hint,
            check_downstream=p.check_downstream))
    return out


DEFAULT_CORPUS = os.path.join(os.path.dirname(__file__), "data", "analogy_patterns.json")


def load_patterns(path: str = DEFAULT_CORPUS) -> list[BugPattern]:
    try:
        with open(path, encoding="utf-8") as fh:
            return [BugPattern.from_dict(d) for d in json.load(fh).get("patterns", [])]
    except (OSError, json.JSONDecodeError, TypeError, ValueError):
        return []


def save_patterns(patterns: list[BugPattern], path: str = DEFAULT_CORPUS,
                  meta: Optional[dict] = None) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"meta": meta or {}, "patterns": [p.to_dict() for p in patterns]},
                  fh, indent=2)


def _http_json(url: str) -> dict:
    import urllib.request
    req = urllib.request.Request(url, headers={"User-Agent": "deluluscan/0.1 (authorized-testing)"})
    with urllib.request.urlopen(req, timeout=60) as fh:
        return json.load(fh)
