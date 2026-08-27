"""Software-composition analysis: known-vulnerable dependencies.

The gap this closes: Deluluscan had 43 scanners and not one of them could read a
dependency manifest. Auditing application code by hand while the vulnerable
component sits in a jar on the classpath is looking in the wrong place — most
CVEs reported against a large Java application are dependency CVEs.

Three inputs, deliberately separable so the logic is testable offline:

  * DECLARED   what the build says it depends on (pom.xml / package.json).
  * SHIPPED    what is actually on the running target's classpath. Optional but
               decisive: the target declares jdom 1.1.3 AND ships the fixed
               jdom2-2.0.6.1, so a manifest-only reading raises a false alarm,
               while a jar-only reading misses build-time risk.
  * ADVISORIES a vulnerability database (OSV by default), injected as a plain
               callable so tests never touch the network.

Discipline: presence of a vulnerable version is a LEAD about a reachable code
path, not proof one is reached. Findings are graded accordingly — `firm` when
the vulnerable artifact is confirmed on the target's classpath, `tentative` when
only the manifest says so — and never claim exploitation that was not observed.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
from dataclasses import dataclass, field
from typing import Callable, Optional

# name-1.2.3.jar / name-1.2.3.Final.jar / name-1.2.3-SNAPSHOT.jar
_JAR_RE = re.compile(r"^(?P<name>.+?)-(?P<version>\d[\w.]*?)\.jar$")
_MAVEN_NS = "{http://maven.apache.org/POM/4.0.0}"


@dataclass
class Dependency:
    name: str                      # groupId:artifactId  (maven) or package (npm)
    version: str
    ecosystem: str = "Maven"       # Maven | npm
    source: str = "manifest"       # manifest | classpath
    location: str = ""             # where we saw it


@dataclass
class VulnHit:
    dep: Dependency
    vuln_id: str
    severity: str = "UNKNOWN"      # CRITICAL|HIGH|MODERATE|LOW|UNKNOWN
    cves: list[str] = field(default_factory=list)
    summary: str = ""
    fixed_in: list[str] = field(default_factory=list)
    shipped: bool = False          # confirmed present on the target classpath


# --------------------------------------------------------------------------- #
# declared dependencies
# --------------------------------------------------------------------------- #
def parse_maven(root: str, max_poms: int = 200) -> list[Dependency]:
    """Every dependency with a resolvable literal version. A version that stays
    a ${property} after resolution is skipped rather than guessed at."""
    import xml.etree.ElementTree as ET

    poms: list[str] = []
    for dirpath, _dirs, files in os.walk(root):
        if "pom.xml" in files:
            poms.append(os.path.join(dirpath, "pom.xml"))
        if len(poms) >= max_poms:
            break

    props: dict[str, str] = {}
    trees = []
    for p in poms:
        try:
            t = ET.parse(p)
        except Exception:
            continue
        trees.append((p, t))
        for pr in t.getroot().findall(f".//{_MAVEN_NS}properties/*"):
            props[pr.tag.split("}")[-1]] = (pr.text or "").strip()

    def resolve(v: Optional[str], depth: int = 0) -> str:
        v = (v or "").strip()
        if depth > 5:
            return v
        m = re.fullmatch(r"\$\{([^}]+)\}", v)
        return resolve(props.get(m.group(1), ""), depth + 1) if m else v

    out: dict[str, Dependency] = {}
    for p, t in trees:
        for d in t.getroot().findall(f".//{_MAVEN_NS}dependency"):
            g = resolve(d.findtext(f"{_MAVEN_NS}groupId"))
            a = resolve(d.findtext(f"{_MAVEN_NS}artifactId"))
            v = resolve(d.findtext(f"{_MAVEN_NS}version"))
            scope = (d.findtext(f"{_MAVEN_NS}scope") or "").strip().lower()
            if not (g and a and v) or v.startswith("${"):
                continue
            if scope in ("test", "provided"):
                continue           # not shipped; a test-only CVE is not a product risk
            out[f"{g}:{a}"] = Dependency(f"{g}:{a}", v, "Maven", "manifest", p)
    return list(out.values())


def parse_npm(root: str, max_files: int = 200) -> list[Dependency]:
    out: dict[str, Dependency] = {}
    seen = 0
    for dirpath, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d != "node_modules"]
        if "package.json" not in files or seen >= max_files:
            continue
        seen += 1
        fp = os.path.join(dirpath, "package.json")
        try:
            with open(fp, encoding="utf-8", errors="replace") as fh:
                doc = json.load(fh)
        except Exception:
            continue
        for key in ("dependencies", "optionalDependencies"):
            for name, spec in (doc.get(key) or {}).items():
                v = re.sub(r"^[\^~>=<\s]+", "", str(spec)).strip()
                if re.fullmatch(r"\d[\w.\-]*", v):
                    out[name] = Dependency(name, v, "npm", "manifest", fp)
    return list(out.values())


# --------------------------------------------------------------------------- #
# what actually ships
# --------------------------------------------------------------------------- #
def jars_in_container(container: str, docker: str = "docker",
                      timeout_s: int = 120) -> list[Dependency]:
    """Artifacts genuinely on the running target's classpath.

    This is what separates a real finding from a false alarm: the target's manifest
    names jdom 1.1.3 while the image also carries the FIXED jdom2-2.0.6.1 — and
    conversely ships poi-3.17 alongside poi-5.5.1, so the old vulnerable copy is
    still loadable. Fail-soft: no Docker, no classpath view, and the caller
    degrades to manifest-only.
    """
    try:
        p = subprocess.run(
            [docker, "exec", container, "sh", "-c",
             "find / -name '*.jar' -not -path '/proc/*' 2>/dev/null || true"],
            capture_output=True, text=True, timeout=timeout_s)
    except Exception:
        return []
    # NOTE: do NOT gate on returncode. `find /` exits 1 as soon as it touches any
    # unreadable directory — which it always does — even with stderr suppressed.
    # Bailing on that silently discarded the whole classpath view and made every
    # finding read as manifest-only.
    if not (p.stdout or "").strip():
        return []
    out: dict[str, Dependency] = {}
    for line in (p.stdout or "").splitlines():
        base = os.path.basename(line.strip())
        m = _JAR_RE.match(base)
        if not m:
            continue
        name, version = m.group("name"), m.group("version").rstrip(".")
        out[f"{name}@{version}"] = Dependency(name, version, "Maven",
                                              "classpath", line.strip())
    return list(out.values())


def artifact_of(name: str) -> str:
    """groupId:artifactId -> artifactId, so a manifest entry can be matched to a
    jar filename."""
    return name.split(":")[-1]


# --------------------------------------------------------------------------- #
# advisories
# --------------------------------------------------------------------------- #
def osv_query(deps: list[Dependency], fetch: Optional[Callable] = None,
              batch: int = 100) -> dict[str, list[str]]:
    """{'name@version': [vuln_id, ...]} from OSV. `fetch(url, payload)->dict` is
    injected so tests stay offline."""
    if fetch is None:
        fetch = _http_json
    hits: dict[str, list[str]] = {}
    items = [d for d in deps if d.version]
    for i in range(0, len(items), batch):
        chunk = items[i:i + batch]
        payload = {"queries": [{"package": {"name": d.name, "ecosystem": d.ecosystem},
                                "version": d.version} for d in chunk]}
        try:
            res = fetch("https://api.osv.dev/v1/querybatch", payload)
        except Exception:
            continue
        for d, r in zip(chunk, (res or {}).get("results", [])):
            ids = [v.get("id") for v in (r.get("vulns") or []) if v.get("id")]
            if ids:
                hits[f"{d.name}@{d.version}"] = ids
    return hits


def osv_detail(vuln_id: str, fetch: Optional[Callable] = None) -> dict:
    if fetch is None:
        fetch = _http_json
    try:
        return fetch(f"https://api.osv.dev/v1/vulns/{vuln_id}", None) or {}
    except Exception:
        return {}


def _http_json(url: str, payload) -> dict:
    import urllib.request
    if payload is None:
        req = urllib.request.Request(url)
    else:
        req = urllib.request.Request(url, data=json.dumps(payload).encode(),
                                     headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as fh:
        return json.load(fh)


def summarize_detail(doc: dict) -> tuple[str, list[str], str, list[str]]:
    """(severity, cves, summary, fixed_in) from an OSV advisory document."""
    sev = (doc.get("database_specific") or {}).get("severity", "") or "UNKNOWN"
    cves = [a for a in (doc.get("aliases") or []) if str(a).startswith("CVE")]
    fixed: set[str] = set()
    for aff in doc.get("affected") or []:
        for rng in aff.get("ranges") or []:
            for ev in rng.get("events") or []:
                if ev.get("fixed"):
                    fixed.add(ev["fixed"])
    return sev.upper(), cves, (doc.get("summary") or "").strip(), sorted(fixed)


# --------------------------------------------------------------------------- #
# correlation
# --------------------------------------------------------------------------- #
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MODERATE": 2, "MEDIUM": 2,
                  "LOW": 3, "UNKNOWN": 4}


def correlate(declared: list[Dependency], shipped: list[Dependency],
              hits: dict[str, list[str]], details: dict[str, dict]) -> list[VulnHit]:
    """Join declared/shipped dependencies with their advisories.

    `shipped` decides confidence, not existence: a manifest entry whose exact
    version is confirmed on the classpath is `shipped=True` and reportable with
    confidence; one contradicted by the classpath (the artifact is present at a
    FIXED version) is dropped, because reporting it is the jdom2 false alarm.
    """
    by_artifact: dict[str, set[str]] = {}
    for s in shipped:
        by_artifact.setdefault(s.name, set()).add(s.version)

    # The classpath view is JAR-based, so it can only adjudicate Maven artifacts.
    # Applying it to npm packages silently dropped every JS finding, because no
    # npm package is ever a .jar.
    have_view = {d.ecosystem for d in shipped} if shipped else set()
    out: list[VulnHit] = []
    for dep in declared:
        ids = hits.get(f"{dep.name}@{dep.version}")
        if not ids:
            continue
        art = artifact_of(dep.name)
        versions = by_artifact.get(art)
        if dep.ecosystem in have_view:
            # With a view of this ecosystem, absence is informative: the artifact
            # is not shipped at that version (build-only, superseded by a
            # differently named artifact, or excluded) -> reporting is a false alarm.
            if not versions or dep.version not in versions:
                continue
            is_shipped = True
        else:
            is_shipped = False     # no view for this ecosystem: reportable, unconfirmed
        for vid in ids:
            sev, cves, summary, fixed = summarize_detail(details.get(vid, {}))
            out.append(VulnHit(dep=dep, vuln_id=vid, severity=sev, cves=cves,
                               summary=summary, fixed_in=fixed, shipped=is_shipped))
    out.sort(key=lambda h: (SEVERITY_ORDER.get(h.severity, 4), not h.shipped))
    return out


def duplicate_artifacts(shipped: list[Dependency]) -> dict[str, list[str]]:
    """Artifacts present at more than one version. An upgrade that leaves the old
    jar on the classpath keeps the vulnerable class loadable — the target ships
    poi-3.17 beside poi-5.5.1 and jdom-1.1.3 beside jdom2-2.0.6.1."""
    by: dict[str, set[str]] = {}
    for s in shipped:
        by.setdefault(s.name, set()).add(s.version)
    return {k: sorted(v) for k, v in by.items() if len(v) > 1}
