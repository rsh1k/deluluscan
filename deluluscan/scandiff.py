"""deluluscan.scandiff — compare two scans; classify what changed.

The question after a remediation cycle is not "what did this scan find?" but
"what changed since last time?". Three answers matter:

    NEW        present now, absent before      -> triage this
    FIXED      present before, absent now      -> verify and close
    UNCHANGED  present in both, same grading   -> still open
    CHANGED    present in both, different      -> severity/verdict moved

The hard part is **identity**. A Deluluscan finding id is `uuid4().hex[:10]`, minted
per scan, so ids never match across runs. Matching on the endpoint alone is too
coarse: on a real scan, 13 of 153 findings collide on (class, endpoint) because
one endpoint yields several distinct issues. This module fingerprints on
class + endpoint + a normalised title + stable discriminators from `detail`,
which on that same scan resolves 152 of 153 uniquely (the remaining pair being a
genuine duplicate).

Normalisation matters as much as the fields: titles carry per-run randomness
(canary markers, generated ids, "×N endpoints" counts). Left in, every finding
would look NEW on every scan and the diff would be worthless.

A FIXED finding is a *claim about absence*, and absence has more than one cause —
the endpoint may simply not have been probed this time. `diff()` therefore
records coverage on both sides and flags a FIXED result as unverified when the
current scan covered less ground than the baseline.

    python3 -m deluluscan.scandiff baseline.json current.json [--json]
"""
from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass, field

# detail keys that identify WHICH instance of a class this is, and are stable
# run to run (unlike payload markers or timing numbers).
_DISCRIMINATORS = ("test", "param", "slot", "probe", "path", "signature",
                   "role", "header", "sink", "technique")

# Per-run noise that must not enter a fingerprint.
_HEX_ID = re.compile(r"\b[0-9a-f]{8,}\b", re.I)
# Canary markers appear both hyphenated ("DELULUSCAN-FORGED-m9ae2i2y") and bare
# ("deluluscan9mv9clz8"), and the random tail is alphanumeric rather than hex — so
# neither a separator nor the hex-id rule can be relied on to catch them.
_MARKER = re.compile(r"\bdeluluscan[-_]?[a-z0-9]{4,}(?:[-_][a-z0-9]+)*\b", re.I)
_ENDPOINT_COUNT = re.compile(r"\s*\(×\s*\d+\s+endpoints?\)", re.I)
_UUID = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I)
_NUM = re.compile(r"\b\d+\b")

STATUS_NEW = "new"
STATUS_FIXED = "fixed"
STATUS_UNCHANGED = "unchanged"
STATUS_CHANGED = "changed"


def normalise_title(title: str) -> str:
    """Strip per-run randomness so the same issue fingerprints identically."""
    text = (title or "").strip()
    text = _ENDPOINT_COUNT.sub("", text)
    text = _UUID.sub("<uuid>", text)
    text = _MARKER.sub("<marker>", text)
    text = _HEX_ID.sub("<id>", text)
    text = _NUM.sub("<n>", text)
    return re.sub(r"\s+", " ", text).strip().lower()


def normalise_endpoint(endpoint: str) -> str:
    """Collapse concrete ids in an endpoint back to their path-template shape."""
    text = (endpoint or "").strip()
    text = _UUID.sub("{id}", text)
    text = _HEX_ID.sub("{id}", text)
    return re.sub(r"\s+", " ", text).lower()


def fingerprint(finding: dict) -> str:
    """A stable cross-scan identity for one finding."""
    detail = finding.get("detail") or {}
    parts = [
        str(finding.get("vuln_class") or ""),
        normalise_endpoint(str(finding.get("endpoint") or "")),
        normalise_title(str(finding.get("title") or "")),
    ]
    for key in _DISCRIMINATORS:
        value = detail.get(key)
        if isinstance(value, (str, int, float, bool)):
            parts.append(f"{key}={normalise_title(str(value))}")
    return "|".join(parts)


def _grading(finding: dict) -> dict:
    """The fields whose movement makes a matched finding CHANGED."""
    report = (finding.get("detail") or {}).get("report") or {}
    cvss = report.get("cvss") or (finding.get("detail") or {}).get("cvss") or {}
    detail = finding.get("detail") or {}
    return {
        "severity": finding.get("severity"),
        "verdict": finding.get("verdict"),
        "exploitability": finding.get("exploitability"),
        "cvss_score": cvss.get("base_score"),
        # A finding that moved between report/observation/refuted has materially
        # changed even when its severity did not.
        "disposition": ("refuted" if detail.get("refuted")
                        else "observation" if detail.get("observation")
                        else "reported"),
    }


@dataclass
class Entry:
    """One finding's status across the two scans."""

    fingerprint: str
    status: str
    title: str
    vuln_class: str
    endpoint: str
    severity: str = ""
    baseline_grading: dict = field(default_factory=dict)
    current_grading: dict = field(default_factory=dict)
    changes: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        out = {
            "fingerprint": self.fingerprint, "status": self.status,
            "title": self.title, "vuln_class": self.vuln_class,
            "endpoint": self.endpoint, "severity": self.severity,
        }
        if self.changes:
            out["changes"] = self.changes
        return out


def _index(payload: dict) -> dict[str, dict]:
    """fingerprint -> finding, keeping the first on a collision."""
    out: dict[str, dict] = {}
    for f in payload.get("findings", []):
        out.setdefault(fingerprint(f), f)
    return out


def _coverage(payload: dict) -> dict:
    meta = payload.get("meta") or {}
    cov = meta.get("coverage") or {}
    return {
        "endpoints_discovered": cov.get("endpoints_discovered")
                                or meta.get("endpoints_total"),
        "endpoints_probed": cov.get("endpoints_probed")
                            or meta.get("endpoints_done")
                            or meta.get("endpoints_scanned"),
    }


def diff(baseline: dict, current: dict) -> dict:
    """Classify every finding across two scan payloads.

    Returns a dict with `entries`, per-status buckets, `summary` counts, and a
    `coverage` block that says whether FIXED results can be trusted.
    """
    base_idx, cur_idx = _index(baseline), _index(current)
    entries: list[Entry] = []

    for fp, cur in cur_idx.items():
        base = base_idx.get(fp)
        common = dict(
            fingerprint=fp, title=str(cur.get("title") or ""),
            vuln_class=str(cur.get("vuln_class") or ""),
            endpoint=str(cur.get("endpoint") or ""),
            severity=str(cur.get("severity") or ""),
        )
        if base is None:
            entries.append(Entry(status=STATUS_NEW, **common))
            continue
        bg, cg = _grading(base), _grading(cur)
        moved = {k: {"from": bg[k], "to": cg[k]} for k in bg if bg[k] != cg[k]}
        entries.append(Entry(
            status=STATUS_CHANGED if moved else STATUS_UNCHANGED,
            baseline_grading=bg, current_grading=cg, changes=moved, **common))

    for fp, base in base_idx.items():
        if fp in cur_idx:
            continue
        entries.append(Entry(
            fingerprint=fp, status=STATUS_FIXED,
            title=str(base.get("title") or ""),
            vuln_class=str(base.get("vuln_class") or ""),
            endpoint=str(base.get("endpoint") or ""),
            severity=str(base.get("severity") or ""),
            baseline_grading=_grading(base)))

    buckets: dict[str, list[Entry]] = {
        STATUS_NEW: [], STATUS_FIXED: [], STATUS_UNCHANGED: [], STATUS_CHANGED: []}
    for e in entries:
        buckets[e.status].append(e)

    base_cov, cur_cov = _coverage(baseline), _coverage(current)
    # "Fixed" is a claim about absence. Absence also results from not looking.
    coverage_regressed = (
        isinstance(base_cov["endpoints_probed"], int)
        and isinstance(cur_cov["endpoints_probed"], int)
        and cur_cov["endpoints_probed"] < base_cov["endpoints_probed"])

    return {
        "summary": {k: len(v) for k, v in buckets.items()},
        "entries": [e.to_dict() for e in entries],
        "new": [e.to_dict() for e in buckets[STATUS_NEW]],
        "fixed": [e.to_dict() for e in buckets[STATUS_FIXED]],
        "changed": [e.to_dict() for e in buckets[STATUS_CHANGED]],
        "unchanged": [e.to_dict() for e in buckets[STATUS_UNCHANGED]],
        "coverage": {
            "baseline": base_cov, "current": cur_cov,
            "current_probed_less": coverage_regressed,
            "fixed_verified": not coverage_regressed,
            "note": (
                "The current scan probed fewer endpoints than the baseline, so a "
                "FIXED result may mean 'not tested' rather than 'remediated'. "
                "Re-test the fixed set explicitly before closing anything."
                if coverage_regressed else
                "Current coverage is at least the baseline's, so FIXED results are "
                "not explained by reduced coverage."),
        },
        "baseline_target": baseline.get("target"),
        "current_target": current.get("target"),
        "baseline_date": baseline.get("date"),
        "current_date": current.get("date"),
    }


def retest_targets(diff_result: dict, *, statuses=(STATUS_NEW, STATUS_CHANGED)) -> list[dict]:
    """Endpoints worth re-probing, for a `--retest-new`-style pass.

    Defaults to NEW and CHANGED: those are the findings a remediation cycle has
    not yet accounted for. Deduplicated by (class, endpoint) so one endpoint is
    probed once even when it carries several findings.
    """
    seen: set[tuple[str, str]] = set()
    out: list[dict] = []
    for e in diff_result.get("entries", []):
        if e["status"] not in statuses:
            continue
        key = (e["vuln_class"], e["endpoint"])
        if key in seen or not e["endpoint"]:
            continue
        seen.add(key)
        out.append({"vuln_class": e["vuln_class"], "endpoint": e["endpoint"],
                    "title": e["title"], "status": e["status"]})
    return out


def render(diff_result: dict) -> str:
    """Human-readable diff summary."""
    s = diff_result["summary"]
    lines = [
        "Scan diff",
        "=" * 62,
        f"  baseline : {diff_result.get('baseline_target') or '?'}  "
        f"({diff_result.get('baseline_date') or 'undated'})",
        f"  current  : {diff_result.get('current_target') or '?'}  "
        f"({diff_result.get('current_date') or 'undated'})",
        "",
        f"  NEW       {s['new']:4}   present now, absent before",
        f"  FIXED     {s['fixed']:4}   present before, absent now",
        f"  CHANGED   {s['changed']:4}   grading moved",
        f"  UNCHANGED {s['unchanged']:4}   still open, same grading",
        "",
    ]
    cov = diff_result.get("coverage", {})
    if not cov.get("fixed_verified", True):
        lines += ["  ! COVERAGE WARNING", "    " + cov.get("note", ""), ""]

    for status, header in ((STATUS_NEW, "NEW findings"),
                           (STATUS_CHANGED, "CHANGED findings"),
                           (STATUS_FIXED, "FIXED (no longer reproducing)")):
        items = diff_result.get(status) or []
        if not items:
            continue
        lines.append(f"  {header}:")
        for e in items[:40]:
            lines.append(f"    [{e['severity'] or '-':8}] {e['title'][:70]}")
            if e.get("endpoint"):
                lines.append(f"               {e['endpoint'][:78]}")
            for k, mv in (e.get("changes") or {}).items():
                lines.append(f"               {k}: {mv['from']} -> {mv['to']}")
        if len(items) > 40:
            lines.append(f"    … and {len(items) - 40} more")
        lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    as_json = "--json" in argv
    argv = [a for a in argv if a != "--json"]
    if len(argv) != 2:
        print(__doc__.strip().splitlines()[-1].strip(), file=sys.stderr)
        print("usage: python3 -m deluluscan.scandiff <baseline.json> <current.json> [--json]",
              file=sys.stderr)
        return 2
    with open(argv[0]) as fh:
        baseline = json.load(fh)
    with open(argv[1]) as fh:
        current = json.load(fh)
    result = diff(baseline, current)
    print(json.dumps(result, indent=2) if as_json else render(result))
    # Exit 1 when there is something new to look at, so CI can gate on it.
    return 1 if result["summary"]["new"] else 0


if __name__ == "__main__":
    sys.exit(main())
