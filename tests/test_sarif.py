"""SARIF export — location anchoring for source vs. web findings."""
from __future__ import annotations

import json
import tempfile

from deluluscan.reporting.sarif import write_sarif, _physical_location

_PASS = 0; _FAIL = 0
def check(name, cond, detail=""):
    global _PASS, _FAIL
    if cond: _PASS += 1; print(f"PASS  {name}")
    else: _FAIL += 1; print(f"FAIL  {name}  {detail}")


def test_source_finding_splits_path_and_line():
    loc = _physical_location("deluluscan/dashboard.py:219")
    check("uri is the file path", loc["artifactLocation"]["uri"] == "deluluscan/dashboard.py", loc)
    check("line goes to region.startLine", loc["region"]["startLine"] == 219, loc)


def test_web_url_kept_as_uri():
    loc = _physical_location("http://host/api/users?id=1")
    check("web URL kept whole", loc["artifactLocation"]["uri"] == "http://host/api/users?id=1", loc)
    check("web URL has no bogus region", "region" not in loc, loc)


def test_write_sarif_valid_document():
    result = {"findings": [
        {"vuln_class": "sqli", "severity": "high", "title": "SQLi", "description": "x",
         "endpoint": "app/db.py:42", "confidence": "firm"},
        {"vuln_class": "misconfig", "severity": "low", "title": "hdr", "description": "y",
         "endpoint": "https://t/"},
    ]}
    with tempfile.TemporaryDirectory() as d:
        path = write_sarif(result, d)
        doc = json.load(open(path))
    check("sarif version 2.1.0", doc["version"] == "2.1.0")
    run = doc["runs"][0]
    check("two results", len(run["results"]) == 2)
    check("rules registered", len(run["tool"]["driver"]["rules"]) == 2)
    src = run["results"][0]
    check("source result has startLine",
          src["locations"][0]["physicalLocation"]["region"]["startLine"] == 42, src)
    check("high -> error level", src["level"] == "error")
    web = run["results"][1]
    check("web result has no region",
          "region" not in web["locations"][0]["physicalLocation"])


if __name__ == "__main__":
    for fn in [v for k, v in sorted(globals().items()) if k.startswith("test_")]:
        fn()
    print(f"\n{_PASS} passed, {_FAIL} failed")
    raise SystemExit(1 if _FAIL else 0)
