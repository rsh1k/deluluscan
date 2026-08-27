#!/usr/bin/env python3
"""fix_sca_findings.py — one-off corrective pass for a scan run captured before
the _verify_generic SCA-reissue bug (deluluscan/verify/verifier.py) was fixed.

That bug re-verified every dependency_scanner (SCA) finding by reissuing its
sentinel, non-HTTP RequestRecord as if it were a real request, then calling the
unrelated real response a "status drift" and downgrading it — severity included
(_apply() downgrades severity on likely_false_positive) — discarding the
scanner's own shipped-vs-manifest-only grading for every single SCA finding.

Rather than patch severities/verdicts in the JSON by hand (which would just be
guessing), this re-runs the actual DependencyScanner against the same
source_root + container the original scan used, producing fresh Findings with
correct severity, then re-verifies them with the FIXED Verifier, then splices
the corrected supply_chain findings back into results.json in place of the
corrupted ones (matched by package+advisory identity).
"""
from __future__ import annotations

import argparse
import json

from deluluscan.config import load_config
from deluluscan.verify import Verifier
from deluluscan.scanners.dependency_scanner import DependencyScanner


class _NullAuth:
    def headers_for(self, identity):
        return {}


class _NullClient:
    def request(self, *a, **kw):
        raise RuntimeError("SCA findings must not issue live HTTP requests")


def main(argv=None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--config", default="config.dev.yaml")
    p.add_argument("--results", default="deluluscan-out/results.json")
    p.add_argument("--source-root", default=".target-src/core")
    args = p.parse_args(argv)

    cfg = load_config(args.config)
    cfg.source_root = args.source_root

    scanner = DependencyScanner(_NullClient(), _NullAuth(), cfg, identities={})
    fresh = list(scanner.run(endpoint=None))
    print(f"[fix_sca] DependencyScanner produced {len(fresh)} fresh finding(s)")

    verifier = Verifier(_NullClient(), _NullAuth(), identities={})
    verifier.verify_all(fresh)

    def key(detail: dict) -> tuple:
        artifacts = detail.get("artifacts") or {}
        artifacts_key = tuple(sorted((k, str(v)) for k, v in artifacts.items()))
        return (detail.get("package", ""), detail.get("version", ""),
                detail.get("advisory", "") or artifacts_key)

    fresh_by_key = {key(f.detail): f for f in fresh}

    with open(args.results) as fh:
        data = json.load(fh)
    findings = data["findings"]

    replaced = 0
    for i, fd in enumerate(findings):
        detail = fd.get("detail") or {}
        if detail.get("test") not in ("sca", "sca_duplicate_artifacts"):
            continue
        k = key(detail)
        fresh_f = fresh_by_key.get(k)
        if fresh_f is None:
            print(f"  [!] no fresh match for {fd.get('title')} — leaving as-is")
            continue
        new_dict = fresh_f.to_dict()
        old_verdict, old_sev = fd.get("verdict"), fd.get("severity")
        findings[i] = new_dict
        replaced += 1
        if new_dict["verdict"] != old_verdict or new_dict["severity"] != old_sev:
            print(f"  corrected: {fd.get('title')[:70]:70s} "
                  f"verdict {old_verdict}->{new_dict['verdict']}  "
                  f"severity {old_sev}->{new_dict['severity']}")

    with open(args.results, "w") as fh:
        json.dump(data, fh, indent=2)
    print(f"[fix_sca] replaced {replaced} SCA finding(s) in {args.results}")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
