"""CLI: one static DevSecOps scan of a whole repo.

    python3 -m deluluscan.reposcan --path . [--formats md,html,json,sarif] [--out-dir ./report]
    python3 -m deluluscan.reposcan --path . --depconfusion   # add registry-lookup dep-confusion

Runs SAST + secrets, git-history secrets, IaC (Terraform/CFN), containers/K8s
(+RBAC), CI/CD workflows, and any SBOM found — merged into one report. Offline
(except --depconfusion). Runs on a repo you own."""
from __future__ import annotations

import argparse
import sys

from .engine import RepoScan


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="deluluscan.reposcan", description="unified repo static DevSecOps scan")
    ap.add_argument("--path", default=".", help="repo root to scan")
    ap.add_argument("--depconfusion", action="store_true", help="also run dependency-confusion (registry lookups)")
    ap.add_argument("--no-prioritize", action="store_true", help="skip ATT&CK/priority enrichment")
    ap.add_argument("--formats", default="", help="also write reports: comma list json,md,html,sarif,csv")
    ap.add_argument("--out-dir", default="./deluluscan-repo-report")
    a = ap.parse_args(argv)

    scanner = RepoScan()
    payload = scanner.payload(a.path, depconfusion=a.depconfusion, prioritize=not a.no_prioritize)
    meta = payload["meta"]
    print(f"[reposcan] {a.path}: {meta['finding_count']} finding(s) from analyzers {meta['analyzers']}")
    counts = meta["severity_counts"]
    for sev in ("critical", "high", "medium", "low", "info"):
        if counts.get(sev):
            print(f"    {sev:8}: {counts[sev]}")
    if a.formats:
        from ..assess.report import write_reports
        written = write_reports(payload, a.out_dir, [f for f in a.formats.split(",") if f.strip()])
        for fmt, p in written.items():
            print(f"  wrote {fmt:>6}: {p}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
