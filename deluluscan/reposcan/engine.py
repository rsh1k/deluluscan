"""RepoScan — one static DevSecOps pass over a whole repository.

Ties the individual static analyzers into a single "scan my codebase" run:
source SAST + secrets, secrets across git history, cloud IaC (Terraform/
CloudFormation), containers + Kubernetes (incl. RBAC), CI/CD workflows, and any
SBOM found in the tree — merged, de-duplicated, and (optionally) enriched with
ATT&CK tags + a priority score. Every analyzer is offline; dependency-confusion
(which makes registry lookups) is opt-in.

Nothing here reimplements a scanner — it dispatches to the existing modules and
aggregates. Fail-soft per analyzer: one blowing up never sinks the whole scan.
"""
from __future__ import annotations

import os

from ..assess.runner import dedup


def _safe(label, fn, out, ran):
    try:
        out.extend(fn() or [])
        ran.append(label)
    except Exception:
        ran.append(label + "!")     # ran but errored — recorded, not fatal


def _find_sboms(root: str, limit: int = 50) -> list:
    from ..sbom.parse import detect_format
    import json
    hits, n = [], 0
    for dp, dirs, names in os.walk(root):
        dirs[:] = [d for d in dirs if d not in {".git", "node_modules", "__pycache__", ".venv", "venv"}]
        for name in names:
            if n >= limit:
                return hits
            if not name.lower().endswith((".json", ".cdx.json", ".spdx.json")):
                continue
            n += 1
            fp = os.path.join(dp, name)
            try:
                with open(fp, encoding="utf-8", errors="replace") as fh:
                    data = json.load(fh)
            except Exception:
                continue
            if detect_format(data):
                hits.append(fp)
    return hits


class RepoScan:
    def scan(self, path: str, *, depconfusion: bool = False, prioritize: bool = True) -> dict:
        findings, ran = [], []

        from ..sast import SastScan
        _safe("sast", lambda: SastScan().scan_path(path), findings, ran)

        if os.path.isdir(os.path.join(path, ".git")):
            from ..githistory import GitSecretScan
            _safe("githistory", lambda: GitSecretScan().scan_repo(path), findings, ran)

        from ..iac import IacScan
        _safe("iac", lambda: IacScan().scan_path(path), findings, ran)

        from ..container.engine import ContainerScan
        _safe("container", lambda: ContainerScan().scan_path(path), findings, ran)  # Docker/K8s/compose (+RBAC)

        from ..cicd import CicdScan
        _safe("cicd", lambda: CicdScan().scan_path(path), findings, ran)

        from ..sbom import SbomScan
        sboms = []
        for fp in _find_sboms(path):
            try:
                sboms.extend(SbomScan().scan_file(fp))
            except Exception:
                pass
        if sboms:
            findings.extend(sboms); ran.append("sbom")

        if depconfusion:
            from ..depconfusion import DepConfusionScan
            _safe("depconfusion", lambda: DepConfusionScan().scan_path(path), findings, ran)

        merged = dedup(findings)

        if prioritize:
            try:
                from ..attack import attach_attack
                attach_attack(merged)
            except Exception:
                pass
            try:
                from ..priority import attach_priority
                attach_priority(merged)
            except Exception:
                pass

        counts = {}
        for f in merged:
            sv = f.severity.value if hasattr(f.severity, "value") else f.severity
            counts[sv] = counts.get(sv, 0) + 1
        return {"findings": merged, "analyzers": ran, "counts": counts, "path": path}

    def payload(self, path: str, **kw) -> dict:
        import time
        res = self.scan(path, **kw)
        return {"findings": [f.to_dict() for f in res["findings"]],
                "meta": {"target": path, "generated_at": time.time(), "tool": "deluluscan",
                         "scan_type": "repo-static", "analyzers": res["analyzers"],
                         "finding_count": len(res["findings"]), "severity_counts": res["counts"]}}
