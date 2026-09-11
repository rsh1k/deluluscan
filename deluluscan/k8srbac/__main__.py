"""CLI: python3 -m deluluscan.k8srbac --path ./k8s [--json]

Analyzes Kubernetes Role/ClusterRole/RoleBinding/ClusterRoleBinding manifests for
over-permissive RBAC. Static, offline."""
from __future__ import annotations

import argparse
import json
import sys

from .engine import K8sRbacScan


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="deluluscan.k8srbac", description="Kubernetes RBAC analyzer")
    ap.add_argument("--path", default=".", help="manifest file or directory")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    finds = K8sRbacScan().scan_path(a.path)
    if a.json:
        print(json.dumps([f.to_dict() for f in finds], indent=2, default=str))
        return 0
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    finds.sort(key=lambda f: order.get(f.severity.value, 9))
    print(f"[k8srbac] {a.path}: {len(finds)} finding(s)")
    for f in finds:
        print(f"  [{f.severity.value.upper():8}] {f.title}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
