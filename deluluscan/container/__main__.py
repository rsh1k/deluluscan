"""CLI: scan container/IaC configs (and optionally an authorized host's control plane).

    python3 -m deluluscan.container --path ./deploy
    python3 -m deluluscan.container --path Dockerfile --json
    python3 -m deluluscan.container --host 127.0.0.1   # probe exposed Docker/kubelet/etcd
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import socket
import sys

from .engine import ContainerScan


def _is_local(host: str) -> bool:
    try:
        return ipaddress.ip_address(socket.gethostbyname(host)).is_loopback or \
               ipaddress.ip_address(socket.gethostbyname(host)).is_private
    except Exception:
        return False


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="deluluscan.container",
                                description="container / Kubernetes / IaC security scan")
    p.add_argument("--path", help="file or directory of Dockerfile/k8s/compose configs")
    p.add_argument("--host", help="probe a host for exposed container/orchestrator control planes")
    p.add_argument("--allow-remote", action="store_true")
    p.add_argument("--json", action="store_true")
    args = p.parse_args(argv)
    if not args.path and not args.host:
        p.error("provide --path and/or --host")

    scan = ContainerScan()
    findings = []
    if args.path:
        findings += scan.scan_path(args.path)
    if args.host:
        if not _is_local(args.host) and not args.allow_remote:
            raise SystemExit(f"[scope] {args.host} is not loopback/RFC1918; use --allow-remote "
                             "only if authorized.")
        findings += scan.check_exposed_services(args.host)

    if args.json:
        print(json.dumps([f.to_dict() for f in findings], indent=2, default=str))
        return 0
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: order.get(f.severity.value, 9))
    print(f"[container] {len(findings)} finding(s)")
    for f in findings:
        print(f"  [{f.severity.value:>8}] {f.title:<42} {f.endpoint}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
