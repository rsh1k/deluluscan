"""ContainerScan — walk a repo/dir, detect container/IaC files, and aggregate
container security findings. Optionally probe a host for exposed container/orchestrator
control planes (Docker API, kubelet, etcd, insecure API server, registry).

Static analysis is offline and safe. The exposed-service probe sends requests, so
callers gate it behind the usual authorization boundary.
"""
from __future__ import annotations

import os
import re
from typing import Callable, Optional

import yaml

from ..models import Finding, Severity, VulnClass
from .analyzers import analyze_compose, analyze_dockerfile, analyze_k8s

_K8S_KINDS = {"pod", "deployment", "daemonset", "statefulset", "replicaset",
              "job", "cronjob"}
_COMPOSE_RE = re.compile(r"(docker-)?compose.*\.ya?ml$", re.I)
_DOCKERFILE_RE = re.compile(r"(^|\.)dockerfile$|^dockerfile(\.|$)", re.I)

# Exposed container/orchestrator control planes: (port, path, marker, name, severity)
EXPOSED_SERVICES = [
    (2375, "/version", r'"ApiVersion"', "Unauthenticated Docker API (2375)", "critical"),
    (2376, "/version", r'"ApiVersion"', "Docker API (2376)", "high"),
    (10250, "/pods", r'"kind"\s*:\s*"PodList"|"items"', "Exposed kubelet API (10250)", "critical"),
    (2379, "/version", r'etcdserver|etcdcluster', "Exposed etcd (2379)", "critical"),
    (8080, "/api", r'"versions"|"serverAddressByClientCIDRs"', "Insecure Kubernetes API (8080)", "critical"),
    (5000, "/v2/", r'{}|"repositories"|registry', "Exposed container registry (5000)", "medium"),
]


class ContainerScan:
    def __init__(self, max_files: int = 2000):
        self.max_files = max_files

    # -- static IaC scan ----------------------------------------------------
    def scan_text(self, text: str, kind: str, name: str) -> list:
        if kind == "dockerfile":
            return analyze_dockerfile(text, name)
        if kind == "compose":
            try:
                return analyze_compose(yaml.safe_load(text) or {}, name)
            except Exception:
                return []
        if kind == "k8s":
            try:
                docs = [d for d in yaml.safe_load_all(text)
                        if isinstance(d, dict) and (d.get("kind") or "").lower() in _K8S_KINDS]
            except Exception:
                return []
            return analyze_k8s(docs, name)
        return []

    def _classify(self, fname: str) -> Optional[str]:
        base = os.path.basename(fname)
        if _DOCKERFILE_RE.search(base):
            return "dockerfile"
        if _COMPOSE_RE.search(base):
            return "compose"
        if base.endswith((".yaml", ".yml")):
            return "k8s"
        return None

    def scan_path(self, path: str) -> list:
        findings: list[Finding] = []
        seen = 0
        if os.path.isfile(path):
            files = [path]
        else:
            files = []
            for root, dirs, names in os.walk(path):
                dirs[:] = [d for d in dirs if d not in (".git", "node_modules", "__pycache__")]
                for n in names:
                    files.append(os.path.join(root, n))
        for fp in files:
            if seen >= self.max_files:
                break
            kind = self._classify(fp)
            if not kind:
                continue
            seen += 1
            try:
                with open(fp, "r", errors="ignore") as fh:
                    text = fh.read()
            except Exception:
                continue
            rel = os.path.relpath(fp, path) if os.path.isdir(path) else fp
            findings.extend(self.scan_text(text, kind, rel))
        return findings

    # -- optional exposed-service probe ------------------------------------
    def check_exposed_services(self, host: str,
                               probe: Optional[Callable] = None) -> list:
        """Probe common control-plane ports on `host`. `probe(port, path) ->
        (status:int, body:str)` is injectable; the default uses requests."""
        if probe is None:
            probe = self._default_probe
        findings: list[Finding] = []
        for port, pth, marker, name, sev in EXPOSED_SERVICES:
            try:
                status, body = probe(port, pth)
            except Exception:
                continue
            if status == 200 and re.search(marker, body or "", re.I):
                findings.append(Finding(
                    vuln_class=VulnClass.MISCONFIG,
                    severity={"critical": Severity.CRITICAL, "high": Severity.HIGH,
                              "medium": Severity.MEDIUM}[sev],
                    title=name, endpoint=f"{host}:{port}{pth}",
                    description=f"{name} is reachable and responded to an unauthenticated request "
                                f"— a direct path to container/host compromise.",
                    detail={"port": port, "path": pth, "rule": "exposed-control-plane"},
                    confidence="confirmed", verdict="true_positive", exploitability="exploitable"))
        return findings

    @staticmethod
    def _default_probe(port, path):
        import requests
        for scheme in ("http", "https"):
            try:
                r = requests.get(f"{scheme}://127.0.0.1:{port}{path}", timeout=4, verify=False)
                return r.status_code, r.text[:20000]
            except Exception:
                continue
        return 0, ""
