"""Deluluscan container & Kubernetes security (WS-4).

Static analysis of Dockerfile / Kubernetes manifests / docker-compose for security
misconfigurations, plus an optional exposed-control-plane probe.

    from deluluscan.container import ContainerScan
    findings = ContainerScan().scan_path("./deploy")

CLI: python3 -m deluluscan.container --path ./deploy
"""
from .engine import ContainerScan, EXPOSED_SERVICES
from .analyzers import analyze_dockerfile, analyze_k8s, analyze_compose

__all__ = ["ContainerScan", "EXPOSED_SERVICES",
           "analyze_dockerfile", "analyze_k8s", "analyze_compose"]
