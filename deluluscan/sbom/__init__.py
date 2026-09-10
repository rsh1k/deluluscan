"""SBOM (CycloneDX / SPDX) analysis: known-vulnerable components + integrity gaps."""
from .engine import SbomScan
from .parse import parse_sbom, Component
from .analyzer import analyze_components

__all__ = ["SbomScan", "parse_sbom", "Component", "analyze_components"]
