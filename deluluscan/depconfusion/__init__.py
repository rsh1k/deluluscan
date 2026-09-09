"""Dependency-confusion / namespace-squatting detection.

A dependency your build resolves from a PRIVATE registry, but whose name is NOT
claimed on the matching PUBLIC registry, can be hijacked: an attacker publishes a
public package of the same name (often with a higher version) and the installer
pulls theirs instead — arbitrary code execution in your build (Alex Birsan, 2021).

This parses dependency manifests + private-registry config, then checks each
declared package against the public registry. A package your project depends on
that is ABSENT from the public registry is a confusion candidate — HIGH when a
private registry is configured (confirmed internal resolution), otherwise MEDIUM.

Registry lookups are injected (`registry_check`) so the whole thing is offline-
testable; the default queries npm/PyPI and FAILS SOFT (unknown -> not flagged, so
a network blip never invents a finding). Detection only.
"""
from .engine import DepConfusionScan, Dependency

__all__ = ["DepConfusionScan", "Dependency"]
