"""CloudScan — evaluate a collected cloud inventory (CSPM) and/or probe instance
metadata for credential exposure."""
from __future__ import annotations

import json
from typing import Callable, Optional

from ..models import Finding
from .checks import PROVIDERS
from .imds import check_imds


class CloudScan:
    def scan_inventory(self, inventory: dict, provider: Optional[str] = None) -> list:
        findings: list[Finding] = []
        if provider:
            fn = PROVIDERS.get(provider)
            if fn:
                findings += fn(inventory.get(provider, inventory))
            return findings
        # auto: inventory keyed by provider, or a single flat dict tried against all
        for name, fn in PROVIDERS.items():
            if name in inventory:
                findings += fn(inventory[name])
        if not findings and not any(p in inventory for p in PROVIDERS):
            for fn in PROVIDERS.values():
                findings += fn(inventory)
        return findings

    def scan_file(self, path: str, provider: Optional[str] = None) -> list:
        with open(path) as fh:
            inv = json.load(fh)
        return self.scan_inventory(inv, provider)

    def check_metadata_exposure(self, fetch: Optional[Callable] = None) -> list:
        return check_imds(fetch)
