"""Base class for all scanners.

A scanner takes the shared scan context (http client, auth manager, config,
identities) and yields Finding objects. Scanners are *detectors*: they send
benign probes and reason about the response. They never attempt to weaponize a
vulnerability (no payload delivery, no command execution, no session theft).
"""
from __future__ import annotations

import string
import random
from typing import Iterable

from ..auth import AuthManager
from ..config import Config
from ..http_client import HttpClient
from ..models import Endpoint, Finding, Identity


def canary(prefix: str = "deluluscan") -> str:
    """A unique, harmless marker we can grep for in responses."""
    rand = "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
    return f"{prefix}{rand}"


def sample_value_for_param(name: str) -> str:
    """A plausible placeholder so id-bearing endpoints return *something*."""
    low = name.lower()
    if "inode" in low or "identifier" in low or "uuid" in low:
        return "00000000-0000-0000-0000-000000000000"
    if low in ("id", "roleid", "userid", "siteid", "folderid", "assetid",
               "taskid", "actionid", "pageid", "bundleid"):
        return "00000000-0000-0000-0000-000000000000"
    if "id" in low and len(low) <= 10:
        return "00000000-0000-0000-0000-000000000000"
    if "lang" in low or "language" in low:
        return "1"
    if "uri" in low or "path" in low:
        return "/"
    if "key" in low or "var" in low or "name" in low:
        return "test"
    if "type" in low or "class" in low:
        return "webPageContent"
    if "site" in low:
        return "default"
    if "param" in low or "field" in low:
        return "test"
    return "1"


class Scanner:
    name = "base"
    vuln_classes: list[str] = []

    def __init__(self, client: HttpClient, auth: AuthManager, config: Config,
                 identities: dict[str, Identity]):
        self.client = client
        self.auth = auth
        self.config = config
        self.identities = identities

    def applies_to(self, endpoint: Endpoint) -> bool:
        return True

    def run(self, endpoint: Endpoint) -> Iterable[Finding]:
        raise NotImplementedError

    # -- helpers ------------------------------------------------------------
    def concrete_path(self, endpoint: Endpoint, overrides: dict | None = None) -> str:
        overrides = overrides or {}
        path = endpoint.path
        for p in endpoint.path_params:
            path = path.replace("{" + p + "}", str(overrides.get(p, sample_value_for_param(p))))
        return path

    def fetch(self, endpoint: Endpoint, identity: Identity, *,
              path_overrides: dict | None = None, params: dict | None = None,
              json_body=None):
        headers = self.auth.headers_for(identity)
        return self.client.request(
            endpoint.method, self.concrete_path(endpoint, path_overrides),
            identity_label=identity.label(), headers=headers,
            params=params, json_body=json_body,
        )
