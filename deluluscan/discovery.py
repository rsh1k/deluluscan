"""Endpoint discovery.

Primary source is the target's own OpenAPI document at /api/openapi.json (the same
spec that powers the admin "API Playground"). We parse it into Endpoint objects
and tag the ones that take an opaque object id / inode / identifier in the path
or query, because those are the prime IDOR candidates.

If the spec can't be reached (older builds, or anonymous access disabled) we fall
back to a curated seed list of well-known REST resources.
"""
from __future__ import annotations

import json
import os
import re
from typing import Any

from .http_client import HttpClient
from .models import Endpoint

# Path/param tokens that usually denote a per-object reference an attacker could
# swap to reach another tenant/user's data -> IDOR candidates.
_ID_TOKENS = re.compile(
    r"(?:^|[/{_])(id|ident|identifier|inode|userid|user_id|roleid|role_id|"
    r"key|token|assetid|asset_id|folderid|folder_id|contentid|guid|uuid)"
    r"(?:$|[}/_])",
    re.IGNORECASE,
)

# A small, target-accurate seed set used when the spec is unavailable. These are
# documented endpoints; many take ids and are classic IDOR/authz surfaces.
SEED_ENDPOINTS: list[Endpoint] = []  # no product-specific seed set (generic tool)


def _is_id_bearing(path: str, params: list[dict]) -> bool:
    if _ID_TOKENS.search(path):
        return True
    return any(_ID_TOKENS.search(str(p.get("name", ""))) for p in params)


def parse_openapi(spec: dict[str, Any], methods: list[str]) -> list[Endpoint]:
    endpoints: list[Endpoint] = []
    allowed = {m.lower() for m in methods}
    for path, item in (spec.get("paths") or {}).items():
        common_params = item.get("parameters", []) if isinstance(item, dict) else []
        for method, op in (item or {}).items():
            if method.lower() not in allowed or not isinstance(op, dict):
                continue
            params = list(common_params) + list(op.get("parameters", []))
            path_params = [p["name"] for p in params if p.get("in") == "path"]
            query_params = [p for p in params if p.get("in") == "query"]
            body = {}
            rb = op.get("requestBody", {})
            try:
                body = (rb.get("content", {}).get("application/json", {})
                        .get("schema", {}))
            except AttributeError:
                body = {}
            endpoints.append(Endpoint(
                method=method.upper(), path=path,
                summary=op.get("summary", "") or op.get("operationId", ""),
                tags=op.get("tags", []),
                path_params=path_params, query_params=query_params,
                request_body_schema=body,
                id_bearing=_is_id_bearing(path, params),
            ))
    return endpoints


def discover(client: HttpClient, openapi_path: str,
             methods: list[str], auth_attempts: list[dict] | None = None,
             local_file: str | None = None) -> tuple[list[Endpoint], str]:
    """Return (endpoints, source_description).

    Source priority:
      1. a local OpenAPI file (saved from your authenticated browser) if given;
      2. the live spec fetched anonymously, then with supplied auth headers
         (the target build 26.x gates /api/openapi.json behind the admin session);
      3. the curated seed list.
    """
    # 1) local file — the most reliable path on locked-down builds.
    if local_file:
        if not os.path.exists(local_file):
            return [], (f"no spec (--openapi-file '{local_file}' NOT FOUND in "
                        f"{os.getcwd()} — check the path/filename; relying on recon/crawl)")
        try:
            with open(local_file) as fh:
                head = fh.read(64).lstrip()
                fh.seek(0)
                if not head.startswith("{"):
                    return [], (f"no spec ('{local_file}' is not JSON — looks like "
                                f"'{head[:24]}...'; you may have saved an HTML page)")
                spec = json.load(fh)
            eps = parse_openapi(spec, methods)
            if eps:
                return eps, f"local file {local_file} ({len(eps)} operations)"
            return [], f"no spec ('{local_file}' parsed but had no paths)"
        except (json.JSONDecodeError, OSError) as exc:
            return [], f"no spec (could not read {local_file}: {exc})"

    # 2) live fetch, anon then authenticated.
    attempts: list[tuple[str, dict]] = [("anonymous", {})]
    for a in (auth_attempts or []):
        attempts.append((a.get("label", "auth"), a.get("headers", {})))

    for label, headers in attempts:
        rec = client.request("GET", openapi_path, identity_label=label,
                             headers=headers or None)
        if rec.status == 200 and rec.resp_body.strip().startswith("{"):
            try:
                spec = json.loads(rec.resp_body)
                eps = parse_openapi(spec, methods)
                if eps:
                    via = "" if label == "anonymous" else f", via {label}"
                    return eps, f"openapi.json ({len(eps)} operations{via})"
            except json.JSONDecodeError:
                pass
    # No spec available. Do NOT probe the target-specific seed list against an
    # arbitrary target — that produced meaningless target-path requests on
    # non-target sites. Return empty and rely on recon/crawl; the seed set
    # is injected later only if the target actually fingerprints as the target.
    return [], "no OpenAPI spec (relying on recon/crawl; pass --openapi-file for full API coverage)"
