"""CLI: security-lint an OpenAPI/Swagger spec.

    python3 -m deluluscan.apispec --spec openapi.json [--json]
"""
from __future__ import annotations

import argparse, json, sys
from .engine import ApiSpecScan


def main(argv=None):
    p = argparse.ArgumentParser(prog="deluluscan.apispec", description="OpenAPI/Swagger security linter")
    p.add_argument("--spec", required=True, help="path to an OpenAPI 3.x / Swagger 2.0 spec (JSON/YAML)")
    p.add_argument("--json", action="store_true")
    a = p.parse_args(argv)
    fs = ApiSpecScan().scan_file(a.spec)
    if a.json:
        print(json.dumps([f.to_dict() for f in fs], indent=2, default=str)); return 0
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    fs.sort(key=lambda f: order.get(f.severity.value, 9))
    print(f"[apispec] {a.spec}: {len(fs)} finding(s)")
    for f in fs:
        print(f"  [{f.severity.value:>8}] {f.title:<52} {f.endpoint}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
