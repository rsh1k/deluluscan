"""CLI: python3 -m deluluscan.platforms --url http://127.0.0.1:8080"""
from __future__ import annotations

import argparse
import json
import sys

from .engine import PlatformScan


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Identify a platform and test its exposed surface.")
    ap.add_argument("--url", required=True, help="base URL of the target")
    ap.add_argument("--json", action="store_true", help="emit JSON")
    ap.add_argument("--timeout", type=int, default=10)
    args = ap.parse_args(argv)

    scan = PlatformScan(timeout=args.timeout)
    det, findings = scan.run(args.url)

    if args.json:
        out = {
            "detected": None if not det else {
                "platform": det.profile.name, "category": det.profile.category,
                "score": det.score, "confidence": det.confidence,
                "matched": det.matched, "api_base": det.profile.api_base,
                "api_style": det.profile.api_style,
                "auth_methods": list(det.profile.auth_methods),
                "sensitive_paths": list(det.profile.sensitive_paths)},
            "findings": [f.to_dict() for f in findings]}
        print(json.dumps(out, indent=2, default=str))
        return 0

    if not det:
        print("No known platform fingerprinted.")
        return 0
    p = det.profile
    print(f"Platform : {p.name} ({p.category})  [{det.confidence}, score {det.score:g}]")
    print(f"Signals  : {', '.join(det.matched)}")
    if p.api_base:
        print(f"API      : {p.api_base}  ({p.api_style})   auth: {', '.join(p.auth_methods)}")
    if p.sensitive_paths:
        print(f"Surface  : {', '.join(p.sensitive_paths)}")
    print(f"\nFindings : {len(findings)}")
    for f in findings:
        print(f"  [{f.severity.value.upper():8}] {f.title}  ({f.endpoint})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
