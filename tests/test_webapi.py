"""Tests for deeper web/API surface checks (deluluscan/webapi/, WS-7).

Fully offline (transports injected). Locks down GraphQL introspection mapping
(dangerous mutations, sensitive fields, disabled-introspection), WebSocket CSWSH
(foreign-origin accepted vs. validated, auth grading), and gRPC reflection.
Run: python3 -m tests.test_webapi
"""
import os
import sys
import types

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from deluluscan.webapi import (analyze_graphql, parse_schema, check_cswsh,  # noqa: E402
                               check_grpc_reflection)
from deluluscan.models import VulnClass  # noqa: E402

_PASS = 0
_FAIL = 0


def check(name, cond, detail=""):
    global _PASS, _FAIL
    if cond:
        _PASS += 1; print(f"PASS  {name}")
    else:
        _FAIL += 1; print(f"FAIL  {name}  [{detail}]")


SCHEMA = {"data": {"__schema": {
    "queryType": {"name": "Query"}, "mutationType": {"name": "Mutation"},
    "types": [
        {"name": "Query", "fields": [{"name": "me"}, {"name": "users"}]},
        {"name": "Mutation", "fields": [{"name": "createPost"}, {"name": "deleteUser"},
                                        {"name": "resetPassword"}]},
        {"name": "User", "fields": [{"name": "id"}, {"name": "email"}, {"name": "passwordHash"},
                                    {"name": "apiKey"}]},
        {"name": "__Type", "fields": [{"name": "x"}]},
    ]}}}


def test_graphql_introspection_surface():
    surf, findings = analyze_graphql(lambda u, b: (200, SCHEMA), "http://t/graphql")
    check("introspection detected as enabled", surf.introspection_enabled)
    check("meta types excluded from count", surf.type_count == 3, surf.type_count)
    check("dangerous mutations flagged",
          {"deleteUser", "resetPassword"} <= {m["name"] for m in surf.mutations if m["dangerous"]})
    check("sensitive fields detected (passwordHash/apiKey)",
          {"passwordHash", "apiKey"} <= {s["field"] for s in surf.sensitive_fields})
    titles = {f.title for f in findings}
    check("introspection-enabled finding emitted", "GraphQL introspection enabled" in titles)
    intros = next(f for f in findings if f.title == "GraphQL introspection enabled")
    check("introspection finding uses GRAPHQL class + confirmed",
          intros.vuln_class == VulnClass.GRAPHQL and intros.verdict == "true_positive")
    check("dangerous mutations -> inventory finding",
          any(f.vuln_class == VulnClass.INVENTORY for f in findings))
    check("sensitive fields -> info_leak finding",
          any(f.vuln_class == VulnClass.INFO_LEAK for f in findings))


def test_graphql_introspection_disabled():
    err = {"errors": [{"message": "introspection is disabled"}]}
    surf, findings = analyze_graphql(lambda u, b: (400, err), "http://t/graphql")
    check("introspection reported off when no schema", surf.introspection_enabled is False)
    check("no findings when introspection disabled", findings == [])


def test_parse_schema_without_data_wrapper():
    surf = parse_schema(SCHEMA["data"], "http://t/graphql")
    check("parse_schema handles bare __schema", surf.introspection_enabled and surf.type_count == 3)


def test_cswsh_detected_when_origin_unvalidated():
    fs = check_cswsh(lambda origin: (101, {"upgrade": "websocket"}), "ws://t/s", authenticated=True)
    check("CSWSH flagged when foreign origin is accepted", len(fs) == 1)
    check("authenticated CSWSH is high/exploitable",
          fs[0].severity.value == "high" and fs[0].exploitability == "exploitable")
    check("CSWSH maps to misconfig", fs[0].vuln_class == VulnClass.MISCONFIG)


def test_cswsh_not_flagged_when_origin_validated():
    def connect(origin):
        return (101, {"upgrade": "websocket"}) if "app.local" in origin else (403, {})
    check("no CSWSH when the server validates Origin",
          check_cswsh(connect, "ws://t/s") == [])


def test_cswsh_unauthenticated_is_lower():
    fs = check_cswsh(lambda o: (101, {"upgrade": "websocket"}), "ws://t/s", authenticated=False)
    check("unauthenticated CSWSH graded lower (conditional)",
          fs and fs[0].exploitability == "conditional" and fs[0].severity.value == "medium")


def test_grpc_reflection():
    fs = check_grpc_reflection(
        lambda: (True, ["pkg.UserService", "pkg.AdminService",
                        "grpc.reflection.v1.ServerReflection"]), "grpc://t")
    check("gRPC reflection flagged", len(fs) == 1)
    check("reflection service filtered out of enumeration",
          "grpc.reflection.v1.ServerReflection" not in fs[0].detail["services"])
    check("gRPC reflection maps to inventory", fs[0].vuln_class == VulnClass.INVENTORY)
    check("no finding when reflection disabled",
          check_grpc_reflection(lambda: (False, []), "grpc://t") == [])


if __name__ == "__main__":
    for fn in [v for v in list(globals().values())
               if isinstance(v, types.FunctionType) and v.__name__.startswith("test_")]:
        try:
            fn()
        except Exception as e:
            import traceback
            _FAIL += 1
            print(f"FAIL  {fn.__name__}  [exception: {e}]")
            traceback.print_exc()
    print(f"\n{_PASS}/{_PASS + _FAIL} checks passed")
    sys.exit(1 if _FAIL else 0)
