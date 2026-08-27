"""Tests for the OpenAPI/Swagger security linter (deluluscan/apispec/)."""
import os, sys, json, tempfile, types
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from deluluscan.apispec import lint_spec, ApiSpecScan  # noqa: E402
from deluluscan.models import VulnClass  # noqa: E402
_PASS = 0; _FAIL = 0
def check(n, c, d=""):
    global _PASS, _FAIL
    if c: _PASS += 1; print(f"PASS  {n}")
    else: _FAIL += 1; print(f"FAIL  {n}  [{d}]")
def titles(fs): return {f.title for f in fs}
def rules(fs): return {f.detail.get("rule") for f in fs}

def test_openapi3_vulnerable_spec():
    spec = {"openapi": "3.0.0", "servers": [{"url": "http://api.example.com"}],
            "components": {"securitySchemes": {"k": {"type": "apiKey", "in": "query", "name": "api_key"}}},
            "security": [{"k": []}],
            "paths": {
                "/admin/delete": {"post": {"security": []}},
                "/users/{id}": {"get": {"security": []},
                                "parameters": [{"in": "path", "name": "token"}]},
                "/items": {"post": {"requestBody": {"content": {"application/json":
                            {"schema": {"additionalProperties": True}}}}}},
                "/old": {"get": {"deprecated": True}},
            }}
    r = rules(lint_spec(spec))
    for rule in ["spec-apikey-query", "spec-http-server", "spec-unauth-write",
                 "spec-sensitive-param", "spec-mass-assignment", "spec-deprecated"]:
        check(f"flags {rule}", rule in r, r)

def test_effective_security_logic():
    # operation without `security` inherits a non-empty global -> secured (no finding)
    spec = {"openapi": "3.0.0", "security": [{"apiKey": []}],
            "components": {"securitySchemes": {"apiKey": {"type": "http", "scheme": "bearer"}}},
            "paths": {"/x": {"post": {}}, "/y": {"post": {"security": []}}}}
    fs = lint_spec(spec)
    eps = {f.endpoint for f in fs if f.detail.get("rule") == "spec-unauth-write"}
    check("inherited global security -> POST /x not flagged", "POST /x" not in eps)
    check("explicit empty security -> POST /y flagged", "POST /y" in eps, eps)

def test_no_scheme_whole_api_unauth():
    spec = {"openapi": "3.0.0", "paths": {"/a": {"post": {}}, "/b": {"delete": {}}}}
    fs = lint_spec(spec)
    check("no security scheme + write ops -> whole-API-unauth finding",
          any(f.detail.get("rule") == "spec-no-auth-scheme" and f.severity.value == "high" for f in fs))

def test_hardened_spec_is_clean():
    spec = {"openapi": "3.0.0", "servers": [{"url": "https://api.example.com"}],
            "components": {"securitySchemes": {"bearer": {"type": "http", "scheme": "bearer"}}},
            "security": [{"bearer": []}],
            "paths": {"/users": {"get": {}, "post": {}}}}
    check("hardened spec yields no findings", lint_spec(spec) == [], [f.title for f in lint_spec(spec)])

def test_swagger2_http_and_defs():
    spec = {"swagger": "2.0", "host": "api.example.com", "schemes": ["http"],
            "securityDefinitions": {"key": {"type": "apiKey", "in": "query", "name": "k"}},
            "security": [{"key": []}],
            "paths": {"/z": {"post": {"security": []}}}}
    r = rules(lint_spec(spec))
    check("swagger2 flags http scheme", "spec-http-server" in r)
    check("swagger2 flags apikey-in-query", "spec-apikey-query" in r)
    check("swagger2 flags unauth write", "spec-unauth-write" in r)

def test_classes_map():
    spec = {"openapi": "3.0.0", "paths": {"/a": {"post": {"security": []}}}}
    fs = lint_spec(spec)
    check("unauth write -> authz", any(f.vuln_class == VulnClass.AUTHZ for f in fs))

def test_engine_scan_file_json():
    spec = {"openapi": "3.0.0", "paths": {"/a": {"post": {"security": []}}}}
    d = tempfile.mkdtemp(); p = os.path.join(d, "openapi.json")
    with open(p, "w") as fh: json.dump(spec, fh)
    check("scan_file loads + lints json", len(ApiSpecScan().scan_file(p)) >= 1)

if __name__ == "__main__":
    for fn in [v for v in list(globals().values()) if isinstance(v, types.FunctionType) and v.__name__.startswith("test_")]:
        try: fn()
        except Exception as e:
            import traceback; _FAIL += 1; print(f"FAIL  {fn.__name__}  [exc: {e}]"); traceback.print_exc()
    print(f"\n{_PASS}/{_PASS + _FAIL} checks passed"); sys.exit(1 if _FAIL else 0)
