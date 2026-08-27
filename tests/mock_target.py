"""A tiny loopback HTTP target that mimics a target-style API with a mix of
REAL vulnerabilities and known FALSE-POSITIVE traps, so we can prove the
verifier end-to-end against the real HttpClient. Detection-only test fixture.

Routes:
  /api/openapi.json                 minimal spec advertising the endpoints below
  /api/vuln/search?q=               REAL reflected XSS (unescaped, text/html, no CSP)
  /api/safe/search?q=               reflection BUT strong CSP  -> mitigated
  /api/json/search?q=               reflection in application/json + nosniff -> not exploitable
  /api/vuln/item?id=                REAL error-based SQLi (DB error only on quote)
  /api/trap/item?id=                FALSE POSITIVE: always prints a stack trace
  /api/vuln/user/{id}               REAL horizontal IDOR (real id -> object, bogus -> 404)
  /api/trap/page/{id}               FALSE POSITIVE IDOR: any id -> same static page
  /api/vuln/roles                   REAL missing-auth: anon gets privileged JSON
"""
from __future__ import annotations
import json
import re
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

from deluluscan.active import jwt_lab as J   # reuse the tool's JWT encode for the fixture

REAL_USER = "11111111-2222-3333-4444-555555555555"
JWT_SECRET = "secret"   # deliberately weak, guessable secret (planted misconfig)


def issue_token(user_id, role):
    import secrets
    return J.encode({"alg": "HS256", "typ": "JWT"},
                    {"sub": user_id, "role": role, "jti": secrets.token_hex(16),
                     "exp": int(time.time()) + 3600},
                    secret=JWT_SECRET, alg="HS256")

SPEC = {
    "openapi": "3.0.0",
    "paths": {
        "/api/vuln/search": {"get": {"parameters": [{"name": "q", "in": "query"}]}},
        "/api/safe/search": {"get": {"parameters": [{"name": "q", "in": "query"}]}},
        "/api/json/search": {"get": {"parameters": [{"name": "q", "in": "query"}]}},
        "/api/vuln/item": {"get": {"parameters": [{"name": "id", "in": "query"}]}},
        "/api/trap/item": {"get": {"parameters": [{"name": "id", "in": "query"}]}},
        "/api/vuln/user/{id}": {"get": {"parameters": [
            {"name": "id", "in": "path", "required": True}], "tags": ["users"]}},
        "/api/trap/page/{id}": {"get": {"parameters": [
            {"name": "id", "in": "path", "required": True}]}},
        "/api/vuln/roles": {"get": {"tags": ["roles"]}},
        "/api/vuln/profile": {"put": {"tags": ["users"]}},
        "/api/leak/account": {"get": {"tags": ["users"]}},
        "/api/vuln/reset": {"post": {"tags": ["password"]}},
        "/api/vuln/verb": {"get": {"tags": ["admin"]}},
    },
}


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="text/html", extra=None):
        b = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(b)

    def _bearer(self):
        auth = self.headers.get("Authorization", "")
        return auth[7:] if auth.startswith("Bearer ") else None

    def _read_body(self):
        try:
            n = int(self.headers.get("Content-Length", 0))
            return json.loads(self.rfile.read(n) or b"{}")
        except Exception:
            return {}

    def do_POST(self):
        u = urlparse(self.path)
        if u.path == "/api/v1/authentication":
            body = self._read_body()
            uid = body.get("userId", "")
            role = "admin" if "admin" in uid.lower() else "backend"
            return self._send(200, json.dumps({"entity": {"token": issue_token(uid, role)}}),
                              "application/json")
        # VULNERABLE GraphQL: introspection on, batching on, no depth limit
        if u.path in ("/api/graphql", "/graphql", "/api/v1/graphql"):
            raw = self.rfile.read(int(self.headers.get("Content-Length", 0) or 0))
            text = raw.decode("utf-8", "replace")
            if text.strip().startswith("["):   # query batching enabled
                try:
                    n = len(json.loads(text))
                except Exception:
                    n = 1
                return self._send(200, json.dumps(
                    [{"data": {"__typename": "Query"}} for _ in range(n)]),
                    "application/json")
            if "a0:__typename" in text or "a0 :__typename" in text:  # alias amplification
                import re as _re
                aliases = _re.findall(r"(a\d+):__typename", text)
                return self._send(200, json.dumps(
                    {"data": {a: "Query" for a in aliases}}), "application/json")
            schema = {"data": {"__schema": {"queryType": {"name": "Query"},
                      "types": [{"name": "User"}, {"name": "Secret"}]}}}
            return self._send(200, json.dumps(schema), "application/json")
        # verb tampering: GET is denied, but POST is (wrongly) allowed
        if u.path == "/api/vuln/verb":
            return self._send(200, json.dumps({"data": "admin op executed via POST"}),
                              "application/json")
        # sensitive business flow with NO rate limiting (always 200)
        if u.path == "/api/vuln/reset":
            return self._send(200, json.dumps({"status": "reset email sent"}),
                              "application/json")
        return self._send(404, json.dumps({"error": "nope"}), "application/json")

    def do_PUT(self):
        u = urlparse(self.path)
        # --- mass assignment: requires auth, but echoes ALL posted fields ---
        if u.path == "/api/vuln/profile":
            if not self._bearer():
                return self._send(401, json.dumps({"error": "auth required"}), "application/json")
            body = self._read_body()
            saved = {"userId": "user-1", "name": body.get("name", "user")}
            saved.update(body)   # VULNERABLE: mass-assigns whatever was sent
            return self._send(200, json.dumps({"entity": saved}), "application/json")
        return self._send(404, json.dumps({"error": "nope"}), "application/json")

    def do_GET(self):
        u = urlparse(self.path)
        path, qs = u.path, parse_qs(u.query)

        # --- verb tampering: canonical GET is denied (auth on the verb) ---
        if path == "/api/vuln/verb":
            return self._send(403, json.dumps({"error": "forbidden"}), "application/json")
        # --- supply-chain / integrity exposure (should never be web-served) ---
        if path == "/.git/config":
            return self._send(200, "[core]\n\trepositoryformatversion = 0\n"
                              "[remote \"origin\"]\n\turl = git@github.com:acme/site.git\n",
                              "text/plain")
        if path == "/.env":
            return self._send(200, "SECRET_KEY=s3cr3t\nDB_PASSWORD=hunter2\n"
                              "AWS_ACCESS_KEY_ID=AKIA...\n", "text/plain")
        if path == "/package.json":
            return self._send(200, json.dumps(
                {"name": "acme-site", "version": "1.2.3",
                 "dependencies": {"lodash": "4.17.11", "express": "4.16.0"}}),
                "application/json")
        # --- shadow / undocumented endpoint ---
        if path == "/api/internal":
            return self._send(200, json.dumps({"internal": True, "build": "dev"}),
                              "application/json")
        # --- VULNERABLE: excessive data exposure (leaks sensitive properties) ---
        if path == "/api/leak/account":
            return self._send(200, json.dumps(
                {"userId": "user-1", "email": "u@x.com", "password": "hunter2",
                 "passwordHash": "$2a$10$abcdef", "apiKey": "sk-live-123",
                 "token": "eyJhbGci"}), "application/json")

        if path == "/api/v1/users/current":
            tok = self._bearer()
            if not tok:
                return self._send(401, json.dumps({"error": "no token"}), "application/json")
            try:
                dec = J.decode(tok)          # decodes but never verifies the signature!
                return self._send(200, json.dumps(
                    {"userId": dec.payload.get("sub", "user-1"),
                     "role": dec.payload.get("role", "backend")}), "application/json")
            except Exception:
                return self._send(401, json.dumps({"error": "bad token"}), "application/json")

        if path == "/api/openapi.json":
            return self._send(200, json.dumps(SPEC), "application/json")

        # --- REAL reflected XSS: unescaped, html, no CSP ---
        if path == "/api/vuln/search":
            q = qs.get("q", [""])[0]
            return self._send(200, f"<html><body>Results for {q}</body></html>")

        # --- reflection but STRONG CSP -> should be 'mitigated' ---
        if path == "/api/safe/search":
            q = qs.get("q", [""])[0]
            return self._send(200, f"<html><body>Results for {q}</body></html>",
                              extra={"Content-Security-Policy":
                                     "default-src 'self'; script-src 'self' 'nonce-r4nd0m'"})

        # --- reflection in JSON + nosniff -> 'not_exploitable' ---
        if path == "/api/json/search":
            q = qs.get("q", [""])[0]
            return self._send(200, json.dumps({"q": q}), "application/json",
                              extra={"X-Content-Type-Options": "nosniff"})

        # --- REAL error-based SQLi: DB error ONLY when a quote is present ---
        if path == "/api/vuln/item":
            v = qs.get("id", [""])[0]
            if "'" in v or '"' in v:
                return self._send(500, "org.postgresql.util.PSQLException: "
                                       "unterminated quoted string at or near \"'\"")
            return self._send(200, json.dumps({"id": v, "title": "Item"}), "application/json")

        # --- FALSE POSITIVE: stack trace on EVERY response (verbose error page) ---
        if path == "/api/trap/item":
            return self._send(500, "org.postgresql.util.PSQLException: connection pool "
                                   "warning (this trace is always shown)")

        # --- REAL horizontal IDOR: only the real id returns an object ---
        m = re.match(r"^/api/vuln/user/([^/]+)$", path)
        if m:
            oid = m.group(1)
            if oid == REAL_USER:
                return self._send(200, json.dumps(
                    {"userId": oid, "email": "victim@example.com",
                     "name": "Victim", "roleId": "9"}), "application/json")
            return self._send(404, json.dumps({"error": "not found"}), "application/json")

        # --- FALSE POSITIVE IDOR: any id returns the same static page ---
        m = re.match(r"^/api/trap/page/([^/]+)$", path)
        if m:
            return self._send(200, json.dumps(
                {"page": "help", "content": "static help content, same for all"}),
                "application/json")

        # --- REAL missing-auth: privileged roles list to anyone ---
        if path == "/api/vuln/roles":
            return self._send(200, json.dumps(
                {"roles": [{"id": "1", "name": "CMS Administrator"},
                           {"id": "2", "name": "Publisher"}]}), "application/json")

        return self._send(404, json.dumps({"error": "nope"}), "application/json")


def serve(port=8099):
    srv = ThreadingHTTPServer(("127.0.0.1", port), H)
    srv.serve_forever()


if __name__ == "__main__":
    import sys
    serve(int(sys.argv[1]) if len(sys.argv) > 1 else 8099)
