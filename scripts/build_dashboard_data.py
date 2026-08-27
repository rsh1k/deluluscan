#!/usr/bin/env python3
"""Convert the Mantis findings corpus (+ live adjudication) into the
results.json the Deluluscan dashboard consumes, enriching each finding with a
structured, pentest-report-style `report` block:

    objective -> location -> method -> steps -> reproduction -> outcome
              -> impact -> remediation -> references

Live-tested findings carry the real curl reproductions and observed outcomes;
code-only findings get a report synthesised from their static evidence.
"""
import json, glob, os

FDIR = ".target-src/mantis-workspace/workspace/findings"
H = "http://127.0.0.1:8080"
OUT = "deluluscan-out/results.json"

def vclass(cwe):
    return {"CWE-269":"authz","CWE-266":"authz","CWE-284":"authz","CWE-862":"authz",
            "CWE-306":"authz","CWE-639":"idor","CWE-502":"deserialization","CWE-89":"sqli",
            "CWE-94":"ssti","CWE-1336":"ssti","CWE-918":"ssrf","CWE-321":"crypto",
            "CWE-327":"crypto","CWE-798":"crypto","CWE-307":"auth","CWE-497":"info",
            "CWE-613":"authz"}.get(cwe,"other")

def ev(identmap, method, path):
    return [{"identity":i,"method":method,"url":H+path,"status":s} for i,s in identmap.items()]

# Generic "how we tested" phrasing per vuln class (for code-only findings)
METHOD_BY_CLASS = {
    "authz":"Differential authorization test — issue the same request unauthenticated, as a low-privilege back-end user, and as an administrator, then compare the HTTP responses. A low-privilege identity that is not rejected (while anonymous is) indicates missing function-level authorization.",
    "idor":"Object-level authorization test — request an object owned by another (higher-privilege) principal using a low-privilege identity and check whether the object is returned.",
    "deserialization":"Reachability test — confirm which identities can reach the import/deserialize endpoint, and whether attacker-controlled bytes flow into an unfiltered ObjectInputStream. Exploit confirmed to proof only (no weaponized gadget).",
    "sqli":"Injection test — send a benign sort/filter value, then a payload that would only change behaviour if the value is concatenated into SQL, and compare responses/errors.",
    "ssti":"Template-injection test — submit a template expression (e.g. 7*7) in the request and check whether the server evaluates it.",
    "ssrf":"SSRF test — supply a server-side URL pointing at an internal/loopback resource and observe whether the server fetches it; check which identities may reach the endpoint.",
    "crypto":"Configuration + cryptographic review — determine which key/secret is in effect on the running instance and whether it is attacker-derivable.",
    "auth":"Authentication-controls test — exercise the login / token surface for missing throttling, lockout, or token-scope enforcement.",
    "info":"Information-exposure test — request the endpoint as each identity and inspect the response for sensitive server internals.",
    "other":"Manual review of the affected endpoint and its authorization/handling logic.",
}

# Live reproductions + outcomes, keyed by a unique title substring.
# steps: numbered methodology; repro: copyable shell; outcome: what happened.
LIVE = {
  "getAllLayouts": {
    "ep":"GET /api/v1/roles/layouts",
    "ev":ev({"anonymous":200,"backend":200,"admin":200},"GET","/api/v1/roles/layouts"),
    "objective":"Verify whether GET /api/v1/roles/layouts enforces authentication — the handler has no WebResource.init() call in source.",
    "steps":[
      "Request the endpoint with no credentials (anonymous).",
      "Repeat as a low-privilege back-end user and as an administrator.",
      "Compare status codes and inspect the anonymous response body for real layout data.",
    ],
    "repro":[
      "# anonymous — no auth header at all\ncurl -s http://127.0.0.1:8080/api/v1/roles/layouts",
    ],
    "outcome":"Anonymous request returned HTTP 200 with the full layout list — including the \"CMS Admin\" (Permissions & Maintenance) layout and every layout's portlet composition. backend=200, admin=200. No authentication is enforced.",
  },
  "Server internals": {
    "ep":"GET /api/v1/jvm",
    "ev":ev({"anonymous":401,"backend":200,"admin":200},"GET","/api/v1/jvm"),
    "objective":"Determine whether a non-admin back-end user can read server internals (env vars, JVM/system properties, DB config) via GET /api/v1/jvm.",
    "steps":[
      "Authenticate as a baseline back-end user (no maintenance portlet, not admin).",
      "GET /api/v1/jvm and inspect the response for environment / configuration data.",
      "Confirm anonymous is denied to establish the endpoint is auth-gated.",
    ],
    "repro":[
      "curl -s -u backend@example.com:Backend123! http://127.0.0.1:8080/api/v1/jvm",
    ],
    "outcome":"Non-admin back-end user received HTTP 200 with `environment` (CATALINA_OPTS and full JVM flags) and `configOverrides`. anon=401, backend=200, admin=200 — server internals are exposed to any back-end user.",
  },
  "Horizontal BOLA: any back-end": {
    "ep":"GET /api/v1/users/{userId}",
    "ev":ev({"anonymous":401,"backend":200,"admin":200},"GET","/api/v1/users/appuser"),
    "objective":"Check whether a low-privilege back-end user can read other users' full profiles (including the administrator's) via GET /api/v1/users/{userId}.",
    "steps":[
      "Authenticate as a baseline back-end user (admin:false).",
      "Request the administrator account by id: GET /api/v1/users/appuser.",
      "Inspect the body for the target's private profile fields.",
    ],
    "repro":[
      "curl -s -u backend@example.com:Backend123! http://127.0.0.1:8080/api/v1/users/appuser",
    ],
    "outcome":"HTTP 200 with the CMS Administrator's full profile — admin:true, emailAddress admin@example.com, companyId, createDate, failedLoginAttempts, etc. anon=401 (auth enforced) but backend=200 (no object-level authorization).",
  },
  "Dynamic VTL": {
    "ep":"POST /api/template/dynamic",
    "ev":ev({"anonymous":403,"backend":403,"admin":200},"POST","/api/template/dynamic"),
    "objective":"Confirm whether /api/template/dynamic compiles and evaluates Velocity supplied in the HTTP request body (SSTI), and what role gates it.",
    "steps":[
      "POST a Velocity expression in the request body as anonymous and as a baseline back-end user (expect denial).",
      "Repeat as an identity holding the Scripting Developer role (admin has it).",
      "Check whether the arithmetic expression was evaluated server-side.",
    ],
    "repro":[
      "curl -s -u user:pass -X POST http://127.0.0.1:8080/api/template/dynamic \\\n  -H 'Content-Type: application/json' \\\n  -d '{\"velocity\":\"#set($x=7*7)res=$x\"}'",
    ],
    "outcome":"As admin the response body was `res=49` — the server evaluated the template. anon=403 and backend=403, so evaluation is gated by the Scripting Developer role (which admin holds). Real SSTI primitive; exploitability is conditional on that role.",
  },
  "Vertical privilege escalation": {
    "ep":"PUT /api/v1/toolgroups/{layoutId}/_addtouser",
    "ev":ev({"anonymous":401,"backend":200,"admin":200},"PUT","/api/v1/toolgroups/{layoutId}/_addtouser"),
    "objective":"Determine whether a non-admin back-end user can grant themselves an administrative layout (the CMS Admin / Permissions & Maintenance portlets) via the toolgroups layout-assignment API.",
    "steps":[
      "As anonymous, discover admin layout ids from the unauthenticated GET /api/v1/roles/layouts (companion finding).",
      "Authenticate as a baseline back-end user (admin:false).",
      "PUT /api/v1/toolgroups/{CMS-Admin-layoutId}/_addtouser with your own userId in the body.",
      "Verify assignment via _userHasLayout.",
      "(Cleanup) reverse with _removefromuser.",
    ],
    "repro":[
      "# CMS Admin layout id = 30ae4683-2452-4715-afde-46b50a1271a5 (from anon getAllLayouts)\n"
      "curl -s -u backend@example.com:Backend123! -X PUT \\\n"
      "  http://127.0.0.1:8080/api/v1/toolgroups/30ae4683-2452-4715-afde-46b50a1271a5/_addtouser \\\n"
      "  -H 'Content-Type: application/json' -d '{\"userIds\":[\"backend@example.com\"]}'\n"
      "# verify:\n"
      "curl -s -u backend@example.com:Backend123! \\\n"
      "  'http://127.0.0.1:8080/api/v1/toolgroups/30ae4683-2452-4715-afde-46b50a1271a5/_userHasLayout?userId=backend@example.com'",
    ],
    "outcome":"The non-admin PUT returned HTTP 200 and _userHasLayout then returned {\"message\":true} — the CMS Admin layout was assigned to a baseline back-end user, granting the admin console (roles/users/maintenance portlets). anon=401. Confirmed vertical privilege escalation. Test assignment was reverted afterward.",
  },
  "Apps secrets import": {
    "ep":"POST /api/v1/apps/import",
    "ev":ev({"anonymous":401,"backend":400},"POST","/api/v1/apps/import"),
    "objective":"Confirm which identities can reach POST /api/v1/apps/import (the decrypt-then-deserialize surface) — source shows it is gated by requiredBackendUser only, with no portlet or admin check.",
    "steps":[
      "Authenticate as a baseline back-end user (no apps portlet, not admin).",
      "POST a multipart file to /api/v1/apps/import and observe whether the request reaches import processing (vs. an authorization rejection).",
      "Confirm anonymous is denied.",
    ],
    "repro":[
      "echo 'x' > /tmp/f.txt\ncurl -s -u backend@example.com:Backend123! -X POST \\\n  http://127.0.0.1:8080/api/v1/apps/import -F 'file=@/tmp/f.txt'",
    ],
    "outcome":"Non-admin back-end user reached the handler: HTTP 400 \"No password has been provided\" (i.e. it entered importSecrets and expects the import password = the client-supplied key material). anon=401. The decrypt->deserialize surface is reachable by ANY back-end user — even weaker than documented. Full deserialization RCE was NOT weaponized (confirm-to-proof only).",
  },
  "SQL injection via discarded": {
    "ep":"GET /api/v1/contentreport/site/{site}",
    "ev":ev({"admin":500},"GET","/api/v1/contentreport/site/{site}?orderby=modDate--"),
    "objective":"Confirm whether the `orderby` parameter of the content-report endpoint is concatenated unsanitized into an ORDER BY clause (the discarded sanitizeSortBy return value).",
    "steps":[
      "Send a benign orderby value (a real column) and confirm HTTP 200.",
      "Send orderby=<column>-- (a value that only errors if interpolated raw into SQL).",
      "Compare — a database-level error proves raw interpolation.",
    ],
    "repro":[
      "S=8a7d5e23-da1e-420a-b4f0-471e7da8ea2d   # a site id\n"
      "curl -s -u user:pass \\\n"
      "  \"http://127.0.0.1:8080/api/v1/contentreport/site/$S?orderby=modDate--\"",
    ],
    "outcome":"orderby=modDate returned HTTP 200 (normal). orderby=modDate-- returned HTTP 500 `ERROR: operator does not exist: - timestamp with time zone` — a raw Postgres error proving the value is interpolated unsanitized into ORDER BY. Injection confirmed (constrained to the ORDER BY context).",
  },
  "OSGi bundle deploy": {
    "ep":"GET /api/v1/plugins",
    "ev":ev({"anonymous":401,"backend":401,"admin":200},"GET","/api/v1/plugins"),
    "objective":"Test whether OSGi bundle management is gated by the specific `dynamic-plugins` portlet rather than the CMS Administrator role (i.e. reachable by a non-admin who holds that portlet).",
    "steps":[
      "Hit /api/v1/plugins as anonymous, as a baseline back-end user, and as admin.",
      "Grant a non-admin the `plugins` portlet (Developers layout) and retry.",
      "Attempt to grant the exact `dynamic-plugins` portlet to a non-admin.",
    ],
    "repro":[
      "curl -s -o /dev/null -w '%{http_code}\\n' -u backend@example.com:Backend123! \\\n  http://127.0.0.1:8080/api/v1/plugins",
    ],
    "outcome":"baseline backend=401, backend+plugins-portlet=401, admin=200. The code gate (PortletID.DYNAMIC_PLUGINS, not CMS-Admin) is confirmed, but `dynamic-plugins` is absent from all standard user-assignable layouts and there is no v1 create-layout API — so it is exploitable only by CHAINING the confirmed layout-assignment privesc to first grant oneself that portlet. Standalone non-admin access not demonstrated.",
  },
  "Unauthenticated SSRF via /api/v1/temp": {
    "ep":"POST /api/v1/temp/byUrl",
    "ev":ev({"anonymous":401,"backend":400},"POST","/api/v1/temp/byUrl"),
    "objective":"Verify the claim that POST /api/v1/temp/byUrl is reachable unauthenticated and can be driven to fetch an attacker-chosen URL (SSRF).",
    "steps":[
      "POST a remoteUrl body as anonymous and observe the status.",
      "Repeat as a back-end user.",
    ],
    "repro":[
      "curl -s -o /dev/null -w '%{http_code}\\n' -X POST http://127.0.0.1:8080/api/v1/temp/byUrl \\\n  -H 'Content-Type: application/json' -d '{\"remoteUrl\":\"http://127.0.0.1:8080/\"}'",
    ],
    "outcome":"anonymous -> HTTP 401 \"Invalid User\" (authentication IS required, contradicting the unauthenticated premise); back-end -> HTTP 400 \"Invalid Origin or referer\" (an origin/referer/CSRF check also blocks it). Not exploitable as an unauthenticated SSRF on this build. FALSE POSITIVE (may differ by version/config).",
  },
}

def build_report(d):
    cwe = d.get("cwe","")
    cls = vclass(cwe)
    title = d["title"]
    hit = next((v for k,v in LIVE.items() if k in title), None)
    endpoint = hit["ep"] if hit else ""
    evidence = hit["ev"] if hit else []
    owasp = None  # dashboard computes owasp from vuln_class
    report = {
        "objective": (hit["objective"] if hit else
                      f"Assess {title[0].lower()+title[1:]}"),
        "location": {"endpoint": endpoint, "code_paths": d.get("code_paths", [])},
        "method": (METHOD_BY_CLASS.get(cls, METHOD_BY_CLASS["other"])),
        "steps": hit["steps"] if hit else [],
        "reproduction": hit["repro"] if hit else [],
        "outcome": (hit["outcome"] if hit else
                    "Static code-scan finding (Mantis). Reachable code path identified from source; "
                    "not yet re-tested against the live instance in this pass."),
        "impact": d.get("impact",""),
        "remediation": d.get("mitigation",""),
        "references": [r for r in [cwe] if r],
        "discovery": d.get("discovery_commit",""),
    }
    return report, endpoint, evidence, cls

findings=[]
for fp in sorted(glob.glob(FDIR+"/*.json")):
    d=json.load(open(fp))
    report, endpoint, evidence, cls = build_report(d)
    # keep a plain description too (fallback / search)
    desc=d["description"]
    findings.append({
        "title":d["title"],
        "description":desc,
        "endpoint":endpoint,
        "scanner":cls,"vuln_class":cls,
        "severity":(d.get("severity","info")).lower(),
        "verdict":d.get("verdict",""),
        "exploitability":d.get("exploitability",""),
        "confidence":d.get("confidence",""),
        "cwe":d.get("cwe",""),
        "evidence":evidence,
        "report":report,
    })

# stable ordering: severity then verdict
sev_rank={"critical":0,"high":1,"medium":2,"low":3,"info":4}
findings.sort(key=lambda f:(sev_rank.get(f["severity"],9), f["title"]))

out={"meta":{"target":H,
      "identities":{"anonymous":{},"backend":{},"readonly":{},"content_editor":{},
                    "publisher":{},"api_user":{},"admin":{}},
      "source":"Mantis code-scan corpus @ e0e83bd4 + live adjudication 2026-07-21",
      "assessment_scope":"Authorized loopback the target dev instance (127.0.0.1:8080)"},
     "findings":findings}
os.makedirs("deluluscan-out",exist_ok=True)
json.dump(out,open(OUT,"w"),indent=2)
print(f"wrote {OUT}: {len(findings)} findings, "
      f"{sum(1 for f in findings if f['report']['reproduction'])} with live reproduction")
