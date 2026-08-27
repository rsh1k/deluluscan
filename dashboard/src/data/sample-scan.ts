import type { Finding, SecurityDashboardData, TriageState } from '@/types/security';

// Realistic sample data for local dashboard testing only — shaped exactly
// like a real security/data/latest.json snapshot (security/ci_runner.py's
// output), covering every identity provisioned by scripts/provision_users.py
// so the evidence viewer + identity reference panel can be exercised fully.

const now = 1783500000; // fixed epoch for reproducible sample output

function ev(overrides: Partial<Finding['evidence'][number]> & { identity: string; status: number }) {
  return {
    method: 'GET',
    url: 'https://127.0.0.1:8443/api/v1/x',
    elapsed_ms: 12.4,
    req_headers: { 'User-Agent': 'deluluscan/0.1 (authorized-testing)' },
    req_body: null,
    resp_headers: { 'Content-Type': 'application/json' },
    resp_body: '{}',
    resp_len: 2,
    error: null,
    ...overrides,
  };
}

const findings: Finding[] = [
  {
    id: 'f_c01',
    vuln_class: 'authz',
    severity: 'critical',
    title: 'BOLA — anonymous request returns another user’s private content (×3 endpoints)',
    endpoint: 'GET /api/v1/content/id/{identifier}',
    description:
      'An anonymous caller retrieves content marked "Members Only" that should require the content_editor or admin role. The same content_id returns full body/metadata regardless of caller identity.',
    evidence: [
      ev({
        identity: 'anonymous',
        status: 200,
        url: 'https://127.0.0.1:8443/api/v1/content/id/6f9d5449-8f48-4c3b-9a10-000000000001',
        resp_body: '{"contentlets":[{"title":"Q3 board minutes","restricted":true}]}',
        resp_len: 512,
      }),
      ev({
        identity: 'admin',
        status: 200,
        url: 'https://127.0.0.1:8443/api/v1/content/id/6f9d5449-8f48-4c3b-9a10-000000000001',
        resp_body: '{"contentlets":[{"title":"Q3 board minutes","restricted":true}]}',
        resp_len: 512,
      }),
    ],
    detail: { param: null },
    confidence: 'confirmed',
    verdict: 'true_positive',
    exploitability: 'exploitable',
    ai_notes:
      'Confirmed: the anonymous response is byte-identical to the admin response for a resource explicitly flagged restricted. This is a genuine authorization bypass, not an artifact of a malformed request.',
    created_at: now,
    retest: {
      verdict: 'true_positive',
      reasons: ['Anonymous and admin responses matched exactly on a restricted resource'],
      repro: 'GET the same content id as anonymous and as admin; compare response bodies.',
    },
  },
  {
    id: 'f_h01',
    vuln_class: 'bopla',
    severity: 'high',
    title: 'Mass assignment — readonly user can set `active`/`role` fields on user update',
    endpoint: 'PUT /api/v1/users/{userId}',
    description:
      'The readonly test account (Back-end User role) can PUT additional, unexposed properties (active, roleId) on its own user record and have them accepted, despite the UI never exposing these fields to that role.',
    evidence: [
      ev({
        method: 'PUT',
        identity: 'readonly',
        status: 200,
        url: 'https://127.0.0.1:8443/api/v1/users/readonly@example.com',
        req_body: '{"firstName":"Read","active":true,"roleId":"admin"}',
        resp_body: '{"active":true,"roleId":"admin"}',
      }),
    ],
    detail: { param: 'roleId' },
    confidence: 'firm',
    verdict: 'likely_true_positive',
    exploitability: 'conditional',
    ai_notes:
      'The write was accepted server-side; whether roleId is actually honored on next login needs a manual follow-up (deluluscan does not re-authenticate to confirm privilege change took effect).',
    created_at: now,
  },
  {
    id: 'f_h02',
    vuln_class: 'xss',
    severity: 'high',
    title: 'Stored XSS in content title field (backend identity)',
    endpoint: 'POST /api/v1/workflow/actions/default/fire/PUBLISH',
    description:
      'A content title containing an unescaped <script> payload, created by the backend test user, is reflected unescaped when rendered via the front-end page API.',
    evidence: [
      ev({
        method: 'POST',
        identity: 'backend',
        status: 200,
        url: 'https://127.0.0.1:8443/api/v1/workflow/actions/default/fire/PUBLISH',
        req_body: '{"title":"<script>alert(document.domain)</script>"}',
        resp_body: '{"identifier":"a1b2c3"}',
      }),
      ev({
        identity: 'anonymous',
        status: 200,
        url: 'https://127.0.0.1:8080/api/v1/page/json/test-page',
        resp_body: '<h1><script>alert(document.domain)</script></h1>',
        resp_len: 220,
      }),
    ],
    detail: { param: 'title' },
    confidence: 'firm',
    verdict: 'true_positive',
    exploitability: 'exploitable',
    ai_notes: 'Payload round-tripped unescaped into HTML served to anonymous visitors — genuine stored XSS.',
    created_at: now,
  },
  {
    id: 'f_m01',
    vuln_class: 'error_handling',
    severity: 'medium',
    title: 'Possible fail-open on malformed input (×2 endpoints)',
    endpoint: 'GET /api/content/id/{identifier}',
    description:
      'Endpoint returned success on malformed/garbage input where a rejection was expected (probe: broken_json). Fail closed, validate input, and return generic errors without internals.',
    evidence: [
      ev({
        identity: 'anonymous',
        status: 200,
        url: 'https://127.0.0.1:8443/api/content/id/00000000-0000-0000-0000-000000000000?q=%7B%22a%22%3A+',
        resp_body: '{"contentlets":[]}',
        resp_len: 18,
      }),
    ],
    detail: { param: 'q' },
    confidence: 'tentative',
    verdict: 'unverified',
    exploitability: 'unknown',
    ai_notes: '',
    created_at: now,
  },
  {
    id: 'f_m02',
    vuln_class: 'ssrf',
    severity: 'medium',
    title: 'SSTI candidate — expression_evaluation on roleId',
    endpoint: 'GET /api/v1/roles/{roleId}',
    description:
      '#{7*7} returned 49 because "49" appeared as a hex substring in a UUID, not an evaluated result.',
    evidence: [
      ev({
        identity: 'content_editor',
        status: 200,
        url: 'https://127.0.0.1:8443/api/v1/roles/%23%7B7*7%7D',
        resp_body: '{"entity":[{"id":"6f9d5449-8f48-4c3b-9a10-abc123","name":"System"}]}',
        resp_len: 5842,
      }),
    ],
    detail: { param: 'roleId' },
    confidence: 'firm',
    verdict: 'false_positive',
    exploitability: 'not_exploitable',
    ai_notes:
      'This is a false positive: the request was malformed relative to what the probe assumed — "49" is a coincidental hex substring of an existing UUID, not an evaluated expression.',
    needs_scanner_review: true,
    created_at: now,
  },
  {
    id: 'f_m03',
    vuln_class: 'idor',
    severity: 'medium',
    title: 'api_user can enumerate sequential content inodes',
    endpoint: 'GET /api/v1/content/inode/{inode}',
    description:
      'Sequential inode values return distinct content records for the api_user identity without any rate limiting or ownership check.',
    evidence: [
      ev({
        identity: 'api_user',
        status: 200,
        url: 'https://127.0.0.1:8443/api/v1/content/inode/1042',
        resp_body: '{"contentlets":[{"title":"Internal memo"}]}',
        resp_len: 340,
      }),
    ],
    detail: { param: 'inode' },
    confidence: 'firm',
    verdict: 'conditional',
    exploitability: 'conditional',
    ai_notes:
      'Genuine enumeration risk, but severity depends on whether inode values are treated as secret elsewhere in the app — flagged conditional pending that confirmation.',
    created_at: now,
    retest: {
      verdict: 'conditional',
      reasons: ['Sequential inode access reproduced across 5 consecutive values'],
      repro: 'Iterate inode values 1040-1045 as api_user and compare response diversity.',
    },
  },
  {
    id: 'f_l01',
    vuln_class: 'cors',
    severity: 'low',
    title: 'Permissive CORS on public search endpoint',
    endpoint: 'GET /api/v1/ai/search/related',
    description: 'Access-Control-Allow-Origin: * on an endpoint that also accepts credentials.',
    evidence: [
      ev({
        identity: 'anonymous',
        status: 200,
        url: 'https://127.0.0.1:8080/api/v1/ai/search/related?query=test',
        resp_headers: { 'Access-Control-Allow-Origin': '*', 'Content-Type': 'application/json' },
        resp_body: '{"results":[]}',
      }),
    ],
    detail: {},
    confidence: 'firm',
    verdict: 'true_positive',
    exploitability: 'not_exploitable',
    ai_notes: 'Low severity: endpoint only returns public search results, no credentialed data at risk today.',
    created_at: now,
  },
  {
    id: 'f_l02',
    vuln_class: 'misconfig',
    severity: 'low',
    title: 'Verbose error stack trace on malformed OSGi upload',
    endpoint: 'POST /api/v1/plugins',
    description: 'A malformed multipart upload returns a full Java stack trace including internal class names.',
    evidence: [
      ev({
        method: 'POST',
        identity: 'admin',
        status: 500,
        url: 'https://127.0.0.1:8080/api/v1/plugins',
        resp_body: 'com.example.rest.exception.mapper... (truncated)',
        resp_len: 4096,
      }),
    ],
    detail: {},
    confidence: 'tentative',
    verdict: 'inconclusive',
    exploitability: 'unknown',
    ai_notes: '',
    created_at: now,
  },
  {
    id: 'f_i01',
    vuln_class: 'passive',
    severity: 'info',
    title: 'Server version disclosed in response headers',
    endpoint: 'GET /api/v1/appconfiguration',
    description: 'x-dot-server header discloses internal build identifiers.',
    evidence: [
      ev({
        identity: 'anonymous',
        status: 200,
        url: 'https://127.0.0.1:8080/api/v1/appconfiguration',
        resp_headers: { 'x-dot-server': '556d403e16bc|3a11fabf90', 'Content-Type': 'application/json' },
      }),
    ],
    detail: {},
    confidence: 'confirmed',
    verdict: 'true_positive',
    exploitability: 'not_exploitable',
    ai_notes: 'Informational only — internal build id disclosure, no direct exploit path.',
    created_at: now,
  },
  {
    id: 'f_h03',
    vuln_class: 'jwt',
    severity: 'high',
    title: 'JWT accepted with alg=none',
    endpoint: 'GET /api/v1/users/current',
    description: 'A token with alg set to "none" and an empty signature was accepted as valid by the API layer.',
    evidence: [
      ev({
        identity: 'backend',
        status: 200,
        url: 'https://127.0.0.1:8443/api/v1/users/current',
        req_headers: { Authorization: 'Bearer eyJhbGciOiJub25lIn0...' },
        resp_body: '{"userId":"backend@example.com"}',
      }),
    ],
    detail: {},
    confidence: 'tentative',
    verdict: 'unverified',
    exploitability: 'unknown',
    ai_notes: '',
    created_at: now,
  },
  {
    id: 'f_c02',
    vuln_class: 'sqli',
    severity: 'critical',
    title: 'Time-based blind SQLi via `orderby` parameter',
    endpoint: 'GET /api/v1/categories',
    description: 'Response time increases proportionally with injected SLEEP() duration in the orderby parameter.',
    evidence: [
      ev({
        identity: 'content_editor',
        status: 200,
        elapsed_ms: 7021.3,
        url: "https://127.0.0.1:8443/api/v1/categories?orderby=1;SELECT SLEEP(7)--",
        resp_body: '{"categories":[]}',
      }),
    ],
    detail: { param: 'orderby' },
    confidence: 'confirmed',
    verdict: 'true_positive',
    exploitability: 'exploitable',
    ai_notes: 'Confirmed via 3 consecutive timing probes with increasing sleep duration, all reproduced within tolerance.',
    created_at: now,
    retest: {
      verdict: 'true_positive',
      reasons: ['3/3 timing probes matched injected SLEEP duration within 500ms tolerance'],
      repro: 'Send orderby=1;SELECT SLEEP(N)-- for N=3,5,7 and confirm response time tracks N.',
    },
  },
  {
    id: 'f_m04',
    vuln_class: 'csrf',
    severity: 'medium',
    title: 'State-changing request accepted without CSRF token (content_editor)',
    endpoint: 'DELETE /api/v1/content/{identifier}',
    description: 'A DELETE request with no CSRF/anti-forgery token and no Origin/Referer check succeeds.',
    evidence: [
      ev({
        method: 'DELETE',
        identity: 'content_editor',
        status: 200,
        url: 'https://127.0.0.1:8443/api/v1/content/a1b2c3',
        req_headers: { Origin: 'https://evil.example.com' },
        resp_body: '{"deleted":true}',
      }),
    ],
    detail: {},
    confidence: 'firm',
    verdict: 'likely_true_positive',
    exploitability: 'conditional',
    ai_notes: 'Cross-origin state-changing request succeeded; conditional on whether session cookies are SameSite-protected in production config.',
    created_at: now,
  },
  {
    id: 'f_l03',
    vuln_class: 'rate_limit',
    severity: 'low',
    title: 'No rate limiting on login endpoint',
    endpoint: 'POST /api/v1/authentication',
    description: '50 consecutive login attempts with wrong passwords were all accepted without throttling or lockout.',
    evidence: [
      ev({
        method: 'POST',
        identity: 'anonymous',
        status: 401,
        url: 'https://127.0.0.1:8443/api/v1/authentication',
        req_body: '{"userId":"admin@example.com","password":"wrong"}',
        resp_body: '{"errors":[{"message":"Unauthorized"}]}',
      }),
    ],
    detail: {},
    confidence: 'firm',
    verdict: 'false_positive',
    exploitability: 'not_exploitable',
    ai_notes: 'The target actually applies rate limiting at the network/WAF layer in front of this dev instance is disabled by default — expected dev-environment behavior, not a scanner artifact.',
    created_at: now,
  },
];

const triage: TriageState = {
  f_h01: {
    status: 'triaging',
    assignee: 'security-team@example.com',
    updated_by: 'rashik.adhikari@example.com',
    updated_at: '2026-07-09T14:22:00Z',
  },
  f_l03: {
    status: 'dismissed',
    assignee: '',
    updated_by: 'rashik.adhikari@example.com',
    updated_at: '2026-07-09T15:03:00Z',
  },
};

export const sampleData: SecurityDashboardData = {
  scan: {
    scan_date: '2026-07-10',
    meta: {
      target: 'http://127.0.0.1:8080',
      endpoints_scanned: 214,
      identities: {
        anonymous: {}, admin: {}, backend: {}, content_editor: {}, readonly: {}, api_user: {},
      },
    },
    findings,
  },
  triage,
  triageSha: 'sample-local-sha',
};
