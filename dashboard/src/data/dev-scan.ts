/**
 * Dev-only fixture, used ONLY by `npm run dev` when no scan payload is injected.
 *
 * It never reaches a build: App reads it behind `import.meta.env.DEV`, so the
 * production bundle that deluluscan/dashboard.py vendors contains no sample findings —
 * a report must never show data that did not come from a scan.
 *
 * Shapes mirror what deluluscan/dashboard.py's _build_scans() emits, including a
 * finding with NO evidence (so the "nothing was captured" path is visible while
 * developing) and a measured escalation pivot.
 */
import type { Scan } from '@/lib/deluluscan-data';

const ev = (identity: string, status: number, body = '{}') => ({
  method: 'GET',
  url: 'http://127.0.0.1:8080/api/v1/roles/layouts',
  identity,
  status,
  elapsed_ms: 14.2,
  req_headers: { Accept: 'application/json', Authorization: '<redacted>' },
  resp_headers: { 'Content-Type': 'application/json' },
  resp_body: body,
  resp_len: body.length,
});

export const devScans: Scan[] = [
  {
    id: 'scan_current',
    label: '2026-07-29 — the target v26.0 (dev fixture)',
    date: '2026-07-29T12:00:00Z',
    version: '26.0',
    target: 'http://127.0.0.1:8080',
    identities: ['anonymous', 'backend', 'admin'],
    meta: {
      target: 'http://127.0.0.1:8080',
      source: 'openapi.json',
      identities: { admin: { ok: true }, backend: { ok: true } },
      coverage: {
        endpoints_discovered: 740,
        endpoints_probed: 712,
        endpoints_probed_pct: 96.2,
        untested_endpoints: ['GET /api/v1/unreachable'],
      },
      probe_stats: { requests: 8421, responses: 8398, errors: 23, deferred: 4, identities: ['anonymous', 'backend', 'admin'] },
      destructive_pass: {
        endpoints: ['DELETE /api/v1/maintenance/_shutdown', 'DELETE /api/v1/esindex/reindex'],
        probed: ['DELETE /api/v1/maintenance/_shutdown'],
        skipped: ['DELETE /api/v1/esindex/reindex'],
        caused_outage: ['DELETE /api/v1/maintenance/_shutdown'],
        restarts: 1,
        findings: 0,
        aborted_reason: 'no scan.destructive.restart_command configured',
      },
      escalation_pivot: {
        identity: 'backend',
        action: "self-assigning the 'System' layout via PUT /api/v1/toolgroups/{layoutId}/_addtouser",
        performed: true,
        reverted: true,
        capabilities_before: ['role-groups'],
        capabilities_after: ['role-groups', 'plugin-list', 'apps-list'],
        capabilities_gained: ['apps-list', 'plugin-list'],
        worst_impact: 'rce',
        worst_impact_label: 'REMOTE CODE EXECUTION',
        narrative:
          "After self-assigning the 'System' layout, the 'backend' identity gained 2 capabilities it could not previously reach.",
      },
    },
    findings: [
      {
        id: 'dev1',
        vuln_class: 'authz',
        severity: 'critical',
        title: 'Anonymous can enumerate every layout via GET /api/v1/roles/layouts',
        endpoint: 'GET /api/v1/roles/layouts',
        description:
          'An unauthenticated caller received the full layout list, including administrative layout identifiers.',
        evidence: [ev('anonymous', 200, '{"entity":[{"id":"abc","name":"System"}]}'), ev('admin', 200)],
        detail: { test: 'conformance' },
        confidence: 'firm',
        verdict: 'true_positive',
        exploitability: 'exploitable',
        ai_notes: '',
        created_at: 0,
        cwe: 'CWE-306',
        owasp: { code: 'A01', name: 'Broken Access Control' },
        required_tier: 3,
        report: {
          objective: 'Determine whether the layout catalogue is gated on authentication.',
          location: { endpoint: 'GET /api/v1/roles/layouts' },
          method: 'Replayed the endpoint as anonymous and as admin, comparing status and body.',
          steps: ['Request the endpoint with no credentials.', 'Compare against the admin baseline.'],
          reproduction: ['curl -s http://127.0.0.1:8080/api/v1/roles/layouts'],
          outcome: 'Anonymous received HTTP 200 with the same body as admin.',
          impact: 'Administrative layout identifiers are disclosed to unauthenticated callers.',
          remediation: 'Require an authenticated CMS Administrator role on this endpoint.',
        },
      },
      {
        id: 'dev2',
        vuln_class: 'authz',
        severity: 'high',
        title: 'Back-end user reached an admin-tier endpoint',
        endpoint: 'GET /api/v1/maintenance/_threads',
        description: 'A baseline back-end account received a thread dump.',
        evidence: [ev('backend', 200, '{"entity":{"threads":42}}'), ev('anonymous', 401)],
        detail: { test: 'conformance' },
        confidence: 'firm',
        verdict: 'true_positive',
        exploitability: 'conditional',
        ai_notes: '',
        created_at: 0,
        cwe: 'CWE-862',
        owasp: { code: 'A01', name: 'Broken Access Control' },
        required_tier: 3,
      },
      {
        id: 'dev3',
        vuln_class: 'info_leak',
        severity: 'medium',
        title: 'Candidate surface flagged for manual review (no traffic captured)',
        endpoint: 'POST /api/v1/apps/import',
        description: 'Source analysis flagged a deserialization path; no live probe was recorded.',
        evidence: [],
        evidence_missing: true,
        detail: { test: 'sourcescan' },
        confidence: 'tentative',
        verdict: 'unverified',
        exploitability: 'unknown',
        ai_notes: '',
        created_at: 0,
        owasp: { code: 'A08', name: 'Software and Data Integrity Failures' },
        required_tier: 3,
      },
      {
        id: 'dev4',
        vuln_class: 'misconfig',
        severity: 'low',
        title: 'Verbose error discloses a stack frame',
        endpoint: 'GET /api/v1/categories',
        description: 'A malformed parameter produced a Java stack frame.',
        evidence: [ev('anonymous', 500, '{"message":"NumberFormatException"}')],
        detail: { test: 'faults' },
        confidence: 'firm',
        verdict: 'likely_false_positive',
        exploitability: 'not_exploitable',
        ai_notes: '',
        created_at: 0,
        owasp: { code: 'A05', name: 'Security Misconfiguration' },
        required_tier: 0,
      },
    ],
  },
];
