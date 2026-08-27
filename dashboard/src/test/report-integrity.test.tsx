/**
 * The report may only state what the scan observed.
 *
 * These replace text-greps that used to run against the old HTML-in-Python
 * template. Identifiers are minified in the built bundle, so the only honest way
 * to assert these properties is to render the components and read the output.
 *
 * Two regressions are locked down here:
 *   1. Fabricated evidence — an admin request/response invented for an identity
 *      that was never probed, which then drove the access matrix's "privilege
 *      escalation" verdicts.
 *   2. A hardcoded attack chain — a fixed roles/layouts -> _addtouser -> OSGi-RCE
 *      narrative emitted whenever any confirmed critical existed, regardless of
 *      what the scan found.
 */
import { describe, expect, it } from 'vitest';
import { render, screen } from '@testing-library/react';
import PentestReportView from '@/components/PentestReportView';
import AccessMatrixView from '@/components/AccessMatrixView';
import EvidencePanel from '@/components/EvidencePanel';
import { buildAccessMatrix, buildReportModel, chainSummary } from '@/lib/model';
import type { Scan, ScanFinding, EscalationPivot } from '@/lib/deluluscan-data';

const CRITICAL: ScanFinding = {
  id: 'f1',
  vuln_class: 'sqli',
  severity: 'critical',
  title: "SQL injection via 'orderby'",
  endpoint: 'GET /api/v1/categories',
  description: 'A database error was returned for a quote payload.',
  evidence: [
    {
      method: 'GET',
      url: 'http://127.0.0.1:8080/api/v1/categories',
      identity: 'anonymous',
      status: 200,
      elapsed_ms: 12,
      req_headers: {},
      resp_headers: {},
      resp_body: '{}',
      resp_len: 2,
    },
  ],
  detail: { test: 'sqli' },
  confidence: 'firm',
  verdict: 'true_positive',
  exploitability: 'exploitable',
  ai_notes: '',
  created_at: 0,
  cwe: 'CWE-89',
  owasp: { code: 'A03', name: 'Injection' },
  required_tier: 1,
};

const PIVOT: EscalationPivot = {
  identity: 'backend',
  action: "self-assigning the 'System' layout",
  performed: true,
  reverted: true,
  capabilities_before: ['role-groups'],
  capabilities_after: ['role-groups', 'plugin-list', 'apps-list'],
  capabilities_gained: ['apps-list', 'plugin-list'],
  worst_impact: 'rce',
  worst_impact_label: 'REMOTE CODE EXECUTION',
  narrative: "After self-assigning the 'System' layout, backend gained 2 capabilities.",
};

function scan(over: Partial<Scan> = {}): Scan {
  return {
    id: 'scan_current',
    label: 'test scan',
    date: '2026-07-29T12:00:00Z',
    version: '26.0',
    target: 'http://127.0.0.1:8080',
    findings: [CRITICAL],
    meta: { target: 'http://127.0.0.1:8080' },
    identities: ['anonymous', 'admin'],
    ...over,
  };
}

const HARDCODED = [
  'unauthenticated request enumerates administrative layout identifiers',
  'Apps secret-import deserialization path',
  'administrator-equivalent control',
  'the target platform enforces authentication effectively',
];

describe('attack narrative is derived, never asserted', () => {
  it('claims no chain when the scan measured none', () => {
    render(<PentestReportView scan={scan()} triage={{}} />);
    const text = document.body.textContent ?? '';
    for (const phrase of HARDCODED) expect(text).not.toContain(phrase);
    expect(text).toContain('No exploit chain was demonstrated');
    // ...but the finding it DID confirm is still reported.
    expect(text).toContain('SQL injection');
  });

  it('reports a measured pivot from its own measurements', () => {
    render(
      <PentestReportView
        scan={scan({ meta: { target: 'http://127.0.0.1:8080', escalation_pivot: PIVOT } })}
        triage={{}}
      />
    );
    const text = document.body.textContent ?? '';
    expect(text).toContain('measured');
    expect(text).toContain('REMOTE CODE EXECUTION');
    expect(text).toContain('plugin-list');
    for (const phrase of HARDCODED) expect(text).not.toContain(phrase);
  });

  it('labels an inferred chain as inferred, not demonstrated', () => {
    const chainFinding: ScanFinding = {
      ...CRITICAL,
      id: 'c1',
      title: 'Attack chain: SSRF to metadata credential theft',
      detail: { test: 'exploit_chain' },
    };
    const M = buildReportModel(scan({ findings: [chainFinding] }), () => 'New');
    expect(chainSummary(M)).toContain('inferred');
    expect(chainSummary(M)).not.toContain('measured, not inferred');
  });

  it('does not invent a dominant theme from a single finding', () => {
    const M = buildReportModel(scan(), () => 'New');
    expect(M.theme).toBeNull();
  });
});

describe('the report details only what was demonstrated exploitable', () => {
  // A confirmed-but-never-exploited observation (a version-derived dependency
  // advisory, a correlated server exception, a reflected param with no proven
  // sink) is a lead, not a vulnerability to report as one.
  const OBSERVED: ScanFinding = {
    ...CRITICAL,
    id: 'obs1',
    severity: 'medium',
    title: 'Vulnerable dependency: example-lib 1.0',
    verdict: 'likely_true_positive',
    exploitability: 'conditional',
  };

  it('separates demonstrated-exploitable findings from mere observations', () => {
    const M = buildReportModel(scan({ findings: [CRITICAL, OBSERVED] }), () => 'New');
    expect(M.reportable.map((f) => f.id)).toEqual([CRITICAL.id]);
    expect(M.observedNotExploitable.map((f) => f.id)).toEqual([OBSERVED.id]);
    // Severity counts follow the reported set, not the wider confirmed set.
    expect(M.crit).toBe(1);
    expect(M.med).toBe(0);
  });

  it('discloses what it set aside instead of quietly dropping it', () => {
    render(<PentestReportView scan={scan({ findings: [CRITICAL, OBSERVED] })} triage={{}} />);
    const text = document.body.textContent ?? '';
    expect(text).toContain('1 observation(s)');
    // The exclusion must never read as an all-clear on those observations.
    expect(text).toMatch(/not a statement that they are safe/i);
    // ...and the excluded finding is not detailed as though it were confirmed.
    expect(text).not.toContain('Vulnerable dependency: example-lib 1.0');
  });
});

describe('curated report scope (meta.report_include)', () => {
  const MED: ScanFinding = {
    ...CRITICAL, id: 'med1', severity: 'medium', title: 'GraphQL introspection enabled',
    verdict: 'true_positive', exploitability: 'exploitable',
  };

  it('details exactly the included ids and no others', () => {
    const M = buildReportModel(
      scan({ findings: [CRITICAL, MED], meta: { target: 'x', report_include: { ids: ['med1'] } } }),
      () => 'New'
    );
    expect(M.curated).toBe(true);
    expect(M.reportable.map((f) => f.id)).toEqual(['med1']);
    // The confirmed critical that was left out is tracked as excluded-higher-severity.
    expect(M.excludedHigherSeverity.map((f) => f.id)).toEqual([CRITICAL.id]);
  });

  it('a curated report never hides an excluded confirmed critical', () => {
    render(
      <PentestReportView
        scan={scan({ findings: [CRITICAL, MED], meta: { target: 'x', report_include: { ids: ['med1'] } } })}
        triage={{}}
      />
    );
    const text = document.body.textContent ?? '';
    // Must call out that a high/critical was excluded by direction, not disproven.
    expect(text).toMatch(/high or critical/i);
    expect(text).toMatch(/engagement owner's direction/i);
    expect(text).toMatch(/not a statement that they are safe/i);
  });
});

describe('evidence is never fabricated', () => {
  it('says so plainly when a finding has no captured traffic', () => {
    const bare: ScanFinding = { ...CRITICAL, evidence: [], evidence_missing: true };
    render(<EvidencePanel finding={bare} />);
    const text = document.body.textContent ?? '';
    expect(text).toContain('No HTTP traffic was captured');
    expect(text).toContain('nothing here demonstrates exploitability');
    // No invented identity switcher, and no fabricated status codes.
    expect(screen.queryByText('Admin')).toBeNull();
    expect(text).not.toContain('401');
    expect(text).not.toContain('200');
  });

  it('renders only the identities that were actually probed', () => {
    render(<EvidencePanel finding={CRITICAL} />);
    // The switcher shows the identity's display label, and ONLY for identities
    // that have a captured record.
    expect(screen.getByRole('button', { name: 'Anonymous' })).toBeTruthy();
    expect(screen.queryByRole('button', { name: 'Admin' })).toBeNull();
    expect(screen.queryByRole('button', { name: 'Backend' })).toBeNull();
  });

  it('marks an incomplete request as not-sent rather than as a response', () => {
    const deferred: ScanFinding = {
      ...CRITICAL,
      evidence: [
        {
          method: 'DELETE',
          url: 'http://127.0.0.1:8080/api/v1/maintenance/_shutdown',
          identity: 'admin',
          status: 0,
          elapsed_ms: 0,
          error: 'not sent — deferred to the dedicated destructive pass',
        },
      ],
    };
    render(<EvidencePanel finding={deferred} />);
    const text = document.body.textContent ?? '';
    expect(text).toContain('did not complete');
    expect(text).toContain('deferred to the dedicated destructive pass');
  });
});

describe('access matrix counts only real observations', () => {
  it('excludes status-0 records from tested/granted', () => {
    const f: ScanFinding = {
      ...CRITICAL,
      required_tier: 3,
      evidence: [
        { method: 'GET', url: 'http://t/x', identity: 'anonymous', status: 0, elapsed_ms: 0 },
        { method: 'GET', url: 'http://t/x', identity: 'backend', status: 200, elapsed_ms: 5 },
      ],
    };
    const rows = buildAccessMatrix([f]);
    expect(Object.keys(rows[0].cells)).toEqual(['backend']);
    expect(rows[0].cells.anonymous).toBeUndefined();
  });

  it('shows an unprobed identity as untested, not denied', () => {
    render(<AccessMatrixView scan={scan()} onSelect={() => {}} />);
    const text = document.body.textContent ?? '';
    expect(text).toContain('not probed');
    expect(text).toContain('not that it was denied');
  });

  it('never flags admin access as a privilege escalation', () => {
    const f: ScanFinding = {
      ...CRITICAL,
      required_tier: 3,
      evidence: [
        { method: 'GET', url: 'http://t/x', identity: 'admin', status: 200, elapsed_ms: 5 },
      ],
    };
    const rows = buildAccessMatrix([f]);
    expect(rows[0].cells.admin.granted).toBe(true);
    expect(rows[0].cells.admin.unauthorized).toBe(false);
  });

  it('flags a sub-tier identity that reached an admin-tier endpoint', () => {
    const f: ScanFinding = {
      ...CRITICAL,
      required_tier: 3,
      evidence: [
        { method: 'GET', url: 'http://t/x', identity: 'backend', status: 200, elapsed_ms: 5 },
      ],
    };
    const rows = buildAccessMatrix([f]);
    expect(rows[0].cells.backend.unauthorized).toBe(true);
  });
});

describe('destructive-pass coverage', () => {
  it('reports unprobed destructive endpoints as UNKNOWN, not clean', () => {
    render(
      <PentestReportView
        scan={scan({
          meta: {
            target: 'http://127.0.0.1:8080',
            destructive_pass: {
              endpoints: ['DELETE /api/v1/maintenance/_shutdown', 'DELETE /api/v1/esindex/reindex'],
              probed: ['DELETE /api/v1/maintenance/_shutdown'],
              skipped: ['DELETE /api/v1/esindex/reindex'],
              restarts: 1,
              aborted_reason: 'no restart_command configured',
            },
          },
        })}
        triage={{}}
      />
    );
    const text = document.body.textContent ?? '';
    expect(text).toContain('Destructive operations');
    expect(text).toContain('UNKNOWN');
    expect(text).toContain('esindex/reindex');
    expect(text).toContain('no restart_command configured');
  });

  it('states that destructive testing happened in the rules of engagement', () => {
    render(
      <PentestReportView
        scan={scan({
          meta: {
            target: 'http://127.0.0.1:8080',
            destructive_pass: {
              endpoints: ['DELETE /api/v1/maintenance/_shutdown'],
              probed: ['DELETE /api/v1/maintenance/_shutdown'],
              skipped: [],
              caused_outage: ['DELETE /api/v1/maintenance/_shutdown'],
            },
          },
        })}
        triage={{}}
      />
    );
    const text = document.body.textContent ?? '';
    expect(text).toContain('included destructive operations');
    expect(text).toContain('took the target down');
  });

  it('omits the destructive section entirely when there was no such pass', () => {
    render(<PentestReportView scan={scan()} triage={{}} />);
    expect(document.body.textContent ?? '').not.toContain('Destructive operations');
  });
});
