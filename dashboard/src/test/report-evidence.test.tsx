/**
 * A finding in the report must show the RESPONSE, not just the request.
 *
 * The regression this locks down is an adjudication failure, not a cosmetic
 * one. The previous the target report asserted "unhandled server error" and
 * "stack trace exposed" on the strength of status codes alone; the actual
 * responses were an empty body and a single open-source class name. A reader
 * given only `curl ... # observed: HTTP 500` cannot tell those apart, so the
 * response body — and specifically the empty-body case — has to render.
 *
 * Also covered: the CVSS block states the scoring system and its per-metric
 * reasoning (a bare number is not reviewable), and the OWASP/CWE category is
 * stated explicitly rather than left implicit.
 */
import { describe, expect, it } from 'vitest';
import { render } from '@testing-library/react';
import PentestReportView from '@/components/PentestReportView';
import type { Scan, ScanFinding } from '@/lib/deluluscan-data';

function findingWith(report: Record<string, unknown>): ScanFinding {
  return {
    id: 'f-evidence',
    vuln_class: 'error_handling',
    severity: 'medium',
    title: 'Unhandled server error on malformed input',
    endpoint: 'GET /api/v1/ai/search/related',
    description: 'Malformed input produced a 5xx.',
    evidence: [],
    detail: { report },
    confidence: 'firm',
    verdict: 'true_positive',
    exploitability: 'exploitable',
    ai_notes: '',
    created_at: 0,
    report: report as never,
  } as ScanFinding;
}

function scanWith(f: ScanFinding): Scan {
  return {
    id: 'scan_current',
    label: 'evidence scan',
    date: '2026-08-21T12:00:00Z',
    version: '1.2.5',
    target: 'http://127.0.0.1:8080',
    findings: [f],
    meta: { target: 'http://127.0.0.1:8080' },
    identities: ['anonymous', 'admin'],
  };
}

describe('reproduction evidence shows the response, not only the request', () => {
  it('renders the observed response body alongside the curl command', () => {
    const f = findingWith({
      objective: 'Assess error handling.',
      exchanges: [
        {
          curl: "curl -s -i 'http://127.0.0.1:8080/api/v1/categories?orderby=title'",
          proves: 'THE VIOLATION: this identity should NOT be served',
          response: {
            status: 500,
            body: '{"message":"ERROR: column \\"title\\" does not exist"}',
            body_bytes: 249,
            body_empty: false,
          },
        },
      ],
    });
    render(<PentestReportView scan={scanWith(f)} triage={{}} />);
    const text = document.body.textContent ?? '';
    expect(text).toContain('orderby=title');           // the request
    expect(text).toContain('column');                  // the RESPONSE body
    expect(text).toContain('HTTP 500');
    expect(text).toContain('249 bytes');
  });

  it('says explicitly when a 5xx disclosed nothing at all', () => {
    // The exact case that was misreported: a 500 with an empty body is a
    // robustness bug, not an information leak, and the report must not let a
    // reader infer a leak from the status code.
    const f = findingWith({
      objective: 'Assess error handling.',
      exchanges: [
        {
          curl: "curl -s -i 'http://127.0.0.1:8080/api/v1/ai/search/related?q=%7B'",
          response: { status: 500, body: '', body_bytes: 0, body_empty: true },
        },
      ],
    });
    render(<PentestReportView scan={scanWith(f)} triage={{}} />);
    const text = document.body.textContent ?? '';
    expect(text).toContain('HTTP 500');
    expect(text).toMatch(/Empty body/i);
    expect(text).toMatch(/nothing was disclosed/i);
  });

  it('marks a truncated body as truncated rather than silently cutting it', () => {
    const f = findingWith({
      objective: 'Assess disclosure.',
      exchanges: [
        {
          curl: "curl -s -i 'http://127.0.0.1:8080/api/openapi.json'",
          response: {
            status: 200, body: '{"openapi":"3.0.1"', body_bytes: 1020923,
            body_empty: false, body_truncated: true,
          },
        },
      ],
    });
    render(<PentestReportView scan={scanWith(f)} triage={{}} />);
    expect(document.body.textContent ?? '').toMatch(/truncated/i);
  });

  it('renders no reproduction block when no exchange was captured', () => {
    const f = findingWith({ objective: 'Nothing captured.' });
    render(<PentestReportView scan={scanWith(f)} triage={{}} />);
    const text = document.body.textContent ?? '';
    expect(text).not.toContain('Reproduction (request & observed response)');
  });
});

describe('CVSS is stated with its version and its reasoning', () => {
  it('shows the score, the vector, the version and the per-metric rationale', () => {
    const f = findingWith({
      objective: 'Assess disclosure.',
      cvss: {
        version: '3.1',
        vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
        base_score: 5.3,
        severity: 'medium',
        metric_rationale: {
          'PR:N': 'reproduced by an unauthenticated caller',
          'C:L/I:N/A:N': 'the complete API specification was disclosed',
        },
      },
    });
    render(<PentestReportView scan={scanWith(f)} triage={{}} />);
    const text = document.body.textContent ?? '';
    expect(text).toContain('5.3');
    expect(text).toContain('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N');
    expect(text).toContain('CVSS v3.1 Base');            // scoring system named
    expect(text).toContain('reproduced by an unauthenticated caller');
  });

  it('falls back to a plain risk rating when no CVSS was assigned', () => {
    const f = findingWith({ objective: 'No score.' });
    render(<PentestReportView scan={scanWith(f)} triage={{}} />);
    expect(document.body.textContent ?? '').not.toContain('CVSS v3.1 Base');
  });
});

describe('OWASP category is stated explicitly', () => {
  it('renders the OWASP 2025 class, the API Top 10 class and the CWEs', () => {
    const f = findingWith({
      objective: 'Assess disclosure.',
      taxonomy: {
        owasp_2025: 'A01:2025',
        owasp_api_top10: 'API3',
        cwe: ['CWE-200', 'CWE-215'],
      },
    });
    render(<PentestReportView scan={scanWith(f)} triage={{}} />);
    const text = document.body.textContent ?? '';
    expect(text).toContain('A01:2025');
    expect(text).toContain('API3');
    expect(text).toContain('CWE-200');
    expect(text).toContain('CWE-215');
  });
});
