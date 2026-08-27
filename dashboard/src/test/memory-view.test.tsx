/**
 * Engagement-memory surfacing in the report UI.
 *
 * The Python side writes detail.memory (per finding) and meta.memory (per scan);
 * these tests lock down that the UI renders them honestly: a recurring finding is
 * badged, the executive strip summarises recall, and the report's prior-assessment
 * section lists recurring findings and frames a regression-watch as a POSSIBLE fix
 * to confirm — never as an asserted fix.
 */
import { beforeEach, describe, expect, it } from 'vitest';
import { render, screen } from '@testing-library/react';
import FindingsView from '@/components/FindingsView';
import PentestReportView from '@/components/PentestReportView';
import { findingMemory, isRecurring, scanMemory } from '@/lib/memory';
import type { Scan, ScanFinding } from '@/lib/deluluscan-data';

const RECURRING: ScanFinding = {
  id: 'f1', vuln_class: 'authz', severity: 'high', title: 'OSGi bundle upload reachable',
  endpoint: 'POST /api/v1/plugins', description: 'reachable', evidence: [],
  detail: { memory: { seen_before: true, first_seen: '2026-06-01T00:00:00Z',
    prior_verdict: 'true_positive', prior_exploitability: 'exploitable', seen_count: 3,
    note: 'recurring: exploitable on a prior scan and still present' } },
  confidence: 'firm', verdict: 'true_positive', exploitability: 'exploitable',
  ai_notes: '', created_at: 0, cwe: 'CWE-862', owasp: { code: 'A01', name: 'Broken Access Control' },
};

const FRESH: ScanFinding = {
  ...RECURRING, id: 'f2', title: 'New reflected value', endpoint: 'GET /api/v1/x',
  detail: {},
};

function scan(regression: string[] = []): Scan {
  return {
    id: 'scan_mem', label: 'x', date: '2026-07-31T12:00:00Z', version: '26.07',
    target: 'http://127.0.0.1:8080', findings: [RECURRING, FRESH],
    identities: ['admin'],
    meta: {
      target: 'http://127.0.0.1:8080',
      memory: { enabled: true, target_key: 'target@1.2.3', recorded: 1,
        known_targets: 1, regression_watch: regression },
    },
  };
}

describe('memory helpers', () => {
  it('detects a memory-annotated finding and a recurring one', () => {
    expect(findingMemory(RECURRING)?.seen_count).toBe(3);
    expect(isRecurring(RECURRING)).toBe(true);
    expect(findingMemory(FRESH)).toBeNull();
  });
  it('reads scan memory but hides it when disabled or errored', () => {
    expect(scanMemory(scan().meta)?.target_key).toBe('target@1.2.3');
    expect(scanMemory({ memory: { enabled: false } })).toBeNull();
    expect(scanMemory({ memory: { error: 'boom' } })).toBeNull();
    expect(scanMemory({})).toBeNull();
  });
});

describe('FindingsView', () => {
  it('badges a recurring finding and summarises recall in the executive strip', () => {
    render(<FindingsView scan={scan(['authz|POST /api/v1/legacy'])} triage={{}} onSelect={() => {}} selectedId={null} />);
    expect(screen.getAllByText(/Recurring/).length).toBeGreaterThan(0);
    expect(screen.getByText(/Engagement memory/)).toBeInTheDocument();
    expect(screen.getByText(/did not reproduce \(possible fix\)/)).toBeInTheDocument();
  });
});

describe('PentestReportView prior-assessment section', () => {
  beforeEach(() => localStorage.clear());

  it('lists recurring findings and frames regression-watch as a possible fix', () => {
    render(<PentestReportView scan={scan(['authz|POST /api/v1/legacy'])} triage={{}} />);
    expect(screen.getByText('Vulnerability Summary')).toBeInTheDocument();
    expect(screen.getByText('Recurring findings')).toBeInTheDocument();
    expect(screen.getByText('Possible fixes since the last assessment')).toBeInTheDocument();
    // honesty: never asserts "fixed", only "possible fix to confirm"
    expect(screen.getByText(/possible fix to confirm/i)).toBeInTheDocument();
    expect(screen.getByText(/POST \/api\/v1\/legacy/)).toBeInTheDocument();
  });

  it('shows a first-assessment note when there is no prior data', () => {
    const s = scan();
    s.findings = [FRESH]; // no memory-annotated findings, no regression watch
    render(<PentestReportView scan={s} triage={{}} />);
    expect(screen.getByText(/first recorded assessment of this target build/)).toBeInTheDocument();
  });
});
