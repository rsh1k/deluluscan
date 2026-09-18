/**
 * AI-note integrity strip in the Findings executive header.
 *
 * The Python side (deluluscan/ai/anchor.audit_ai_integrity) writes
 * meta.ai_integrity: how many AI triage notes made a concrete claim the scan did
 * not observe. These tests lock down that the UI reports it honestly — a clean
 * run reads as backed, a run with an unbacked note reads as advisory-only — and
 * shows nothing when the AI never ran.
 */
import { describe, expect, it } from 'vitest';
import { render, screen } from '@testing-library/react';
import FindingsView from '@/components/FindingsView';
import type { Scan, ScanFinding } from '@/lib/deluluscan-data';

const F: ScanFinding = {
  id: 'f1', vuln_class: 'idor', severity: 'high', title: 'IDOR',
  endpoint: 'GET /api/v1/accounts/{id}', description: 'x', evidence: [],
  detail: {}, confidence: 'firm', verdict: 'true_positive', exploitability: 'conditional',
  ai_notes: '', created_at: 0,
};

function scan(ai: Scan['meta']['ai_integrity']): Scan {
  return {
    id: 's', label: 'x', date: '2026-09-18T00:00:00Z', version: '1',
    target: 'http://127.0.0.1', findings: [F], identities: ['admin'],
    meta: { target: 'http://127.0.0.1', ai_integrity: ai },
  };
}

const view = (s: Scan) =>
  render(<FindingsView scan={s} triage={{}} onSelect={() => {}} selectedId={null} />);

describe('AI-note integrity strip', () => {
  it('reads as backed when every AI note is anchored', () => {
    view(scan({ ai_notes_audited: 3, anchored: 3, unverified: 0, flagged: [] }));
    expect(screen.getByText(/AI note integrity/)).toBeInTheDocument();
    expect(screen.getByText(/all 3 AI notes backed by captured evidence/)).toBeInTheDocument();
  });

  it('flags notes that claim something the scan did not observe', () => {
    view(scan({
      ai_notes_audited: 4, anchored: 3, unverified: 1,
      flagged: [{ endpoint: 'GET /admin', unanchored: ['status:403', 'path:/admin/secrets'] }],
    }));
    expect(screen.getByText(/1 of 4 AI notes made a claim the scan did not observe/))
      .toBeInTheDocument();
    expect(screen.getByText(/advisory only/)).toBeInTheDocument();
  });

  it('renders nothing when the AI never ran', () => {
    view(scan(undefined));
    expect(screen.queryByText(/AI note integrity/)).toBeNull();
  });

  it('renders nothing when no AI notes were audited', () => {
    view(scan({ ai_notes_audited: 0, anchored: 0, unverified: 0, flagged: [] }));
    expect(screen.queryByText(/AI note integrity/)).toBeNull();
  });
});
