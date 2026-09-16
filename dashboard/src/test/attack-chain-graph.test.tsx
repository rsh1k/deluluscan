/**
 * Attack-chain graph view.
 *
 * The Python `correlate` module emits chain findings (detail.source === 'correlate')
 * whose detail.members list the confirmed findings that combine into an objective.
 * These tests lock down that the graph: renders one diagram per chain (member
 * nodes → objective), stays hidden when nothing correlated, sorts by severity,
 * navigates to the underlying finding on click, and — per the honesty rule —
 * frames chains as derived hypotheses, never independently proven exploits.
 */
import { describe, expect, it, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import AttackChainGraph, { hasAttackChains } from '@/components/AttackChainGraph';
import type { Scan, ScanFinding } from '@/lib/deluluscan-data';

const SSRF: ScanFinding = {
  id: 'ssrf1', vuln_class: 'ssrf', severity: 'high', title: 'SSRF on fetch param',
  endpoint: 'GET /api/v1/fetch', description: 'x', evidence: [], detail: {},
  confidence: 'firm', verdict: 'true_positive', exploitability: 'exploitable',
  ai_notes: '', created_at: 0,
};
const IMDS: ScanFinding = {
  ...SSRF, id: 'imds1', vuln_class: 'ssrf', title: 'Cloud metadata reachable',
  endpoint: 'GET /api/v1/fetch?url=169.254.169.254',
};
const CHAIN: ScanFinding = {
  id: 'chain1', vuln_class: 'business_logic', severity: 'critical',
  title: 'Correlated attack chain: SSRF to cloud credential theft',
  endpoint: 'chain', description: 'derived from 2 confirmed findings.', evidence: [],
  detail: {
    source: 'correlate', chain: 'ssrf_imds_creds',
    objective: 'Steal cloud IAM credentials via the instance metadata service',
    remediation: 'Block link-local ranges at the egress proxy.',
    members: [
      { title: SSRF.title, endpoint: SSRF.endpoint, vuln_class: 'ssrf' },
      { title: IMDS.title, endpoint: IMDS.endpoint, vuln_class: 'ssrf' },
    ],
  },
  confidence: 'tentative', verdict: 'inconclusive', exploitability: 'conditional',
  ai_notes: '', created_at: 0,
};
// A correlate finding with an empty member list must NOT count as a chain.
const EMPTY_CHAIN: ScanFinding = {
  ...CHAIN, id: 'chain0', title: 'Correlated attack chain: nothing',
  detail: { source: 'correlate', chain: 'x', objective: 'y', members: [] },
};

function scan(findings: ScanFinding[]): Scan {
  return {
    id: 's', label: 'x', date: '2026-09-01T00:00:00Z', version: '1',
    target: 'http://127.0.0.1:8080', findings, identities: ['admin'],
    meta: { target: 'http://127.0.0.1:8080' },
  };
}

describe('hasAttackChains', () => {
  it('is true only for a correlate finding with members', () => {
    expect(hasAttackChains(scan([SSRF, IMDS, CHAIN]))).toBe(true);
    expect(hasAttackChains(scan([SSRF, IMDS]))).toBe(false);
    expect(hasAttackChains(scan([EMPTY_CHAIN]))).toBe(false);
  });
});

describe('AttackChainGraph', () => {
  it('renders a diagram per chain with its objective and remediation', () => {
    render(<AttackChainGraph scan={scan([SSRF, IMDS, CHAIN])} onSelect={() => {}} />);
    expect(screen.getByText('SSRF to cloud credential theft')).toBeInTheDocument();
    expect(screen.getByText(/Steal cloud IAM credentials/)).toBeInTheDocument();
    expect(screen.getByText(/Block link-local ranges/)).toBeInTheDocument();
    // honesty: chains are derived hypotheses, not independently proven
    expect(screen.getByText(/hypotheses derived from the findings/i)).toBeInTheDocument();
  });

  it('shows an explicit empty state when nothing correlated', () => {
    render(<AttackChainGraph scan={scan([SSRF, IMDS])} onSelect={() => {}} />);
    expect(screen.getByText(/No correlated attack chains/i)).toBeInTheDocument();
  });

  it('navigates to the underlying finding when a member node is clicked', () => {
    const onSelect = vi.fn();
    render(<AttackChainGraph scan={scan([SSRF, IMDS, CHAIN])} onSelect={onSelect} />);
    fireEvent.click(screen.getByText('SSRF on fetch param'));
    expect(onSelect).toHaveBeenCalledTimes(1);
    expect(onSelect.mock.calls[0][0].id).toBe('ssrf1');
  });
});
