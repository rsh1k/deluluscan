/**
 * Letter of Attestation view.
 *
 * Locks down the two things the user asked for — it is EDITABLE and it is a real
 * letter — plus the integrity rule that matters most for an attestation: the
 * CONCLUSION is derived from the actual confirmed findings and never hard-codes
 * "SECURE". A scan with a confirmed High says so and recommends remediation; a
 * clean scan states no Critical/High were identified.
 */
import { beforeEach, describe, expect, it } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import AttestationView from '@/components/AttestationView';
import { loadAttestationEdits, saveAttestationEdits, emptyAttestation } from '@/lib/attestation-edits';
import type { Scan, ScanFinding } from '@/lib/deluluscan-data';

const HIGH: ScanFinding = {
  id: 'f1', vuln_class: 'authz', severity: 'high', title: 'Anonymous reaches admin layouts',
  endpoint: 'GET /api/v1/roles/layouts', description: 'anon 200', evidence: [],
  detail: {}, confidence: 'firm', verdict: 'true_positive', exploitability: 'exploitable',
  ai_notes: '', created_at: 0, cwe: 'CWE-862', owasp: { code: 'A01', name: 'Broken Access Control' },
};

function scan(findings: ScanFinding[]): Scan {
  return {
    id: 'scan_a', label: 'x', date: '2026-08-07T12:00:00Z', version: '26.07',
    target: 'http://127.0.0.1:8080', findings,
    meta: { target: 'http://127.0.0.1:8080' }, identities: ['admin'],
  };
}

describe('attestation-edits store', () => {
  beforeEach(() => localStorage.clear());
  it('persists per scan in its own key (independent of report edits)', () => {
    const e = emptyAttestation();
    e.sections['conclusion'] = { bodyMd: 'custom conclusion' };
    saveAttestationEdits('scan_a', e);
    expect(loadAttestationEdits('scan_a').sections['conclusion']?.bodyMd).toBe('custom conclusion');
    expect(loadAttestationEdits('other')).toEqual(emptyAttestation());
  });
});

describe('Letter of Attestation', () => {
  beforeEach(() => localStorage.clear());

  it('renders as a letter with the derived reference and target', () => {
    render(<AttestationView scan={scan([])} triage={{}} />);
    expect(screen.getByText('Letter of Attestation')).toBeInTheDocument();
    expect(screen.getByText(/target-ATT-2026-08/)).toBeInTheDocument();
    expect(screen.getByText(/127\.0\.0\.1:8080/)).toBeInTheDocument();
  });

  it('derives a clean conclusion when no Critical/High are exploitable (never hard-codes SECURE)', () => {
    render(<AttestationView scan={scan([])} triage={{}} />);
    expect(
      screen.getByText(/no exploitable Critical- or High-risk vulnerabilities/i)
    ).toBeInTheDocument();
  });

  it('derives a remediation conclusion when a High is demonstrated exploitable', () => {
    render(<AttestationView scan={scan([HIGH])} triage={{}} />);
    expect(screen.getByText(/exploitable High-risk finding/i)).toBeInTheDocument();
    expect(screen.getByText(/Remediation is recommended/i)).toBeInTheDocument();
  });

  it('discloses observations that were recorded but never proven exploitable', () => {
    // A confirmed finding that was NOT rated exploitable must not silently
    // vanish from the attestation — staying quiet would read as "nothing else
    // was seen", which is not what the scan observed.
    const OBSERVED: ScanFinding = {
      ...HIGH, id: 'f2', severity: 'medium', title: 'Vulnerable dependency',
      verdict: 'likely_true_positive', exploitability: 'conditional',
    };
    render(<AttestationView scan={scan([HIGH, OBSERVED])} triage={{}} />);
    expect(
      screen.getByText(/1 observation\(s\) were recorded but not demonstrated exploitable/i)
    ).toBeInTheDocument();
  });

  it('is editable: entering edit mode exposes controls and reset works', () => {
    const e = emptyAttestation();
    e.sections['intro'] = { bodyMd: 'my custom introduction' };
    saveAttestationEdits('scan_a', e);
    render(<AttestationView scan={scan([])} triage={{}} />);
    expect(screen.getByText('my custom introduction')).toBeInTheDocument();
    fireEvent.click(screen.getByText('Edit letter'));
    fireEvent.click(screen.getAllByText('Reset to generated')[0]);
    expect(loadAttestationEdits('scan_a').sections['intro']).toBeUndefined();
  });

  it('lets the operator fill in the signatory (left blank by default, not fabricated)', () => {
    render(<AttestationView scan={scan([])} triage={{}} />);
    expect(screen.getByText(/Add the authorized signatory/i)).toBeInTheDocument();
  });
});
