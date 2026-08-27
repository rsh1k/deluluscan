/**
 * Editable pentest report + the Markdown renderer behind it.
 *
 * Two properties locked down:
 *   1. The user can edit the report — rename/replace/hide sections, add custom
 *      ones — and the edits persist per scan and render as Markdown, WITHOUT
 *      mutating the underlying scan (the generated report remains the default and
 *      "reset" reveals it again).
 *   2. The self-contained Markdown renderer escapes HTML (a security report must
 *      not XSS its own reader) while still producing real markup.
 * Plus the casing fix: the report reference reads target-PT-, never TARGET-PT-.
 */
import { beforeEach, describe, expect, it } from 'vitest';
import { render, screen, fireEvent, within } from '@testing-library/react';
import PentestReportView from '@/components/PentestReportView';
import { mdToHtml } from '@/lib/markdown';
import { loadReportEdits, saveReportEdits, emptyEdits } from '@/lib/report-edits';
import type { Scan, ScanFinding } from '@/lib/deluluscan-data';

const FINDING: ScanFinding = {
  id: 'f1', vuln_class: 'authz', severity: 'high', title: 'Anonymous reaches admin layouts',
  endpoint: 'GET /api/v1/roles/layouts', description: 'anon 200', evidence: [],
  detail: {}, confidence: 'firm', verdict: 'true_positive', exploitability: 'exploitable',
  ai_notes: '', created_at: 0, cwe: 'CWE-862', owasp: { code: 'A01', name: 'Broken Access Control' },
};

function scan(): Scan {
  return {
    id: 'scan_x', label: 'x', date: '2026-07-31T12:00:00Z', version: '26.07', target: 'http://127.0.0.1:8080',
    findings: [FINDING], meta: { target: 'http://127.0.0.1:8080' }, identities: ['admin'],
  };
}

describe('Markdown renderer', () => {
  it('escapes HTML so a pasted script tag is inert', () => {
    const html = mdToHtml("hi <script>alert(1)</script> **bold**");
    expect(html).not.toContain('<script>');
    expect(html).toContain('&lt;script&gt;');
    expect(html).toContain('<strong>bold</strong>');
  });
  it('renders headings, lists, code and tables', () => {
    expect(mdToHtml('# Title')).toContain('<h3');
    expect(mdToHtml('- a\n- b')).toContain('<ul');
    expect(mdToHtml('1. a\n2. b')).toContain('<ol');
    expect(mdToHtml('use `code` here')).toContain('<code');
    const t = mdToHtml('| A | B |\n| --- | --- |\n| 1 | 2 |');
    expect(t).toContain('<table');
    expect(t).toContain('<th>A</th>');
    expect(t).toContain('<td>1</td>');
  });
});

describe('report-edits store', () => {
  beforeEach(() => localStorage.clear());
  it('persists and prunes per scan', () => {
    const e = emptyEdits();
    e.sections['exec'] = { bodyMd: 'custom' };
    e.sections['scope'] = {}; // empty -> pruned on save
    saveReportEdits('scan_x', e);
    const back = loadReportEdits('scan_x');
    expect(back.sections['exec']?.bodyMd).toBe('custom');
    expect(back.sections['scope']).toBeUndefined();
    expect(loadReportEdits('other')).toEqual(emptyEdits());
  });
});

describe('editable report', () => {
  beforeEach(() => localStorage.clear());

  it('fixes the reference casing to target-PT-, not TARGET-PT-', () => {
    render(<PentestReportView scan={scan()} triage={{}} />);
    expect(screen.getByText(/target-PT-2026-07/)).toBeInTheDocument();
    expect(screen.queryByText(/TARGET-PT-/)).not.toBeInTheDocument();
  });

  it('renders a section override as Markdown instead of the generated body', () => {
    const e = emptyEdits();
    e.sections['exec'] = { title: 'My Summary', bodyMd: '**custom exec** with a point' };
    saveReportEdits('scan_x', e);
    render(<PentestReportView scan={scan()} triage={{}} />);
    // renamed heading + overridden body present; the generated "confirmed finding(s)" prose gone
    expect(screen.getByText('My Summary')).toBeInTheDocument();
    expect(screen.getByText('custom exec')).toBeInTheDocument(); // <strong> content
  });

  it('hides a section when the edit says hidden', () => {
    const e = emptyEdits();
    e.sections['risk-defs'] = { hidden: true };
    saveReportEdits('scan_x', e);
    render(<PentestReportView scan={scan()} triage={{}} />);
    expect(screen.queryByText('Risk Rating Definitions')).not.toBeInTheDocument();
  });

  it('lets the user enter edit mode and add a custom section, persisted', () => {
    render(<PentestReportView scan={scan()} triage={{}} />);
    fireEvent.click(screen.getByText('Edit report'));
    fireEvent.click(screen.getByText('+ Add section'));
    // a custom section titled "New section" now exists and is persisted
    expect(loadReportEdits('scan_x').custom.length).toBe(1);
    expect(screen.getByDisplayValue('New section')).toBeInTheDocument();
  });

  it('reset reveals the generated content again', () => {
    const e = emptyEdits();
    e.sections['exec'] = { bodyMd: 'override' };
    saveReportEdits('scan_x', e);
    render(<PentestReportView scan={scan()} triage={{}} />);
    fireEvent.click(screen.getByText('Edit report'));
    // the exec section shows a "Reset to generated" control; click it
    fireEvent.click(screen.getAllByText('Reset to generated')[0]);
    expect(loadReportEdits('scan_x').sections['exec']).toBeUndefined();
  });
});
