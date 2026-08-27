import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, within, fireEvent, cleanup } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import SecurityDashboard from '@/components/SecurityDashboard';
import { sampleData } from '@/data/sample-scan';
import { isFalsePositive } from '@/lib/security-findings';

// Covers the SecurityDashboard component tree that is mirrored 1:1 in
// target-aios/frontend. It is no longer what THIS app renders — App now mounts
// the Deluluscan report views (findings / access matrix / pentest report) against the
// scan payload deluluscan/dashboard.py injects; see report-integrity.test.tsx. This
// suite is kept so the mirrored tree stays verified here rather than only in the
// other repo, and is rendered directly instead of through App.

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe('SecurityDashboard (mirrored target-aios tree, sample data)', () => {
  it('renders the header, logo, and scan summary without throwing', () => {
    render(<SecurityDashboard initialData={sampleData} />);
    expect(screen.getByAltText('the target')).toBeInTheDocument();
    expect(screen.getByText('Security dashboard')).toBeInTheDocument();
    expect(
      screen.getByText(`Last scan: ${sampleData.scan.scan_date} · ${sampleData.scan.findings.length} findings`)
    ).toBeInTheDocument();
  });

  it('renders the risk gauge with a numeric score and posture label', () => {
    render(<SecurityDashboard initialData={sampleData} />);
    expect(screen.getByText('/ 100')).toBeInTheDocument();
    expect(screen.getByText(/OVERALL RISK:/)).toBeInTheDocument();
  });

  it('excludes false positives from the findings table but keeps them in the sample data', () => {
    render(<SecurityDashboard initialData={sampleData} />);
    const falsePositiveCount = sampleData.scan.findings.filter(isFalsePositive).length;
    const nonFalsePositiveCount = sampleData.scan.findings.length - falsePositiveCount;
    expect(falsePositiveCount).toBeGreaterThan(0); // sanity: sample actually has some

    const table = screen.getByRole('table');
    const rows = within(table).getAllByRole('row');
    // header row + one row per non-false-positive finding
    expect(rows.length).toBe(nonFalsePositiveCount + 1);

    // The false-positive SSTI finding must not appear in the table body.
    expect(within(table).queryByText(/SSTI candidate/)).not.toBeInTheDocument();
  });

  it('shows which identity(ies) exploited each finding, using friendly role labels', () => {
    render(<SecurityDashboard initialData={sampleData} />);
    const table = screen.getByRole('table');
    // f_c01's evidence includes both anonymous and admin identities.
    expect(within(table).getAllByText('Anonymous').length).toBeGreaterThan(0);
    expect(within(table).getAllByText('Admin').length).toBeGreaterThan(0);
  });

  it('opens the identity & role reference panel with honest role context', async () => {
    const user = userEvent.setup();
    render(<SecurityDashboard initialData={sampleData} />);
    await user.click(screen.getByRole('button', { name: /Test identities & roles/i }));

    expect(screen.getByRole('heading', { name: 'Test identities & roles' })).toBeInTheDocument();
    // "Read Only" also appears as a table badge (f_h01's evidence uses that
    // identity), so scope to the reference panel's own heading for that row.
    expect(screen.getByRole('heading', { name: 'Read Only' })).toBeInTheDocument();
    expect(
      screen.getByText(/Currently provisioned with the SAME role as "backend"/)
    ).toBeInTheDocument();
    expect(screen.getAllByText(/CMS Administrator/).length).toBeGreaterThan(0);
  });

  it('opens a finding\'s detail drawer showing evidence with inline role context', async () => {
    const user = userEvent.setup();
    render(<SecurityDashboard initialData={sampleData} />);

    await user.click(screen.getByText(/BOLA — anonymous request returns/));

    // Drawer shows the finding title again plus per-identity evidence with
    // the role annotated inline (not just the bare identity key). Evidence
    // is filtered to one identity at a time via the "View as" switcher,
    // defaulting to the first identity in the finding's evidence array.
    const drawerHeading = screen.getByRole('heading', { name: /BOLA — anonymous request returns/ });
    expect(drawerHeading).toBeInTheDocument();
    expect(screen.getByText(/no target role/)).toBeInTheDocument(); // anonymous evidence (default view)

    await user.click(screen.getByRole('button', { name: 'Admin' }));
    expect(screen.getByText(/CMS Administrator/)).toBeInTheDocument(); // admin evidence, after switching
  });

  it('persists a triage status change via the dev triage endpoint (optimistic + confirmed)', async () => {
    const user = userEvent.setup();
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        entry: {
          status: 'confirmed',
          assignee: '',
          updated_by: 'local-test@example.com',
          updated_at: '2026-07-11T00:00:00Z',
        },
      }),
    });
    vi.stubGlobal('fetch', fetchMock);

    render(<SecurityDashboard initialData={sampleData} />);
    await user.click(screen.getByText(/BOLA — anonymous request returns/));

    // Triage status buttons render lowercase, e.g. "confirmed".
    const confirmButtons = screen.getAllByRole('button', { name: 'confirmed' });
    await user.click(confirmButtons[0]);

    expect(fetchMock).toHaveBeenCalledWith(
      '/api/security/triage',
      expect.objectContaining({
        method: 'POST',
        body: expect.stringContaining('"finding_id":"f_c01"'),
      })
    );
    expect(await screen.findByText(/Last updated by local-test@example.com/)).toBeInTheDocument();
  });

  it('reverts the optimistic triage update if the request fails', async () => {
    const user = userEvent.setup();
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: false }));

    render(<SecurityDashboard initialData={sampleData} />);
    await user.click(screen.getByText(/BOLA — anonymous request returns/));
    const confirmButtons = screen.getAllByRole('button', { name: 'confirmed' });
    await user.click(confirmButtons[0]);

    // No "Last updated by" text should appear since the write failed and the
    // optimistic update was rolled back.
    expect(screen.queryByText(/Last updated by/)).not.toBeInTheDocument();
  });

  it('filters the table down when a severity KPI card is toggled', async () => {
    const user = userEvent.setup();
    render(<SecurityDashboard initialData={sampleData} />);
    const table = screen.getByRole('table');
    const initialRows = within(table).getAllByRole('row').length;

    await user.click(screen.getByRole('button', { name: /^critical/i }));

    const filteredRows = within(screen.getByRole('table')).getAllByRole('row').length;
    expect(filteredRows).toBeLessThan(initialRows);
    expect(filteredRows).toBeGreaterThan(1); // header + at least one critical finding
  });

  it('filters the table via the search box', () => {
    render(<SecurityDashboard initialData={sampleData} />);
    fireEvent.change(screen.getByPlaceholderText('Title, endpoint…'), {
      target: { value: 'SQLi' },
    });
    const table = screen.getByRole('table');
    expect(within(table).getByText(/Time-based blind SQLi/)).toBeInTheDocument();
    expect(within(table).queryByText(/BOLA — anonymous request returns/)).not.toBeInTheDocument();
  });
});
