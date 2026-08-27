import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  embeddedScans,
  encryptedBlob,
  type EncBlob,
  type Scan,
  type ScanFinding,
} from '@/lib/deluluscan-data';
import { fmtDate } from '@/lib/model';
import { loadTriage, saveTriage, type TriageEntry, type TriageMap } from '@/lib/triage';
import { loadReportEdits } from '@/lib/report-edits';
import PasswordGate from '@/components/PasswordGate';
import FindingsView from '@/components/FindingsView';
import AccessMatrixView from '@/components/AccessMatrixView';
import PentestReportView from '@/components/PentestReportView';
import TelemetryView, { isTelemetryFinding } from '@/components/TelemetryView';
import AttestationView from '@/components/AttestationView';
import FindingDrawer from '@/components/FindingDrawer';
import { Empty } from '@/components/ui';
// Inlined so the Deluluscan logo renders in the self-contained single-file dashboard
// (an external /logo-dark.svg cannot load when the HTML is opened standalone).
import brandLogo from '@/logo-dark.svg?raw';

type Tab = 'findings' | 'access' | 'telemetry' | 'report' | 'attestation';
const BASE_TABS: [Tab, string][] = [
  ['findings', 'Findings'],
  ['access', 'Users & Access'],
  ['report', 'Pentest Report'],
  ['attestation', 'Attestation'],
];
const TELEMETRY_TAB: [Tab, string] = ['telemetry', 'Behavioral'];

/** Hash routing: #<tab>[/<findingId>] — so a specific finding is linkable. */
function parseHash(): { tab: Tab; findingId: string | null } {
  const raw = decodeURIComponent((location.hash || '').replace(/^#/, ''));
  const [tab, ...rest] = raw.split('/');
  const id = rest.join('/');
  const known: Tab[] = ['findings', 'access', 'telemetry', 'report', 'attestation'];
  return {
    tab: (known.includes(tab as Tab) ? tab : 'findings') as Tab,
    findingId: id || null,
  };
}

function Dashboard({ scans }: { scans: Scan[] }) {
  const [scanId, setScanId] = useState(scans[0].id);
  const [{ tab, findingId }, setRoute] = useState(parseHash);

  const scan = useMemo(() => scans.find((s) => s.id === scanId) ?? scans[0], [scans, scanId]);
  // The Behavioral tab only appears on a grey-box (--observe) scan that actually
  // produced telemetry, so a black-box report is not cluttered with an empty tab.
  const hasTelemetry = useMemo(
    () => Boolean(scan.meta?.telemetry) || scan.findings.some(isTelemetryFinding),
    [scan]
  );
  const tabs = useMemo<[Tab, string][]>(
    () => (hasTelemetry ? [...BASE_TABS.slice(0, 2), TELEMETRY_TAB, ...BASE_TABS.slice(2)] : BASE_TABS),
    [hasTelemetry]
  );
  const [triage, setTriage] = useState<TriageMap>(() => loadTriage(scan.id));

  useEffect(() => setTriage(loadTriage(scan.id)), [scan.id]);

  useEffect(() => {
    const onHash = () => setRoute(parseHash());
    window.addEventListener('hashchange', onHash);
    return () => window.removeEventListener('hashchange', onHash);
  }, []);

  const go = useCallback((next: Tab, id?: string | null) => {
    location.hash = id ? `${next}/${encodeURIComponent(id)}` : next;
    setRoute({ tab: next, findingId: id ?? null });
  }, []);

  const selected = useMemo(
    () => (findingId ? scan.findings.find((f) => f.id === findingId) ?? null : null),
    [scan, findingId]
  );

  const select = useCallback((f: ScanFinding) => go(tab, f.id), [go, tab]);

  const save = useCallback(
    (patch: Partial<TriageEntry>) => {
      if (!selected) return;
      setTriage((prev) => {
        const next: TriageMap = {
          ...prev,
          [selected.id]: {
            status: patch.status ?? prev[selected.id]?.status ?? 'New',
            assignee: patch.assignee ?? prev[selected.id]?.assignee ?? '',
            notes: patch.notes ?? prev[selected.id]?.notes ?? '',
            updated: new Date().toISOString(),
          },
        };
        saveTriage(scan.id, next);
        return next;
      });
    },
    [selected, scan.id]
  );

  const exportJson = () => {
    const blob = new Blob(
      [JSON.stringify({ scan, triage, reportEdits: loadReportEdits(scan.id) }, null, 2)],
      { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `deluluscan-${scan.date?.slice(0, 10) || 'scan'}.json`;
    a.click();
    URL.revokeObjectURL(a.href);
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-200">
      <header className="rd-print-hide sticky top-0 z-30 border-b border-slate-800 bg-slate-950/95 backdrop-blur">
        <div className="mx-auto flex max-w-[1400px] flex-wrap items-center gap-3 px-4 py-3">
          <div className="flex items-center gap-2">
            <span className="rk-logo inline-flex items-center [&_svg]:h-5 [&_svg]:w-auto"
                  aria-label="the target" dangerouslySetInnerHTML={{ __html: brandLogo }} />
            <span className="text-slate-700">·</span>
            <span className="text-[15px] font-bold tracking-tight text-slate-100">Deluluscan</span>
            <span className="text-[11px] text-slate-500">Security Assessment</span>
          </div>
          <div className="hidden h-5 w-px bg-slate-800 sm:block" />
          <div className="min-w-0 text-[11.5px] text-slate-500">
            <span className="font-mono">{scan.target}</span>
            {scan.version && scan.version !== 'unknown' && (
              <span className="ml-2">· the target v{scan.version}</span>
            )}
            <span className="ml-2">· {fmtDate(scan.date)}</span>
          </div>
          <div className="ml-auto flex items-center gap-2">
            {scans.length > 1 && (
              <select
                value={scanId}
                onChange={(e) => setScanId(e.target.value)}
                aria-label="Scan history"
                className="rounded-md border border-slate-700 bg-slate-900 px-2 py-1 text-[11.5px] text-slate-300"
              >
                {scans.map((s) => (
                  <option key={s.id} value={s.id}>
                    {s.label}
                  </option>
                ))}
              </select>
            )}
            <button
              type="button"
              onClick={exportJson}
              className="rounded-md border border-slate-700 px-2.5 py-1 text-[11.5px] text-slate-400 hover:text-slate-200"
            >
              Export JSON
            </button>
            <button
              type="button"
              onClick={() => window.print()}
              className="rounded-md border border-slate-700 px-2.5 py-1 text-[11.5px] text-slate-400 hover:text-slate-200"
            >
              Print / PDF
            </button>
          </div>
        </div>
        <nav className="mx-auto flex max-w-[1400px] gap-1 px-4">
          {tabs.map(([t, label]) => (
            <button
              key={t}
              type="button"
              onClick={() => go(t, null)}
              aria-current={tab === t ? 'page' : undefined}
              className={`-mb-px border-b-2 px-3 py-2 text-[12.5px] font-medium transition ${
                tab === t
                  ? 'border-indigo-500 text-slate-100'
                  : 'border-transparent text-slate-500 hover:text-slate-300'
              }`}
            >
              {label}
            </button>
          ))}
        </nav>
      </header>

      <main className="mx-auto max-w-[1400px] px-4 py-5">
        {tab === 'findings' && (
          <FindingsView
            scan={scan}
            triage={triage}
            onSelect={select}
            selectedId={selected?.id ?? null}
          />
        )}
        {tab === 'access' && <AccessMatrixView scan={scan} onSelect={select} />}
        {tab === 'telemetry' && <TelemetryView scan={scan} onSelect={select} />}
        {tab === 'report' && <PentestReportView scan={scan} triage={triage} />}
        {tab === 'attestation' && <AttestationView scan={scan} triage={triage} />}
      </main>

      {selected && (
        <FindingDrawer
          finding={selected}
          entry={triage[selected.id]}
          onClose={() => go(tab, null)}
          onSave={save}
        />
      )}
    </div>
  );
}

/** Dev fixture, so `npm run dev` shows something. Tree-shaken out of the built
 *  bundle: a shipped report must never display data that did not come from a scan. */
function devFallback(): Scan[] | null {
  if (!import.meta.env.DEV) return null;
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  return (globalThis as { __DELULUSCAN_DEV__?: Scan[] }).__DELULUSCAN_DEV__ ?? null;
}

export default function App({ initialScans }: { initialScans?: Scan[] } = {}) {
  const [scans, setScans] = useState<Scan[] | null>(
    initialScans ?? embeddedScans() ?? devFallback()
  );
  const [blob] = useState<EncBlob | null>(() => (initialScans ? null : encryptedBlob()));

  // Encrypted payload and no plaintext: the findings are genuinely not in this
  // file until the passphrase is entered.
  if (!scans && blob) return <PasswordGate blob={blob} onUnlock={setScans} />;
  if (!scans || !scans.length) {
    return (
      <div className="grid min-h-screen place-items-center bg-slate-950 text-slate-200">
        <Empty
          title="No scan data in this file"
          sub="Generate the report with: python3 -m deluluscan.dashboard deluluscan-out/results.json out.html"
        />
      </div>
    );
  }
  return <Dashboard scans={scans} />;
}
