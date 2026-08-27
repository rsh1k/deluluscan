import { useMemo, useState } from 'react';
import type { Scan, ScanFinding } from '@/lib/deluluscan-data';
import {
  CLOSED_STATUSES,
  EXPLOIT_LABEL,
  OWASP_NAME,
  SEVERITY_ORDER,
  SEV_META,
  VERDICT_LABEL,
  isConfirmed,
  riskBand,
  riskScore,
  sevMeta,
} from '@/lib/model';
import type { TriageMap } from '@/lib/triage';
import { statusOf } from '@/lib/triage';
import { findingMemory, isRecurring, scanMemory, shortDate } from '@/lib/memory';
import { Card, Empty, Pill, SevTag } from '@/components/ui';

type SortKey = 'severity' | 'title' | 'endpoint' | 'verdict' | 'status';

function Gauge({ score }: { score: number }) {
  const band = riskBand(score);
  const R = 52;
  const C = 2 * Math.PI * R;
  return (
    <div className="flex flex-col items-center">
      <div className="relative h-32 w-32">
        <svg viewBox="0 0 120 120" className="h-full w-full -rotate-90">
          <circle cx="60" cy="60" r={R} fill="none" stroke="#e2e8f0" strokeWidth="12" />
          <circle
            cx="60"
            cy="60"
            r={R}
            fill="none"
            stroke={band.color}
            strokeWidth="12"
            strokeLinecap="round"
            strokeDasharray={`${(C * score) / 100} ${C}`}
          />
        </svg>
        <div className="absolute inset-0 grid place-items-center">
          <div className="text-center">
            <div className="text-3xl font-bold text-slate-100">{score}</div>
            <div className="text-[10px] uppercase tracking-wider" style={{ color: band.color }}>
              {band.label}
            </div>
          </div>
        </div>
      </div>
      <p className="mt-2 max-w-[15rem] text-center text-[11.5px] leading-relaxed text-slate-500">
        {band.note}
      </p>
    </div>
  );
}

function Bars({ data, color }: { data: { label: string; count: number }[]; color: string }) {
  const max = Math.max(1, ...data.map((d) => d.count));
  if (!data.length) return <p className="text-xs text-slate-600">Nothing to chart.</p>;
  return (
    <div className="space-y-2">
      {data.map((d) => (
        <div key={d.label}>
          <div className="mb-1 flex justify-between text-[11px]">
            <span className="truncate text-slate-400">{d.label}</span>
            <span className="text-slate-500">{d.count}</span>
          </div>
          <div className="h-1.5 overflow-hidden rounded-full bg-slate-800">
            <div
              className="h-full rounded-full"
              style={{ width: `${(d.count / max) * 100}%`, background: color }}
            />
          </div>
        </div>
      ))}
    </div>
  );
}

export default function FindingsView({ scan, triage, onSelect, selectedId }: {
  scan: Scan;
  triage: TriageMap;
  onSelect: (f: ScanFinding) => void;
  selectedId: string | null;
}) {
  const all = scan.findings ?? [];
  const [sevFilter, setSevFilter] = useState<string[]>([]);
  const [clsFilter, setClsFilter] = useState<string[]>([]);
  const [confirmedOnly, setConfirmedOnly] = useState(false);
  const [showClosed, setShowClosed] = useState(false);
  const [q, setQ] = useState('');
  const [sort, setSort] = useState<SortKey>('severity');
  const [dir, setDir] = useState<-1 | 1>(-1);

  const status = (f: ScanFinding) => statusOf(triage, f.id, f.verdict);
  const score = useMemo(() => riskScore(all), [all]);

  const sevCounts = useMemo(() => {
    const c: Record<string, number> = {};
    for (const f of all) if (!CLOSED_STATUSES.has(status(f))) c[f.severity] = (c[f.severity] ?? 0) + 1;
    return c;
  }, [all, triage]);

  const classes = useMemo(
    () => Array.from(new Set(all.map((f) => f.owasp?.code).filter(Boolean) as string[])).sort(),
    [all]
  );

  const visible = useMemo(() => {
    const needle = q.trim().toLowerCase();
    const rows = all.filter((f) => {
      const closed = CLOSED_STATUSES.has(status(f));
      if (closed !== showClosed) return false;
      if (sevFilter.length && !sevFilter.includes(f.severity)) return false;
      if (clsFilter.length && !clsFilter.includes(f.owasp?.code ?? '')) return false;
      if (confirmedOnly && !isConfirmed(f)) return false;
      if (
        needle &&
        !`${f.title} ${f.endpoint} ${f.description} ${f.cwe ?? ''}`.toLowerCase().includes(needle)
      )
        return false;
      return true;
    });
    const key = (f: ScanFinding) => {
      switch (sort) {
        case 'title':
          return f.title.toLowerCase();
        case 'endpoint':
          return f.endpoint.toLowerCase();
        case 'verdict':
          return VERDICT_LABEL[f.verdict] ?? '';
        case 'status':
          return status(f);
        default:
          return sevMeta(f.severity).rank;
      }
    };
    return rows.sort((a, b) => {
      const ka = key(a);
      const kb = key(b);
      return (ka < kb ? -1 : ka > kb ? 1 : 0) * dir;
    });
  }, [all, q, sevFilter, clsFilter, confirmedOnly, showClosed, sort, dir, triage]);

  const active = all.filter((f) => !CLOSED_STATUSES.has(status(f)));
  const confirmed = active.filter(isConfirmed);
  const exploitable = confirmed.filter((f) => f.exploitability === 'exploitable');

  const exploitBars = useMemo(() => {
    const c: Record<string, number> = {};
    for (const f of active) {
      const k = EXPLOIT_LABEL[f.exploitability] ?? 'Unknown';
      c[k] = (c[k] ?? 0) + 1;
    }
    return Object.entries(c)
      .map(([label, count]) => ({ label, count }))
      .sort((a, b) => b.count - a.count);
  }, [active]);

  const owaspBars = useMemo(() => {
    const c: Record<string, number> = {};
    for (const f of active) {
      const k = f.owasp?.code;
      if (k) c[k] = (c[k] ?? 0) + 1;
    }
    return Object.entries(c)
      .map(([code, count]) => ({ label: `${code} ${OWASP_NAME[code] ?? ''}`.trim(), count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 8);
  }, [active]);

  const toggle = (list: string[], v: string, set: (x: string[]) => void) =>
    set(list.includes(v) ? list.filter((x) => x !== v) : [...list, v]);

  const th = (key: SortKey, label: string, className = '') => (
    <th className={`px-3 py-2 text-left font-medium ${className}`}>
      <button
        type="button"
        onClick={() => {
          if (sort === key) setDir((d) => (d === 1 ? -1 : 1));
          else {
            setSort(key);
            setDir(key === 'severity' ? -1 : 1);
          }
        }}
        className="inline-flex items-center gap-1 hover:text-slate-200"
      >
        {label}
        {sort === key && <span className="text-[9px]">{dir === 1 ? '▲' : '▼'}</span>}
      </button>
    </th>
  );

  return (
    <div className="space-y-4">
      {/* Executive strip */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
        <p className="text-[15px] font-semibold text-slate-100">
          {confirmed.filter((f) => f.severity === 'critical').length > 0
            ? `${confirmed.filter((f) => f.severity === 'critical').length} confirmed critical and ${
                confirmed.filter((f) => f.severity === 'high').length
              } high finding(s) need immediate attention`
            : confirmed.length
              ? `${confirmed.length} confirmed finding(s) across the assessed surface`
              : 'No confirmed findings in the current view'}
        </p>
        <p className="mt-1 font-mono text-[11.5px] text-slate-500">{scan.target}</p>
        <div className="mt-3 flex flex-wrap gap-x-6 gap-y-2 text-[11px]">
          {[
            ['Risk', String(score)],
            ['Confirmed', String(confirmed.length)],
            ['Exploitable', String(exploitable.length)],
            ['Excluded', String(all.length - active.length)],
            ['Total', String(all.length)],
          ].map(([k, v]) => (
            <span key={k} className="text-slate-500">
              <strong className="mr-1.5 text-base font-semibold text-slate-200">{v}</strong>
              {k}
            </span>
          ))}
        </div>
        {(() => {
          const mem = scanMemory(scan.meta);
          if (!mem) return null;
          const recurring = all.filter(isRecurring).length;
          const regressed = mem.regression_watch ?? [];
          if (!recurring && !regressed.length && !mem.known_targets) return null;
          return (
            <div className="mt-3 flex flex-wrap items-center gap-x-4 gap-y-1 border-t border-slate-800 pt-2.5 text-[11px]">
              <span className="font-semibold text-slate-400">↻ Engagement memory</span>
              {recurring > 0 && (
                <span className="text-rose-700">
                  {recurring} recurring finding{recurring === 1 ? '' : 's'} seen on a prior scan
                </span>
              )}
              {regressed.length > 0 && (
                <span className="text-emerald-700">
                  {regressed.length} previously-exploitable endpoint
                  {regressed.length === 1 ? '' : 's'} did not reproduce (possible fix)
                </span>
              )}
              {mem.target_key && (
                <span className="font-mono text-slate-600">{mem.target_key}</span>
              )}
            </div>
          );
        })()}
      </div>

      <div className="grid gap-4 lg:grid-cols-[minmax(0,260px)_1fr]">
        <Card title="Risk posture">
          <div className="grid place-items-center py-2">
            <Gauge score={score} />
          </div>
        </Card>
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5">
          {SEVERITY_ORDER.map((s) => {
            const m = SEV_META[s];
            const on = sevFilter.includes(s);
            return (
              <button
                key={s}
                type="button"
                onClick={() => toggle(sevFilter, s, setSevFilter)}
                aria-pressed={on}
                className={`rounded-xl border p-3 text-left transition ${
                  on ? 'border-slate-500 bg-slate-800/60' : 'border-slate-800 bg-slate-900/60 hover:border-slate-700'
                }`}
              >
                <div className="text-2xl font-bold" style={{ color: m.color }}>
                  {sevCounts[s] ?? 0}
                </div>
                <div className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">
                  {m.label}
                </div>
              </button>
            );
          })}
        </div>
      </div>

      <div className="grid gap-4 md:grid-cols-2">
        <Card title="Exploitability">
          <Bars data={exploitBars} color="#c2410c" />
        </Card>
        <Card title="OWASP Top 10">
          <Bars data={owaspBars} color="#2563eb" />
        </Card>
      </div>

      {/* Filters + table */}
      <Card
        title={`${showClosed ? 'Excluded' : 'Active'} findings · ${visible.length}`}
        action={
          <div className="flex flex-wrap items-center gap-2">
            <input
              value={q}
              onChange={(e) => setQ(e.target.value)}
              placeholder="Search title, endpoint, CWE…"
              aria-label="Search findings"
              className="w-48 rounded-md border border-slate-700 bg-slate-950 px-2.5 py-1 text-[12px] text-slate-200 placeholder:text-slate-600"
            />
            <label className="flex items-center gap-1.5 text-[11px] text-slate-400">
              <input
                type="checkbox"
                checked={confirmedOnly}
                onChange={(e) => setConfirmedOnly(e.target.checked)}
              />
              Confirmed only
            </label>
            <label className="flex items-center gap-1.5 text-[11px] text-slate-400">
              <input
                type="checkbox"
                checked={showClosed}
                onChange={(e) => setShowClosed(e.target.checked)}
              />
              Show excluded
            </label>
          </div>
        }
      >
        {classes.length > 1 && (
          <div className="mb-3 flex flex-wrap gap-1.5">
            {classes.map((c) => (
              <button key={c} type="button" onClick={() => toggle(clsFilter, c, setClsFilter)}>
                <Pill color={clsFilter.includes(c) ? '#4338ca' : undefined} title={OWASP_NAME[c]}>
                  {c}
                </Pill>
              </button>
            ))}
            {(sevFilter.length > 0 || clsFilter.length > 0 || q !== '' || confirmedOnly) && (
              <button
                type="button"
                onClick={() => {
                  setSevFilter([]);
                  setClsFilter([]);
                  setQ('');
                  setConfirmedOnly(false);
                }}
                className="text-[11px] text-slate-500 underline hover:text-slate-300"
              >
                clear filters
              </button>
            )}
          </div>
        )}

        {visible.length === 0 ? (
          <Empty
            title="No findings match"
            sub="Try clearing the search or filter selections."
          />
        ) : (
          <div className="-mx-4 overflow-x-auto">
            <table className="w-full min-w-[52rem] text-[12.5px]">
              <thead>
                <tr className="border-b border-slate-800 text-[10px] uppercase tracking-wider text-slate-500">
                  {th('severity', 'Sev', 'w-16')}
                  {th('title', 'Finding')}
                  {th('endpoint', 'Endpoint')}
                  <th className="px-3 py-2 text-left font-medium">OWASP</th>
                  {th('verdict', 'Verdict')}
                  {th('status', 'Status')}
                </tr>
              </thead>
              <tbody>
                {visible.map((f) => (
                  <tr
                    key={f.id}
                    onClick={() => onSelect(f)}
                    className={`cursor-pointer border-b border-slate-800/60 transition hover:bg-slate-800/40 ${
                      selectedId === f.id ? 'bg-slate-800/60' : ''
                    }`}
                  >
                    <td className="px-3 py-2">
                      <SevTag severity={f.severity} />
                    </td>
                    <td className="max-w-[22rem] px-3 py-2">
                      <div className="flex items-center gap-1.5">
                        <span className="truncate text-slate-200" title={f.title}>
                          {f.title}
                        </span>
                        {(() => {
                          const mem = findingMemory(f);
                          if (!mem) return null;
                          const recur = isRecurring(f);
                          return (
                            <span
                              title={
                                (recur
                                  ? 'Recurring: exploitable on a prior scan and still present'
                                  : 'Seen on this target before') +
                                (mem.first_seen ? ` (since ${shortDate(mem.first_seen)})` : '')
                              }
                              className={`shrink-0 rounded px-1.5 py-0.5 text-[9px] font-semibold uppercase tracking-wide ${
                                recur
                                  ? 'bg-rose-500/15 text-rose-700'
                                  : 'bg-slate-700/50 text-slate-400'
                              }`}
                            >
                              ↻ {recur ? 'Recurring' : 'Seen before'}
                            </span>
                          );
                        })()}
                      </div>
                      {f.evidence_missing && (
                        <div className="text-[10px] text-amber-700/80">no evidence captured</div>
                      )}
                    </td>
                    <td className="max-w-[14rem] truncate px-3 py-2 font-mono text-[11px] text-slate-500">
                      {f.endpoint}
                    </td>
                    <td className="px-3 py-2 text-slate-400">{f.owasp?.code ?? '—'}</td>
                    <td className="px-3 py-2">
                      <span
                        className={
                          isConfirmed(f)
                            ? 'text-rose-700'
                            : f.verdict === 'false_positive' || f.verdict === 'likely_false_positive'
                              ? 'text-emerald-700'
                              : 'text-slate-400'
                        }
                      >
                        {VERDICT_LABEL[f.verdict] ?? 'Not verified'}
                      </span>
                    </td>
                    <td className="px-3 py-2 text-slate-400">{status(f)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
}
