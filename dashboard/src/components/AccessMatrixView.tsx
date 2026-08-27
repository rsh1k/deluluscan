import { useMemo, useState } from 'react';
import type { Scan, ScanFinding } from '@/lib/deluluscan-data';
import { ID_ORDER, accessSummary, buildAccessMatrix, identityMeta } from '@/lib/model';
import { Card, Empty } from '@/components/ui';

/**
 * Who could actually reach what.
 *
 * Every cell is a real observed HTTP status from captured evidence. There is no
 * cell for an identity that was not probed — a blank means untested, and untested
 * is not the same as denied. (An earlier build synthesised an admin 200 here,
 * which turned an unprobed identity into a fabricated "privilege escalation".)
 */
export default function AccessMatrixView({ scan, onSelect }: {
  scan: Scan;
  onSelect: (f: ScanFinding) => void;
}) {
  const [q, setQ] = useState('');
  const [flaggedOnly, setFlaggedOnly] = useState(false);

  const rows = useMemo(() => buildAccessMatrix(scan.findings ?? []), [scan]);
  const summary = useMemo(() => accessSummary(rows), [rows]);
  const ids = useMemo(() => {
    const present = new Set<string>();
    for (const r of rows) for (const id of Object.keys(r.cells)) present.add(id);
    return ID_ORDER.filter((id) => present.has(id)).concat(
      [...present].filter((id) => !ID_ORDER.includes(id)).sort()
    );
  }, [rows]);

  const byId = new Map(scan.findings.map((f) => [f.id, f]));

  const visible = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return rows
      .map((row) => ({ row, risky: Object.values(row.cells).some((c) => c.unauthorized) }))
      .filter(({ row }) => !needle || row.endpoint.toLowerCase().includes(needle))
      .filter(({ risky }) => !flaggedOnly || risky)
      .sort((a, b) => Number(b.risky) - Number(a.risky) || a.row.endpoint.localeCompare(b.row.endpoint));
  }, [rows, q, flaggedOnly]);

  if (!rows.length) {
    return (
      <Card title="Users & access">
        <Empty
          title="No per-identity evidence in this scan"
          sub="The matrix is built only from captured HTTP exchanges, so there is nothing to show."
        />
      </Card>
    );
  }

  return (
    <div className="space-y-4">
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        {ids.map((id) => {
          const m = identityMeta(id);
          const s = summary[id] ?? { tested: 0, granted: 0, unauthorized: 0 };
          return (
            <div
              key={id}
              className={`rounded-xl border p-3 ${
                s.unauthorized ? 'border-rose-200/70 bg-rose-500/5' : 'border-slate-800 bg-slate-900/60'
              }`}
            >
              <div className="flex items-center gap-2">
                <span className="h-2 w-2 rounded-full" style={{ background: m.color }} />
                <span className="text-[13px] font-semibold" style={{ color: m.color }}>
                  {m.label}
                </span>
              </div>
              <p className="mt-0.5 text-[11px] leading-snug text-slate-500">{m.role}</p>
              <p className="mt-2 text-[13px] text-slate-300">
                <strong className="text-lg font-semibold">{s.granted}</strong>
                <span className="text-slate-500"> / {s.tested} endpoints reachable</span>
              </p>
              {m.entitledToAll ? (
                <p className="mt-1 text-[11px] text-emerald-700">✓ authorized for all (baseline)</p>
              ) : s.unauthorized ? (
                <p className="mt-1 text-[11px] text-rose-700">
                  ⚠ {s.unauthorized} privilege escalation{s.unauthorized > 1 ? 's' : ''}
                </p>
              ) : null}
            </div>
          );
        })}
      </div>

      <Card
        title={`Endpoint × identity · ${visible.length} endpoints`}
        action={
          <div className="flex items-center gap-2">
            <input
              value={q}
              onChange={(e) => setQ(e.target.value)}
              placeholder="Filter endpoints…"
              aria-label="Filter endpoints"
              className="w-44 rounded-md border border-slate-700 bg-slate-950 px-2.5 py-1 text-[12px] text-slate-200 placeholder:text-slate-600"
            />
            <label className="flex items-center gap-1.5 text-[11px] text-slate-400">
              <input
                type="checkbox"
                checked={flaggedOnly}
                onChange={(e) => setFlaggedOnly(e.target.checked)}
              />
              Violations only
            </label>
          </div>
        }
      >
        <p className="mb-3 text-[11.5px] leading-relaxed text-slate-500">
          Each cell is an observed HTTP status. A blank means that identity was{' '}
          <strong className="text-slate-400">not probed</strong> on that endpoint — not that it was
          denied. Red marks a status in the 2xx range for an identity whose privilege tier is below
          what the endpoint requires; admin is entitled to everything, so admin access is the
          authorized baseline.
        </p>
        <div className="-mx-4 overflow-x-auto">
          <table className="w-full min-w-[44rem] text-[12px]">
            <thead>
              <tr className="border-b border-slate-800 text-[10px] uppercase tracking-wider text-slate-500">
                <th className="px-3 py-2 text-left font-medium">Endpoint</th>
                {ids.map((id) => (
                  <th
                    key={id}
                    className="px-2 py-2 text-center font-medium"
                    style={{ color: identityMeta(id).color }}
                  >
                    {identityMeta(id).label}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {visible.map(({ row, risky }) => {
                const [method, ...rest] = row.endpoint.split(' ');
                return (
                  <tr
                    key={row.endpoint}
                    className={`border-b border-slate-800/60 ${risky ? 'bg-rose-500/5' : ''}`}
                  >
                    <td className="px-3 py-1.5 font-mono text-[11px]">
                      <span className="font-semibold text-slate-400">{rest.length ? method : ''}</span>{' '}
                      <span className="text-slate-300">{rest.join(' ') || row.endpoint}</span>
                    </td>
                    {ids.map((id) => {
                      const c = row.cells[id];
                      if (!c)
                        return (
                          <td key={id} className="px-2 py-1.5 text-center text-slate-700" title="not probed">
                            –
                          </td>
                        );
                      const f = byId.get(c.findingId);
                      const cls = c.unauthorized
                        ? 'bg-rose-500/20 text-rose-700'
                        : c.granted
                          ? 'bg-emerald-500/15 text-emerald-700'
                          : 'bg-slate-700/40 text-slate-400';
                      return (
                        <td key={id} className="px-2 py-1.5 text-center">
                          <button
                            type="button"
                            disabled={!f}
                            onClick={() => f && onSelect(f)}
                            title={
                              c.unauthorized
                                ? `PRIVILEGE ESCALATION — ${c.title}`
                                : c.title
                            }
                            className={`rounded px-1.5 py-0.5 font-mono text-[11px] ${cls} ${
                              f ? 'cursor-pointer hover:brightness-125' : ''
                            }`}
                          >
                            {c.status}
                          </button>
                        </td>
                      );
                    })}
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
}
