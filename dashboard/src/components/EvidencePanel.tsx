import { useState } from 'react';
import type { EvidenceRecord } from '@/types/security';
import type { ScanFinding } from '@/lib/deluluscan-data';
import { identityMeta } from '@/lib/model';
import { NotRecorded, StatusBadge } from '@/components/ui';

function prettyBody(b: string | null | undefined): string {
  if (!b) return '';
  try {
    return JSON.stringify(JSON.parse(b), null, 2);
  } catch {
    return b;
  }
}

function Headers({ h }: { h?: Record<string, string> }) {
  const entries = Object.entries(h ?? {});
  if (!entries.length) return null;
  return (
    <>
      {entries.map(([k, v]) => (
        <div key={k}>
          <span className="text-sky-700">{k}</span>
          <span className="text-slate-500">: </span>
          <span className="text-slate-300">{String(v)}</span>
        </div>
      ))}
    </>
  );
}

function Exchange({ rec, index }: { rec: EvidenceRecord; index: number }) {
  const path = (rec.url || '').replace(/^https?:\/\/[^/]+/, '');
  const host = (rec.url || '').match(/https?:\/\/([^/]+)/)?.[1] ?? '';
  const reqBody = prettyBody(rec.req_body);
  const respBody = prettyBody(rec.resp_body);
  return (
    <div className="overflow-hidden rounded-lg border border-slate-800">
      <div className="flex items-center gap-2 border-b border-slate-800 bg-slate-900 px-3 py-1.5 text-[11px]">
        <span className="text-slate-500">#{index + 1}</span>
        <span className="min-w-0 flex-1 truncate font-mono text-slate-300">
          {rec.method} {path}
        </span>
        {rec.elapsed_ms ? <span className="text-slate-500">{rec.elapsed_ms}ms</span> : null}
        <StatusBadge status={rec.status} />
      </div>

      {/* status 0 = the request never completed. Say which, and why — never render
          it as though a response came back. */}
      {rec.status === 0 && (
        <div className="border-b border-slate-800 bg-amber-500/10 px-3 py-2 text-[12px] text-amber-700">
          No response — this request did not complete.
          {rec.error ? <span className="text-amber-800/80"> {rec.error}</span> : null}
        </div>
      )}

      <div className="grid grid-cols-1 gap-px bg-slate-800 md:grid-cols-2">
        <div className="bg-slate-950 p-3">
          <p className="mb-1.5 text-[10px] font-semibold uppercase tracking-wider text-slate-600">
            Request
          </p>
          <pre className="overflow-x-auto whitespace-pre-wrap break-all font-mono text-[11px] leading-relaxed">
            <span className="text-emerald-700">
              {rec.method} {path} HTTP/1.1
            </span>
            {host && <span className="text-slate-400">{`\nHost: ${host}`}</span>}
            {'\n'}
            <Headers h={rec.req_headers} />
            {reqBody && (
              <>
                <span className="text-slate-700">{'\n────────────\n'}</span>
                <span className="text-slate-300">{reqBody}</span>
              </>
            )}
          </pre>
        </div>
        <div className="bg-slate-950 p-3">
          <p className="mb-1.5 text-[10px] font-semibold uppercase tracking-wider text-slate-600">
            Response
          </p>
          <pre className="overflow-x-auto whitespace-pre-wrap break-all font-mono text-[11px] leading-relaxed">
            {rec.status !== 0 && (
              <span className="text-violet-700">{`HTTP/1.1 ${rec.status}\n`}</span>
            )}
            <Headers h={rec.resp_headers} />
            {respBody && (
              <>
                <span className="text-slate-700">{'\n────────────\n'}</span>
                <span className="text-slate-300">{respBody}</span>
              </>
            )}
          </pre>
        </div>
      </div>
    </div>
  );
}

/**
 * The captured HTTP traffic behind a finding — and nothing else.
 *
 * Earlier builds synthesised records here when a finding had none (inventing an
 * admin 200, or guessing backend=200/anon=401 from the title), which made an
 * untested finding visually indistinguishable from a proven one. If there is no
 * traffic, this says so.
 */
export default function EvidencePanel({ finding }: { finding: ScanFinding }) {
  const ev = finding.evidence ?? [];
  const identities = Array.from(new Set(ev.map((e) => e.identity).filter(Boolean)));
  const [active, setActive] = useState<string | null>(identities[0] ?? null);

  if (!ev.length) {
    return (
      <div className="space-y-3">
        <div className="rounded-lg border border-slate-700 bg-slate-800/40 p-3">
          <NotRecorded>
            No HTTP traffic was captured for this finding, so nothing here demonstrates
            exploitability. Re-test it with <code className="text-slate-400">deluluscan.recheck</code> to
            capture some.
          </NotRecorded>
        </div>
      </div>
    );
  }

  const shown = active ?? identities[0];
  const forIdentity = ev.filter((e) => e.identity === shown);
  const statusByIdentity = identities.map((id) => ({
    id,
    status: ev.find((e) => e.identity === id)?.status ?? 0,
  }));
  const distinct = new Set(statusByIdentity.map((s) => s.status));

  return (
    <div className="space-y-3">
      {identities.length > 1 && (
        <div
          className={`rounded-lg border p-3 text-[12.5px] ${
            distinct.size === 1
              ? 'border-emerald-200/60 bg-emerald-500/10 text-emerald-700'
              : 'border-amber-200/60 bg-amber-500/10 text-amber-800'
          }`}
        >
          {distinct.size === 1
            ? `All ${identities.length} probed identities received HTTP ${
                statusByIdentity[0].status
              } — access control is consistent across these roles.`
            : `Responses differ across identities — ${statusByIdentity
                .map((s) => `${identityMeta(s.id).label}: ${s.status}`)
                .join(' · ')}.`}
        </div>
      )}

      {identities.length > 0 && (
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="mr-1 text-[11px] uppercase tracking-wider text-slate-600">View as</span>
          {identities.map((id) => {
            const m = identityMeta(id);
            const on = id === shown;
            return (
              <button
                key={id}
                type="button"
                onClick={() => setActive(id)}
                title={m.role}
                className={`rounded-full border px-2.5 py-1 text-[11px] transition ${
                  on ? 'border-transparent font-semibold' : 'border-slate-700 text-slate-400'
                }`}
                style={on ? { background: `${m.color}22`, color: m.color } : undefined}
              >
                {m.label}
              </button>
            );
          })}
        </div>
      )}

      <div className="space-y-3">
        {forIdentity.map((rec, i) => (
          <Exchange key={i} rec={rec} index={i} />
        ))}
        {!forIdentity.length && (
          <NotRecorded>No requests recorded for this identity.</NotRecorded>
        )}
      </div>
    </div>
  );
}
