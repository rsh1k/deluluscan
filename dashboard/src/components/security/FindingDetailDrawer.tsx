import { useState } from 'react';
import type { Finding, TriageEntry } from '@/types/security';
import { SEVERITY_COLOR } from '@/lib/security-findings';
import { IDENTITY_REFERENCE } from '@/lib/identity-reference';

interface Props {
  finding: Finding;
  triageEntry: TriageEntry | undefined;
  onClose: () => void;
  onUpdateTriage: (findingId: string, patch: { status?: TriageEntry['status']; assignee?: string }) => void;
}

const STATUS_OPTIONS: TriageEntry['status'][] = ['new', 'triaging', 'confirmed', 'dismissed', 'resolved'];

export default function FindingDetailDrawer({ finding, triageEntry, onClose, onUpdateTriage }: Props) {
  const identities = Array.from(new Set(finding.evidence.map((e) => e.identity)));
  const [activeIdentity, setActiveIdentity] = useState<string | null>(identities[0] ?? null);
  const [assignee, setAssignee] = useState(triageEntry?.assignee ?? '');

  const shownEvidence = activeIdentity
    ? finding.evidence.filter((e) => e.identity === activeIdentity)
    : finding.evidence;

  return (
    <div className="fixed inset-0 z-50 flex justify-end">
      <div className="absolute inset-0 bg-slate-500/40" onClick={onClose} />
      <div className="relative w-full max-w-xl h-full bg-gray-950 border-l border-gray-800 overflow-y-auto p-6">
        <div className="flex items-start justify-between gap-4">
          <div>
            <span
              className="inline-block px-2 py-0.5 rounded text-xs font-medium uppercase mb-2"
              style={{
                color: SEVERITY_COLOR[finding.severity],
                background: `${SEVERITY_COLOR[finding.severity]}1a`,
              }}
            >
              {finding.severity}
            </span>
            <h2 className="text-lg font-semibold text-gray-100">{finding.title}</h2>
            <p className="text-sm text-gray-500 mt-0.5">{finding.endpoint}</p>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="text-gray-500 hover:text-gray-200 text-xl leading-none"
            aria-label="Close"
          >
            ×
          </button>
        </div>

        <div className="flex flex-wrap gap-2 mt-4 text-xs">
          <span className="px-2 py-1 rounded bg-gray-900 border border-gray-800 text-gray-300">
            {finding.vuln_class}
          </span>
          <span className="px-2 py-1 rounded bg-gray-900 border border-gray-800 text-gray-300">
            verdict: {finding.verdict}
          </span>
          <span className="px-2 py-1 rounded bg-gray-900 border border-gray-800 text-gray-300">
            exploitability: {finding.exploitability}
          </span>
          <span className="px-2 py-1 rounded bg-gray-900 border border-gray-800 text-gray-300">
            confidence: {finding.confidence}
          </span>
        </div>

        {finding.needs_scanner_review && (
          <div className="mt-4 bg-amber-900/20 border border-amber-200 rounded px-3 py-2 text-sm text-amber-800">
            ⚑ Flagged for scanner review — the AI adjudication reasoning suggests this may be a
            scanner artifact. Confirm with the interactive deluluscan-audit skill before treating it as
            resolved.
          </div>
        )}

        <section className="mt-5">
          <h3 className="text-xs uppercase tracking-wide text-gray-500 mb-1.5">Description</h3>
          <p className="text-sm text-gray-300 whitespace-pre-wrap">{finding.description}</p>
        </section>

        {finding.ai_notes && (
          <section className="mt-5">
            <h3 className="text-xs uppercase tracking-wide text-gray-500 mb-1.5">AI adjudication notes</h3>
            <p className="text-sm text-gray-300 whitespace-pre-wrap">{finding.ai_notes}</p>
          </section>
        )}

        {finding.retest && (
          <section className="mt-5">
            <h3 className="text-xs uppercase tracking-wide text-gray-500 mb-1.5">Live retest</h3>
            <p className="text-sm text-gray-300">verdict: {finding.retest.verdict}</p>
            {finding.retest.repro && (
              <p className="text-sm text-gray-400 mt-1 whitespace-pre-wrap">{finding.retest.repro}</p>
            )}
          </section>
        )}

        <section className="mt-6 border-t border-gray-800 pt-5">
          <h3 className="text-xs uppercase tracking-wide text-gray-500 mb-2">Triage</h3>
          <div className="flex flex-col gap-3">
            <div className="flex gap-2 flex-wrap">
              {STATUS_OPTIONS.map((status) => (
                <button
                  key={status}
                  type="button"
                  onClick={() => onUpdateTriage(finding.id, { status })}
                  className={`text-xs px-2.5 py-1 rounded border ${
                    (triageEntry?.status ?? 'new') === status
                      ? 'bg-gray-100 text-gray-900 border-gray-100'
                      : 'text-gray-300 border-gray-700 hover:border-gray-500'
                  }`}
                >
                  {status}
                </button>
              ))}
            </div>
            <div>
              <label className="block text-xs text-gray-500 mb-1">Assignee</label>
              <div className="flex gap-2">
                <input
                  type="text"
                  value={assignee}
                  onChange={(e) => setAssignee(e.target.value)}
                  placeholder="name@example.com"
                  className="flex-1 bg-gray-900 border border-gray-800 rounded px-2.5 py-1.5 text-sm text-gray-100 focus:outline-none focus:border-gray-600"
                />
                <button
                  type="button"
                  onClick={() => onUpdateTriage(finding.id, { assignee })}
                  className="text-xs px-3 py-1.5 rounded bg-gray-800 text-gray-200 hover:bg-gray-700"
                >
                  Save
                </button>
              </div>
            </div>
            {triageEntry?.updated_by && (
              <p className="text-xs text-gray-600">
                Last updated by {triageEntry.updated_by} at{' '}
                {new Date(triageEntry.updated_at).toLocaleString()}
              </p>
            )}
          </div>
        </section>

        <section className="mt-6 border-t border-gray-800 pt-5">
          <div className="flex items-center justify-between mb-2">
            <h3 className="text-xs uppercase tracking-wide text-gray-500">Evidence</h3>
            {identities.length > 1 && (
              <div className="flex gap-1">
                {identities.map((id) => (
                  <button
                    key={id}
                    type="button"
                    onClick={() => setActiveIdentity(id)}
                    className={`text-xs px-2 py-0.5 rounded ${
                      activeIdentity === id ? 'bg-gray-800 text-gray-100' : 'text-gray-500 hover:text-gray-300'
                    }`}
                  >
                    {IDENTITY_REFERENCE[id]?.label ?? id}
                  </button>
                ))}
              </div>
            )}
          </div>
          <div className="flex flex-col gap-3">
            {shownEvidence.map((ev, i) => {
              const idInfo = IDENTITY_REFERENCE[ev.identity];
              return (
              <div key={i} className="bg-gray-900 border border-gray-800 rounded p-3 text-xs font-mono">
                <div className="text-gray-300 mb-1">
                  {ev.method} {ev.url}
                </div>
                <div className="text-gray-500 mb-1">
                  identity: <span className="text-gray-300">{ev.identity}</span>
                  {idInfo && (
                    <span className="text-gray-600">
                      {' '}({idInfo.productRoles.length ? idInfo.productRoles.join(', ') : 'no target role'})
                    </span>
                  )}
                  {' '}· status: {ev.status} · {ev.elapsed_ms.toFixed(1)}ms
                </div>
                {idInfo?.notes && (
                  <div className="text-amber-700/80 mb-2 font-sans">⚠ {idInfo.notes}</div>
                )}
                {ev.resp_body && (
                  <pre className="text-gray-400 whitespace-pre-wrap break-all max-h-40 overflow-y-auto">
                    {ev.resp_body.slice(0, 800)}
                  </pre>
                )}
              </div>
              );
            })}
            {shownEvidence.length === 0 && <p className="text-sm text-gray-600">No evidence recorded.</p>}
          </div>
        </section>
      </div>
    </div>
  );
}
