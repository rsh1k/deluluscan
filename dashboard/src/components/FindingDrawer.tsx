import { useEffect, useState } from 'react';
import type { ScanFinding } from '@/lib/deluluscan-data';
import {
  EXPLOIT_LABEL,
  TRIAGE_STATUSES,
  VERDICT_LABEL,
  isConfirmed,
  isFalsePositive,
  sevMeta,
} from '@/lib/model';
import type { TriageEntry } from '@/lib/triage';
import { findingMemory, isRecurring, shortDate } from '@/lib/memory';
import { NotRecorded, Pill, SevTag } from '@/components/ui';
import EvidencePanel from '@/components/EvidencePanel';

type Tab = 'report' | 'evidence' | 'triage';

function Section({ n, title, children }: { n: number; title: string; children: React.ReactNode }) {
  return (
    <section className="border-t border-slate-800 py-4 first:border-t-0">
      <h4 className="mb-2 flex items-center gap-2 text-[13px] font-semibold text-slate-200">
        <span className="grid h-5 w-5 place-items-center rounded bg-slate-800 text-[10px] text-slate-400">
          {n}
        </span>
        {title}
      </h4>
      {children}
    </section>
  );
}

function Prose({ text }: { text: string }) {
  return <p className="text-[13px] leading-relaxed text-slate-300">{text}</p>;
}

function CodeBlock({ code }: { code: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="relative">
      <button
        type="button"
        onClick={() => {
          navigator.clipboard?.writeText(code);
          setCopied(true);
          setTimeout(() => setCopied(false), 1400);
        }}
        className="absolute right-2 top-2 rounded border border-slate-700 bg-slate-900 px-2 py-0.5
                   text-[10px] text-slate-400 hover:text-slate-200"
      >
        {copied ? 'Copied' : 'Copy'}
      </button>
      <pre className="overflow-x-auto rounded-lg border border-slate-800 bg-slate-950 p-3 pr-16
                      font-mono text-[11.5px] leading-relaxed text-slate-300">
        {code}
      </pre>
    </div>
  );
}

function ReportTab({ f }: { f: ScanFinding }) {
  const r = f.report ?? {};
  const loc = r.location ?? {};
  const m = sevMeta(f.severity);
  const mem = findingMemory(f);
  let n = 0;
  return (
    <div>
      <div className="mb-3 flex flex-wrap gap-1.5">
        <Pill color={m.color}>Severity · {m.label}</Pill>
        <Pill>Verdict · {VERDICT_LABEL[f.verdict] ?? 'Not verified'}</Pill>
        <Pill>Exploit · {EXPLOIT_LABEL[f.exploitability] ?? 'Unknown'}</Pill>
        {f.confidence && <Pill>Confidence · {f.confidence}</Pill>}
        {f.cwe && <Pill>{f.cwe}</Pill>}
        {f.owasp?.code && <Pill>OWASP {f.owasp.code}</Pill>}
        {mem && <Pill color={isRecurring(f) ? '#be123c' : undefined}>↻ {isRecurring(f) ? 'Recurring' : 'Seen before'}</Pill>}
      </div>

      {mem && (
        <div
          className={`mb-3 rounded-lg border p-3 text-[12.5px] leading-relaxed ${
            isRecurring(f)
              ? 'border-rose-200/60 bg-rose-500/10 text-rose-800'
              : 'border-slate-700 bg-slate-800/40 text-slate-300'
          }`}
        >
          <span className="font-semibold">Engagement memory — </span>
          {mem.note || 'Previously observed on this target.'}
          {(mem.first_seen || mem.seen_count) && (
            <span className="text-slate-400">
              {mem.first_seen ? ` First seen ${shortDate(mem.first_seen)}.` : ''}
              {mem.seen_count ? ` Observed on ${mem.seen_count} scan(s).` : ''}
              {mem.prior_exploitability
                ? ` Prior exploitability: ${EXPLOIT_LABEL[mem.prior_exploitability as ScanFinding['exploitability']] ?? mem.prior_exploitability}.`
                : ''}
            </span>
          )}
        </div>
      )}

      <Section n={++n} title="What was tested">
        {r.objective || f.description ? (
          <Prose text={r.objective || f.description} />
        ) : (
          <NotRecorded>No description was recorded for this finding.</NotRecorded>
        )}
      </Section>

      <Section n={++n} title="Where">
        {loc.endpoint || loc.code_paths?.length ? (
          <div className="space-y-1.5">
            {loc.endpoint && (
              <p className="font-mono text-[12.5px] text-slate-200">{loc.endpoint}</p>
            )}
            {loc.code_paths?.map((c) => (
              <p key={c} className="font-mono text-[11.5px] text-slate-400">
                {c}
              </p>
            ))}
          </div>
        ) : (
          <NotRecorded>No endpoint or source location recorded for this finding.</NotRecorded>
        )}
      </Section>

      <Section n={++n} title="How it was tested">
        {r.method ? (
          <Prose text={r.method} />
        ) : (
          <NotRecorded>
            Methodology not recorded — this finding was not produced by an
            evidence-capturing probe.
          </NotRecorded>
        )}
      </Section>

      {!!r.steps?.length && (
        <Section n={++n} title="Reproduction steps">
          <ol className="list-decimal space-y-1.5 pl-5 text-[13px] leading-relaxed text-slate-300">
            {r.steps.map((s, i) => (
              <li key={i}>{s}</li>
            ))}
          </ol>
        </Section>
      )}

      {!!r.reproduction?.length && (
        <Section n={++n} title="Reproduction commands">
          <div className="space-y-2">
            {r.reproduction.map((c, i) => (
              <CodeBlock key={i} code={c} />
            ))}
          </div>
        </Section>
      )}

      <Section n={++n} title="Outcome">
        {r.outcome ? (
          <div
            className={`rounded-lg border p-3 ${
              isConfirmed(f)
                ? 'border-rose-200/60 bg-rose-500/10'
                : isFalsePositive(f)
                  ? 'border-emerald-200/60 bg-emerald-500/10'
                  : 'border-slate-700 bg-slate-800/40'
            }`}
          >
            <Prose text={r.outcome} />
          </div>
        ) : (
          <NotRecorded>No outcome recorded. Re-test this finding to capture one.</NotRecorded>
        )}
      </Section>

      {r.impact && (
        <Section n={++n} title="Impact">
          <Prose text={r.impact} />
        </Section>
      )}
      {r.remediation && (
        <Section n={++n} title="Remediation">
          <div className="rounded-lg border border-sky-200/60 bg-sky-500/10 p-3">
            <Prose text={r.remediation} />
          </div>
        </Section>
      )}
    </div>
  );
}

function TriageTab({ f, entry, onSave }: {
  f: ScanFinding;
  entry: TriageEntry | undefined;
  onSave: (patch: Partial<TriageEntry>) => void;
}) {
  const [status, setStatus] = useState(entry?.status ?? '');
  const [assignee, setAssignee] = useState(entry?.assignee ?? '');
  const [notes, setNotes] = useState(entry?.notes ?? '');
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    setStatus(entry?.status ?? '');
    setAssignee(entry?.assignee ?? '');
    setNotes(entry?.notes ?? '');
  }, [f.id, entry?.status, entry?.assignee, entry?.notes]);

  return (
    <div className="space-y-4">
      <p className="rounded-lg border border-slate-700 bg-slate-800/40 p-3 text-[12.5px] leading-relaxed text-slate-400">
        Triage records what <em>you</em> decided. It never changes the finding's
        verdict — that is what the scan observed, and only a live re-test can move it.
      </p>

      <label className="block">
        <span className="mb-1 block text-[11px] uppercase tracking-wider text-slate-500">Status</span>
        <select
          value={status || TRIAGE_STATUSES[0]}
          onChange={(e) => setStatus(e.target.value)}
          className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-200"
        >
          {TRIAGE_STATUSES.map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
      </label>

      <label className="block">
        <span className="mb-1 block text-[11px] uppercase tracking-wider text-slate-500">Assignee</span>
        <input
          value={assignee}
          onChange={(e) => setAssignee(e.target.value)}
          placeholder="Unassigned"
          className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-200"
        />
      </label>

      <label className="block">
        <span className="mb-1 block text-[11px] uppercase tracking-wider text-slate-500">Notes</span>
        <textarea
          value={notes}
          onChange={(e) => setNotes(e.target.value)}
          rows={5}
          placeholder="Rationale, links, follow-up…"
          className="w-full resize-y rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-200"
        />
      </label>

      <div className="flex items-center gap-3">
        <button
          type="button"
          onClick={() => {
            onSave({ status: status || TRIAGE_STATUSES[0], assignee, notes });
            setSaved(true);
            setTimeout(() => setSaved(false), 1800);
          }}
          className="rounded-lg bg-indigo-600 px-4 py-2 text-sm font-semibold text-white hover:bg-indigo-500"
        >
          Save triage
        </button>
        {saved && <span className="text-xs text-emerald-700">Saved</span>}
        {entry?.updated && (
          <span className="text-xs text-slate-600">
            last updated {new Date(entry.updated).toLocaleString()}
          </span>
        )}
      </div>
    </div>
  );
}

export default function FindingDrawer({ finding, entry, onClose, onSave }: {
  finding: ScanFinding;
  entry: TriageEntry | undefined;
  onClose: () => void;
  onSave: (patch: Partial<TriageEntry>) => void;
}) {
  const [tab, setTab] = useState<Tab>('report');

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);

  const tabs: [Tab, string][] = [
    ['report', 'Report'],
    ['evidence', `Evidence${finding.evidence?.length ? ` (${finding.evidence.length})` : ''}`],
    ['triage', 'Triage'],
  ];

  return (
    <div className="fixed inset-0 z-40 flex justify-end" role="dialog" aria-modal="true">
      <button
        type="button"
        aria-label="Close"
        onClick={onClose}
        className="flex-1 bg-slate-500/40"
      />
      <div className="flex w-full max-w-3xl flex-col border-l border-slate-800 bg-slate-950 shadow-2xl">
        <header className="border-b border-slate-800 px-5 py-4">
          <div className="mb-2 flex items-start justify-between gap-3">
            <div className="min-w-0">
              <div className="mb-1.5 flex items-center gap-2">
                <SevTag severity={finding.severity} />
                <span className="font-mono text-[11px] text-slate-500">{finding.endpoint}</span>
              </div>
              <h2 className="text-[15px] font-semibold leading-snug text-slate-100">
                {finding.title}
              </h2>
            </div>
            <button
              type="button"
              onClick={onClose}
              className="shrink-0 rounded p-1 text-slate-500 hover:text-slate-200"
              aria-label="Close panel"
            >
              ✕
            </button>
          </div>
          <nav className="flex gap-1">
            {tabs.map(([t, label]) => (
              <button
                key={t}
                type="button"
                onClick={() => setTab(t)}
                className={`rounded-md px-3 py-1.5 text-[12.5px] font-medium transition ${
                  tab === t
                    ? 'bg-slate-800 text-slate-100'
                    : 'text-slate-500 hover:text-slate-300'
                }`}
              >
                {label}
              </button>
            ))}
          </nav>
        </header>

        <div className="flex-1 overflow-y-auto px-5 py-2">
          {tab === 'report' && <ReportTab f={finding} />}
          {tab === 'evidence' && (
            <div className="py-3">
              <EvidencePanel finding={finding} />
            </div>
          )}
          {tab === 'triage' && (
            <div className="py-3">
              <TriageTab f={finding} entry={entry} onSave={onSave} />
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
