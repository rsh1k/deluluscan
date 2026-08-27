/**
 * Behavioral & Telemetry view.
 *
 * Surfaces the grey-box observability channel (deluluscan/telemetry): what the target
 * actually DID — logs, memory/CPU — while the APIs were exercised on an
 * `--observe` run. Two parts:
 *   1. a summary of what the observability plane saw (meta.telemetry), and
 *   2. the findings that channel produced, grouped by how they were derived
 *      (server-log-confirmed injection, secrets in logs, unlogged operations,
 *      memory behaviour, exposed diagnostics surfaces).
 *
 * Renders nothing but an explainer when a scan was black-box (no telemetry), so
 * the tab is honest about what was and wasn't observed.
 */
import { useMemo } from 'react';
import type { Scan, ScanFinding } from '@/lib/deluluscan-data';
import { sevMeta } from '@/lib/model';
import { Empty } from '@/components/ui';

const TELEMETRY_CLASSES = new Set(['logging_failure', 'log_injection', 'memory_disclosure']);
const TELEMETRY_TESTS = new Set([
  'telemetry_trace', 'secret_in_logs', 'detection_gap', 'telemetry_oom',
  'telemetry_mem_growth', 'log_injection', 'memory_disclosure', 'resource_consumption',
]);

/** A finding that came from the observability channel (either tagged at source,
 *  a grey-box class, or one of the telemetry-derived tests). */
export function isTelemetryFinding(f: ScanFinding): boolean {
  const d = (f.detail ?? {}) as Record<string, unknown>;
  return (
    d.source === 'telemetry' ||
    TELEMETRY_CLASSES.has(f.vuln_class) ||
    TELEMETRY_TESTS.has(String(d.test ?? ''))
  );
}

const GROUPS: [string, string, (f: ScanFinding) => boolean][] = [
  ['Server-log–confirmed injection', 'A probe provoked a server stack trace (SQLi/SSTI/deser/…) in the log stream — confirmed by the target, not just inferred from the HTTP response.',
    (f) => (f.detail as Record<string, unknown>)?.test === 'telemetry_trace'],
  ['Secrets written to logs', 'Credentials / session material observed in the log stream (redacted here).',
    (f) => (f.detail as Record<string, unknown>)?.test === 'secret_in_logs'],
  ['Detection gaps (no audit trail)', 'Successful state-changing operations that produced no correlated log entry — invisible to defenders.',
    (f) => f.vuln_class === 'logging_failure'],
  ['Log injection / forging', 'Input with an embedded newline forged its own log line.',
    (f) => f.vuln_class === 'log_injection'],
  ['Memory & resource behaviour', 'Heap growth, OOM, or measured request-driven memory amplification during the scan.',
    (f) => (f.detail as Record<string, unknown>)?.test === 'telemetry_oom' ||
           (f.detail as Record<string, unknown>)?.test === 'telemetry_mem_growth' ||
           (f.detail as Record<string, unknown>)?.test === 'resource_consumption'],
  ['Exposed diagnostics / memory surfaces', 'Heap/thread dumps or diagnostics consoles reachable over HTTP.',
    (f) => f.vuln_class === 'memory_disclosure'],
];

function Tile({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900/60 px-3 py-2.5">
      <div className="text-[18px] font-semibold tabular-nums text-slate-100">{value}</div>
      <div className="text-[11px] text-slate-500">{label}</div>
    </div>
  );
}

function FindingRow({ f, onSelect }: { f: ScanFinding; onSelect: (f: ScanFinding) => void }) {
  const sm = sevMeta(f.severity);
  return (
    <button
      type="button"
      onClick={() => onSelect(f)}
      className="flex w-full items-start gap-3 rounded-md border border-slate-800 bg-slate-900/40 px-3 py-2 text-left hover:border-slate-600"
    >
      <span className="mt-0.5 inline-block h-2 w-2 shrink-0 rounded-full" style={{ background: sm.color }} />
      <span className="min-w-0">
        <span className="block truncate text-[12.5px] text-slate-200">{f.title}</span>
        <span className="block truncate font-mono text-[11px] text-slate-500">{f.endpoint}</span>
      </span>
      <span className="ml-auto shrink-0 text-[10.5px] uppercase tracking-wide text-slate-500">
        {f.verdict?.replace(/_/g, ' ')}
      </span>
    </button>
  );
}

export default function TelemetryView({
  scan,
  onSelect,
}: {
  scan: Scan;
  onSelect: (f: ScanFinding) => void;
}) {
  const t = scan.meta?.telemetry;
  const findings = useMemo(() => scan.findings.filter(isTelemetryFinding), [scan.findings]);

  if (!t && findings.length === 0) {
    return (
      <Empty
        title="No behavioral telemetry for this scan"
        sub="This was a black-box run. Re-scan with --observe to tap the target container's own logs and memory/CPU and correlate them with each probe."
      />
    );
  }

  return (
    <div className="space-y-5">
      <section>
        <h2 className="mb-1 text-[13px] font-semibold text-slate-200">Behavioral &amp; Telemetry</h2>
        <p className="mb-3 max-w-3xl text-[12px] leading-relaxed text-slate-400">
          Grey-box observability: what the target actually did — logs, memory, CPU — while the
          APIs were exercised, correlated with the exact probe that caused each event. Secrets in
          logs are redacted at capture; nothing here left the local host.
        </p>
        {t && (
          <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-6">
            <Tile label="telemetry events" value={(t.events ?? 0).toLocaleString()} />
            <Tile label="probe windows" value={(t.probe_windows ?? 0).toLocaleString()} />
            <Tile label="server exception lines" value={t.exception_lines ?? 0} />
            <Tile label="secret lines" value={t.secret_lines ?? 0} />
            <Tile label="findings" value={t.findings ?? findings.length} />
            <Tile
              label="sources"
              value={
                <span className="text-[12px] font-normal">
                  {Object.keys(t.by_source ?? {}).join(', ') || '—'}
                </span>
              }
            />
          </div>
        )}
      </section>

      {GROUPS.map(([title, blurb, pred]) => {
        const rows = findings.filter(pred);
        if (rows.length === 0) return null;
        return (
          <section key={title}>
            <h3 className="text-[12.5px] font-semibold text-slate-200">
              {title} <span className="text-slate-500">({rows.length})</span>
            </h3>
            <p className="mb-2 text-[11.5px] text-slate-500">{blurb}</p>
            <div className="space-y-1.5">
              {rows.map((f) => (
                <FindingRow key={f.id} f={f} onSelect={onSelect} />
              ))}
            </div>
          </section>
        );
      })}
    </div>
  );
}
