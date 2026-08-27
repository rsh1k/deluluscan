import type { ReactNode } from 'react';
import { sevMeta } from '@/lib/model';

export function Card({ title, children, className = '', action }: {
  title?: string;
  children: ReactNode;
  className?: string;
  action?: ReactNode;
}) {
  return (
    <section className={`rounded-xl border border-slate-800 bg-slate-900/60 p-4 ${className}`}>
      {(title || action) && (
        <header className="mb-3 flex items-center justify-between gap-2">
          {title && (
            <h3 className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">
              {title}
            </h3>
          )}
          {action}
        </header>
      )}
      {children}
    </section>
  );
}

export function SevTag({ severity }: { severity: string }) {
  const m = sevMeta(severity);
  return (
    <span
      className="inline-block rounded px-1.5 py-0.5 text-[10px] font-bold tracking-wide"
      style={{ color: m.color, background: m.bg }}
    >
      {m.label}
    </span>
  );
}

export function Pill({ children, color, title }: {
  children: ReactNode;
  color?: string;
  title?: string;
}) {
  return (
    <span
      title={title}
      className="inline-block rounded-full border border-slate-700 px-2 py-0.5 text-[11px] text-slate-300"
      style={color ? { color, borderColor: `${color}55` } : undefined}
    >
      {children}
    </span>
  );
}

const STATUS_COLOR = (n: number) =>
  n >= 500 ? '#991b1b' : n >= 400 ? '#a16207' : n >= 300 ? '#7c3aed' : n >= 200 ? '#15803d' : '#475569';

export function StatusBadge({ status }: { status: number }) {
  const c = STATUS_COLOR(status);
  return (
    <span
      className="inline-block rounded px-1.5 py-0.5 font-mono text-[11px] font-semibold"
      style={{ color: c, background: `${c}1f` }}
    >
      {status === 0 ? '—' : status}
    </span>
  );
}

/** An explicit statement that something was not measured. The report must never
 *  render an empty panel where a reader could infer a clean result. */
export function NotRecorded({ children }: { children: ReactNode }) {
  return <p className="text-[13px] italic leading-relaxed text-slate-500">{children}</p>;
}

export function Empty({ title, sub }: { title: string; sub?: string }) {
  return (
    <div className="px-4 py-12 text-center">
      <p className="text-sm font-medium text-slate-400">{title}</p>
      {sub && <p className="mt-1 text-xs text-slate-600">{sub}</p>}
    </div>
  );
}
