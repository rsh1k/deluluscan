/**
 * Engagement-memory view helpers.
 *
 * The Python side (deluluscan/memory.py) writes two things the report surfaces:
 *   - per finding: detail.memory  — "we've seen this on this target before"
 *   - per scan:    meta.memory     — recall summary + regression-watch
 *
 * These are advisory context, never a verdict: a "recurring" tag says the same
 * endpoint was exploitable on a prior run, and a regression-watch entry says a
 * previously-exploitable endpoint did NOT reproduce this run (a POSSIBLE fix to
 * confirm manually) — it is deliberately not emitted as a finding, because the
 * report may only assert what THIS scan observed.
 */
import type { ScanFinding, ScanMeta } from '@/lib/deluluscan-data';

export interface FindingMemory {
  seen_before?: boolean;
  first_seen?: string;
  prior_verdict?: string;
  prior_exploitability?: string;
  seen_count?: number;
  note?: string;
}

export interface ScanMemory {
  enabled?: boolean;
  target_key?: string;
  recorded?: number;
  known_targets?: number;
  regression_watch?: string[];
  file?: string;
  error?: string;
}

function isObj(v: unknown): v is Record<string, unknown> {
  return !!v && typeof v === 'object';
}

/** The memory block a finding carries, or null when the finding is new/unseen. */
export function findingMemory(f: ScanFinding): FindingMemory | null {
  const m = isObj(f.detail) ? (f.detail as Record<string, unknown>).memory : null;
  if (!isObj(m) || !m.seen_before) return null;
  return m as FindingMemory;
}

/** True when this endpoint was exploitable on a prior scan and is still present. */
export function isRecurring(f: ScanFinding): boolean {
  const m = findingMemory(f);
  return !!m && (m.prior_exploitability === 'exploitable' || m.prior_exploitability === 'conditional');
}

/** The scan-level memory block, or null when memory was disabled/absent. */
export function scanMemory(meta: ScanMeta | undefined): ScanMemory | null {
  const m = meta && isObj((meta as Record<string, unknown>).memory)
    ? ((meta as Record<string, unknown>).memory as ScanMemory)
    : null;
  if (!m || m.enabled === false || m.error) return null;
  return m;
}

/** A short human date (YYYY-MM-DD) from an ISO stamp, for badges/tooltips. */
export function shortDate(iso?: string): string {
  return (iso || '').slice(0, 10);
}
