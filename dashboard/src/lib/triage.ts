/**
 * Triage overlay persistence.
 *
 * The report ships as a static file (GitHub Pages, or opened from disk), so there
 * is no server to POST to — triage lives in localStorage, keyed per scan so
 * re-running a scan does not inherit stale decisions from a different run.
 *
 * Triage NEVER edits a finding's verdict. A verdict is what the scan observed; a
 * status is what a human decided to do about it. Keeping them separate is why
 * "Dismissed" can hide a finding from the active counts without rewriting the
 * evidence that produced it.
 */
export interface TriageEntry {
  status: string;
  assignee: string;
  notes: string;
  confirmed?: boolean;
  updated: string;
}

export type TriageMap = Record<string, TriageEntry>;

const KEY = 'deluluscan.triage.v2';

type Store = Record<string, TriageMap>;

function readStore(): Store {
  try {
    const raw = localStorage.getItem(KEY);
    return raw ? (JSON.parse(raw) as Store) : {};
  } catch {
    return {};
  }
}

export function loadTriage(scanId: string): TriageMap {
  return readStore()[scanId] ?? {};
}

export function saveTriage(scanId: string, map: TriageMap): void {
  try {
    const store = readStore();
    store[scanId] = map;
    localStorage.setItem(KEY, JSON.stringify(store));
  } catch {
    /* private mode / quota — the UI still works for this session */
  }
}

export function defaultStatus(verdict: string): string {
  if (verdict === 'false_positive' || verdict === 'likely_false_positive') return 'Dismissed';
  return 'New';
}

/** Effective status: the human's decision if there is one, else derived from the
 *  scan's own verdict. */
export function statusOf(
  triage: TriageMap,
  id: string,
  verdict: string
): string {
  return triage[id]?.status ?? defaultStatus(verdict);
}
