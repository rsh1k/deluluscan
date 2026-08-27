// Shapes mirror security/deluluscan/deluluscan/models.py's Finding.to_dict() output and
// security/ci_runner.py's snapshot, plus the triage overlay the dashboard's
// triage API writes. Kept intentionally loose (most fields optional/unknown)
// since this is scanner-produced JSON from a separate Python codebase, not
// data this app controls the shape of.

export type Verdict =
  | 'true_positive'
  | 'likely_true_positive'
  | 'inconclusive'
  | 'likely_false_positive'
  | 'false_positive'
  | 'unverified'
  | 'conditional';

export type Exploitability =
  | 'exploitable'
  | 'conditional'
  | 'mitigated'
  | 'not_exploitable'
  | 'unknown';

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface EvidenceRecord {
  method: string;
  url: string;
  identity: string;
  status: number;
  elapsed_ms: number;
  req_headers?: Record<string, string>;
  req_body?: string | null;
  resp_headers?: Record<string, string>;
  resp_body?: string;
  resp_len?: number;
  error?: string | null;
}

export interface Finding {
  id: string;
  vuln_class: string;
  severity: Severity;
  title: string;
  endpoint: string;
  description: string;
  evidence: EvidenceRecord[];
  detail: Record<string, unknown>;
  confidence: 'tentative' | 'firm' | 'confirmed';
  verdict: Verdict;
  exploitability: Exploitability;
  ai_notes: string;
  created_at: number;
  /** Set by security/ci_runner.py when a live recheck ran against this finding. */
  retest?: { verdict: string; reasons: string[]; repro: string };
  /** Set by security/ci_runner.py when the AI analyst's reasoning suggests a
   *  scanner artifact rather than genuine target behavior — needs a human to
   *  address via the interactive deluluscan-audit skill, never auto-resolved. */
  needs_scanner_review?: boolean;
}

export interface ScanSnapshot {
  scan_date: string;
  meta: Record<string, unknown>;
  findings: Finding[];
}

/** One finding's triage overlay, keyed by finding id in triage-state.json. */
export interface TriageEntry {
  status: 'new' | 'triaging' | 'confirmed' | 'dismissed' | 'resolved';
  assignee: string;
  updated_by: string;
  updated_at: string;
}

export type TriageState = Record<string, TriageEntry>;

export interface SecurityDashboardData {
  scan: ScanSnapshot;
  triage: TriageState;
  /** Blob sha of triage-state.json at fetch time — sent back with triage
   *  edits for optimistic-concurrency conflict detection. */
  triageSha: string | null;
}
