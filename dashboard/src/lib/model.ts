/**
 * Derived model for the report views.
 *
 * The governing rule (CLAUDE.md): the report may only state what the scan
 * observed. Every narrative claim here is computed from scan data or omitted —
 * nothing is hand-authored. Two specific things this file must never reintroduce:
 *
 *   1. Synthesised evidence. If an identity was not probed, it has no record and
 *      the matrix shows it untested. status===0 means the request never completed
 *      (transport error, or a destructive op deferred by policy) and is NOT an
 *      observation of access.
 *   2. A hardcoded attack chain. The narrative comes from meta.escalation_pivot
 *      (measured: grant -> re-probe -> diff -> revert) or from ChainAnalyzer
 *      findings labelled as inferred, or it says nothing.
 */
import type { Scan, ScanFinding, EscalationPivot } from '@/lib/deluluscan-data';
import type { Severity } from '@/types/security';

export const CONFIRMED = new Set(['true_positive', 'likely_true_positive', 'confirmed']);
export const FALSE_POS = new Set(['false_positive', 'likely_false_positive']);

export const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

export interface SevMeta {
  label: string;
  color: string;
  bg: string;
  rank: number;
}

/* Severity is a STATUS palette (reserved states), not a categorical series and
 * not a single-hue ordinal ramp — so it is stepped for the light surface rather
 * than inverted, and every step is >= 4.5:1 against it (#f8fafc) because these
 * colors are used as label TEXT, not just as fills:
 *     critical 7.94:1 · high 4.95:1 · medium 4.71:1 · low 4.94:1 · info 7.24:1
 * Red/orange/amber sit close together under protanopia by construction; the
 * secondary encoding that carries the meaning is the always-present uppercase
 * label below (`label`), never the hue alone. */
export const SEV_META: Record<Severity, SevMeta> = {
  critical: { label: 'CRITICAL', color: '#991b1b', bg: 'rgba(153,27,27,.10)', rank: 4 },
  high: { label: 'HIGH', color: '#c2410c', bg: 'rgba(194,65,12,.10)', rank: 3 },
  medium: { label: 'MEDIUM', color: '#a16207', bg: 'rgba(161,98,7,.10)', rank: 2 },
  low: { label: 'LOW', color: '#2563eb', bg: 'rgba(37,99,235,.10)', rank: 1 },
  info: { label: 'INFO', color: '#475569', bg: 'rgba(71,85,105,.10)', rank: 0 },
};

export function sevMeta(s: string | undefined): SevMeta {
  return SEV_META[(s as Severity) ?? 'info'] ?? SEV_META.info;
}

export const OWASP_NAME: Record<string, string> = {
  A01: 'Broken Access Control',
  A02: 'Cryptographic Failures',
  A03: 'Injection',
  A04: 'Insecure Design',
  A05: 'Security Misconfiguration',
  A06: 'Vulnerable and Outdated Components',
  A07: 'Identification and Authentication Failures',
  A08: 'Software and Data Integrity Failures',
  A09: 'Logging and Monitoring Failures',
  A10: 'Server-Side Request Forgery',
};

export const VERDICT_LABEL: Record<string, string> = {
  true_positive: 'True Positive',
  confirmed: 'Confirmed',
  likely_true_positive: 'Likely TP',
  false_positive: 'False Positive',
  likely_false_positive: 'Likely FP',
  inconclusive: 'Inconclusive',
  not_tested: 'Not Tested',
  unverified: 'Not verified',
};

export const EXPLOIT_LABEL: Record<string, string> = {
  exploitable: 'Exploitable',
  conditional: 'Conditional',
  mitigated: 'Mitigated',
  not_exploitable: 'Not exploitable',
  unknown: 'Unknown',
};

export const CLOSED_STATUSES = new Set(['Dismissed', 'Not Applicable']);

export const TRIAGE_STATUSES = [
  'New',
  'In Progress',
  'Fixed',
  'Accepted Risk',
  'Not Applicable',
  'Dismissed',
] as const;

export function isConfirmed(f: ScanFinding): boolean {
  return CONFIRMED.has(f.verdict);
}
export function isFalsePositive(f: ScanFinding): boolean {
  return FALSE_POS.has(f.verdict);
}

/** A finding this engagement actually DEMONSTRATED could be exploited: a live
 *  re-test confirmed it AND the verification layer rated it `exploitable`.
 *
 *  This is deliberately narrower than `isConfirmed`. A great many findings are
 *  real observations that were never shown to be exploitable — a version-derived
 *  dependency advisory, a server exception correlated from the container log, a
 *  reflected parameter with no proven sink. Those are leads for the next pass,
 *  not vulnerabilities to report as such, and the pentest report renders only
 *  what cleared this bar. They are NOT discarded: the count of what was set
 *  aside is stated in the report (see `observedNotExploitable`) and every one of
 *  them remains in the Findings tab, so "excluded from the report" can never be
 *  misread as "the scan found nothing there". */
export function isExploitable(f: ScanFinding): boolean {
  return isConfirmed(f) && f.exploitability === 'exploitable';
}

const SEV_WEIGHT: Record<Severity, number> = {
  critical: 25,
  high: 12,
  medium: 5,
  low: 2,
  info: 0,
};

/** 0-100 posture score from CONFIRMED findings only — an unverified candidate
 *  must not inflate the headline number. */
export function riskScore(findings: ScanFinding[]): number {
  return Math.min(
    100,
    findings.filter(isConfirmed).reduce((n, f) => n + (SEV_WEIGHT[f.severity] ?? 0), 0)
  );
}

export function riskBand(score: number): { label: string; color: string; note: string } {
  if (score >= 70)
    return {
      label: 'CRITICAL',
      color: '#dc2626',
      note: 'Confirmed exploitable vulnerabilities. Immediate remediation required.',
    };
  if (score >= 50)
    return {
      label: 'HIGH',
      color: '#c2410c',
      note: 'High-risk findings present. Prioritise in the current sprint.',
    };
  if (score >= 30)
    return {
      label: 'ELEVATED',
      color: '#b45309',
      note: 'Moderate risk. Plan fixes and monitor closely.',
    };
  if (score > 0)
    return { label: 'MODERATE', color: '#0e7490', note: 'Limited confirmed exposure.' };
  return {
    label: 'LOW',
    color: '#15803d',
    note: 'No confirmed findings in view — see coverage before reading this as assurance.',
  };
}

// ---------------------------------------------------------------------------
// Identity model. `tier` is the privilege floor an identity satisfies, matching
// deluluscan/entitlements.py (0=public, 1=back-end, 3=admin).
// ---------------------------------------------------------------------------
export interface IdentityMeta {
  label: string;
  color: string;
  tier: number;
  role: string;
  entitledToAll?: boolean;
}

export const IDENTITY_META: Record<string, IdentityMeta> = {
  anonymous: {
    label: 'Anonymous',
    color: '#475569',
    tier: 0,
    role: 'Unauthenticated — no session',
  },
  frontend_user: {
    label: 'Front-end User',
    color: '#0e7490',
    tier: 0,
    role: 'Front-end User — logged in, NO back-end/API access',
  },
  backend: {
    label: 'Backend',
    color: '#7c3aed',
    tier: 1,
    role: 'Back-end User — baseline console/API, no content grants',
  },
  api_user: {
    label: 'API User',
    color: '#a16207',
    tier: 1,
    role: 'Back-end User — baseline (API-token auth)',
  },
  readonly: {
    label: 'Read-Only',
    color: '#2563eb',
    tier: 1,
    role: 'Back-end User + View Content (view only)',
  },
  content_editor: {
    label: 'Content Editor',
    color: '#0f766e',
    tier: 1,
    role: 'Back-end User + Edit Content',
  },
  publisher: {
    label: 'Publisher',
    color: '#a21caf',
    tier: 1,
    role: 'Back-end User + Edit + Publish Content',
  },
  admin: {
    label: 'Admin',
    color: '#4338ca',
    tier: 3,
    role: 'CMS Administrator — full access',
    entitledToAll: true,
  },
};

export const ID_ORDER = Object.keys(IDENTITY_META);

export function identityMeta(id: string): IdentityMeta {
  return (
    IDENTITY_META[id] ?? { label: id, color: '#475569', tier: 1, role: 'Unknown identity' }
  );
}

// ---------------------------------------------------------------------------
// Access matrix
// ---------------------------------------------------------------------------
export interface AccessCell {
  status: number;
  granted: boolean;
  unauthorized: boolean;
  confirmed: boolean;
  findingId: string;
  title: string;
}

export interface AccessRow {
  endpoint: string;
  reqTier: number;
  cells: Record<string, AccessCell>;
}

export function buildAccessMatrix(findings: ScanFinding[]): AccessRow[] {
  const rows: Record<string, AccessRow> = {};
  for (const f of findings) {
    const ev = f.evidence ?? [];
    if (!ev.length) continue;
    const confirmed = isConfirmed(f);
    const reqTier = typeof f.required_tier === 'number' ? f.required_tier : 1;
    const row = (rows[f.endpoint] ??= { endpoint: f.endpoint, reqTier, cells: {} });
    row.reqTier = Math.max(row.reqTier ?? 0, reqTier);
    for (const e of ev) {
      if (!e.identity || typeof e.status !== 'number') continue;
      // status 0 = never completed (transport error, or a destructive op the
      // policy deferred). Not an observation of access, so not "tested".
      if (e.status === 0) continue;
      const cur = row.cells[e.identity];
      if (!cur || (confirmed && !cur.confirmed)) {
        row.cells[e.identity] = {
          status: e.status,
          granted: e.status >= 200 && e.status < 300,
          unauthorized: false,
          confirmed,
          findingId: f.id,
          title: f.title,
        };
      }
    }
  }
  // A privilege violation only where the caller actually got in AND sits below
  // the tier the endpoint requires. Admin is entitled to everything, so admin
  // access is the authorized baseline, never a violation.
  for (const row of Object.values(rows)) {
    for (const [id, c] of Object.entries(row.cells)) {
      const m = identityMeta(id);
      c.unauthorized = c.granted && c.confirmed && !m.entitledToAll && m.tier < (row.reqTier ?? 0);
    }
  }
  return Object.values(rows);
}

export function accessSummary(rows: AccessRow[]) {
  const s: Record<string, { tested: number; granted: number; unauthorized: number }> = {};
  for (const row of rows) {
    for (const [id, c] of Object.entries(row.cells)) {
      const e = (s[id] ??= { tested: 0, granted: 0, unauthorized: 0 });
      e.tested++;
      if (c.granted) e.granted++;
      if (c.unauthorized) e.unauthorized++;
    }
  }
  return s;
}

// ---------------------------------------------------------------------------
// Report model
// ---------------------------------------------------------------------------
export interface Theme {
  code: string;
  name: string;
  count: number;
}

export interface ReportModel {
  scan: Scan;
  all: ScanFinding[];
  confirmed: ScanFinding[];
  /** The set the report details. Normally = confirmed AND demonstrated
   *  exploitable; when the scan carries meta.report_include it is exactly that
   *  curated set instead. */
  reportable: ScanFinding[];
  /** Recorded but NOT detailed in the report (leads, or curated out); counted
   *  and disclosed, never dropped. */
  observedNotExploitable: ScanFinding[];
  /** True when reportable came from an explicit curated include-list. */
  curated: boolean;
  /** Confirmed findings excluded from a curated report that are rated
   *  high/critical — surfaced so the report cannot imply a lower ceiling than
   *  the scan actually established. */
  excludedHigherSeverity: ScanFinding[];
  unresolved: ScanFinding[];
  excluded: ScanFinding[];
  crit: number;
  high: number;
  med: number;
  low: number;
  exploitable: number;
  pivot: EscalationPivot | null;
  chains: ScanFinding[];
  theme: Theme | null;
  statusOf: (f: ScanFinding) => string;
}

const bySeverity = (a: ScanFinding, b: ScanFinding) =>
  sevMeta(b.severity).rank - sevMeta(a.severity).rank;

export function buildReportModel(
  scan: Scan,
  statusOf: (f: ScanFinding) => string
): ReportModel {
  const all = scan.findings ?? [];
  const excluded = all.filter((f) => CLOSED_STATUSES.has(statusOf(f))).sort(bySeverity);
  const open = all.filter((f) => !CLOSED_STATUSES.has(statusOf(f)));
  const confirmed = open.filter(isConfirmed).sort(bySeverity);

  // Scope of the detailed report. Two modes:
  //   • Curated: the scan carries an explicit engagement-owner include-list, so
  //     the report details exactly those findings (any verdict/severity). This
  //     is a deliberate human selection, NOT a data verdict — every other
  //     finding keeps its true verdict and stays in the Findings view.
  //   • Default: the report details what was DEMONSTRATED exploitable.
  // Either way, whatever is set aside is counted and disclosed, never dropped.
  const includeIds = scan.meta?.report_include?.ids ?? null;
  const curated = !!includeIds && includeIds.length > 0;
  const inList = (f: ScanFinding) => !!includeIds && includeIds.includes(f.id);

  // Curated: preserve the engagement owner's listed order (so the auto-assigned
  // F-refs follow their M1/M2/… sequence within a severity band). Default:
  // severity-ranked.
  const reportable = curated
    ? open.filter(inList).sort((a, b) => includeIds!.indexOf(a.id) - includeIds!.indexOf(b.id))
    : confirmed.filter(isExploitable).sort(bySeverity);
  const reportableIds = new Set(reportable.map((f) => f.id));
  const observedNotExploitable = (curated
    ? open.filter((f) => !reportableIds.has(f.id) && isConfirmed(f))
    : confirmed.filter((f) => !isExploitable(f))
  ).sort(bySeverity);
  // In a curated report, a confirmed high/critical that was left out must not be
  // hidden — the exec summary calls it out so the report can't imply a lower
  // ceiling than the scan established.
  const excludedHigherSeverity = curated
    ? observedNotExploitable.filter((f) => f.severity === 'critical' || f.severity === 'high')
    : [];
  const unresolved = open.filter((f) => !isConfirmed(f) && !reportableIds.has(f.id)).sort(bySeverity);
  const n = (s: string) => reportable.filter((f) => f.severity === s).length;

  // Dominant category, only when the data actually supports one. This replaced a
  // fixed "broken function- and object-level authorization" sentence that was
  // emitted regardless of findings.
  let theme: Theme | null = null;
  if (reportable.length) {
    const tally: Record<string, number> = {};
    for (const f of reportable) {
      const code = f.owasp?.code;
      if (code) tally[code] = (tally[code] ?? 0) + 1;
    }
    const top = Object.entries(tally).sort((a, b) => b[1] - a[1])[0];
    if (top && top[1] > 1) theme = { code: top[0], name: OWASP_NAME[top[0]] ?? '', count: top[1] };
  }

  return {
    scan,
    all,
    confirmed,
    reportable,
    observedNotExploitable,
    curated,
    excludedHigherSeverity,
    unresolved,
    excluded,
    crit: n('critical'),
    high: n('high'),
    med: n('medium'),
    low: n('low'),
    exploitable: reportable.length,
    pivot: scan.meta?.escalation_pivot ?? null,
    chains: reportable.filter(
      (f) => (f.detail as Record<string, unknown>)?.test === 'exploit_chain' ||
        Boolean((f.detail as Record<string, unknown>)?.chain)
    ),
    theme,
    statusOf,
  };
}

export function refOf(confirmed: ScanFinding[], f: ScanFinding): string {
  const i = confirmed.indexOf(f);
  return i >= 0 ? `F-${String(i + 1).padStart(2, '0')}` : '—';
}

/** One-sentence chain claim for the executive summary, or '' when the scan
 *  established none. Measured beats inferred; inferred is labelled as such. */
export function chainSummary(m: ReportModel): string {
  const p = m.pivot;
  if (p?.performed && (p.capabilities_gained?.length ?? 0) > 0) {
    return (
      `An escalation was measured, not inferred: ${p.action ?? 'a confirmed privilege gain'} ` +
      `gave the "${p.identity ?? 'low-privilege'}" identity ${p.capabilities_gained!.length} ` +
      `capability/capabilities it could not previously reach, the most serious being ` +
      `${p.worst_impact_label ?? 'additional access'}.`
    );
  }
  if (p?.performed) {
    return (
      `A confirmed privilege gain (${p.action ?? ''}) was measured and unlocked none of the ` +
      `monitored high-value capabilities, so no escalation chain is claimed.`
    );
  }
  if (m.chains.length) {
    return (
      `${m.chains.length} exploit chain${m.chains.length === 1 ? ' was' : 's were'} inferred by ` +
      `correlating confirmed findings. These are reasoned from their constituents, not ` +
      `demonstrated end to end.`
    );
  }
  return '';
}

export function hasDestructivePass(scan: Scan): boolean {
  return (scan.meta?.destructive_pass?.probed?.length ?? 0) > 0;
}

export function fmtDate(d: string | undefined): string {
  if (!d) return '';
  const t = new Date(d);
  return Number.isNaN(t.getTime())
    ? d
    : t.toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });
}
