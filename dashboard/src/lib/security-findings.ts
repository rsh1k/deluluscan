import type { Finding, Severity } from '@/types/security';

// Mirrors security/deluluscan/deluluscan/dashboard.py's _CONFIRMED / _FALSE_P sets, so
// this dashboard's "confirmed" / "false positive" grouping matches deluluscan's
// own standalone HTML report.
export const CONFIRMED_VERDICTS = new Set(['true_positive', 'likely_true_positive']);
export const FALSE_POSITIVE_VERDICTS = new Set(['false_positive', 'likely_false_positive']);

export function isConfirmed(f: Finding): boolean {
  return CONFIRMED_VERDICTS.has(f.verdict);
}

export function isFalsePositive(f: Finding): boolean {
  return FALSE_POSITIVE_VERDICTS.has(f.verdict);
}

export const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

const SEVERITY_WEIGHT: Record<Severity, number> = {
  critical: 25,
  high: 12,
  medium: 5,
  low: 2,
  info: 0,
};

/* Light-surface severity steps — kept in lockstep with SEV_META in lib/model.ts
 * (same values, same rationale: >= 4.5:1 on #f8fafc, meaning carried by the
 * label rather than the hue). */
export const SEVERITY_COLOR: Record<Severity, string> = {
  critical: '#991b1b',
  high: '#c2410c',
  medium: '#a16207',
  low: '#2563eb',
  info: '#475569',
};

/** 0-100 posture score: weighted sum of confirmed findings by severity, capped. */
export function riskScore(findings: Finding[]): number {
  const score = findings
    .filter(isConfirmed)
    .reduce((sum, f) => sum + (SEVERITY_WEIGHT[f.severity] ?? 0), 0);
  return Math.min(100, score);
}

export type RiskLabel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export function riskLabel(score: number): RiskLabel {
  if (score >= 50) return 'CRITICAL';
  if (score >= 25) return 'HIGH';
  if (score >= 10) return 'MEDIUM';
  return 'LOW';
}

/** Severity breakdown, excluding false positives (matches the findings table's own filter). */
export function severityCounts(findings: Finding[]): Record<Severity, number> {
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) {
    if (!isFalsePositive(f)) counts[f.severity] = (counts[f.severity] ?? 0) + 1;
  }
  return counts;
}

export function countBy<T extends string>(findings: Finding[], key: (f: Finding) => T): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const f of findings) {
    const k = key(f);
    counts[k] = (counts[k] ?? 0) + 1;
  }
  return counts;
}
