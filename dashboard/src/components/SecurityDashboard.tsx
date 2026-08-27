import { useCallback, useMemo, useState } from 'react';
import type { Finding, Severity, SecurityDashboardData, TriageEntry, TriageState } from '@/types/security';
import {
  isFalsePositive,
  isConfirmed,
  riskScore,
  riskLabel,
  severityCounts,
  countBy,
  SEVERITY_COLOR,
} from '@/lib/security-findings';
import RiskGauge from '@/components/security/RiskGauge';
import SeverityKpiCards from '@/components/security/SeverityKpiCards';
import VerificationDonut from '@/components/security/VerificationDonut';
import HorizontalBars from '@/components/security/HorizontalBars';
import SidebarFilters, { type VerdictFilter } from '@/components/security/SidebarFilters';
import FindingsTable from '@/components/security/FindingsTable';
import FindingDetailDrawer from '@/components/security/FindingDetailDrawer';
import IdentityReferencePanel from '@/components/security/IdentityReferencePanel';

export default function SecurityDashboard({ initialData }: { initialData: SecurityDashboardData }) {
  const allFindings = initialData.scan.findings;

  const [triage, setTriage] = useState<TriageState>(initialData.triage);
  const [activeSeverities, setActiveSeverities] = useState<Severity[]>([]);
  const [activeVulnClasses, setActiveVulnClasses] = useState<string[]>([]);
  const [verdictFilter, setVerdictFilter] = useState<VerdictFilter>('all');
  const [needsReviewOnly, setNeedsReviewOnly] = useState(false);
  const [search, setSearch] = useState('');
  const [showIdentityReference, setShowIdentityReference] = useState(false);
  const [selectedId, setSelectedId] = useState<string | null>(null);

  // Findings visible in the table exclude false positives entirely (matching
  // deluluscan/dashboard.py's own behavior) — they're still counted in the
  // verification donut below, just not listed as actionable rows.
  const nonFalsePositive = useMemo(() => allFindings.filter((f) => !isFalsePositive(f)), [allFindings]);

  const vulnClasses = useMemo(
    () => Array.from(new Set(allFindings.map((f) => f.vuln_class))).sort(),
    [allFindings]
  );

  const filteredFindings = useMemo(() => {
    const q = search.trim().toLowerCase();
    return nonFalsePositive.filter((f) => {
      if (activeSeverities.length > 0 && !activeSeverities.includes(f.severity)) return false;
      if (activeVulnClasses.length > 0 && !activeVulnClasses.includes(f.vuln_class)) return false;
      if (verdictFilter === 'confirmed' && !isConfirmed(f)) return false;
      if (verdictFilter === 'unresolved' && isConfirmed(f)) return false;
      if (needsReviewOnly && !f.needs_scanner_review) return false;
      if (q && !`${f.title} ${f.endpoint} ${f.description}`.toLowerCase().includes(q)) return false;
      return true;
    });
  }, [nonFalsePositive, activeSeverities, activeVulnClasses, verdictFilter, needsReviewOnly, search]);

  const kpiCounts = useMemo(() => severityCounts(allFindings), [allFindings]);
  const score = useMemo(() => riskScore(allFindings), [allFindings]);
  const label = riskLabel(score);

  const donutSegments = useMemo(() => {
    const confirmed = allFindings.filter(isConfirmed).length;
    const falsePositive = allFindings.filter(isFalsePositive).length;
    const other = allFindings.length - confirmed - falsePositive;
    return [
      { label: 'Confirmed', count: confirmed, color: '#991b1b' },
      { label: 'False positive', count: falsePositive, color: '#15803d' },
      { label: 'Needs triage', count: other, color: '#475569' },
    ];
  }, [allFindings]);

  const exploitabilityBars = useMemo(() => {
    const counts = countBy(nonFalsePositive, (f) => f.exploitability);
    return Object.entries(counts).map(([label, count]) => ({ label, count }));
  }, [nonFalsePositive]);

  const categoryBars = useMemo(() => {
    const counts = countBy(nonFalsePositive, (f) => f.vuln_class);
    return Object.entries(counts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 8)
      .map(([label, count]) => ({ label, count }));
  }, [nonFalsePositive]);

  const toggleSeverity = useCallback((sev: Severity) => {
    setActiveSeverities((prev) => (prev.includes(sev) ? prev.filter((s) => s !== sev) : [...prev, sev]));
  }, []);

  const toggleVulnClass = useCallback((vc: string) => {
    setActiveVulnClasses((prev) => (prev.includes(vc) ? prev.filter((v) => v !== vc) : [...prev, vc]));
  }, []);

  const clearFilters = useCallback(() => {
    setActiveSeverities([]);
    setActiveVulnClasses([]);
    setVerdictFilter('all');
    setNeedsReviewOnly(false);
    setSearch('');
  }, []);

  // Optimistic triage update: apply locally immediately, persist via the
  // triage API (which commits to triage-state.json on the security-data
  // branch — here, a local dev-only file, see vite.config.ts), revert on
  // failure — same pattern as the real target-aios dashboard.
  const updateTriage = useCallback(
    async (findingId: string, patch: { status?: TriageEntry['status']; assignee?: string }) => {
      const prevTriage = triage;
      const prevEntry = prevTriage[findingId];
      const optimisticEntry: TriageEntry = {
        status: patch.status ?? prevEntry?.status ?? 'new',
        assignee: patch.assignee ?? prevEntry?.assignee ?? '',
        updated_by: prevEntry?.updated_by ?? '',
        updated_at: prevEntry?.updated_at ?? '',
      };
      setTriage((prev) => ({ ...prev, [findingId]: optimisticEntry }));

      try {
        const res = await fetch('/api/security/triage', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            finding_id: findingId,
            status: optimisticEntry.status,
            assignee: optimisticEntry.assignee,
          }),
        });
        if (!res.ok) throw new Error('triage update failed');
        const body = (await res.json()) as { entry: TriageEntry };
        setTriage((prev) => ({ ...prev, [findingId]: body.entry }));
      } catch {
        setTriage(prevTriage);
      }
    },
    [triage]
  );

  const selectedFinding: Finding | null = selectedId
    ? allFindings.find((f) => f.id === selectedId) ?? null
    : null;

  return (
    <div className="min-h-screen bg-gray-950 text-gray-100 p-6">
      <header className="mb-6 flex items-start justify-between gap-4">
        <div>
          <div className="flex items-center gap-3 mb-1">
            <img src="/logo-dark.svg" alt="the target" className="h-5 w-auto" />
            <h1 className="text-xl font-semibold">Security dashboard</h1>
          </div>
          <p className="text-sm text-gray-500">
            Last scan: {initialData.scan.scan_date} · {allFindings.length} findings
          </p>
        </div>
        <button
          type="button"
          onClick={() => setShowIdentityReference(true)}
          className="shrink-0 text-xs px-3 py-1.5 rounded border border-gray-700 text-gray-300 hover:border-gray-500 hover:text-gray-100"
        >
          Test identities &amp; roles
        </button>
      </header>

      <div className="grid grid-cols-1 xl:grid-cols-[280px_1fr] gap-4 mb-6">
        <div className="bg-gray-900 border border-gray-800 rounded-lg p-4 flex items-center justify-center">
          <RiskGauge score={score} label={label} />
        </div>
        <SeverityKpiCards counts={kpiCounts} active={activeSeverities} onToggle={toggleSeverity} />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 mb-6">
        <div className="bg-gray-900 border border-gray-800 rounded-lg p-4">
          <h3 className="text-xs uppercase tracking-wide text-gray-500 mb-3">Verification</h3>
          <VerificationDonut segments={donutSegments} />
        </div>
        <div className="bg-gray-900 border border-gray-800 rounded-lg p-4">
          <HorizontalBars title="Exploitability" bars={exploitabilityBars} color={SEVERITY_COLOR.high} />
        </div>
        <div className="bg-gray-900 border border-gray-800 rounded-lg p-4">
          <HorizontalBars title="Category" bars={categoryBars} color={SEVERITY_COLOR.low} />
        </div>
      </div>

      <div className="flex flex-col sm:flex-row gap-4">
        <SidebarFilters
          vulnClasses={vulnClasses}
          activeVulnClasses={activeVulnClasses}
          onToggleVulnClass={toggleVulnClass}
          verdictFilter={verdictFilter}
          onVerdictFilterChange={setVerdictFilter}
          needsReviewOnly={needsReviewOnly}
          onNeedsReviewOnlyChange={setNeedsReviewOnly}
          search={search}
          onSearchChange={setSearch}
          onClearFilters={clearFilters}
        />
        <div className="flex-1 min-w-0">
          <FindingsTable
            findings={filteredFindings}
            triage={triage}
            onSelect={(f) => setSelectedId(f.id)}
            selectedId={selectedId ?? undefined}
          />
        </div>
      </div>

      {selectedFinding && (
        <FindingDetailDrawer
          finding={selectedFinding}
          triageEntry={triage[selectedFinding.id]}
          onClose={() => setSelectedId(null)}
          onUpdateTriage={updateTriage}
        />
      )}

      {showIdentityReference && (
        <IdentityReferencePanel onClose={() => setShowIdentityReference(false)} />
      )}
    </div>
  );
}
