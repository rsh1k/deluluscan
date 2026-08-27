import type { Finding, TriageState } from '@/types/security';
import { SEVERITY_COLOR } from '@/lib/security-findings';
import { IDENTITY_REFERENCE } from '@/lib/identity-reference';

interface Props {
  findings: Finding[];
  triage: TriageState;
  onSelect: (finding: Finding) => void;
  selectedId?: string;
}

const STATUS_LABEL: Record<string, string> = {
  new: 'New',
  triaging: 'Triaging',
  confirmed: 'Confirmed',
  dismissed: 'Dismissed',
  resolved: 'Resolved',
};

export default function FindingsTable({ findings, triage, onSelect, selectedId }: Props) {
  return (
    <div className="bg-gray-900 border border-gray-800 rounded-lg overflow-hidden overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="text-left text-xs uppercase tracking-wide text-gray-500 border-b border-gray-800">
            <th className="px-4 py-2.5 font-medium">Severity</th>
            <th className="px-4 py-2.5 font-medium">Finding</th>
            <th className="px-4 py-2.5 font-medium">Category</th>
            <th className="px-4 py-2.5 font-medium">Exploited as</th>
            <th className="px-4 py-2.5 font-medium">Exploitability</th>
            <th className="px-4 py-2.5 font-medium">Confidence</th>
            <th className="px-4 py-2.5 font-medium">Status</th>
          </tr>
        </thead>
        <tbody>
          {findings.map((f) => {
            const t = triage[f.id];
            const exploitedAs = Array.from(new Set(f.evidence.map((e) => e.identity)));
            return (
              <tr
                key={f.id}
                onClick={() => onSelect(f)}
                className={`border-b border-gray-800/60 cursor-pointer hover:bg-gray-800/40 ${
                  selectedId === f.id ? 'bg-gray-800/60' : ''
                }`}
              >
                <td className="px-4 py-2.5">
                  <span
                    className="inline-block px-2 py-0.5 rounded text-xs font-medium uppercase"
                    style={{
                      color: SEVERITY_COLOR[f.severity],
                      background: `${SEVERITY_COLOR[f.severity]}1a`,
                    }}
                  >
                    {f.severity}
                  </span>
                </td>
                <td className="px-4 py-2.5 max-w-md">
                  <div className="text-gray-100 truncate">{f.title}</div>
                  <div className="text-gray-500 text-xs truncate">{f.endpoint}</div>
                </td>
                <td className="px-4 py-2.5 text-gray-400">{f.vuln_class}</td>
                <td className="px-4 py-2.5">
                  <div className="flex flex-wrap gap-1">
                    {exploitedAs.length === 0 && <span className="text-gray-600">—</span>}
                    {exploitedAs.map((id) => (
                      <span
                        key={id}
                        title={IDENTITY_REFERENCE[id]?.productRoles.join(', ') || 'no target role'}
                        className="text-xs px-1.5 py-0.5 rounded bg-gray-800 text-gray-300"
                      >
                        {IDENTITY_REFERENCE[id]?.label ?? id}
                      </span>
                    ))}
                  </div>
                </td>
                <td className="px-4 py-2.5 text-gray-400">{f.exploitability}</td>
                <td className="px-4 py-2.5 text-gray-400">{f.confidence}</td>
                <td className="px-4 py-2.5">
                  <span className="text-gray-300">{STATUS_LABEL[t?.status ?? 'new']}</span>
                  {f.needs_scanner_review && (
                    <span className="ml-2 text-amber-700" title="Flagged for scanner review">
                      ⚑
                    </span>
                  )}
                </td>
              </tr>
            );
          })}
          {findings.length === 0 && (
            <tr>
              <td colSpan={7} className="px-4 py-8 text-center text-gray-500">
                No findings match the current filters.
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}
