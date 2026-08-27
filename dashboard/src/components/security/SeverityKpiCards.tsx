import type { Severity } from '@/types/security';
import { SEVERITY_ORDER, SEVERITY_COLOR } from '@/lib/security-findings';

interface Props {
  counts: Record<Severity, number>;
  active: Severity[];
  onToggle: (sev: Severity) => void;
}

const SUB_LABEL: Record<Severity, string> = {
  critical: 'immediate action',
  high: 'action needed',
  medium: 'plan a fix',
  low: 'low priority',
  info: 'informational',
};

export default function SeverityKpiCards({ counts, active, onToggle }: Props) {
  return (
    <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
      {SEVERITY_ORDER.map((sev) => {
        const isActive = active.includes(sev);
        return (
          <button
            key={sev}
            type="button"
            onClick={() => onToggle(sev)}
            className={`text-left bg-gray-900 border rounded-lg px-4 py-3 transition-colors ${
              isActive ? 'border-gray-500' : 'border-gray-800 hover:border-gray-700'
            }`}
          >
            <div className="flex items-center justify-between">
              <span
                className="text-xs font-medium uppercase tracking-wide"
                style={{ color: SEVERITY_COLOR[sev] }}
              >
                {sev}
              </span>
              <span className="w-2 h-2 rounded-full" style={{ background: SEVERITY_COLOR[sev] }} />
            </div>
            <div className="text-2xl font-semibold text-gray-100 mt-1">{counts[sev] ?? 0}</div>
            <div className="text-xs text-gray-500 mt-0.5">{SUB_LABEL[sev]}</div>
          </button>
        );
      })}
    </div>
  );
}
