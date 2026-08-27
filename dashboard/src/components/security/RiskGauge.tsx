import type { RiskLabel } from '@/lib/security-findings';

interface Props {
  score: number; // 0-100
  label: RiskLabel;
}

const RADIUS = 52;
const CIRCUMFERENCE = 2 * Math.PI * RADIUS;

const LABEL_COLOR: Record<RiskLabel, string> = {
  LOW: 'text-emerald-700',
  MEDIUM: 'text-amber-700',
  HIGH: 'text-orange-700',
  CRITICAL: 'text-red-700',
};

const STROKE_COLOR: Record<RiskLabel, string> = {
  LOW: '#15803d',
  MEDIUM: '#a16207',
  HIGH: '#c2410c',
  CRITICAL: '#991b1b',
};

export default function RiskGauge({ score, label }: Props) {
  const clamped = Math.max(0, Math.min(100, score));
  const offset = CIRCUMFERENCE - (clamped / 100) * CIRCUMFERENCE;

  return (
    <div className="flex flex-col items-center gap-3">
      <div className="relative w-[130px] h-[130px]">
        <svg width="130" height="130" viewBox="0 0 130 130" className="-rotate-90">
          <circle cx="65" cy="65" r={RADIUS} fill="none" stroke="#e2e8f0" strokeWidth="12" />
          <circle
            cx="65"
            cy="65"
            r={RADIUS}
            fill="none"
            stroke={STROKE_COLOR[label]}
            strokeWidth="12"
            strokeDasharray={CIRCUMFERENCE}
            strokeDashoffset={offset}
            strokeLinecap="round"
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-3xl font-semibold text-gray-100">{Math.round(clamped)}</span>
          <span className="text-xs text-gray-500">/ 100</span>
        </div>
      </div>
      <div className={`text-sm font-semibold tracking-wide ${LABEL_COLOR[label]}`}>
        OVERALL RISK: {label}
      </div>
    </div>
  );
}
