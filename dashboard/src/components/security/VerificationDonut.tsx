interface Segment {
  label: string;
  count: number;
  color: string;
}

interface Props {
  segments: Segment[];
}

const R = 42;
const CIRC = 2 * Math.PI * R;

export default function VerificationDonut({ segments }: Props) {
  const total = segments.reduce((s, seg) => s + seg.count, 0) || 1;

  // Precompute each segment's dash length + cumulative start offset without
  // mutating anything during render (React Compiler forbids reassigning a
  // captured variable inside a map callback).
  const arcs = segments
    .filter((seg) => seg.count > 0)
    .reduce<{ label: string; color: string; dash: number; offset: number }[]>((acc, seg) => {
      const dash = (seg.count / total) * CIRC;
      const prevOffset = acc.length > 0 ? acc[acc.length - 1].offset + acc[acc.length - 1].dash : 0;
      acc.push({ label: seg.label, color: seg.color, dash, offset: prevOffset });
      return acc;
    }, []);

  return (
    <div className="flex items-center gap-4">
      <svg width="104" height="104" viewBox="0 0 104 104" className="-rotate-90 shrink-0">
        <circle cx="52" cy="52" r={R} fill="none" stroke="#e2e8f0" strokeWidth="16" />
        {arcs.map((arc) => (
          <circle
            key={arc.label}
            cx="52"
            cy="52"
            r={R}
            fill="none"
            stroke={arc.color}
            strokeWidth="16"
            strokeDasharray={`${arc.dash} ${CIRC - arc.dash}`}
            strokeDashoffset={-arc.offset}
          />
        ))}
      </svg>
      <div className="flex flex-col gap-2">
        {segments.map((seg) => (
          <div key={seg.label} className="flex items-center gap-2 text-sm">
            <span className="w-2.5 h-2.5 rounded-full shrink-0" style={{ background: seg.color }} />
            <span className="text-gray-400">{seg.label}</span>
            <span className="text-gray-200 font-medium ml-auto pl-4">{seg.count}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
