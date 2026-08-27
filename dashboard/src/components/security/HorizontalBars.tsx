interface Bar {
  label: string;
  count: number;
}

interface Props {
  title: string;
  bars: Bar[];
  color?: string;
}

/** Shared by the exploitability and category breakdowns in SecurityDashboard. */
export default function HorizontalBars({ title, bars, color = '#2563eb' }: Props) {
  const max = Math.max(1, ...bars.map((b) => b.count));
  return (
    <div>
      <h3 className="text-xs uppercase tracking-wide text-gray-500 mb-3">{title}</h3>
      <div className="flex flex-col gap-2.5">
        {bars.map((b) => (
          <div key={b.label} className="flex items-center gap-2 text-sm">
            <span className="w-28 shrink-0 text-gray-400 truncate">{b.label}</span>
            <div className="flex-1 h-2 bg-gray-800 rounded-full overflow-hidden">
              <div
                className="h-full rounded-full"
                style={{ width: `${(b.count / max) * 100}%`, background: color }}
              />
            </div>
            <span className="w-6 text-right text-gray-300 text-xs">{b.count}</span>
          </div>
        ))}
        {bars.length === 0 && <p className="text-sm text-gray-600">No data</p>}
      </div>
    </div>
  );
}
