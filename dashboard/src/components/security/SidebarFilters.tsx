export type VerdictFilter = 'all' | 'confirmed' | 'unresolved';

interface Props {
  vulnClasses: string[];
  activeVulnClasses: string[];
  onToggleVulnClass: (vc: string) => void;
  verdictFilter: VerdictFilter;
  onVerdictFilterChange: (v: VerdictFilter) => void;
  needsReviewOnly: boolean;
  onNeedsReviewOnlyChange: (v: boolean) => void;
  search: string;
  onSearchChange: (v: string) => void;
  onClearFilters: () => void;
}

const VERDICT_OPTIONS: { value: VerdictFilter; label: string }[] = [
  { value: 'all', label: 'All' },
  { value: 'confirmed', label: 'Confirmed' },
  { value: 'unresolved', label: 'Needs triage' },
];

export default function SidebarFilters({
  vulnClasses,
  activeVulnClasses,
  onToggleVulnClass,
  verdictFilter,
  onVerdictFilterChange,
  needsReviewOnly,
  onNeedsReviewOnlyChange,
  search,
  onSearchChange,
  onClearFilters,
}: Props) {
  return (
    <aside className="w-full sm:w-64 shrink-0 bg-gray-900 border border-gray-800 rounded-lg p-4 flex flex-col gap-5 h-fit">
      <div className="flex items-center justify-between">
        <h2 className="text-sm font-semibold text-gray-100">Filters</h2>
        <button
          type="button"
          onClick={onClearFilters}
          className="text-xs text-gray-500 hover:text-gray-300"
        >
          Clear
        </button>
      </div>

      <div>
        <label className="block text-xs uppercase tracking-wide text-gray-500 mb-1.5">Search</label>
        <input
          type="text"
          value={search}
          onChange={(e) => onSearchChange(e.target.value)}
          placeholder="Title, endpoint…"
          className="w-full bg-gray-950 border border-gray-800 rounded px-2.5 py-1.5 text-sm text-gray-100 focus:outline-none focus:border-gray-600"
        />
      </div>

      <div>
        <label className="block text-xs uppercase tracking-wide text-gray-500 mb-1.5">Verdict</label>
        <div className="flex flex-col gap-1">
          {VERDICT_OPTIONS.map((opt) => (
            <button
              key={opt.value}
              type="button"
              onClick={() => onVerdictFilterChange(opt.value)}
              className={`text-left text-sm px-2 py-1 rounded ${
                verdictFilter === opt.value
                  ? 'bg-gray-800 text-gray-100'
                  : 'text-gray-400 hover:text-gray-200'
              }`}
            >
              {opt.label}
            </button>
          ))}
        </div>
      </div>

      <div>
        <label className="flex items-center gap-2 text-sm text-gray-300">
          <input
            type="checkbox"
            checked={needsReviewOnly}
            onChange={(e) => onNeedsReviewOnlyChange(e.target.checked)}
            className="accent-amber-500"
          />
          Flagged for scanner review
        </label>
      </div>

      <div>
        <label className="block text-xs uppercase tracking-wide text-gray-500 mb-1.5">Category</label>
        <div className="flex flex-col gap-1 max-h-64 overflow-y-auto">
          {vulnClasses.map((vc) => (
            <label key={vc} className="flex items-center gap-2 text-sm text-gray-300">
              <input
                type="checkbox"
                checked={activeVulnClasses.includes(vc)}
                onChange={() => onToggleVulnClass(vc)}
                className="accent-blue-500"
              />
              {vc}
            </label>
          ))}
        </div>
      </div>
    </aside>
  );
}
