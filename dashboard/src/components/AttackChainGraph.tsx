import { useMemo } from 'react';
import type { Scan, ScanFinding } from '@/lib/deluluscan-data';
import { sevMeta } from '@/lib/model';
import { Card, Empty, SevTag } from '@/components/ui';

/** A correlated attack chain: constituent findings that combine into an objective.
 *  Produced by deluluscan/correlate (detail.source === 'correlate'). */
interface ChainMember {
  title: string;
  endpoint: string;
  vuln_class: string;
}
interface Chain {
  id: string;
  name: string;
  objective: string;
  severity: string;
  remediation: string;
  members: ChainMember[];
  finding: ScanFinding;
}

function toChains(findings: ScanFinding[]): Chain[] {
  return findings
    .filter((f) => (f.detail as Record<string, unknown>)?.source === 'correlate')
    .map((f) => {
      const d = (f.detail ?? {}) as Record<string, unknown>;
      const members = Array.isArray(d.members) ? (d.members as ChainMember[]) : [];
      return {
        id: String(d.chain ?? f.id),
        name: f.title.replace(/^Correlated attack chain:\s*/i, ''),
        objective: String(d.objective ?? ''),
        severity: f.severity,
        remediation: String(d.remediation ?? ''),
        members,
        finding: f,
      };
    })
    .filter((c) => c.members.length > 0)
    .sort((a, b) => sevMeta(b.severity).rank - sevMeta(a.severity).rank);
}

/** A left→right fan-in: each constituent finding flows into the objective node. */
function ChainDiagram({ chain, onPick }: { chain: Chain; onPick: (m: ChainMember) => void }) {
  const rowH = 46;
  const pad = 12;
  const memberW = 300;
  const gap = 150; // horizontal gap between members column and objective
  const objW = 230;
  const height = Math.max(chain.members.length * rowH + pad * 2, rowH * 2);
  const width = memberW + gap + objW + pad * 2;
  const objCx = pad + memberW + gap;
  const objCy = height / 2;
  const objColor = sevMeta(chain.severity).color;

  return (
    <div className="overflow-x-auto">
      <svg
        viewBox={`0 0 ${width} ${height}`}
        width="100%"
        style={{ minWidth: width, maxWidth: '100%' }}
        role="img"
        aria-label={`Attack chain: ${chain.name}`}
      >
        {/* connectors first, so nodes paint over them */}
        {chain.members.map((m, i) => {
          const y = pad + i * rowH + rowH / 2;
          const x1 = pad + memberW;
          const x2 = objCx;
          const mid = (x1 + x2) / 2;
          return (
            <path
              key={`c${i}`}
              d={`M ${x1} ${y} C ${mid} ${y}, ${mid} ${objCy}, ${x2} ${objCy}`}
              fill="none"
              stroke={objColor}
              strokeWidth={1.5}
              strokeOpacity={0.5}
            />
          );
        })}
        {/* member nodes */}
        {chain.members.map((m, i) => {
          const y = pad + i * rowH;
          return (
            <g
              key={`m${i}`}
              transform={`translate(${pad}, ${y})`}
              style={{ cursor: 'pointer' }}
              onClick={() => onPick(m)}
            >
              <rect width={memberW} height={rowH - 10} rx={6} fill="var(--card, #0f172a)" stroke="#334155" />
              <rect width={4} height={rowH - 10} rx={2} fill={sevMeta(chain.severity).color} />
              <text x={14} y={17} fontSize={12} fontWeight={600} fill="#e2e8f0">
                {m.title.length > 46 ? m.title.slice(0, 45) + '…' : m.title}
              </text>
              <text x={14} y={31} fontSize={10.5} fill="#94a3b8">
                {m.vuln_class} · {m.endpoint.length > 44 ? m.endpoint.slice(0, 43) + '…' : m.endpoint}
              </text>
            </g>
          );
        })}
        {/* objective node */}
        <g transform={`translate(${objCx}, ${objCy - (rowH + 10) / 2})`}>
          <rect
            width={objW}
            height={rowH + 10}
            rx={8}
            fill={sevMeta(chain.severity).bg}
            stroke={objColor}
            strokeWidth={1.5}
          />
          <text x={12} y={20} fontSize={12} fontWeight={700} fill={objColor}>
            🎯 {chain.name}
          </text>
          <text x={12} y={38} fontSize={10.5} fill="#cbd5e1">
            {chain.objective.length > 34 ? chain.objective.slice(0, 33) + '…' : chain.objective}
          </text>
        </g>
      </svg>
    </div>
  );
}

export default function AttackChainGraph({
  scan,
  onSelect,
}: {
  scan: Scan;
  onSelect: (f: ScanFinding) => void;
}) {
  const chains = useMemo(() => toChains(scan.findings), [scan.findings]);

  if (chains.length === 0) {
    return (
      <Empty
        title="No correlated attack chains"
        sub="Attack chains appear when multiple confirmed findings combine into a single objective (e.g. SSRF + reachable metadata → cloud credential theft). None were correlated in this scan."
      />
    );
  }

  const pick = (m: ChainMember) => {
    // navigate to the underlying finding if we can match it by title+endpoint
    const match = scan.findings.find(
      (f) => f.title === m.title && f.endpoint === m.endpoint
    );
    if (match) onSelect(match);
  };

  return (
    <div className="space-y-4">
      <p className="text-[13px] leading-relaxed text-slate-400">
        {chains.length} correlated attack chain{chains.length > 1 ? 's' : ''} — each combines the
        confirmed findings on the left into the objective on the right. These are{' '}
        <strong>hypotheses derived from the findings</strong>, not independently proven; click a node to open the finding.
      </p>
      {chains.map((chain) => (
        <Card key={chain.id}>
          <header className="mb-3 flex items-center gap-2">
            <SevTag severity={chain.severity} />
            <h3 className="text-sm font-semibold text-slate-200">{chain.name}</h3>
            <span className="ml-auto text-[11px] text-slate-500">
              {chain.members.length} finding{chain.members.length > 1 ? 's' : ''} → 1 objective
            </span>
          </header>
          <ChainDiagram chain={chain} onPick={pick} />
          {chain.remediation && (
            <p className="mt-3 border-t border-slate-800 pt-2 text-[12px] leading-relaxed text-slate-400">
              <span className="font-semibold text-slate-300">Break the chain:</span> {chain.remediation}
            </p>
          )}
        </Card>
      ))}
    </div>
  );
}

export function hasAttackChains(scan: Scan): boolean {
  return scan.findings.some(
    (f) =>
      (f.detail as Record<string, unknown>)?.source === 'correlate' &&
      Array.isArray((f.detail as Record<string, unknown>)?.members) &&
      ((f.detail as Record<string, unknown>).members as unknown[]).length > 0
  );
}
