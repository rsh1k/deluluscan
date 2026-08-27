/**
 * Letter of Attestation — a formal, signable summary that a security assessment
 * was performed and what its posture was.
 *
 * Editable and downloadable exactly like the Pentest Report: prose sections are
 * generated from the scan and can be reworded (overrides live in
 * attestation-edits.ts, per scan, in localStorage); the global Print/PDF button
 * renders whatever tab is active, so printing here produces the letter.
 *
 * Integrity (same rule as the rest of the report): the CONCLUSION is DERIVED from
 * the actual confirmed findings — it never hard-codes "SECURE". If confirmed
 * Critical/High issues exist, the default says so and recommends remediation; if
 * none do, it states that honestly, scoped to what THIS assessment observed. The
 * signatory is left as an editable placeholder — this is the target's own
 * self-attestation, not a third party's, and no signature is fabricated.
 */
import { useEffect, useMemo, useState } from 'react';
import type { Scan } from '@/lib/deluluscan-data';
import { buildReportModel, fmtDate } from '@/lib/model';
import type { TriageMap } from '@/lib/triage';
import { statusOf } from '@/lib/triage';
import { Markdown } from '@/lib/markdown';
import { hasAnyEdit, type ReportEdits } from '@/lib/report-edits';
import { emptyAttestation, loadAttestationEdits, saveAttestationEdits } from '@/lib/attestation-edits';
import brandLogo from '@/logo-dark.svg?raw';

function clone(e: ReportEdits): ReportEdits {
  return { cover: { ...e.cover }, sections: { ...e.sections }, custom: e.custom.map((c) => ({ ...c })) };
}

/** A prose section whose default is Markdown; editing pre-fills the effective
 *  text (override or generated) so the operator tweaks the letter in place. */
function LetterSection({
  id, title, defaultMd, edits, editing, patch,
}: {
  id: string; title: string; defaultMd: string; edits: ReportEdits; editing: boolean;
  patch: (id: string, p: { bodyMd?: string }) => void;
}) {
  const se = edits.sections[id] || {};
  const effective = se.bodyMd ?? defaultMd;
  const [open, setOpen] = useState(false);
  const [draft, setDraft] = useState(effective);
  useEffect(() => setDraft(se.bodyMd ?? defaultMd), [se.bodyMd, defaultMd, id]);

  return (
    <section className="mb-4">
      <h2 className="mb-2 flex items-baseline gap-2 text-[15px] font-bold text-slate-100">
        {title}
        {se.bodyMd !== undefined && !editing && (
          <span className="rd-print-hide rounded bg-indigo-500/15 px-1.5 py-0.5 text-[9px] font-semibold text-indigo-700">EDITED</span>
        )}
      </h2>

      {editing && (
        <div className="rd-print-hide mb-2 flex flex-wrap items-center gap-2 text-[11px]">
          <button onClick={() => setOpen((o) => !o)}
            className="rounded border border-slate-700 px-2 py-0.5 text-slate-300 hover:text-white">
            {open ? 'Close editor' : 'Edit text'}
          </button>
          {se.bodyMd !== undefined && (
            <button onClick={() => { patch(id, { bodyMd: undefined }); setOpen(false); }}
              className="rounded border border-slate-700 px-2 py-0.5 text-amber-700 hover:text-amber-800">Reset to generated</button>
          )}
        </div>
      )}

      {editing && open && (
        <div className="rd-print-hide mb-3">
          <textarea value={draft} onChange={(e) => setDraft(e.target.value)} rows={8}
            className="w-full resize-y rounded-lg border border-slate-700 bg-slate-950 p-3 font-mono text-[12px] text-slate-200" />
          <div className="mt-1.5 flex gap-2">
            <button onClick={() => patch(id, { bodyMd: draft.trim() && draft !== defaultMd ? draft : undefined })}
              className="rounded bg-indigo-600 px-3 py-1 text-[12px] font-semibold text-white hover:bg-indigo-500">Save section</button>
            <span className="self-center text-[11px] text-slate-500">Markdown: **bold**, lists, `code`, headings</span>
          </div>
        </div>
      )}

      <Markdown md={effective} />
    </section>
  );
}

function Field({ label, value, editing, onChange }: {
  label: string; value: string; editing: boolean; onChange: (v: string) => void;
}) {
  return (
    <div className="flex gap-2">
      <dt className="shrink-0 text-slate-500">{label}</dt>
      {editing ? (
        <input value={value} onChange={(e) => onChange(e.target.value)}
          className="min-w-0 flex-1 rounded border border-slate-700 bg-slate-950 px-1.5 py-0.5 font-medium text-slate-200" />
      ) : (
        <dd className="min-w-0 break-words font-medium text-slate-300">{value}</dd>
      )}
    </div>
  );
}

export default function AttestationView({ scan, triage }: { scan: Scan; triage: TriageMap }) {
  const M = useMemo(
    () => buildReportModel(scan, (f) => statusOf(triage, f.id, f.verdict)),
    [scan, triage]
  );
  const [edits, setEdits] = useState<ReportEdits>(() => loadAttestationEdits(scan.id));
  const [editing, setEditing] = useState(false);
  useEffect(() => setEdits(loadAttestationEdits(scan.id)), [scan.id]);

  const mutate = (fn: (e: ReportEdits) => void) =>
    setEdits((prev) => { const next = clone(prev); fn(next); saveAttestationEdits(scan.id, next); return next; });
  const patch = (id: string, p: { bodyMd?: string }) =>
    mutate((e) => { e.sections[id] = { ...(e.sections[id] || {}), ...p }; });

  const date = fmtDate(scan.date);
  const target = scan.target || '(target not recorded)';
  const critHigh = M.crit + M.high;

  const cover = (label: string, def: string) => edits.cover[label] ?? def;
  const coverFields: [string, string][] = [
    ['Report reference', `target-ATT-${(scan.date ?? '').slice(0, 7) || 'unknown'}`],
    ['Report date', date],
    ['Date of final testing', date],
    ['Prepared for', 'Example Organization'],
    ['Prepared by', 'the Security Team'],
  ];

  // Conclusion is DERIVED from findings demonstrated exploitable — never a
  // hard-coded "SECURE". `critHigh` counts the same (reportable) set, so this
  // must too, or the arithmetic silently mixes two different scopes.
  const lowerCount = Math.max(M.reportable.length - critHigh, 0);
  // Observations that were recorded but never proven exploitable. An attestation
  // that stayed silent about these would read as "nothing else was seen", which
  // is not what the scan observed.
  const setAside = M.observedNotExploitable.length;
  // If the report was curated down to an explicit subset, a confirmed high/
  // critical may have been excluded from it. The attestation must say so — a
  // "no exploitable Critical/High" line would otherwise be actively misleading.
  const excludedHi = M.excludedHigherSeverity.length;
  const setAsideNote =
    setAside === 0
      ? ``
      : M.curated
        ? ` A further ${setAside} finding(s) were recorded but are not detailed in the accompanying (curated) report` +
          (excludedHi > 0
            ? `, ${excludedHi} of which ${excludedHi === 1 ? 'is' : 'are'} rated high or critical and ${excludedHi === 1 ? 'was' : 'were'} excluded at the engagement owner's direction rather than disproven`
            : ``) +
          `; this attestation makes no assurance about them and they remain in the findings register.`
        : ` A further ${setAside} observation(s) were recorded but not demonstrated exploitable in this engagement; they are listed in the accompanying report and this attestation makes no assurance about them.`;
  const conclusionMd =
    critHigh === 0
      ? `This analysis is based on the technologies and known threats as of **${date}**, the date of final testing of the Target Application.\n\n` +
        `Vulnerabilities within the Critical- and High-risk categories pose enough risk that mitigation is always recommended, and retesting should take place until such vulnerabilities are mitigated.\n\n` +
        `**Final testing demonstrated no exploitable Critical- or High-risk vulnerabilities within the Target Application.** ` +
        (lowerCount > 0
          ? `${lowerCount} lower-severity finding(s) were demonstrated exploitable and are detailed in the accompanying report.`
          : `No finding was demonstrated to be exploitable in the assessed scope.`) +
        setAsideNote +
        `\n\nThis attestation reflects conditions found at the time of testing and is not to be projected beyond the date of delivery of this report. As technologies and risks change, the vulnerabilities associated with the operation of the systems described here, and the actions necessary to reduce exposure, will also change.`
      : `This analysis is based on the technologies and known threats as of **${date}**, the date of final testing of the Target Application.\n\n` +
        `Vulnerabilities within the Critical- and High-risk categories pose enough risk that mitigation is always recommended, and retesting should take place until such vulnerabilities are mitigated.\n\n` +
        `**Final testing demonstrated ${M.crit} exploitable Critical- and ${M.high} exploitable High-risk finding(s)** within the Target Application` +
        (lowerCount > 0 ? `, together with ${lowerCount} lower-severity finding(s)` : ``) +
        `. Remediation is recommended and retesting should take place until these are mitigated; details are in the accompanying report.` +
        setAsideNote +
        `\n\nThis attestation reflects conditions found at the time of testing and is not to be projected beyond the date of delivery of this report.`;

  const sections: [string, string, string][] = [
    ['intro', 'Introduction',
      `This letter attests to the completion of a security assessment of the application(s) identified below, performed by **the Security Team** using **Deluluscan**, the target's authorized security auditor. The assessment followed OWASP testing methodology and the target's internal penetration-testing process, and was conducted against a dedicated, authorized target instance — no customer systems or production data were involved.`],
    ['scope', 'Scope',
      `The objective of application penetration testing is to detect design and implementation weaknesses in the application that could be used by an attacker to gain unauthorized access to information, damage the reputation of Example Organization or its clients, or impair normal business operations. Periodic assessments are a precautionary measure to safeguard Example Organization's information assets.\n\nThis letter attests to the successful completion of penetration testing of the following Target Application(s):\n\n- \`${target}\``],
    ['testing', 'Testing',
      `During the assessment, the Security Team attempted to determine the overall security of the Target Application, perform unauthorized transactions, and obtain confidential information by performing a wide variety of vulnerability checks. Exploitation was carried out only to the point of proof; findings were confirmed as reachable but were not weaponized. Such testing was an assessment of the Target Application only, not of every Example Organization network or application.`],
    ['conclusion', 'Conclusion', conclusionMd],
  ];

  return (
    <div className="mx-auto max-w-4xl">
      {/* toolbar */}
      <div className="rd-print-hide mb-4 flex flex-wrap items-center gap-2">
        <button onClick={() => setEditing((e) => !e)}
          className={`rounded-md px-3 py-1.5 text-[12.5px] font-semibold ${
            editing ? 'bg-indigo-600 text-white' : 'border border-slate-700 text-slate-300 hover:text-white'}`}>
          {editing ? 'Done editing' : 'Edit letter'}
        </button>
        {editing && hasAnyEdit(edits) && (
          <button onClick={() => { if (confirm('Discard all edits to this attestation and revert to the generated version?')) { const e = emptyAttestation(); saveAttestationEdits(scan.id, e); setEdits(e); } }}
            className="rounded-md border border-slate-700 px-3 py-1.5 text-[12.5px] text-amber-700 hover:text-amber-800">Reset all</button>
        )}
        {editing && <span className="text-[11px] text-slate-500">Edits are saved locally per scan; Print/PDF reflects them.</span>}
        {!editing && hasAnyEdit(edits) && (
          <span className="rounded bg-indigo-500/15 px-2 py-0.5 text-[11px] text-indigo-700">This letter has manual edits</span>
        )}
      </div>

      {/* letterhead */}
      <div className="mb-6 rounded-xl border border-slate-800 bg-slate-900/60 p-6 text-center">
        <span className="rk-logo mb-4 inline-flex items-center justify-center [&_svg]:h-6 [&_svg]:w-auto"
              aria-label="the target"
              dangerouslySetInnerHTML={{ __html: brandLogo.replace(/clip0_52_16649/g, 'clip0_att') }} />
        <p className="mb-3 text-[10px] font-bold uppercase tracking-widest text-amber-700">
          {cover('Classification banner', 'Confidential')}
        </p>
        <h1 className="text-2xl font-bold text-slate-100">{cover('Report title', 'Letter of Attestation')}</h1>
        <p className="mt-1.5 text-[13px] font-medium text-slate-300">Penetration Testing Services</p>
        <p className="mt-1 text-[12px] text-slate-500">
          Prepared for {cover('Prepared for', 'Example Organization')} by {cover('Prepared by', 'the Security Team')}
        </p>
        <dl className="mx-auto mt-5 grid max-w-lg grid-cols-1 gap-x-8 gap-y-1.5 text-left text-[12.5px] sm:grid-cols-2">
          {coverFields.map(([label, def]) => (
            <Field key={label} label={label} value={cover(label, def)} editing={editing}
              onChange={(v) => mutate((e) => { if (v === def) delete e.cover[label]; else e.cover[label] = v; })} />
          ))}
        </dl>
      </div>

      {sections.map(([id, title, md]) => (
        <LetterSection key={id} id={id} title={title} defaultMd={md}
          edits={edits} editing={editing} patch={patch} />
      ))}

      {/* signatory */}
      <section className="mt-8 border-t border-slate-800 pt-5">
        <p className="mb-8 text-[12.5px] text-slate-400">
          Signed on behalf of {cover('Organization', 'Example Organization')}:
        </p>
        <div className="max-w-sm">
          <div className="mb-1 border-b border-slate-600 pb-6" aria-hidden />
          <dl className="space-y-1 text-[12.5px]">
            <Field label="Name" value={cover('Signatory name', '')} editing={editing}
              onChange={(v) => mutate((e) => { if (!v) delete e.cover['Signatory name']; else e.cover['Signatory name'] = v; })} />
            <Field label="Title" value={cover('Signatory title', '')} editing={editing}
              onChange={(v) => mutate((e) => { if (!v) delete e.cover['Signatory title']; else e.cover['Signatory title'] = v; })} />
            <Field label="Organization" value={cover('Organization', 'Example Organization')} editing={editing}
              onChange={(v) => mutate((e) => { if (v === 'Example Organization') delete e.cover['Organization']; else e.cover['Organization'] = v; })} />
            <Field label="Date" value={cover('Signatory date', date)} editing={editing}
              onChange={(v) => mutate((e) => { if (v === date) delete e.cover['Signatory date']; else e.cover['Signatory date'] = v; })} />
          </dl>
          {!editing && !cover('Signatory name', '') && (
            <p className="rd-print-hide mt-2 text-[11px] text-amber-700/80">
              Add the authorized signatory (Edit letter) before issuing this attestation.
            </p>
          )}
        </div>
      </section>

      <div className="mt-8 border-t border-slate-800 pt-3 text-center text-[10px] uppercase tracking-widest text-slate-500">
        Confidential · {cover('Prepared for', 'Example Organization')} · {cover('Report date', date)}
      </div>
    </div>
  );
}
