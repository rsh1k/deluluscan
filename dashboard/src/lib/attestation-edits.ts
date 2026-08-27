/**
 * Editable-attestation overrides, persisted per scan in localStorage.
 *
 * Mirrors report-edits.ts but in its OWN store key, so editing the Letter of
 * Attestation never collides with edits to the Pentest Report. The letter's
 * default prose + its findings conclusion are DERIVED from the scan (the same
 * integrity rule as the report); a human owns the final wording, so an edit only
 * shadows the generated text and "reset" reveals it again. Nothing here mutates
 * the underlying scan/findings.
 */
import type { ReportEdits, SectionEdit, CustomSection } from './report-edits';

export type { ReportEdits, SectionEdit, CustomSection } from './report-edits';

const KEY = 'deluluscan.attestation.v1';

export function emptyAttestation(): ReportEdits {
  return { cover: {}, sections: {}, custom: [] };
}

type Store = Record<string, ReportEdits>;

function read(): Store {
  try {
    return JSON.parse(localStorage.getItem(KEY) || '{}') as Store;
  } catch {
    return {};
  }
}

export function loadAttestationEdits(scanId: string): ReportEdits {
  const e = read()[scanId];
  return e ? { cover: e.cover || {}, sections: e.sections || {}, custom: e.custom || [] }
           : emptyAttestation();
}

export function saveAttestationEdits(scanId: string, edits: ReportEdits): void {
  try {
    const store = read();
    const sections: Record<string, SectionEdit> = {};
    for (const [k, v] of Object.entries(edits.sections)) {
      if (v && (v.title !== undefined || v.bodyMd !== undefined || v.hidden)) sections[k] = v;
    }
    store[scanId] = { cover: edits.cover, sections, custom: edits.custom };
    localStorage.setItem(KEY, JSON.stringify(store));
  } catch {
    /* private mode / quota — edits still work for the session */
  }
}
