/**
 * Editable-report overrides, persisted per scan in localStorage.
 *
 * The pentest report is DERIVED from scan data (that's the integrity rule), but a
 * human owns the final document — they need to reword the executive summary, add
 * client-specific caveats, drop a section, or append an appendix. So overrides
 * live in a separate layer: the generated report is always the default; an edit
 * only shadows it, and "reset" removes the shadow to reveal the generated text
 * again. Nothing here mutates the underlying scan/findings.
 */
export interface SectionEdit {
  title?: string;      // rename the section heading
  bodyMd?: string;     // replace the generated body with Markdown (undefined = use generated)
  hidden?: boolean;    // omit the section from the document
}

export interface CustomSection {
  id: string;          // "custom-<n>"
  title: string;
  bodyMd: string;
}

export interface ReportEdits {
  cover: Record<string, string>;          // cover field label -> override value
  sections: Record<string, SectionEdit>;  // built-in section id -> edit
  custom: CustomSection[];                 // appended sections
}

const KEY = 'deluluscan.report.v1';

export function emptyEdits(): ReportEdits {
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

export function loadReportEdits(scanId: string): ReportEdits {
  const e = read()[scanId];
  return e ? { cover: e.cover || {}, sections: e.sections || {}, custom: e.custom || [] }
           : emptyEdits();
}

export function saveReportEdits(scanId: string, edits: ReportEdits): void {
  try {
    const store = read();
    // prune to keep storage tidy: drop empty section edits
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

export function hasAnyEdit(e: ReportEdits): boolean {
  return (
    Object.keys(e.cover).length > 0 ||
    Object.keys(e.sections).length > 0 ||
    e.custom.length > 0
  );
}
