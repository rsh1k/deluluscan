/**
 * The scan payload, as `deluluscan/dashboard.py` injects it.
 *
 * Two shapes, decided at generation time:
 *   plaintext  ->  var SCANS=[...]              ; var __ENC__=null
 *   encrypted  ->  var SCANS=null               ; var __ENC__={v,iter,salt,iv,ct}
 *
 * When encrypted, the findings genuinely are not in the file until the passphrase
 * is entered — a wrong one fails the AES-GCM auth tag. The published report is a
 * public URL, so that passphrase is the whole access boundary; see
 * _encrypt_payload() in deluluscan/dashboard.py for the matching parameters.
 */
import type { Finding } from '@/types/security';

export interface CoverageMeta {
  endpoints_discovered?: number;
  endpoints_probed?: number;
  endpoints_probed_pct?: number;
  untested_endpoints?: string[];
  scanners_run?: string[];
  per_scanner_pct?: Record<string, number>;
}

export interface ProbeStats {
  requests?: number;
  responses?: number;
  errors?: number;
  deferred?: number;
  identities?: string[];
}

/** orchestrator._measure_escalations(): grant -> re-probe -> diff -> revert. */
export interface EscalationPivot {
  identity?: string;
  action?: string;
  performed?: boolean;
  reverted?: boolean | null;
  revert_warning?: string;
  capabilities_before?: string[];
  capabilities_after?: string[];
  capabilities_gained?: string[];
  worst_impact?: string;
  worst_impact_label?: string;
  skipped_reason?: string;
  narrative?: string;
}

/** orchestrator._destructive_pass(): what the deferred destructive pass reached. */
export interface DestructivePass {
  endpoints?: string[];
  probed?: string[];
  skipped?: string[];
  restarts?: number;
  findings?: number;
  aborted_reason?: string;
  post_pass_warning?: string;
  /** Endpoints whose probe actually took the target down — direct evidence the
   *  operation is reachable and works. */
  caused_outage?: string[];
}

export interface ScanMeta {
  target?: string;
  source?: string;
  endpoints_scanned?: number;
  duration_s?: number;
  identities?: Record<string, { ok?: boolean; message?: string }>;
  coverage?: CoverageMeta;
  probe_stats?: ProbeStats;
  escalation_pivot?: EscalationPivot;
  destructive_pass?: DestructivePass;
  destructive_policy?: { enabled?: boolean; deferred_during_main_sweep?: string[] };
  identity_integrity?: Record<string, unknown>;
  /** Curated report scope. When present, the Pentest Report + Attestation detail
   *  ONLY these finding ids (an explicit engagement-owner selection), regardless
   *  of verdict/exploitability. Every other finding keeps its true verdict and
   *  stays in the Findings view; the report discloses the count it set aside. */
  report_include?: { ids: string[]; reason?: string };
  fingerprint?: { detections?: { tech: string; version?: string }[] };
  verification?: { true_positive?: number; false_positive?: number; exploitable?: number };
  /** Engagement memory (deluluscan/memory.py): cross-scan recall summary + a
   *  regression-watch of previously-exploitable endpoints not reproduced. */
  memory?: {
    enabled?: boolean;
    target_key?: string;
    recorded?: number;
    known_targets?: number;
    regression_watch?: string[];
    file?: string;
    error?: string;
  };
  /** Grey-box observability (deluluscan/telemetry): what the --observe run saw. */
  telemetry?: {
    events?: number;
    by_source?: Record<string, number>;
    exception_lines?: number;
    secret_lines?: number;
    probe_windows?: number;
    findings?: number;
    dropped?: number;
  };
  [k: string]: unknown;
}

/** A finding as the generator hands it over: Finding.to_dict() plus the fields
 *  _normalize_evidence() annotates (owasp, required_tier, report, evidence_missing). */
export interface ReportBlock {
  objective?: string;
  location?: { endpoint?: string; code_paths?: string[] };
  method?: string;
  steps?: string[];
  reproduction?: string[];
  /** The same reproduction steps, but each request paired with the response it
   *  actually produced. A curl line on its own asserts nothing — the reader
   *  needs the body to tell a leak from an empty failure. */
  exchanges?: ReportExchange[];
  /** Explicit OWASP/CWE classification, so the category is stated rather than
   *  buried in a free-text references list. */
  taxonomy?: { owasp_2025?: string; owasp_api_top10?: string; cwe?: string[] };
  /** CVSS v3.1 base score with its vector and per-metric reasoning, as produced
   *  by deluluscan.cvss.derive(). Absent when no adjudicator assigned a score. */
  cvss?: {
    version?: string;
    vector?: string;
    base_score?: number;
    severity?: string;
    metric_rationale?: Record<string, string>;
    scored_by?: string;
  };
  outcome?: string;
  impact?: string;
  remediation?: string;
}

/** One captured request/response pair backing a finding. */
export interface ReportExchange {
  /** Runnable curl command rebuilt from the real exchange. */
  curl?: string;
  /** What this particular exchange demonstrates (the violation vs a baseline). */
  proves?: string;
  response?: {
    status?: number;
    identity?: string;
    headers?: Record<string, string>;
    body?: string;
    body_bytes?: number;
    body_truncated?: boolean;
    /** Distinguishes "500 with a stack trace" from "500 that disclosed nothing". */
    body_empty?: boolean;
    elapsed_ms?: number;
    error?: string;
  };
}

export interface ScanFinding extends Finding {
  owasp?: { code: string; name: string };
  required_tier?: number;
  report?: ReportBlock;
  cwe?: string;
  /** True when NO HTTP traffic was captured. The report must say so rather than
   *  render a plausible-looking blank — earlier builds synthesised records here. */
  evidence_missing?: boolean;
}

export interface Scan {
  id: string;
  label: string;
  date: string;
  version: string;
  target: string;
  findings: ScanFinding[];
  meta: ScanMeta;
  identities: string[];
}

/** Security domain ("surface") a finding belongs to, derived from its producing
 *  module (detail.source). Groups the network-posture findings — TLS, DNS,
 *  takeover, request smuggling, SMB/LDAP, edge — as first-class alongside Web/API,
 *  so the report can facet by attack surface, not just by OWASP class. */
export function surfaceOf(f: Finding): string {
  const src = String((f.detail as Record<string, unknown>)?.source ?? '');
  if (src === 'netscan.tls') return 'Transport (TLS)';
  if (src === 'recon.dnsintel') return 'DNS / Email';
  if (src === 'recon.takeover') return 'Subdomain takeover';
  if (src === 'active.smuggling') return 'Request smuggling';
  if (src === 'netscan.adintel') return 'Network (SMB/LDAP)';
  if (src === 'netscan.ports') return 'Network (ports)';
  if (src.startsWith('netscan')) return 'Edge (WAF/CDN)';
  if (src === 'recon.jsanalysis' || src === 'crawler') return 'API inventory';
  if (src.startsWith('platforms')) return 'Platform';
  if (src === 'passive') return 'Passive';
  if (src.startsWith('recon')) return 'Recon';
  return 'Web / API';
}

/** Order surfaces sensibly when rendered as facet chips. */
export const SURFACE_ORDER = [
  'Web / API', 'API inventory', 'Platform', 'Transport (TLS)', 'DNS / Email',
  'Subdomain takeover', 'Request smuggling', 'Edge (WAF/CDN)', 'Network (ports)',
  'Network (SMB/LDAP)', 'Passive', 'Recon',
];

export interface EncBlob {
  v: number;
  iter: number;
  salt: string;
  iv: string;
  ct: string;
}

declare global {
  // eslint-disable-next-line no-var
  var SCANS: Scan[] | null;
  // eslint-disable-next-line no-var
  var __ENC__: EncBlob | null;
}

export function embeddedScans(): Scan[] | null {
  const s = (globalThis as { SCANS?: Scan[] | null }).SCANS;
  return Array.isArray(s) && s.length > 0 ? s : null;
}

export function encryptedBlob(): EncBlob | null {
  const e = (globalThis as { __ENC__?: EncBlob | null }).__ENC__;
  return e && typeof e === 'object' && 'ct' in e ? e : null;
}

/** base64 -> ArrayBuffer. Returns the buffer rather than the view because Web
 *  Crypto's BufferSource rejects a Uint8Array whose backing store might be a
 *  SharedArrayBuffer, which is what TS models for a bare Uint8Array. */
function b64(s: string): ArrayBuffer {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out.buffer;
}

/**
 * PBKDF2-HMAC-SHA256 -> AES-256-GCM, matching _encrypt_payload() exactly.
 * Throws on a wrong passphrase (GCM tag mismatch), which is what the gate uses
 * to tell "wrong password" from "corrupt file".
 */
export async function decryptScans(blob: EncBlob, password: string): Promise<Scan[]> {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) {
    throw new Error(
      'This browser exposes no Web Crypto API, so the encrypted report cannot be ' +
        'opened. Web Crypto requires a secure context — open the file over https:// ' +
        'or from localhost rather than an insecure origin.'
    );
  }
  const base = await subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, [
    'deriveKey',
  ]);
  const key = await subtle.deriveKey(
    { name: 'PBKDF2', salt: b64(blob.salt), iterations: blob.iter || 210000, hash: 'SHA-256' },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt']
  );
  const pt = await subtle.decrypt({ name: 'AES-GCM', iv: b64(blob.iv) }, key, b64(blob.ct));
  const parsed = JSON.parse(new TextDecoder().decode(pt));
  if (!Array.isArray(parsed)) throw new Error('decrypted payload is not a scan list');
  return parsed as Scan[];
}
