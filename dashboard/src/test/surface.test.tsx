import { describe, it, expect } from 'vitest';
import { surfaceOf, SURFACE_ORDER } from '@/lib/deluluscan-data';

const mk = (source: string) =>
  ({ vuln_class: 'misconfig', detail: source ? { source } : {} }) as unknown as Parameters<typeof surfaceOf>[0];

describe('surfaceOf', () => {
  it('maps each network-posture module to its domain', () => {
    expect(surfaceOf(mk('netscan.tls'))).toBe('Transport (TLS)');
    expect(surfaceOf(mk('recon.dnsintel'))).toBe('DNS / Email');
    expect(surfaceOf(mk('recon.takeover'))).toBe('Subdomain takeover');
    expect(surfaceOf(mk('active.smuggling'))).toBe('Request smuggling');
    expect(surfaceOf(mk('netscan.adintel'))).toBe('Network (SMB/LDAP)');
    expect(surfaceOf(mk('netscan.ports'))).toBe('Network (ports)');
    expect(surfaceOf(mk('netscan.waf'))).toBe('Edge (WAF/CDN)');
    expect(surfaceOf(mk('recon.jsanalysis'))).toBe('API inventory');
    expect(surfaceOf(mk('platforms.cves'))).toBe('Platform');
    expect(surfaceOf(mk('passive'))).toBe('Passive');
  });

  it('falls back to Web / API when no source is present', () => {
    expect(surfaceOf(mk(''))).toBe('Web / API');
    expect(surfaceOf(mk('scanners.sqli'))).toBe('Web / API');
  });

  it('every mapped label is present in SURFACE_ORDER', () => {
    for (const s of ['netscan.tls', 'recon.dnsintel', 'recon.takeover', 'active.smuggling',
                     'netscan.adintel', 'netscan.ports', 'netscan.waf', 'recon.jsanalysis',
                     'platforms.cves', 'passive']) {
      expect(SURFACE_ORDER).toContain(surfaceOf(mk(s)));
    }
    expect(SURFACE_ORDER).toContain('Web / API');
  });
});
