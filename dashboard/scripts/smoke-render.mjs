// Load the GENERATED report in jsdom exactly as a browser would, and assert the
// React app actually mounts and renders the real scan's findings.
import fs from 'node:fs';
import { JSDOM, VirtualConsole } from 'jsdom';
import { webcrypto } from 'node:crypto';

const [file, mode, password] = process.argv.slice(2);
const html = fs.readFileSync(file, 'utf-8');

const vc = new VirtualConsole();
const errors = [];
// jsdom's CSS parser predates Tailwind v4 syntax (@property, color-mix(), oklch()),
// so it reports the stylesheet as unparseable. That is a jsdom limitation with no
// bearing on the bundle — a real browser renders it. Ignore only that.
const IGNORE = /Could not parse CSS stylesheet/i;
const note = (m) => {
  const s = String(m);
  if (!IGNORE.test(s)) errors.push(s);
};
vc.on('jsdomError', (e) => note(e?.message ?? e));
vc.on('error', (...a) => note(a.join(' ')));

const dom = new JSDOM(html, {
  runScripts: 'dangerously',
  pretendToBeVisual: true,
  url: 'https://target.github.io/deluluscan/dashboard.html',
  virtualConsole: vc,
});
// jsdom's window lacks Web Crypto's subtle and the TextEncoder/TextDecoder pair.
// Every browser has all three; supply them so the encrypted path can be exercised.
if (!dom.window.crypto?.subtle) {
  Object.defineProperty(dom.window, 'crypto', { value: webcrypto, configurable: true });
}
for (const [name, impl] of [
  ['TextEncoder', TextEncoder],
  ['TextDecoder', TextDecoder],
]) {
  if (!dom.window[name]) {
    Object.defineProperty(dom.window, name, { value: impl, configurable: true });
  }
}

// jsdom does not implement ES modules, so it silently skips the app's
// <script type="module"> (the data script, being classic, does run). Evaluate the
// module body by hand — the production bundle is a single chunk with no imports,
// so this is the same code a browser executes, just triggered explicitly.
await new Promise((r) => setTimeout(r, 50));
const appScript = [...dom.window.document.querySelectorAll('script[type=module]')]
  .map((s) => s.textContent)
  .filter(Boolean)
  .join('\n');
if (!appScript) {
  console.log('FAIL  bundle contains an app module script');
  process.exit(1);
}
dom.window.eval(appScript);

await new Promise((r) => setTimeout(r, 700));

const doc = dom.window.document;
const root = doc.getElementById('root');
const text = () => (doc.body.textContent || '').replace(/\s+/g, ' ');

function ok(label, cond, extra = '') {
  console.log(`${cond ? 'PASS' : 'FAIL'}  ${label}${cond ? '' : `  ${extra}`}`);
  if (!cond) process.exitCode = 1;
}

if (mode === 'encrypted') {
  ok('gate rendered instead of findings', text().includes('Protected Report'));
  ok('no finding text present before unlock', !text().includes('Verbose error'));
  // Unlock it the way a viewer would.
  const input = doc.querySelector('input[type=password]');
  const form = doc.querySelector('form');
  // React tracks a controlled input's value through its own property descriptor,
  // so assigning .value directly does not notify it. Go through the native setter
  // and then dispatch, exactly as testing-library does.
  const setter = Object.getOwnPropertyDescriptor(
    dom.window.HTMLInputElement.prototype,
    'value'
  ).set;
  setter.call(input, password);
  input.dispatchEvent(new dom.window.Event('input', { bubbles: true }));
  form.dispatchEvent(new dom.window.Event('submit', { bubbles: true, cancelable: true }));
  // PBKDF2 at 210k iterations is deliberately slow; give it room.
  for (let i = 0; i < 40 && text().includes('Protected Report'); i++) {
    await new Promise((r) => setTimeout(r, 250));
  }
  ok('unlocked with the correct passphrase', !text().includes('Protected Report'), text().slice(0, 160));
}

ok('React mounted into #root', root && root.children.length > 0);
ok('header rendered', text().includes('Deluluscan'));
ok('target shown', text().includes('127.0.0.1:8080'));
ok('tabs present', text().includes('Users & Access') && text().includes('Pentest Report'));

const results = JSON.parse(fs.readFileSync(process.env.DELULUSCAN_RESULTS || '../deluluscan-out/results.json', 'utf-8'));
const titles = results.findings.map((f) => f.title);
const shown = titles.filter((t) => text().includes(t.slice(0, 34)));
ok(`real finding titles rendered (${shown.length}/${titles.length})`, shown.length > 0,
   `none of ${titles.length} titles found`);

// Navigate: the access matrix and the report must render without throwing.
dom.window.location.hash = 'access';
dom.window.dispatchEvent(new dom.window.Event('hashchange'));
await new Promise((r) => setTimeout(r, 500));
ok('access matrix renders', text().includes('not probed') || text().includes('No per-identity evidence'));

dom.window.location.hash = 'report';
dom.window.dispatchEvent(new dom.window.Event('hashchange'));
await new Promise((r) => setTimeout(r, 700));
const rep = text();
ok('pentest report renders', rep.includes('Engagement Report'));
ok('coverage section present', rep.includes('Untested is not the same as secure'));
ok('narrative is derived, not hardcoded',
   !rep.includes('unauthenticated request enumerates administrative layout identifiers'));
ok('no chain claimed when none measured', rep.includes('No exploit chain was demonstrated'));

ok('no script errors', errors.length === 0, errors.slice(0, 3).join(' | '));
