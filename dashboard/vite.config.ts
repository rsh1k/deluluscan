import { defineConfig, type Plugin } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';
import path from 'node:path';
import fs from 'node:fs';

const TRIAGE_STATE_PATH = path.resolve(__dirname, 'src/data/triage-state.local.json');

/**
 * Dev-only stand-in for frontend/app/api/security/triage/route.ts — exercises
 * the SAME fetch('/api/security/triage', ...) call the real dashboard makes,
 * but persists to a local JSON file instead of committing via the GitHub API.
 * Not used in production; this whole app only exists for local testing.
 */
function triageDevApi(): Plugin {
  return {
    name: 'triage-dev-api',
    configureServer(server) {
      server.middlewares.use('/api/security/triage', (req, res) => {
        if (req.method !== 'POST') {
          res.statusCode = 405;
          res.end('Method not allowed');
          return;
        }
        let body = '';
        req.on('data', (chunk) => (body += chunk));
        req.on('end', () => {
          try {
            const { finding_id, status, assignee } = JSON.parse(body || '{}');
            if (!finding_id) throw new Error('finding_id is required');
            const state = fs.existsSync(TRIAGE_STATE_PATH)
              ? JSON.parse(fs.readFileSync(TRIAGE_STATE_PATH, 'utf-8'))
              : {};
            const prev = state[finding_id];
            const entry = {
              status: status ?? prev?.status ?? 'new',
              assignee: assignee ?? prev?.assignee ?? '',
              updated_by: 'local-test@example.com',
              updated_at: new Date().toISOString(),
            };
            state[finding_id] = entry;
            fs.writeFileSync(TRIAGE_STATE_PATH, JSON.stringify(state, null, 2));
            res.setHeader('Content-Type', 'application/json');
            res.end(JSON.stringify({ entry }));
          } catch (err) {
            res.statusCode = 400;
            res.end(JSON.stringify({ error: err instanceof Error ? err.message : 'bad request' }));
          }
        });
      });
    },
  };
}

/**
 * Inline every asset into index.html so `npm run build` emits ONE file.
 *
 * The report ships as a single static artifact: it is published to GitHub Pages,
 * opened from disk, and mailed around, and its scan payload is AES-GCM encrypted
 * with the passphrase as the only access boundary. A build that emitted
 * /assets/*.js would break all three — external requests fail from file://, and
 * a sidecar chunk is another thing to keep in sync with the encrypted page.
 *
 * Hand-rolled rather than pulling in vite-plugin-singlefile: this is a security
 * tool, and ~30 lines we control beats another transitive dependency in the
 * artifact that carries the findings.
 */
function singleFile(): Plugin {
  return {
    name: 'deluluscan-single-file',
    enforce: 'post',
    apply: 'build',
    generateBundle(_options, bundle) {
      const html = Object.values(bundle).find(
        (c): c is import('rollup').OutputAsset =>
          c.type === 'asset' && c.fileName.endsWith('.html')
      );
      if (!html) throw new Error('single-file build: no HTML asset in the bundle');
      let source = String(html.source);

      for (const chunk of Object.values(bundle)) {
        if (chunk === html) continue;
        if (chunk.type === 'chunk') {
          // Keep type="module". Vite emits the tag in <head>, and a module script
          // is DEFERRED — it runs after the document is parsed, so #root exists.
          // Inlining it as a classic script instead makes it execute immediately,
          // in <head>, and the app dies with "root element missing". (The file://
          // restriction that motivates classic scripts applies to module IMPORTS
          // and external srcs; a self-contained inline module has neither.)
          const tag = new RegExp(
            `<script[^>]*src="[^"]*${escapeRe(chunk.fileName)}"[^>]*></script>`
          );
          const inlined = `<script type="module">\n${chunk.code}\n</script>`;
          // A replacer FUNCTION, never a replacement string: `$&`, `$1` etc. are
          // special in a replacement string, and minified React contains `"$&/"`.
          // Passing the code as a string silently expanded that into the matched
          // <script> tag and corrupted the bundle.
          source = tag.test(source)
            ? source.replace(tag, () => inlined)
            : source.replace('</body>', () => `${inlined}\n</body>`);
        } else if (chunk.fileName.endsWith('.css')) {
          const link = new RegExp(
            `<link[^>]*href="[^"]*${escapeRe(chunk.fileName)}"[^>]*>`
          );
          const inlined = `<style>\n${String(chunk.source)}\n</style>`;
          source = link.test(source)
            ? source.replace(link, () => inlined)
            : source.replace('</head>', () => `${inlined}\n</head>`);
        }
        delete bundle[chunk.fileName];
      }

      if (!source.includes('/*__DATA__*/')) {
        throw new Error(
          'single-file build: the /*__DATA__*/ injection marker was stripped — ' +
            'deluluscan/dashboard.py would have nowhere to write the scan payload'
        );
      }
      // Nothing may remain that the browser would have to fetch: the report is
      // opened from file:// and served behind a strict static host, so a leftover
      // /assets/ reference is a blank page rather than a degraded one.
      const dangling = source.match(/(?:src|href)="\/?assets\/[^"]*"/g);
      if (dangling) {
        throw new Error(
          `single-file build: ${dangling.length} asset reference(s) were not inlined: ` +
            `${dangling.slice(0, 3).join(', ')}`
        );
      }
      html.source = source;
    },
  };
}

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

export default defineConfig({
  plugins: [react(), tailwindcss(), triageDevApi(), singleFile()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  build: {
    // One chunk, no code-splitting, no hashed sidecars — everything gets inlined.
    assetsInlineLimit: 100 * 1024 * 1024,
    cssCodeSplit: false,
    modulePreload: { polyfill: false },
    rollupOptions: { output: { inlineDynamicImports: true } },
    outDir: 'dist',
    emptyOutDir: true,
  },
});
