/**
 * A tiny, dependency-free Markdown renderer for user-edited report prose.
 *
 * The report bundle must stay self-contained (no CDN, strict CSP), so we cannot
 * pull in react-markdown. This covers what a pentest editor actually types —
 * headings, bold/italic/code, links, lists, blockquotes, rules, fenced code and
 * simple pipe tables — and escapes HTML first so a pasted `<script>` renders as
 * text, not markup (this is a security report; it must not XSS its own reader).
 */
import { useMemo } from 'react';

function esc(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function inline(s: string): string {
  // operate on already HTML-escaped text
  return s
    .replace(/`([^`]+)`/g, '<code class="rk-md-code">$1</code>')
    .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
    .replace(/\*([^*]+)\*/g, '<em>$1</em>')
    .replace(/\[([^\]]+)\]\((https?:[^)\s]+)\)/g,
             '<a href="$2" target="_blank" rel="noopener noreferrer" class="rk-md-a">$1</a>');
}

export function mdToHtml(md: string): string {
  const lines = (md || '').replace(/\r\n/g, '\n').split('\n');
  const out: string[] = [];
  let i = 0;

  const flushList = (buf: string[], ordered: boolean) => {
    if (!buf.length) return;
    const tag = ordered ? 'ol' : 'ul';
    out.push(`<${tag} class="rk-md-${tag}">` +
      buf.map((li) => `<li>${inline(esc(li))}</li>`).join('') + `</${tag}>`);
    buf.length = 0;
  };

  while (i < lines.length) {
    const line = lines[i];

    // fenced code
    if (/^```/.test(line)) {
      const body: string[] = [];
      i++;
      while (i < lines.length && !/^```/.test(lines[i])) { body.push(lines[i]); i++; }
      i++; // closing fence
      out.push(`<pre class="rk-md-pre"><code>${esc(body.join('\n'))}</code></pre>`);
      continue;
    }
    // horizontal rule
    if (/^\s*([-*_])\1\1+\s*$/.test(line)) { out.push('<hr class="rk-md-hr"/>'); i++; continue; }
    // heading
    const h = /^(#{1,6})\s+(.*)$/.exec(line);
    if (h) {
      const lvl = Math.min(h[1].length + 2, 6); // # -> h3 (report h1/h2 are structural)
      out.push(`<h${lvl} class="rk-md-h">${inline(esc(h[2].trim()))}</h${lvl}>`);
      i++; continue;
    }
    // blockquote
    if (/^\s*>\s?/.test(line)) {
      const body: string[] = [];
      while (i < lines.length && /^\s*>\s?/.test(lines[i])) {
        body.push(lines[i].replace(/^\s*>\s?/, '')); i++;
      }
      out.push(`<blockquote class="rk-md-quote">${inline(esc(body.join(' ')))}</blockquote>`);
      continue;
    }
    // table (header row + | --- | separator)
    if (line.includes('|') && i + 1 < lines.length && /^\s*\|?[\s:|-]+\|?\s*$/.test(lines[i + 1])) {
      const cells = (r: string) => r.replace(/^\s*\|/, '').replace(/\|\s*$/, '').split('|').map((c) => c.trim());
      const head = cells(line);
      i += 2;
      const rows: string[][] = [];
      while (i < lines.length && lines[i].includes('|')) { rows.push(cells(lines[i])); i++; }
      out.push('<table class="rk-md-table"><thead><tr>' +
        head.map((c) => `<th>${inline(esc(c))}</th>`).join('') + '</tr></thead><tbody>' +
        rows.map((r) => '<tr>' + r.map((c) => `<td>${inline(esc(c))}</td>`).join('') + '</tr>').join('') +
        '</tbody></table>');
      continue;
    }
    // unordered list
    if (/^\s*[-*]\s+/.test(line)) {
      const buf: string[] = [];
      while (i < lines.length && /^\s*[-*]\s+/.test(lines[i])) {
        buf.push(lines[i].replace(/^\s*[-*]\s+/, '')); i++;
      }
      flushList(buf, false);
      continue;
    }
    // ordered list
    if (/^\s*\d+\.\s+/.test(line)) {
      const buf: string[] = [];
      while (i < lines.length && /^\s*\d+\.\s+/.test(lines[i])) {
        buf.push(lines[i].replace(/^\s*\d+\.\s+/, '')); i++;
      }
      flushList(buf, true);
      continue;
    }
    // blank line
    if (/^\s*$/.test(line)) { i++; continue; }
    // paragraph (gather until blank / block start)
    const para: string[] = [];
    while (i < lines.length && !/^\s*$/.test(lines[i]) &&
           !/^(#{1,6}\s|```|\s*>\s?|\s*[-*]\s+|\s*\d+\.\s+)/.test(lines[i])) {
      para.push(lines[i]); i++;
    }
    out.push(`<p class="rk-md-p">${inline(esc(para.join(' ')))}</p>`);
  }
  return out.join('\n');
}

export function Markdown({ md }: { md: string }) {
  const html = useMemo(() => mdToHtml(md), [md]);
  return <div className="rk-md" dangerouslySetInnerHTML={{ __html: html }} />;
}
