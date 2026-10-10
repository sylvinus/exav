#!/usr/bin/env node
// Check every internal link of the built docs site (www/dist): the page it
// names must exist, and so must the `#anchor` on it.
//
// Run on the rendered HTML rather than on the Markdown, so an anchor is checked
// against the id Starlight actually generated for the heading, not against a
// guess at its slug rule. No dependencies: the build output is plain HTML.
//
// USAGE: node scripts/check-links.mjs [DIST_DIR]   (default: www/dist)

import { readdirSync, readFileSync, existsSync, statSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const repo = join(fileURLToPath(import.meta.url), '..', '..');
const dist = process.argv[2] ?? join(repo, 'www', 'dist');
if (!existsSync(dist)) {
  console.error(`error: ${dist} not found; build the site first (npm run build in www/)`);
  process.exit(2);
}

function htmlFiles(dir) {
  return readdirSync(dir, { withFileTypes: true }).flatMap((e) => {
    const p = join(dir, e.name);
    if (e.isDirectory()) return htmlFiles(p);
    return e.name.endsWith('.html') ? [p] : [];
  });
}

// `dist/a/b/index.html` is served as `/a/b/`, any other file under its own name.
function urlOf(file) {
  const rel = relative(dist, file).split(sep).join('/');
  return '/' + (rel.endsWith('index.html') ? rel.slice(0, -'index.html'.length) : rel);
}

// `&amp;` last, so `&amp;lt;` stays `&lt;`.
const unescape = (s) =>
  s.replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&');

// A malformed `%` escape is a broken link, not a crash: `null`.
const decode = (s) => {
  try {
    return decodeURIComponent(s);
  } catch {
    return null;
  }
};

const pages = new Map(); // url -> { ids, hrefs }
for (const file of htmlFiles(dist)) {
  const html = readFileSync(file, 'utf8');
  const ids = new Set([...html.matchAll(/\sid="([^"]*)"/g)].map((m) => unescape(m[1])));
  const hrefs = [...html.matchAll(/<a(?:\s[^>]*?)?\shref="([^"]*)"/g)].map((m) => unescape(m[1]));
  pages.set(urlOf(file), { ids, hrefs });
}

// The page a path lands on: `/x/` and `/x` both mean `/x/index.html`.
function target(pathname) {
  if (pages.has(pathname)) return pathname;
  const dir = pathname.endsWith('/') ? pathname : pathname + '/';
  if (pages.has(dir)) return dir;
  return null;
}

// A non-page file (an image, a stylesheet) only has to exist.
function assetExists(pathname) {
  const path = decode(pathname);
  if (path === null) return false;
  const p = join(dist, path);
  return existsSync(p) && statSync(p).isFile();
}

// Served from the same site by another build: the viewer demo
// (crates/exav-viewer, `npm run demo:build`), which www.yml copies in and
// checks for itself.
const ELSEWHERE = ['/viewer/demo/'];

const broken = [];
for (const [from, { hrefs }] of pages) {
  for (const href of hrefs) {
    if (!href || /^[a-z][a-z0-9+.-]*:/i.test(href) || href.startsWith('//')) continue;
    const url = new URL(href, 'https://site.invalid' + from);
    if (ELSEWHERE.some((p) => url.pathname.startsWith(p))) continue;
    const page = target(url.pathname);
    if (!page) {
      if (!assetExists(url.pathname)) broken.push(`${from}: ${href} (no such page)`);
      continue;
    }
    const anchor = decode(url.hash.slice(1));
    if (anchor === null) {
      broken.push(`${from}: ${href} (malformed escape in the anchor)`);
    } else if (anchor && !pages.get(page).ids.has(anchor)) {
      broken.push(`${from}: ${href} (no #${anchor} on ${page})`);
    }
  }
}

if (broken.length) {
  console.error(`${broken.length} broken internal link(s):`);
  for (const b of [...new Set(broken)].sort()) console.error(`  ${b}`);
  process.exit(1);
}
console.log(`checked internal links across ${pages.size} pages: all resolve`);
