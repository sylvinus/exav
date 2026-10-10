// Fails when a built bundle (the frame app, the demo) holds a sink that is
// not one of the known, reviewed occurrences below: what a dependency update
// that starts writing markup or compiling strings would add. The bundles are
// minified, so each occurrence is matched by the code around it (60
// characters on each side), not by file name or line. An entry that matches
// nothing in any bundle fails too, so the list follows the dependencies.
//
// Usage: node scripts/check-bundle-sinks.mjs <dir>...
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

/** What is searched for, in minified code. */
export const SINKS = /\binnerHTML\b|\bouterHTML\b|insertAdjacentHTML|document\.write|createContextualFragment|\bsrcdoc\b|\beval\(|\bFunction\(|javascript:|importScripts|parseFromString|setHTMLUnsafe|dangerouslySetInnerHTML/g;

/** The reviewed occurrences: which sink, the code around it, and why it is safe. */
export const ALLOWED = [
  { sink: "innerHTML", around: /\binnerHTML=""/, why: "an element cleared (@silurus/ooxml, React)" },
  {
    sink: "innerHTML",
    around: /\.innerHTML=`<svg width="\$\{\w+\}" height="\$\{\w+\}" viewBox="0 0 10 6"/,
    why: "@silurus/ooxml: the spreadsheet's validation arrow, a constant SVG sized by a number",
  },
  { sink: "innerHTML", around: /\.innerHTML='<svg viewBox="0 0 24 24" width="100%" height="100%" aria-h/, why: "@silurus/ooxml: the comment icon, a constant SVG" },
  { sink: "innerHTML", around: /\.innerHTML="<script><\\\/script>"/, why: "React: makes an inert script element to clone" },
  { sink: "innerHTML", around: /__html!==\w+&&\(\w+\.innerHTML=\w+\)/, why: "React: dangerouslySetInnerHTML, which no component of the package uses (check-sinks.mjs)" },
  { sink: "innerHTML", around: /case"innerHTML":/, why: "React: a prop name it skips" },
  { sink: "dangerouslySetInnerHTML", around: /"dangerouslySetInnerHTML"|\.dangerouslySetInnerHTML[=!.]/, why: "React: its own handling of the prop, unused by the package" },
  { sink: "javascript:", around: /"javascript:throw new Error\('(React has blocked a javascript: URL|A React form was unexpectedly submitted)/, why: "React: the URLs it puts in place of a javascript: URL" },
  { sink: "Function(", around: /`Function\(\$\{\w+\}\)`/, why: "wasm-bindgen's debug string of a function: text" },
  { sink: "importScripts", around: /importScripts\(p \? p\.createScriptURL\(\$\{/, why: "@exav/viewer's frame: the text of a worker's blob (ts/frame/app/workers.ts)" },
  { sink: "parseFromString", around: /parseFromString\(\w+\)\{if\(this\._currentFragment=\[\]/, why: "pdf.js's own XML parser, a method of its class: no DOM" },
  { sink: "parseFromString", around: /new \w+\(\{(lowerCaseName|hasAttributes):!0\}\)\.parseFromString\(/, why: "pdf.js's own XML parser" },
  { sink: "parseFromString", around: /\w+\.parseFromString\(\w+\["xdp:xdp"\]\)/, why: "pdf.js's own XML parser (XFA, which is off)" },
  { sink: "parseFromString", around: /case"document":return \w+\.text\(\)\.then\(\w+=>new DOMParser\(\)\.parseFromString\(\w+,\w+\)\)/, why: "three's FileLoader for responseType document, which no loader the package uses asks for" },
];

const WINDOW = 60;

/** Whether `pattern` matches, in `text`, a stretch that covers [from, to). */
function covers(pattern, text, from, to) {
  const all = new RegExp(pattern.source, pattern.flags.includes("g") ? pattern.flags : `${pattern.flags}g`);
  for (const r of text.matchAll(all)) if (r.index <= from && r.index + r[0].length >= to) return true;
  return false;
}

/** Every occurrence in `files` ({ path, text }), with the entry that allows it, if any. */
export function scan(files, allowed = ALLOWED) {
  const out = [];
  for (const f of files) {
    SINKS.lastIndex = 0;
    let m;
    while ((m = SINKS.exec(f.text))) {
      const start = Math.max(0, m.index - WINDOW);
      const around = f.text.slice(start, m.index + m[0].length + WINDOW);
      // The entry's code must be this occurrence's, not a neighbour's.
      const at = m.index - start;
      const entry = allowed.findIndex((a) => a.sink === m[0] && covers(a.around, around, at, at + m[0].length));
      out.push({ file: f.path, sink: m[0], around, entry });
    }
  }
  return out;
}

/** What fails: occurrences no entry allows, and entries nothing matched. */
export function checkBundles(files, allowed = ALLOWED) {
  const found = scan(files, allowed);
  const used = new Set(found.map((o) => o.entry));
  return { refused: found.filter((o) => o.entry < 0), stale: allowed.filter((_, i) => !used.has(i)) };
}

/** The JavaScript files under `dir`. */
export function bundleFiles(dir) {
  const out = [];
  const walk = (d) => {
    for (const e of fs.readdirSync(d, { withFileTypes: true })) {
      const p = path.join(d, e.name);
      if (e.isDirectory()) walk(p);
      else if (/\.(m?js)$/.test(e.name)) out.push({ path: path.relative(dir, p), text: fs.readFileSync(p, "utf8") });
    }
  };
  walk(dir);
  return out;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const dirs = process.argv.slice(2);
  if (!dirs.length) {
    console.error("usage: check-bundle-sinks.mjs <dir>...");
    process.exit(2);
  }
  const files = dirs.flatMap((d) => bundleFiles(d).map((f) => ({ ...f, path: path.join(d, f.path) })));
  const { refused, stale } = checkBundles(files);
  for (const o of refused) console.error(`${o.file}: ${o.sink}: …${o.around}…`);
  for (const a of stale) console.error(`allowed but not found (remove it from ALLOWED): ${a.sink}: ${a.around}`);
  if (refused.length || stale.length) {
    console.error("check-bundle-sinks: failed");
    process.exit(1);
  }
  console.log(`check-bundle-sinks: ${files.length} files, every occurrence reviewed (${scan(files).length})`);
}
