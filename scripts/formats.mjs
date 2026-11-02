#!/usr/bin/env node
// The format registry (formats/registry.json) against the code and the docs.
//
//     node scripts/formats.mjs check      # the registry matches the code, the docs are up to date
//     node scripts/formats.mjs generate   # writes the generated parts of the docs
//
// What `check` compares, and with what:
//   - the extractor's `Format` enum (crates/exav-unpack/src/lib.rs): every
//     variant is in the registry, and every registry variant exists;
//   - the streaming walkers of `dispatch` (crates/exav-unpack/src/stream.rs):
//     a format is "stream" in the registry exactly when it has one;
//   - the Cargo features of exav-unpack;
//   - the scanner's `FileType::as_str` (crates/exav-core/src/filetype.rs);
//   - the viewer's `BUILTIN_ORDER` (the matchers themselves are compared by the
//     viewer's own test, ts/core/registry.test.ts) ;
//   - the generated docs: the matrix page and the summary sentences.
// The detection of the scanner is compared by a Rust test
// (crates/exav-core/tests/suites/format_registry.rs). No dependencies.
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const repo = join(dirname(fileURLToPath(import.meta.url)), "..");
const read = (p) => readFileSync(join(repo, p), "utf8");
export const registry = JSON.parse(read("formats/registry.json"));

const KINDS = Object.keys(registry.kinds);
const SCAN_MODES = Object.keys(registry.scanModes);
const READS = ["stream", "members", "whole", "reported"];
/** FileType values that type no file on their own. */
const INTERNAL_TYPES = ["graphics", "data", "normalised HTML", "normalised text"];

// ── Checks ───────────────────────────────────────────────────────────────────

/** The text between `start` and the matching closing brace of the block opening at it. */
function block(text, start) {
  const open = text.indexOf("{", start);
  let depth = 0;
  for (let i = open; i < text.length; i++) {
    if (text[i] === "{") depth++;
    else if (text[i] === "}" && --depth === 0) return text.slice(open + 1, i);
  }
  throw new Error("unbalanced braces");
}

export function rustFormats() {
  const lib = read("crates/exav-unpack/src/lib.rs");
  const body = block(lib, lib.indexOf("pub enum Format"));
  return [...body.matchAll(/^\s{4}([A-Z][A-Za-z0-9]*),/gm)].map((m) => m[1]);
}

export function streamingFormats() {
  const text = read("crates/exav-unpack/src/stream.rs");
  const body = block(text, text.indexOf("let walk: WalkFn<T> = match fmt"));
  return [...body.matchAll(/Format::([A-Za-z0-9]+)\s*=>\s*f::/g)].map((m) => m[1]);
}

export function unpackFeatures() {
  const toml = read("crates/exav-unpack/Cargo.toml");
  const section = toml.slice(toml.indexOf("[features]"));
  return new Set([...section.matchAll(/^([a-z0-9][a-z0-9-]*)\s*=/gm)].map((m) => m[1]));
}

export function scannerTypes() {
  const text = read("crates/exav-core/src/filetype.rs");
  const body = block(text, text.indexOf("pub fn as_str(self)"));
  return [...body.matchAll(/FileType::[A-Za-z0-9]+\s*=>\s*"([^"]+)"/g)].map((m) => m[1]);
}

export function viewerPlugins() {
  const text = read("crates/exav-viewer/ts/core/formats.ts");
  const start = text.indexOf("export const BUILTIN_ORDER");
  return [...text.slice(start, text.indexOf("];", start)).matchAll(/"([a-z0-9]+)"/g)].map((m) => m[1]);
}

export function problems() {
  const out = [];
  const add = (m) => out.push(m);
  const ids = new Set();
  const exts = new Map();
  for (const f of registry.formats) {
    const where = `format ${f.id}`;
    if (!/^[a-z0-9][a-z0-9-]*$/.test(f.id ?? "")) add(`${where}: the id is lower-case words`);
    if (ids.has(f.id)) add(`${where}: duplicate id`);
    ids.add(f.id);
    if (typeof f.name !== "string" || !f.name) add(`${where}: no name`);
    if (!KINDS.includes(f.kind)) add(`${where}: kind ${f.kind} is none of ${KINDS.join(", ")}`);
    if (!Array.isArray(f.ext) || !Array.isArray(f.mime)) add(`${where}: ext and mime are lists`);
    for (const e of f.ext ?? []) {
      if (e !== e.toLowerCase() || !(e.startsWith(".") || e === "winmail.dat")) add(`${where}: extension ${e} is lower case with its dot`);
      if (exts.has(e)) add(`${where}: extension ${e} is also ${exts.get(e)}'s`);
      exts.set(e, f.id);
    }
    for (const alt of f.magic ?? []) {
      if (!Array.isArray(alt) || !alt.length || !alt.every((c) => /^\d+:([0-9a-f]{2})+$/.test(c))) add(`${where}: magic is a list of alternatives, each offset:hex conditions`);
    }
    if (!f.scan || !SCAN_MODES.includes(f.scan.mode) || !("type" in f.scan)) add(`${where}: scan is { type, mode }`);
    if (f.unpack !== null && f.unpack !== undefined) {
      if (!READS.includes(f.unpack.read)) add(`${where}: unpack.read is ${READS.join(", ")}`);
    } else if (f.unpack === undefined) add(`${where}: unpack is null or an object`);
    if (f.viewer === undefined) add(`${where}: viewer is a plugin id or null`);
  }

  // The extractor.
  const variants = rustFormats();
  const stream = new Set(streamingFormats());
  const features = unpackFeatures();
  const byFormat = new Map();
  for (const f of registry.formats) {
    if (!f.unpack) continue;
    const { format, feature, read } = f.unpack;
    if (!variants.includes(format)) add(`format ${f.id}: no Format::${format} in exav-unpack`);
    if (feature !== null && !features.has(feature)) add(`format ${f.id}: exav-unpack has no feature ${feature}`);
    const reads = byFormat.get(format) ?? new Set();
    reads.add(read);
    byFormat.set(format, reads);
    const walks = read === "stream" || read === "members";
    if (walks && !stream.has(format)) add(`format ${f.id}: Format::${format} has no walker in stream.rs`);
    if (!walks && stream.has(format)) add(`format ${f.id}: Format::${format} has a walker in stream.rs, the registry says ${read}`);
  }
  for (const v of variants) if (!byFormat.has(v)) add(`Format::${v} is in no registry entry`);
  for (const [format, reads] of byFormat) if (reads.size > 1) add(`Format::${format} is read ${[...reads].join(" and ")} in different entries`);
  for (const s of stream) if (!variants.includes(s)) add(`stream.rs walks Format::${s}, which does not exist`);

  // The scanner.
  const types = new Set(scannerTypes());
  const used = new Set();
  for (const f of registry.formats) {
    const t = f.scan?.type;
    if (t == null) continue;
    used.add(t);
    if (!types.has(t)) add(`format ${f.id}: exav-core has no file type "${t}"`);
  }
  for (const t of types) if (!used.has(t) && !INTERNAL_TYPES.includes(t)) add(`exav-core's file type "${t}" is in no registry entry`);

  // The viewer.
  const plugins = viewerPlugins();
  const claimed = new Set();
  for (const f of registry.formats) {
    if (!f.viewer) continue;
    claimed.add(f.viewer);
    if (!plugins.includes(f.viewer)) add(`format ${f.id}: the viewer has no plugin ${f.viewer}`);
  }
  for (const p of plugins) if (!claimed.has(p)) add(`the viewer's plugin ${p} is in no registry entry`);

  // The docs.
  for (const [file, want] of Object.entries(generated())) {
    if (!existsSync(join(repo, file)) || read(file) !== want) out.push(`${file} is out of date: run node scripts/formats.mjs generate`);
  }
  for (const { file, terms } of registry.summaries.checks ?? []) {
    const text = read(file).toLowerCase();
    for (const t of terms) if (!text.includes(t.toLowerCase())) add(`${file} does not mention ${t}`);
  }
  return out;
}

// ── Generated docs ───────────────────────────────────────────────────────────

const scanText = (f) => ({ container: "Opened, members scanned", reported: "Reported, not opened", view: "Scanned with its text", type: "Typed, signatures applied", none: "Bytes only" })[f.scan.mode];

const unpackText = (f) => {
  if (!f.unpack) return "No";
  return { stream: "Streamed", members: "Read whole, members streamed", whole: "Read whole", reported: "Recognised, reported" }[f.unpack.read];
};

const viewerText = (f) => (f.viewer ? `\`${f.viewer}\`` : "No");

const escapeCell = (s) => s.replaceAll("|", "\\|");

function matrix() {
  const lines = [
    "---",
    "title: Format matrix",
    "description: Which of exav's tools reads each file format, the scanner, the extractor or the viewer, and whether the extractor streams it or reads it whole.",
    "---",
    "",
    "<!-- Generated from formats/registry.json by scripts/formats.mjs: edit the registry. -->",
    "",
    "One table for \"can exav handle my file\": for each format, what the",
    "[scanner](/scanner/reference/formats/) does with it, whether the",
    "[extractor](/unpack/formats/) streams it or reads it whole (a format read",
    "whole is held in memory up to the buffer limit), and which plugin of the",
    "[viewer](/viewer/) opens it. The pages of each tool have the detail:",
    "codecs, encryption, limits.",
    "",
    "- **Scanner.** " + Object.entries(registry.scanModes).map(([, d]) => d).join("; ") + ".",
    "- **Extractor.** *Streamed*: the members are decoded as they are read, at any size. *Read whole*: the container is read into memory first; *members streamed* says the members then come out one at a time. *Recognised, reported*: the format is told apart and the file is reported as not examined, never clean.",
    "- **Viewer.** The plugin, as `@exav/viewer` names it. *No*: the viewer does not open it.",
    "",
  ];
  for (const [kind, title] of Object.entries(registry.kinds)) {
    const rows = registry.formats.filter((f) => f.kind === kind);
    if (!rows.length) continue;
    lines.push(`## ${title}`, "", "| Format | Extensions | Scanner | Extractor | Viewer |", "|---|---|---|---|---|");
    for (const f of rows) {
      const ext = f.ext.length ? f.ext.map((e) => `\`${e}\``).join(" ") : "";
      lines.push(`| ${escapeCell(f.name)} | ${ext} | ${scanText(f)} | ${unpackText(f)} | ${viewerText(f)} |`);
    }
    lines.push("");
  }
  return lines.join("\n");
}

/** `text` with what lies between the markers of `name` replaced. */
export function withBlock(text, name, body) {
  const start = `<!-- formats:${name} -->`;
  const end = `<!-- /formats:${name} -->`;
  const a = text.indexOf(start);
  const b = text.indexOf(end);
  if (a < 0 || b < a) throw new Error(`no ${start} ... ${end} in the file`);
  return text.slice(0, a + start.length) + body + text.slice(b);
}

/** The files this script writes, and what they hold. */
export function generated() {
  const out = { "www/src/content/docs/project/formats.md": matrix() };
  for (const file of registry.summaries.files ?? []) {
    out[file] = withBlock(read(file), "viewer-summary", registry.summaries.viewer);
  }
  return out;
}

// ── Main ─────────────────────────────────────────────────────────────────────

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const mode = process.argv[2];
  if (mode === "generate") {
    for (const [file, text] of Object.entries(generated())) writeFileSync(join(repo, file), text);
  } else if (mode === "check") {
    const found = problems();
    for (const p of found) console.error(`formats: ${p}`);
    if (found.length) process.exit(1);
    console.log(`formats: ${registry.formats.length} formats, registry and docs agree`);
  } else {
    console.error("usage: node scripts/formats.mjs check | generate");
    process.exit(2);
  }
}
