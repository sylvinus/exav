#!/usr/bin/env node
// The format registry (formats/registry.json) against the code and the docs.
//
//     node scripts/formats.mjs check      # the registry matches the code, the docs are up to date
//     node scripts/formats.mjs generate   # writes the generated parts of the docs and of the viewer
//
// What `check` compares, and with what:
//   - the extractor's `Format` enum (crates/exav-unpack/src/lib.rs): every
//     variant is in the registry, and every registry variant exists;
//   - the streaming walkers of `dispatch` (crates/exav-unpack/src/stream.rs):
//     a format is "stream" in the registry exactly when it has one;
//   - the Cargo features of exav-unpack;
//   - the scanner's `FileType::as_str` (crates/exav-core/src/filetype.rs);
//   - the viewer's `BUILTIN_ORDER` (the extensions and types of its matchers
//     are generated from the registry, below);
//   - every format the extractor reads has a reader module in
//     crates/exav-unpack/src/formats;
//   - the generated files: the summary sentences in the docs, the viewer's
//     ts/core/formats.generated.ts, and formats/code.generated.json (each
//     format's reader and the crates its feature pulls in). The site's formats
//     page reads the registry and that file when the site is built.
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
const INTERNAL_TYPES = ["graphics", "data", "normalised HTML", "normalised text", "normalised script"];

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
  const body = block(text, text.indexOf("let walk: WalkFn = match fmt"));
  return [...body.matchAll(/Format::([A-Za-z0-9]+)\s*=>\s*f::/g)].map((m) => m[1]);
}

export function unpackFeatures() {
  const section = tomlSection(read("crates/exav-unpack/Cargo.toml"), "features");
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

const READERS = "crates/exav-unpack/src/formats";

/** The module stream.rs walks each `Format` variant with. */
function streamingModules() {
  const text = read("crates/exav-unpack/src/stream.rs");
  const body = block(text, text.indexOf("let walk: WalkFn = match fmt"));
  return new Map([...body.matchAll(/Format::([A-Za-z0-9]+)\s*=>\s*f::([a-z0-9_]+)::/g)].map((m) => [m[1], m[2]]));
}

/** The extractor's reader of registry entry `f`: the module stream.rs walks it with, else the one its feature or its
 * variant names. A file, or the directory of a module in parts; `null` when there is none. */
function readerPath(f, walked) {
  const { format, feature } = f.unpack;
  const snake = format.replace(/(?<!^)(?=[A-Z])/g, "_").toLowerCase();
  for (const name of [walked.get(format), feature, snake, format.toLowerCase()]) {
    if (!name) continue;
    if (existsSync(join(repo, READERS, `${name}.rs`))) return `${READERS}/${name}.rs`;
    if (existsSync(join(repo, READERS, name, "mod.rs"))) return `${READERS}/${name}/`;
  }
  return null;
}

/** The `[name]` section of a Cargo manifest, comments removed. */
function tomlSection(toml, name) {
  const start = toml.indexOf(`\n[${name}]\n`);
  if (start < 0) throw new Error(`no [${name}] in the manifest`);
  const end = toml.indexOf("\n[", start + 1);
  return toml.slice(start, end < 0 ? undefined : end).replace(/#.*$/gm, "");
}

/** For each of exav-unpack's features, the crates it pulls in, with the features it turns on: their package names. */
function featureCrates() {
  const toml = read("crates/exav-unpack/Cargo.toml");
  const packages = new Map();
  for (const m of tomlSection(toml, "dependencies").matchAll(/^([A-Za-z0-9_-]+)\s*=\s*(.*)$/gm)) {
    packages.set(m[1], m[2].match(/package\s*=\s*"([^"]+)"/)?.[1] ?? m[1]);
  }
  const features = new Map();
  for (const m of tomlSection(toml, "features").matchAll(/^([a-z0-9][a-z0-9-]*)\s*=\s*\[([^\]]*)\]/gm)) {
    features.set(m[1], [...m[2].matchAll(/"([^"]+)"/g)].map((i) => i[1]));
  }
  const of = (name, out, seen) => {
    if (seen.has(name)) return out;
    seen.add(name);
    for (const item of features.get(name) ?? []) {
      const dep = item.startsWith("dep:") ? item.slice(4) : item.split("/")[0].replace(/\?$/, "");
      if (features.has(dep) && !item.startsWith("dep:")) of(dep, out, seen);
      else if (packages.has(dep)) out.add(packages.get(dep));
      else throw new Error(`exav-unpack's feature ${name}: ${item} is neither a feature nor a dependency`);
    }
    return out;
  };
  return new Map([...features.keys()].map((name) => [name, [...of(name, new Set(), new Set())].sort()]));
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
  const walked = streamingModules();
  const features = unpackFeatures();
  const byFormat = new Map();
  for (const f of registry.formats) {
    if (!f.unpack) continue;
    const { format, feature, read } = f.unpack;
    if (!variants.includes(format)) add(`format ${f.id}: no Format::${format} in exav-unpack`);
    if (feature !== null && !features.has(feature)) add(`format ${f.id}: exav-unpack has no feature ${feature}`);
    if ((feature !== null || read !== "reported") && !readerPath(f, walked)) {
      add(`format ${f.id}: no reader module for Format::${format} in ${READERS}`);
    }
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

  // The generated files.
  for (const [file, want] of Object.entries(generated())) {
    if (!existsSync(join(repo, file)) || read(file) !== want) out.push(`${file} is out of date: run node scripts/formats.mjs generate`);
  }
  for (const { file, terms } of registry.summaries.checks ?? []) {
    const text = read(file).toLowerCase();
    for (const t of terms) if (!text.includes(t.toLowerCase())) add(`${file} does not mention ${t}`);
  }
  return out;
}

// ── Generated files ──────────────────────────────────────────────────────────
// The site's formats page reads the registry itself when it is built
// (www/src/components/FormatTable.astro), with formats/code.generated.json.

const VIEWER_MODULE = "crates/exav-viewer/ts/core/formats.generated.ts";
const WIDTH = 120;

/** `items` as a TypeScript array of strings, wrapped at WIDTH columns when `indent` and the line would pass it. */
function stringList(items, indent) {
  if (!items.length) return "[]";
  const quoted = items.map((s) => JSON.stringify(s));
  const inline = `[${quoted.join(", ")}]`;
  if (indent.length + "extensions: ".length + inline.length + 1 <= WIDTH) return inline;
  const rows = [];
  let row = "";
  for (const s of quoted) {
    if (row && indent.length + 2 + row.length + 2 + s.length + 1 > WIDTH) {
      rows.push(row);
      row = s;
    } else row = row ? `${row}, ${s}` : s;
  }
  rows.push(row);
  return `[\n${rows.map((r) => `${indent}  ${r},`).join("\n")}\n${indent}]`;
}

/** The viewer's module of names and types: one record per registry entry that has a viewer plugin. */
function viewerModule() {
  const out = [
    "// Generated by scripts/formats.mjs from formats/registry.json. Do not edit:",
    "// change the registry and run `node scripts/formats.mjs generate`.",
    'import type { BuiltinFormat } from "./types.js";',
    "",
    "/** The extensions and types of a registry entry, and the plugin that opens it. */",
    "export interface Registered {",
    "  readonly plugin: BuiltinFormat;",
    "  readonly extensions: readonly string[];",
    "  readonly types: readonly string[];",
    "}",
    "",
    "/** The registry entries the viewer opens, by id. */",
    "export const REGISTERED: Readonly<Record<string, Registered>> = {",
  ];
  for (const f of registry.formats) {
    if (!f.viewer) continue;
    out.push(`  ${JSON.stringify(f.id)}: {`);
    out.push(`    plugin: ${JSON.stringify(f.viewer)},`);
    out.push(`    extensions: ${stringList(f.ext, "    ")},`);
    out.push(`    types: ${stringList(f.mime, "    ")},`);
    out.push("  },");
  }
  out.push("};", "");
  return out.join("\n");
}

const CODE = "formats/code.generated.json";

/** The site's table of where each format's code is: per registry entry the extractor reads, its reader module and
 * the crates its feature pulls in. */
function codeTable() {
  const walked = streamingModules();
  const crates = featureCrates();
  const formats = {};
  for (const f of registry.formats) {
    if (!f.unpack) continue;
    const reader = readerPath(f, walked);
    const used = f.unpack.feature === null ? [] : (crates.get(f.unpack.feature) ?? []);
    if (reader || used.length) formats[f.id] = { reader, crates: used };
  }
  const about =
    "Generated by scripts/formats.mjs from formats/registry.json, exav-unpack's stream.rs and Cargo.toml: " +
    "the reader of each format the extractor reads, and the crates its feature pulls in. Do not edit: " +
    "run node scripts/formats.mjs generate.";
  return `${JSON.stringify({ about, formats }, null, 2)}\n`;
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
  const out = {};
  for (const file of registry.summaries.files ?? []) {
    out[file] = withBlock(read(file), "viewer-summary", registry.summaries.viewer);
  }
  out[VIEWER_MODULE] = viewerModule();
  out[CODE] = codeTable();
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
