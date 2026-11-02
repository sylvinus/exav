#!/usr/bin/env node
// Writes ../examples.json from catalog.json and the files in ../files/.
//
//     node generate/make-manifest.mjs
//
// catalog.json lists what each example is (title, features, author, licence,
// where it came from); this script adds what the bytes say (size, SHA-256) and
// fills the facts that every generated file shares. A file that is fetched and
// not committed keeps the size and hash the catalog gives.
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.join(here, "..");
const REPO = "https://github.com/sylvinus/exav/blob/main/crates/exav-viewer/demo/examples";

const catalog = JSON.parse(fs.readFileSync(path.join(here, "catalog.json"), "utf8"));
const examples = [];
const seen = new Set();

for (const block of catalog.blocks) {
  for (const f of block.files) {
    const e = { file: f.file, group: f.group ?? block.group, family: f.family ?? block.family, title: f.title };
    if (f.features) e.features = f.features;
    const kind = f.source ?? block.source;
    if (kind === "generated") {
      const script = f.gen ?? block.gen;
      const e0 = { script: `generate/${script}`, args: f.args ?? block.args ?? [] };
      const tools = f.tools ?? block.tools;
      if (tools) e0.tools = tools;
      Object.assign(e, {
        path: `${f.dir ?? block.dir}/${f.file}`,
        committed: true,
        author: f.author ?? "exav project",
        source: `${REPO}/generate/${script}`,
        evidence: `${REPO}/generate/${script}`,
        evidence_quote: "Output: CC0-1.0, a public domain dedication by the exav project.",
        licence: "CC0-1.0",
        attribution: "",
        generated: e0,
      });
    } else {
      // A `ref` names facts that several files share (the author, the page that states the licence, ...).
      const ref = f.ref ?? block.ref;
      if (ref && !catalog.refs?.[ref]) throw new Error(`${f.file}: unknown ref ${ref}`);
      const g = { ...(ref ? catalog.refs[ref] : {}), ...f };
      for (const k of ["author", "source", "evidence", "evidence_quote", "licence", "attribution"]) {
        if (g[k] === undefined) throw new Error(`${f.file}: no ${k}`);
        e[k] = g[k];
      }
      for (const k of ["fetched", "fixture", "generated"]) if (g[k] !== undefined) e[k] = g[k];
      if (g.derived) e.derived = g.derived;
      if (g.evidence_row) e.evidence_row = g.evidence_row;
      if (f.path) {
        e.path = f.path;
        e.committed = true;
      } else {
        e.committed = false;
      }
    }
    if (seen.has(e.file)) throw new Error(`${e.file}: listed twice`);
    seen.add(e.file);
    if (e.committed) {
      const data = fs.readFileSync(path.join(root, "files", e.path));
      e.bytes = data.length;
      e.sha256 = crypto.createHash("sha256").update(data).digest("hex");
    } else {
      if (!f.bytes || !f.sha256) throw new Error(`${f.file}: a fetched file needs bytes and sha256 in the catalog`);
      e.bytes = f.bytes;
      e.sha256 = f.sha256;
    }
    examples.push(e);
  }
}

const out = { version: 1, examples };
fs.writeFileSync(path.join(root, "examples.json"), `${JSON.stringify(out, null, 2)}\n`);
const committed = examples.filter((e) => e.committed);
const total = (list) => list.reduce((n, e) => n + e.bytes, 0);
console.log(`${examples.length} examples: ${committed.length} committed (${total(committed)} bytes), ${examples.length - committed.length} fetched (${total(examples.filter((e) => !e.committed))} bytes)`);
