#!/usr/bin/env node
// Checks demo/examples/examples.json against the files:
//
//     node demo/examples/check.mjs            # the manifest and files/
//     node demo/examples/check.mjs --public   # also demo/public/examples/ (after `npm run demo:examples`)
//
// Fails (exit 1) on a missing field, a licence that is not allowed, a missing
// attribution, a file whose size or SHA-256 differs, a file in files/ that the
// manifest does not list, a group the demo does not know, or a script that is
// not there.
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const pkg = path.join(here, "..", "..");
const repo = path.join(pkg, "..", "..");
const withPublic = process.argv.includes("--public");

const manifest = JSON.parse(fs.readFileSync(path.join(here, "examples.json"), "utf8"));
const problems = [];
const bad = (file, msg) => problems.push(`${file}: ${msg}`);

// Public domain, CC0, CC-BY, and MIT, BSD and Apache test files. No share-alike or copyleft licence.
const SPDX = /^(CC0-1\.0|CC-BY-(1\.0|2\.0|2\.5|3\.0|4\.0)|MIT|BSD-2-Clause|BSD-3-Clause|Apache-2\.0)$/;
const NEEDS_ATTRIBUTION = /^(CC-BY|MIT|BSD|Apache)/;
const REFUSED = /\b(GPL|LGPL|AGPL|MPL|NC|ND|non-?commercial|no derivatives)\b/i;

const groups = new Set([...fs.readFileSync(path.join(pkg, "demo", "src", "showcase.ts"), "utf8").matchAll(/^\s+(?:"([\w-]+)"|(\w+)): \{ en: /gm)].map((m) => m[1] ?? m[2]));

const sha256 = (data) => crypto.createHash("sha256").update(data).digest("hex");
const isUrl = (s) => typeof s === "string" && /^https:\/\/[^\s]+$/.test(s);
const names = new Set();
const paths = new Set();
let committedBytes = 0;
let fetchedBytes = 0;

for (const e of manifest.examples) {
  const f = e.file ?? "(no file)";
  for (const k of ["file", "group", "family", "title", "author", "source", "evidence", "evidence_quote", "licence", "sha256"]) {
    if (typeof e[k] !== "string" || !e[k].trim()) bad(f, `no ${k}`);
  }
  if (typeof e.attribution !== "string") bad(f, "no attribution (use \"\" when the licence asks for none)");
  if (!Number.isInteger(e.bytes) || e.bytes <= 0) bad(f, "no bytes");
  if (typeof e.committed !== "boolean") bad(f, "no committed flag");
  if (names.has(e.file)) bad(f, "listed twice");
  names.add(e.file);
  if (e.file && e.file !== path.basename(e.file)) bad(f, "not a plain file name");
  if (e.group && !groups.has(e.group)) bad(f, `group ${e.group} is not in demo/src/showcase.ts`);
  if (!isUrl(e.source)) bad(f, "source is not an https URL");
  if (!isUrl(e.evidence)) bad(f, "evidence is not an https URL");
  if (e.sha256 && !/^[0-9a-f]{64}$/.test(e.sha256)) bad(f, "sha256 is not 64 hex digits");

  const lic = e.licence ?? "";
  if (!SPDX.test(lic) && !/^public-domain \(.{8,}\)$/.test(lic)) bad(f, `licence "${lic}" is not allowed (use an SPDX id of the list, or "public-domain (reason)")`);
  if (REFUSED.test(lic)) bad(f, `licence "${lic}" is refused`);
  if (NEEDS_ATTRIBUTION.test(lic) && !(e.attribution ?? "").trim()) bad(f, `${lic} needs an attribution line`);
  if (e.attribution && /—|load-bearing|genuinely/i.test(e.attribution + e.title)) bad(f, "dash or AI wording in the credit");

  const origins = ["generated", "fetched", "fixture"].filter((k) => e[k] !== undefined);
  if (!origins.length) bad(f, "none of generated, fetched, fixture");
  if (e.generated) {
    if (typeof e.generated.script !== "string" || !Array.isArray(e.generated.args)) bad(f, "generated needs a script and its args");
    else if (!fs.existsSync(path.join(here, e.generated.script))) bad(f, `script ${e.generated.script} is missing`);
  }
  if (e.fetched !== undefined && !isUrl(e.fetched)) bad(f, "fetched is not an https URL");
  if (e.fixture !== undefined && !fs.existsSync(path.join(repo, e.fixture))) bad(f, `fixture ${e.fixture} is not in the repository`);
  if (!e.committed && !isUrl(e.fetched)) bad(f, "not committed and not fetched: nothing to serve");

  if (e.committed) {
    if (!e.path) {
      bad(f, "committed without a path");
      continue;
    }
    paths.add(path.normalize(e.path));
    const p = path.join(here, "files", e.path);
    if (!fs.existsSync(p)) {
      bad(f, `files/${e.path} is missing`);
      continue;
    }
    const data = fs.readFileSync(p);
    if (data.length !== e.bytes) bad(f, `files/${e.path} is ${data.length} bytes, the manifest says ${e.bytes}`);
    if (sha256(data) !== e.sha256) bad(f, `files/${e.path} has sha256 ${sha256(data)}, the manifest says ${e.sha256}`);
    if (path.basename(e.path) !== e.file) bad(f, "path and file name differ");
    if (data.length > 1_000_000) bad(f, `committed file of ${data.length} bytes: over 1 MB goes by download`);
    committedBytes += data.length;
  } else {
    if (e.bytes > 12_000_000) bad(f, `fetched file of ${e.bytes} bytes is too large`);
    fetchedBytes += e.bytes;
  }

  if (withPublic) {
    const p = path.join(pkg, "demo", "public", "examples", e.file);
    if (fs.existsSync(p)) {
      const data = fs.readFileSync(p);
      if (data.length !== e.bytes || sha256(data) !== e.sha256) bad(f, `demo/public/examples/${e.file} does not match the manifest`);
    } else if (e.committed) {
      bad(f, `demo/public/examples/${e.file} is missing: run npm run demo:examples`);
    }
  }
}

// Every file under files/ is listed.
const listed = (dir, base = "") =>
  fs.readdirSync(path.join(dir, base), { withFileTypes: true }).flatMap((d) => (d.isDirectory() ? listed(dir, path.join(base, d.name)) : [path.join(base, d.name)]));
const filesDir = path.join(here, "files");
if (fs.existsSync(filesDir)) for (const p of listed(filesDir)) if (!paths.has(path.normalize(p))) bad(p, "in files/ but not in the manifest");

if (problems.length) {
  console.error(`${problems.length} problem${problems.length === 1 ? "" : "s"} in demo/examples/examples.json:\n  ${problems.join("\n  ")}`);
  process.exit(1);
}
console.log(`${manifest.examples.length} examples ok: ${committedBytes} bytes committed, ${fetchedBytes} bytes fetched`);
