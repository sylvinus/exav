#!/usr/bin/env node
// Put the demo's example files in demo/public/examples/ (not committed): the
// small ones are copied from demo/examples/files/, the others are downloaded
// from the pinned URLs demo/examples/examples.json gives, and each is checked
// against its size and SHA-256. The licence of every file is in that manifest
// and in demo/examples/NOTICE.md.
//
//     npm run demo:examples               # copy and download
//     npm run demo:examples -- --offline  # copy only; the files that need a download are left out of the list
//
// A file already in demo/public/examples/ with the right hash is not fetched again.
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const pkg = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const from = path.join(pkg, "demo", "examples");
const out = path.join(pkg, "demo", "public", "examples");
const offline = process.argv.includes("--offline") || process.env.EXAV_EXAMPLES_OFFLINE === "1";
const USER_AGENT = "exav-examples/1.0 (https://github.com/sylvinus/exav)";

const sha256 = (data) => crypto.createHash("sha256").update(data).digest("hex");
const { examples } = JSON.parse(fs.readFileSync(path.join(from, "examples.json"), "utf8"));

async function download(url) {
  let last;
  for (let attempt = 1; attempt <= 4; attempt++) {
    try {
      const res = await fetch(url, { headers: { "User-Agent": USER_AGENT }, redirect: "follow", signal: AbortSignal.timeout(180_000) });
      if (res.ok) return Buffer.from(await res.arrayBuffer());
      last = new Error(`HTTP ${res.status}`);
      if (res.status !== 429 && res.status < 500) break;
    } catch (e) {
      last = e;
    }
    await new Promise((r) => setTimeout(r, 1500 * attempt));
  }
  throw new Error(`${url}: ${last?.message ?? last}`);
}

fs.mkdirSync(out, { recursive: true });
const bad = [];
const present = [];
let copied = 0;
let downloaded = 0;
let kept = 0;
let skipped = 0;

for (const e of examples) {
  if (e.file !== path.basename(e.file)) {
    bad.push(`${e.file}: not a plain file name`);
    continue;
  }
  const target = path.join(out, e.file);
  const check = (data, what) => {
    if (data.length === e.bytes && sha256(data) === e.sha256) return true;
    bad.push(`${e.file} (${what}): ${data.length} bytes, sha256 ${sha256(data)}`);
    return false;
  };
  if (e.committed) {
    const data = fs.readFileSync(path.join(from, "files", e.path));
    if (!check(data, "committed copy")) continue;
    fs.writeFileSync(target, data);
    copied++;
  } else {
    if (fs.existsSync(target)) {
      const data = fs.readFileSync(target);
      if (data.length === e.bytes && sha256(data) === e.sha256) {
        present.push(e);
        kept++;
        continue;
      }
    }
    if (offline) {
      skipped++;
      continue;
    }
    const url = e.fetched;
    if (typeof url !== "string") {
      bad.push(`${e.file}: neither committed nor fetched`);
      continue;
    }
    let data;
    try {
      data = await download(url);
    } catch (err) {
      bad.push(String(err.message ?? err));
      continue;
    }
    if (!check(data, url)) continue;
    fs.writeFileSync(target, data);
    downloaded++;
  }
  present.push(e);
}

if (bad.length) {
  console.error(`examples that do not match demo/examples/examples.json:\n  ${bad.join("\n  ")}`);
  process.exitCode = 1;
}

// Only what is here is listed, and what is not in the manifest any more is removed.
const names = new Set(present.map((e) => e.file));
for (const f of fs.readdirSync(out)) {
  if (f !== "examples.json" && !names.has(f) && !f.startsWith(".fuse_hidden")) fs.rmSync(path.join(out, f), { recursive: true, force: true });
}
fs.writeFileSync(path.join(out, "examples.json"), `${JSON.stringify({ version: 1, examples: present })}\n`);
console.log(`${present.length} examples in ${path.relative(process.cwd(), out) || "."}: ${copied} copied, ${downloaded} downloaded, ${kept} already there${skipped ? `, ${skipped} left out (offline)` : ""}`);
