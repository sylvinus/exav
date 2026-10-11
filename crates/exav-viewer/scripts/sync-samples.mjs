#!/usr/bin/env node
// Copy the demo's sample files from the exav-samples repository into
// demo/public/showcase/ (not committed), checking each against the size and
// SHA-256 its viewer/samples.json gives.
//
//     npm run demo:showcase                          # clone github.com/sylvinus/exav-samples, HEAD
//     EXAV_SAMPLES=/path/to/exav-samples npm run demo:showcase   # a local checkout
import { execFileSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const REPO = "https://github.com/sylvinus/exav-samples";
const out = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "demo", "public", "showcase");

let checkout = process.env.EXAV_SAMPLES;
let clone = null;
if (!checkout) {
  clone = fs.mkdtempSync(path.join(os.tmpdir(), "exav-samples-"));
  execFileSync("git", ["clone", "--quiet", "--depth", "1", REPO, clone], { stdio: "inherit" });
  checkout = clone;
}

try {
  const from = path.join(checkout, "viewer");
  const { samples } = JSON.parse(fs.readFileSync(path.join(from, "samples.json"), "utf8"));
  const bad = [];
  for (const s of samples) {
    if (s.file !== path.basename(s.file)) bad.push(`${s.file}: not a plain file name`);
    const data = fs.readFileSync(path.join(from, s.file));
    const sha256 = crypto.createHash("sha256").update(data).digest("hex");
    if (data.length !== s.bytes || sha256 !== s.sha256) bad.push(`${s.file}: ${data.length} bytes, sha256 ${sha256}`);
  }
  if (bad.length) throw new Error(`files that do not match samples.json:\n  ${bad.join("\n  ")}`);

  // Whole files, into an emptied folder: what was there before is replaced.
  // A FUSE mount keeps a deleted file that is still open as `.fuse_hidden*`
  // until it is closed, and refuses to remove it: left alone.
  fs.mkdirSync(out, { recursive: true });
  for (const f of fs.readdirSync(out)) {
    if (!f.startsWith(".fuse_hidden")) fs.rmSync(path.join(out, f), { recursive: true, force: true });
  }
  for (const s of samples) fs.copyFileSync(path.join(from, s.file), path.join(out, s.file));
  fs.copyFileSync(path.join(from, "samples.json"), path.join(out, "samples.json"));
  console.log(`${samples.length} samples in ${path.relative(process.cwd(), out) || "."}`);
} finally {
  if (clone) fs.rmSync(clone, { recursive: true, force: true });
}
