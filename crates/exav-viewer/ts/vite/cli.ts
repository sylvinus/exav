#!/usr/bin/env node
/**
 * `exav-viewer-assets <dir> [--root <project>] [--frame <frame dir>
 * [--frame-origin <origin>] [--media-origin <origin>]... [--connect-origin
 * <origin>]...]`: copies the engines' runtime files and `manifest.json` into
 * `<dir>`, which the host serves as the viewer's `assetBase`, and with
 * `--frame` the sandboxed frame app into `<frame dir>`. `--frame-origin`:
 * where it is served from, for Safari; `--media-origin`, `--connect-origin`:
 * what its policy allows besides (see `frameCsp`). For bundlers other than
 * Vite; `@exav/viewer/vite` does the same on its own.
 */
import fs from "node:fs";
import path from "node:path";

import { frameCsp } from "../frame/policy.js";
import { collectAssets, frameFileBytes, frameFiles } from "./assets.js";

const USAGE =
  "usage: exav-viewer-assets <dir> [--root <project>] [--frame <frame dir> [--frame-origin <origin>] [--media-origin <origin>]... [--connect-origin <origin>]...]";
const REPEATED = ["--media-origin", "--connect-origin"];
const ONCE = ["--root", "--frame", "--frame-origin"];

const args = process.argv.slice(2);
const flags = new Map<string, string[]>();
const positional: string[] = [];
let bad = false;
for (let i = 0; i < args.length; i++) {
  const a = args[i]!;
  if (!a.startsWith("--")) {
    positional.push(a);
    continue;
  }
  const value = args[++i];
  const seen = flags.get(a) ?? [];
  if (!value || (!REPEATED.includes(a) && !ONCE.includes(a)) || (ONCE.includes(a) && seen.length)) bad = true;
  flags.set(a, [...seen, value ?? ""]);
}
const one = (f: string) => flags.get(f)?.[0];
const root = one("--root") ?? process.cwd();
const frameDir = one("--frame");
const frameOrigin = one("--frame-origin");
const origins = { media: flags.get("--media-origin") ?? [], connect: flags.get("--connect-origin") ?? [] };
const out = positional[0];
const frameOnly = frameOrigin || origins.media.length || origins.connect.length;
if (bad || !out || positional.length > 1 || (frameOnly && !frameDir)) {
  console.error(USAGE);
  process.exit(2);
}
let policy = "";
try {
  policy = frameCsp(frameOrigin, origins);
} catch (error) {
  console.error(`${(error as Error).message} (scheme://host[:port], lower case, no path)`);
  process.exit(2);
}

const write = (to: string, bytes: Buffer) => {
  fs.mkdirSync(path.dirname(to), { recursive: true });
  fs.writeFileSync(to, bytes);
};

const { assets, manifest } = collectAssets(root);
for (const a of assets) write(path.join(out, a.path), fs.readFileSync(a.source));
write(path.join(out, "manifest.json"), Buffer.from(JSON.stringify(manifest)));
console.log(`${assets.length} files in ${out}`);
if (frameDir) {
  const files = frameFiles();
  for (const f of files) write(path.join(frameDir, f.path), frameFileBytes(f, frameOrigin, origins));
  console.log(`${files.length} files of the frame app in ${frameDir}`);
  // The page carries the policy in a meta tag; headers must say the same.
  console.log(`The frame's Content-Security-Policy header: ${policy}; frame-ancestors <the host's origin>; sandbox allow-scripts`);
}
