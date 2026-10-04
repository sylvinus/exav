// Checks what `npm publish` would upload, before it does (`prepublishOnly`):
//
// - every `exports` target and the `bin` are in it;
// - every `new URL("...", import.meta.url)` in its JavaScript, which is how a
//   host's bundler finds the workers, wasm and fonts to emit, points at a file
//   that is in it too;
// - the notices are in it, and no test, demo or Rust source;
// - pdf.js's decoder fallbacks are in it, and nothing of OpenJPEG or PDFium;
// - the sandboxed frame app is in it, whole (dist/frame/app/);
// - the wasm modules, the frame's included, import only what their lists
//   allow (check-wasm-imports.mjs).
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const pkg = JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf8"));
const [pack] = JSON.parse(execFileSync("npm", ["pack", "--dry-run", "--json", "--ignore-scripts"], { cwd: root, encoding: "utf8" }));
const files = new Set(pack.files.map((f) => f.path));
const problems = [];
const need = (file, why) => files.has(file) || problems.push(`${file} is not packed (${why})`);

const targets = (value) => (typeof value === "string" ? [value] : Object.values(value).flatMap(targets));
for (const [key, value] of Object.entries(pkg.exports)) {
  for (const target of targets(value)) {
    const file = target.replace(/^\.\//, "");
    if (file.includes("*")) {
      const prefix = file.slice(0, file.indexOf("*"));
      if (![...files].some((f) => f.startsWith(prefix))) problems.push(`nothing is packed under ${prefix} (exports ${key})`);
    } else need(file, `exports ${key}`);
  }
}
for (const bin of Object.values(pkg.bin)) need(bin.replace(/^\.\//, ""), "bin");

const STATIC_URL = /new URL\(\s*(["'`])([^"'`]+)\1\s*,\s*import\.meta\.url\s*\)/g;
for (const file of files) {
  // The frame app is already built, never bundled by a host: what it fetches
  // is in its own directory, which the browser tests serve as published.
  if (!file.endsWith(".js") || file.startsWith("dist/frame/app/")) continue;
  const source = fs.readFileSync(path.join(root, file), "utf8");
  for (const [, , relative] of source.matchAll(STATIC_URL)) {
    need(path.posix.normalize(path.posix.join(path.posix.dirname(file), relative)), `new URL in ${file}`);
  }
}

for (const file of ["LICENSE", "NOTICE", "README.md", "LICENSES/CC0-1.0.txt", "LICENSES/Apache-2.0.txt", "assets/fonts/OFL-1.1.txt", "assets/fonts/NOTICE.md"]) need(file, "notice");

// What `@exav/viewer/vite` and `exav-viewer-assets` put in pdf.js's `wasmUrl`
// in place of its OpenJPEG and PDFium decoders (dist/vite/assets.js).
for (const file of ["wasm/openjpeg_nowasm_fallback.js", "wasm/jbig2_nowasm_fallback.js", "wasm/pdf_decoders.js", "assets/pdfjs/absent.wasm"]) need(file, "pdf.js decoders");
if (files.has("assets/pdfjs/absent.wasm") && fs.statSync(path.join(root, "assets/pdfjs/absent.wasm")).size !== 0) problems.push("assets/pdfjs/absent.wasm must be empty");
// No OpenJPEG or PDFium code: the only files named after them are the
// fallbacks, which embed exav-render's decoders, and in the frame app the
// empty .wasm pdf.js tries first.
const FRAME_PDFJS_WASM = /^dist\/frame\/app\/exav-viewer\/pdfjs\/[^/]+\/wasm-[0-9a-f]{10}\//;
for (const file of files) {
  if (!/openjpeg|jbig2|pdfium/i.test(file)) continue;
  const name = file.replace(FRAME_PDFJS_WASM, "wasm/");
  const fallback = /^wasm\/(openjpeg|jbig2)_nowasm_fallback\.js$/.test(name) && fs.readFileSync(path.join(root, file), "utf8").startsWith("// @exav/viewer: pdf.js's decoder fallback");
  const empty = FRAME_PDFJS_WASM.test(file) && /^wasm\/(openjpeg|jbig2)\.wasm$/.test(name) && fs.statSync(path.join(root, file)).size === 0;
  if (!fallback && !empty) problems.push(`${file} looks like pdf.js's OpenJPEG or PDFium build`);
}

// The frame app: its page, its policy, its code, its workers and its licences.
for (const file of ["index.html", "app.js", "styles.css", "frame.css", "cad.worker.js", "decode.worker.js", "model.worker.js", "pdfjs.worker.js", "worker.js", "exav-viewer/manifest.json", "licenses/README.txt"]) {
  need(`dist/frame/app/${file}`, "the frame app");
}
for (const file of files) {
  if (/\.test\.|(^|\/)(e2e|demo|src|ts|target)\//.test(file) || file.endsWith(".rs")) problems.push(`${file} should not be packed`);
}

execFileSync(process.execPath, [path.join(root, "scripts", "check-wasm-imports.mjs"), path.join(root, "wasm")], { stdio: "inherit" });
execFileSync(process.execPath, [path.join(root, "scripts", "check-wasm-imports.mjs"), "--all", path.join(root, "dist", "frame", "app")], { stdio: "inherit" });

if (problems.length) {
  console.error(problems.join("\n"));
  process.exit(1);
}
console.log(`${files.size} files, ${(pack.unpackedSize / 1e6).toFixed(1)} MB unpacked: the package is complete`);
