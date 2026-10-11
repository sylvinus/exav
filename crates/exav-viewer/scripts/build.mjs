// Builds dist/ from ts/ with tsc, copies the stylesheet, then builds the
// frame app into dist/frame/app/ (build-frame.mjs). The wasm modules (wasm/,
// from scripts/build-wasm.sh) and the fonts (assets/) are shipped from the
// package root, where dist's `new URL(..., import.meta.url)` point.
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const tsc = path.join(root, "node_modules", "typescript", "bin", "tsc");

for (const f of [
  "exav_viewer_image.js",
  "exav_viewer_image_bg.wasm",
  "exav_viewer_dwg.js",
  "exav_viewer_dwg_bg.wasm",
  "exav_viewer_model.js",
  "exav_viewer_model_bg.wasm",
  "openjpeg_nowasm_fallback.js",
  "jbig2_nowasm_fallback.js",
  "pdf_decoders.js",
]) {
  if (!fs.existsSync(path.join(root, "wasm", f))) {
    console.error(`wasm/${f} is missing: run npm run build:wasm first`);
    process.exit(1);
  }
}

fs.rmSync(path.join(root, "dist"), { recursive: true, force: true });
execFileSync(process.execPath, [tsc, "-p", path.join(root, "tsconfig.build.json")], { stdio: "inherit" });
fs.copyFileSync(path.join(root, "ts", "react", "styles.css"), path.join(root, "dist", "react", "styles.css"));
fs.chmodSync(path.join(root, "dist", "vite", "cli.js"), 0o755);
execFileSync(process.execPath, [path.join(root, "scripts", "build-frame.mjs")], { stdio: "inherit" });
console.log("dist/ built");
