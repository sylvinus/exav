// Builds the frame app into dist/frame/app/: the page a host serves for the
// sandboxed viewer (see ts/frame/). Run after `tsc` (scripts/build.mjs), as it
// reads dist/vite/ and dist/frame/policy.js.
//
// The frame's origin is opaque, so everything it runs is laid out here:
// - app.js and its chunks (ES modules), every engine bundled in;
// - each worker an engine starts, as a classic script at the URL the engine
//   names (a module worker cannot start there), with `import.meta.url` read
//   from `self.EXAV_SCRIPT`, which the frame sets to that URL;
// - the wasm modules beside the code that fetches them;
// - pdf.js's assets under exav-viewer/ (the copy step's layout and manifest);
// - the fonts, the stylesheet, the licences, and index.html with the policy
//   in a meta tag.
import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import * as esbuild from "esbuild";

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const out = path.join(root, "dist", "frame", "app");
const nodeModules = path.join(root, "node_modules");
const pkg = (name) => path.dirname(fs.realpathSync(path.join(nodeModules, name, "package.json")));

const { collectAssets } = await import(path.join(root, "dist", "vite", "assets.js"));
const { FRAME_CSP, OFFICE_STYLE_HASH } = await import(path.join(root, "dist", "frame", "policy.js"));

// The spreadsheet engine's stylesheet, which the policy allows by its hash:
// an engine whose stylesheet changed would be refused it.
{
  const dir = path.join(pkg("@silurus/ooxml"), "dist");
  const found = [];
  for (const f of fs.readdirSync(dir).filter((f) => f.endsWith(".js"))) {
    const m = /"data-xlsx-viewer-styles",\s*\w+\s*=\s*("(?:[^"\\]|\\.)*")/.exec(fs.readFileSync(path.join(dir, f), "utf8"));
    if (m) found.push(`sha256-${createHash("sha256").update(JSON.parse(m[1])).digest("base64")}`);
  }
  if (found.length !== 1 || found[0] !== OFFICE_STYLE_HASH) {
    console.error(`@silurus/ooxml's stylesheet hashes to ${found.join(", ") || "nothing found"}, not ${OFFICE_STYLE_HASH} (ts/frame/policy.ts)`);
    process.exit(1);
  }
}

fs.rmSync(out, { recursive: true, force: true });
fs.mkdirSync(out, { recursive: true });

const common = {
  bundle: true,
  minify: true,
  target: "es2022",
  platform: "browser",
  legalComments: "none",
  logLevel: "warning",
  plugins: [],
};

// The package's modules have no side effects on import (package.json says
// so, which esbuild applies to packages, not to this one's own files): an
// engine re-exported beside its plugin factory (`isCadSupported` beside
// `dwg`) must not be pulled into the page's first chunk.
const pure = {
  name: "pure",
  setup(build) {
    build.onResolve({ filter: /^\.\.?\// }, async (args) => {
      if (args.pluginData?.pure || !args.importer.startsWith(path.join(root, "ts"))) return undefined;
      const r = await build.resolve(args.path, { kind: args.kind, resolveDir: args.resolveDir, importer: args.importer, pluginData: { pure: true } });
      if (r.errors.length) return { errors: r.errors };
      return { ...r, sideEffects: !r.path.startsWith(path.join(root, "ts")) || /\.css$/.test(r.path) ? r.sideEffects : false };
    });
  },
};

// The page's code, engines loaded as chunks when a file needs them.
await esbuild.build({
  ...common,
  plugins: [...common.plugins, pure],
  entryPoints: { app: path.join(root, "ts", "frame", "app", "main.ts") },
  outdir: out,
  format: "esm",
  splitting: true,
  chunkNames: "[name]-[hash]",
});

// Each worker, where the code above will ask for it.
const ooxml = pkg("@silurus/ooxml");
const { assets, manifest } = collectAssets(root);
const WORKERS = [
  ["cad.worker.js", path.join(root, "ts", "cad", "cad.worker.ts")],
  ["decode.worker.js", path.join(root, "ts", "image", "decode.worker.ts")],
  ["model.worker.js", path.join(root, "ts", "model", "model.worker.ts")],
  ["pdfjs.worker.js", path.join(root, "ts", "pdf", "pdfjs.worker.ts")],
  ["ranges.worker.js", path.join(root, "ts", "archive", "ranges.worker.ts")],
  ["worker.js", path.join(pkg("@exav/unpack-wasm"), "js", "worker.js")],
  ...fs
    .readdirSync(path.join(ooxml, "dist", "assets"))
    .filter((f) => /^render-worker-[\w-]+\.js$/.test(f))
    .map((f) => [`assets/${f}`, path.join(ooxml, "dist", "assets", f)]),
];
for (const [to, from] of WORKERS) {
  await esbuild.build({
    ...common,
    entryPoints: [from],
    outfile: path.join(out, to),
    format: "iife",
    define: { "import.meta.url": "self.EXAV_SCRIPT" },
  });
}

const copy = (from, to) => {
  fs.mkdirSync(path.dirname(path.join(out, to)), { recursive: true });
  fs.copyFileSync(from, path.join(out, to));
};

// The wasm, where each module's glue resolves it from.
for (const f of ["exav_viewer_dwg_bg.wasm", "exav_viewer_image_bg.wasm", "exav_viewer_model_bg.wasm"]) copy(path.join(root, "wasm", f), f);
copy(path.join(pkg("@exav/unpack-wasm"), "pkg", "exav_unpack_wasm_bg.wasm"), "exav_unpack_wasm_bg.wasm");
for (const f of fs.readdirSync(path.join(ooxml, "dist")).filter((f) => f.endsWith(".wasm"))) copy(path.join(ooxml, "dist", f), f);

// pdf.js's assets and the manifest.
for (const a of assets) copy(a.source, `exav-viewer/${a.path}`);
fs.writeFileSync(path.join(out, "exav-viewer", "manifest.json"), JSON.stringify(manifest));

for (const f of fs.readdirSync(path.join(root, "assets", "fonts")).filter((f) => f.endsWith(".woff2"))) copy(path.join(root, "assets", "fonts", f), `fonts/${f}`);
copy(path.join(root, "ts", "react", "styles.css"), "styles.css");
copy(path.join(root, "ts", "frame", "app", "frame.css"), "frame.css");

// The licences of what is bundled, which the minifier stripped.
const ENGINES = ["pdfjs-dist", "@silurus/ooxml", "three", "@exav/unpack-wasm"];
const index = ["The frame's third-party notices.", "", "@exav/viewer: NOTICE, LICENSE, LICENSES/, fonts/"];
copy(path.join(root, "NOTICE"), "licenses/NOTICE");
copy(path.join(root, "LICENSE"), "licenses/LICENSE");
for (const f of fs.readdirSync(path.join(root, "LICENSES"))) copy(path.join(root, "LICENSES", f), `licenses/LICENSES/${f}`);
for (const f of ["OFL-1.1.txt", "NOTICE.md"]) copy(path.join(root, "assets", "fonts", f), `licenses/fonts/${f}`);
for (const name of ENGINES) {
  const dir = pkg(name);
  const meta = JSON.parse(fs.readFileSync(path.join(dir, "package.json"), "utf8"));
  const files = fs.readdirSync(dir).filter((f) => /^(licen[cs]e|notice|copying|third_party_notices)/i.test(f));
  for (const f of files) copy(path.join(dir, f), `licenses/${name}/${f}`);
  index.push(`${name} ${meta.version}: ${meta.license}${files.length ? `, ${files.map((f) => `${name}/${f}`).join(", ")}` : ""}`);
}
index.push("", "Of pdfjs-dist's wasm/, only its ICC engine (qcms, MIT; LICENSE_QCMS beside it under exav-viewer/pdfjs/) is here.");
fs.writeFileSync(path.join(out, "licenses", "README.txt"), `${index.join("\n")}\n`);

const html = `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <!-- Served with headers, the frame also gets frame-ancestors and sandbox, which a meta tag cannot carry. -->
    <meta http-equiv="Content-Security-Policy" content="${FRAME_CSP}" />
    <meta name="referrer" content="no-referrer" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <link rel="stylesheet" href="./styles.css" />
    <link rel="stylesheet" href="./frame.css" />
    <script type="module" src="./app.js"></script>
  </head>
  <body>
    <div id="root" class="exv-frame-root"></div>
  </body>
</html>
`;
fs.writeFileSync(path.join(out, "index.html"), html);

let bytes = 0;
const count = (dir) => {
  let n = 0;
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) n += count(p);
    else {
      n += 1;
      bytes += fs.statSync(p).size;
    }
  }
  return n;
};
console.log(`dist/frame/app/: ${count(out)} files, ${(bytes / 1048576).toFixed(1)} MiB`);
