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
const { ENGINES, FRAME_FORMATS_META } = await import(path.join(root, "dist", "frame", "engines.js"));

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

// What each peer package puts in the frame: bytes per file, from the bundles'
// inputs and from the files copied whole (dist/frame/files.json `packages`,
// which scripts/size-tables.mjs reads).
const packages = {};
const packageOf = (input) => {
  const m = [...input.matchAll(/node_modules\/((?:@[^/]+\/)?[^/]+)\//g)].pop();
  if (m) return m[1];
  return input.includes("exav-unpack-wasm/") ? "@exav/unpack-wasm" : null;
};
const credit = (name, file, bytes) => {
  const p = (packages[name] ??= { version: "", files: {} });
  p.files[file] = (p.files[file] ?? 0) + bytes;
};
const creditBundle = (meta) => {
  for (const [key, o] of Object.entries(meta.outputs)) {
    for (const [input, i] of Object.entries(o.inputs)) {
      const name = packageOf(input);
      if (name) credit(name, path.relative(out, path.resolve(root, key)).split(path.sep).join("/"), i.bytesInOutput);
    }
  }
};

// The page's code, engines loaded as chunks when a file needs them.
const { metafile } = await esbuild.build({
  ...common,
  plugins: [...common.plugins, pure],
  absWorkingDir: root,
  entryPoints: { app: path.join(root, "ts", "frame", "app", "main.ts") },
  outdir: out,
  format: "esm",
  splitting: true,
  chunkNames: "[name]-[hash]",
  metafile: true,
});

// Each worker, where the code above will ask for it.
const ooxml = pkg("@silurus/ooxml");
// No external converter is shipped in the package: the host's build adds
// its own from its node_modules (`frameFiles(root, name)`), licence included.
const { assets, manifest } = collectAssets(root);
const WORKERS = [
  ["cad.worker.js", path.join(root, "ts", "cad", "cad.worker.ts")],
  ["decode.worker.js", path.join(root, "ts", "image", "decode.worker.ts")],
  ["markdown.worker.js", path.join(root, "ts", "text", "markdown.worker.ts")],
  ["model.worker.js", path.join(root, "ts", "model", "model.worker.ts")],
  ["pdfjs.worker.js", path.join(root, "ts", "pdf", "pdfjs.worker.ts")],
  ["ranges.worker.js", path.join(root, "ts", "archive", "ranges.worker.ts")],
  ["sheets.worker.js", path.join(root, "ts", "office", "sheets.worker.ts")],
  ["slides.worker.js", path.join(root, "ts", "office", "slides.worker.ts")],
  ["docs.worker.js", path.join(root, "ts", "office", "docs.worker.ts")],
  ["worker.js", path.join(pkg("@exav/unpack-wasm"), "js", "worker.js")],
  ...fs
    .readdirSync(path.join(ooxml, "dist", "assets"))
    .filter((f) => /^render-worker-[\w-]+\.js$/.test(f))
    .map((f) => [`assets/${f}`, path.join(ooxml, "dist", "assets", f)]),
];
for (const [to, from] of WORKERS) {
  const { metafile: workerMeta } = await esbuild.build({
    ...common,
    absWorkingDir: root,
    metafile: true,
    entryPoints: [from],
    outfile: path.join(out, to),
    format: "iife",
    define: { "import.meta.url": "self.EXAV_SCRIPT" },
  });
  creditBundle(workerMeta);
}
creditBundle(metafile);

const copy = (from, to, peer) => {
  fs.mkdirSync(path.dirname(path.join(out, to)), { recursive: true });
  fs.copyFileSync(from, path.join(out, to));
  if (peer) credit(peer, to, fs.statSync(from).size);
};

// The wasm, where each module's glue resolves it from.
for (const f of fs.readdirSync(path.join(root, "wasm")).filter((f) => /^exav_viewer_\w+_bg\.wasm$/.test(f))) copy(path.join(root, "wasm", f), f);
copy(path.join(pkg("@exav/unpack-wasm"), "pkg", "exav_unpack_wasm_bg.wasm"), "exav_unpack_wasm_bg.wasm", "@exav/unpack-wasm");
for (const f of fs.readdirSync(path.join(ooxml, "dist")).filter((f) => f.endsWith(".wasm"))) copy(path.join(ooxml, "dist", f), f, "@silurus/ooxml");

// pdf.js's assets and the manifest.
const pdfjsDir = pkg("pdfjs-dist");
for (const a of assets) copy(a.source, `exav-viewer/${a.path}`, a.source.startsWith(`${pdfjsDir}${path.sep}`) ? "pdfjs-dist" : undefined);
fs.writeFileSync(path.join(out, "exav-viewer", "manifest.json"), JSON.stringify(manifest));

for (const f of fs.readdirSync(path.join(root, "assets", "fonts")).filter((f) => f.endsWith(".woff2"))) copy(path.join(root, "assets", "fonts", f), `fonts/${f}`);
copy(path.join(root, "ts", "react", "styles.css"), "styles.css");
copy(path.join(root, "ts", "frame", "app", "frame.css"), "frame.css");

// The licences of what is bundled, which the minifier stripped.
// What README.txt says of each package, by name: a frame published for some
// formats only (frameFiles) lists the packages of those formats' engines.
const noticeHeader = ["The frame's third-party notices.", "", "@exav/viewer: NOTICE, LICENSE, LICENSES/, fonts/"];
const notices = {};
copy(path.join(root, "NOTICE"), "licenses/NOTICE");
copy(path.join(root, "LICENSE"), "licenses/LICENSE");
for (const f of fs.readdirSync(path.join(root, "LICENSES"))) copy(path.join(root, "LICENSES", f), `licenses/LICENSES/${f}`);
for (const f of ["OFL-1.1.txt", "NOTICE.md"]) copy(path.join(root, "assets", "fonts", f), `licenses/fonts/${f}`);
for (const name of [...new Set(Object.values(ENGINES).flatMap((e) => e.notices ?? []))]) {
  const dir = pkg(name);
  const meta = JSON.parse(fs.readFileSync(path.join(dir, "package.json"), "utf8"));
  const files = fs.readdirSync(dir).filter((f) => /^(licen[cs]e|notice|copying|third_party_notices)/i.test(f));
  for (const f of files) copy(path.join(dir, f), `licenses/${name}/${f}`);
  notices[name] = [`${name} ${meta.version}: ${meta.license}${files.length ? `, ${files.map((f) => `${name}/${f}`).join(", ")}` : ""}`];
}
notices["pdfjs-dist"].push("", "Of pdfjs-dist's wasm/, only its ICC engine (qcms, MIT; LICENSE_QCMS beside it under exav-viewer/pdfjs/) is here.");
fs.writeFileSync(path.join(out, "licenses", "README.txt"), `${[...noticeHeader, ...Object.values(notices).flat()].join("\n")}\n`);

const html = `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <!-- Served with headers, the frame also gets frame-ancestors and sandbox, which a meta tag cannot carry. -->
    <meta http-equiv="Content-Security-Policy" content="${FRAME_CSP}" />
    <meta name="referrer" content="no-referrer" />
    <!-- Every format; a frame published for some says which (frameFiles). -->
    <meta name="${FRAME_FORMATS_META}" content="*" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <link rel="stylesheet" href="./styles.css" />
    <link rel="stylesheet" href="./frame.css" />
    <script type="module" src="./app.js"></script>
  </head>
  <body>
    <div id="root" class="exav-viewer-frame-root"></div>
  </body>
</html>
`;
fs.writeFileSync(path.join(out, "index.html"), html);

// ── Whose each file is ───────────────────────────────────────────────────────
// dist/frame/files.json: the files of each engine (ts/frame/engines.ts), and
// the core, which every frame needs. `frameFiles` publishes the core and the
// engines of the formats a host asks for, and nothing else. A chunk is an
// engine's when it is reached from the entry modules the table names, without
// passing through the core or another engine's entries; a file beside the
// chunks, when the table names it, or when the chunks of the engine name it
// (the Office engine's render workers).
{
  const files = [];
  const list = (dir) => {
    for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
      const p = path.join(dir, e.name);
      if (e.isDirectory()) list(p);
      else files.push(path.relative(out, p).split(path.sep).join("/"));
    }
  };
  list(out);
  const present = new Set(files);

  const chunks = new Map();
  for (const [key, o] of Object.entries(metafile.outputs)) {
    chunks.set(path.basename(key), {
      entry: o.entryPoint ?? null,
      imports: o.imports.map((i) => ({ name: path.basename(i.path), kind: i.kind })),
      inputs: Object.keys(o.inputs),
    });
  }
  // What the page loads before it knows what the file is.
  const core = new Set();
  const visit = (name) => {
    if (core.has(name)) return;
    core.add(name);
    for (const i of chunks.get(name).imports) if (i.kind === "import-statement") visit(i.name);
  };
  visit("app.js");

  const seeds = new Map();
  const owner = new Map();
  for (const [id, e] of Object.entries(ENGINES)) {
    const mine = [...chunks].filter(([name, c]) => !core.has(name) && c.entry !== null && (e.entries ?? []).some((p) => c.entry.startsWith(p))).map(([name]) => name);
    if ((e.entries ?? []).length && !mine.length) throw new Error(`engine ${id}: no chunk starts at ${e.entries.join(" or ")} (ts/frame/engines.ts)`);
    seeds.set(id, mine);
    for (const name of mine) {
      if (owner.has(name)) throw new Error(`${name} is the entry of two engines: ${owner.get(name)} and ${id}`);
      owner.set(name, id);
    }
  }

  const matches = (pattern, file) => (pattern.endsWith("/**") ? file.startsWith(pattern.slice(0, -2)) : file === pattern);
  const claimed = {};
  for (const [id, e] of Object.entries(ENGINES)) {
    const reached = new Set();
    const walkChunks = (name) => {
      if (reached.has(name) || core.has(name) || (owner.has(name) && owner.get(name) !== id)) return;
      reached.add(name);
      for (const i of chunks.get(name).imports) walkChunks(i.name);
    };
    for (const s of seeds.get(id)) walkChunks(s);
    const mine = new Set(reached);
    const named = [...(e.files ?? []), ...(e.notices ?? []).map((n) => `licenses/${n}/**`)];
    for (const pattern of named) {
      const found = files.filter((f) => matches(pattern, f));
      if (!found.length) throw new Error(`engine ${id}: nothing at ${pattern} in the frame app (ts/frame/engines.ts)`);
      for (const f of found) mine.add(f);
    }
    // The Office engine starts its renderers from workers it names in its chunks.
    for (const name of reached) {
      for (const input of chunks.get(name).inputs.filter((i) => i.includes("node_modules/@silurus/ooxml/"))) {
        for (const [worker] of fs.readFileSync(path.join(root, input), "utf8").matchAll(/render-worker-[\w-]+\.js/g)) if (present.has(`assets/${worker}`)) mine.add(`assets/${worker}`);
      }
    }
    for (const f of mine) if (!present.has(f)) throw new Error(`engine ${id}: ${f} is not in the frame app`);
    claimed[id] = [...mine].sort();
  }

  const taken = new Set(Object.values(claimed).flat());
  const coreFiles = files.filter((f) => !taken.has(f));
  // A file that belongs to no engine is the core's: only what is meant to be.
  const CORE_FILES = ["index.html", "styles.css", "frame.css", "exav-viewer/manifest.json", "licenses/README.txt", "licenses/NOTICE", "licenses/LICENSE", "licenses/LICENSES/**"];
  const strays = coreFiles.filter((f) => !chunks.has(f) && !CORE_FILES.some((p) => matches(p, f)));
  if (strays.length) throw new Error(`files of no engine, and not the core's (ts/frame/engines.ts): ${strays.join(", ")}`);

  for (const [name, p] of Object.entries(packages)) {
    p.version = JSON.parse(fs.readFileSync(path.join(pkg(name), "package.json"), "utf8")).version;
    for (const f of Object.keys(p.files)) if (!present.has(f)) throw new Error(`${name}: ${f} is not in the frame app`);
  }
  fs.writeFileSync(
    path.join(root, "dist", "frame", "files.json"),
    `${JSON.stringify({ core: coreFiles.sort(), engines: claimed, packages, notices: { header: noticeHeader, packages: notices } }, null, 1)}\n`,
  );
}

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
