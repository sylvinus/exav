// The demo, built against the package as a host would get it from npm: every
// `@exav/viewer` import resolves to `dist/` (run `npm run build` first),
// through the same `exports` map.
//
//     npm run demo          # dev server, http://localhost:4322/
//     npm run demo:build    # static site in demo/dist; DEMO_BASE sets its base path
import fs from "node:fs";
import type { ServerResponse } from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { defineConfig, type Plugin } from "vite";

import { exavViewer } from "../dist/vite/index.js";
import type { Sample } from "./src/showcase.js";

const pkgDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const pkg = JSON.parse(fs.readFileSync(path.join(pkgDir, "package.json"), "utf8"));

// "./react": { default: "./dist/react/index.js" } -> "@exav/viewer/react": <dir>/dist/react/index.js
const alias = Object.entries(pkg.exports as Record<string, string | { default: string }>)
  .filter(([key]) => !key.includes("*"))
  .map(([key, value]) => ({
    find: new RegExp(`^@exav/viewer${key.slice(1).replace(/[.*+?^${}()|[\]\\/]/g, "\\$&")}$`),
    replacement: path.join(pkgDir, typeof value === "string" ? value : value.default),
  }));

const nodeModules = fs.realpathSync(path.join(pkgDir, "node_modules"));
// A `file:` dependency resolves outside node_modules (to its crate), and the
// dev server serves its worker and wasm from there.
const unpackWasm = fs.realpathSync(path.join(nodeModules, "@exav", "unpack-wasm"));

/** The packages the demo bundles or copies, whose licences travel with it. */
const ENGINES = ["pdfjs-dist", "three", "@silurus/ooxml", "@exav/unpack-wasm", "react", "react-dom"];

/**
 * `licenses/`: the viewer's notices and licence texts, and each engine's own
 * licence file, which the minifier strips from the code. Emitted into the
 * build, and served by the dev server.
 */
function licenceFiles(): Map<string, Buffer> {
  const files = new Map<string, Buffer>();
  const add = (fileName: string, from: string) => files.set(fileName, fs.readFileSync(from));
  const index = ["The demo's third-party notices.", "", "@exav/viewer: NOTICE, LICENSE, LICENSES/, fonts/"];
  add("NOTICE", path.join(pkgDir, "NOTICE"));
  add("LICENSE", path.join(pkgDir, "LICENSE"));
  for (const f of fs.readdirSync(path.join(pkgDir, "LICENSES"))) add(`LICENSES/${f}`, path.join(pkgDir, "LICENSES", f));
  for (const f of ["OFL-1.1.txt", "NOTICE.md"]) add(`fonts/${f}`, path.join(pkgDir, "assets", "fonts", f));
  for (const name of ENGINES) {
    const dir = path.join(nodeModules, name);
    const meta = JSON.parse(fs.readFileSync(path.join(dir, "package.json"), "utf8"));
    const found = fs.readdirSync(dir).filter((f) => /^(licen[cs]e|notice|copying|third_party_notices)/i.test(f));
    for (const f of found) add(`${name}/${f}`, path.join(dir, f));
    index.push(`${name} ${meta.version}: ${meta.license}${found.length ? `, ${found.map((f) => `${name}/${f}`).join(", ")}` : ""}`);
  }
  index.push(
    "",
    "Of pdfjs-dist's wasm/, only its ICC engine (qcms, MIT; LICENSE_QCMS beside it under exav-viewer/pdfjs/) is in the build.",
    "Its OpenJPEG and PDFium image decoders are not: @exav/viewer's own decoders take their place (see its NOTICE).",
  );
  // The samples copied in by `npm run demo:showcase`, if they were.
  const list = path.join(pkgDir, "demo", "public", "showcase", "samples.json");
  if (fs.existsSync(list)) {
    const { samples } = JSON.parse(fs.readFileSync(list, "utf8")) as { samples: Sample[] };
    index.push("", "The sample files, under showcase/, from https://github.com/sylvinus/exav-samples:");
    for (const s of samples) index.push("", s.file, `  ${s.credit}`, `  ${s.source}`, `  ${s.licence}`);
  }
  files.set("README.txt", Buffer.from(`${index.join("\n")}\n`));
  return files;
}

function licences(): Plugin {
  let base = "/";
  return {
    name: "demo-licences",
    configResolved(config) {
      base = config.base;
    },
    configureServer(server) {
      const files = licenceFiles();
      server.middlewares.use((req, res, next) => {
        const url = (req.url ?? "").split("?")[0] ?? "";
        const file = url.startsWith(`${base}licenses/`) ? files.get(decodeURIComponent(url.slice(base.length + "licenses/".length))) : undefined;
        if (!file) return next();
        res.setHeader("Content-Type", "text/plain; charset=utf-8");
        res.end(file);
      });
    },
    generateBundle() {
      for (const [fileName, source] of licenceFiles()) this.emitFile({ type: "asset", fileName: `licenses/${fileName}`, source });
    },
  };
}

/**
 * In `vite preview` only: the browser tests' files (e2e/delivery-setup.ts
 * writes them in e2e/.out/, the samples in its samples/), under `${base}e2e/`, with range requests and
 * CORS, as a file server would answer them; `${base}e2e/whole/` ignores
 * ranges; `${base}e2e/paced/` sends PACE bytes a second, so that a player
 * cannot have the end of a file before it needs it (from loopback the first
 * response can bring the whole file first).
 */
function e2eFiles(): Plugin {
  const dir = path.join(pkgDir, "e2e", ".out");
  const TYPES: Record<string, string> = { ".pdf": "application/pdf", ".zip": "application/zip", ".webm": "video/webm", ".png": "image/png" };
  // A third above clip.webm's bitrate (10 MB for 13 s): it plays without stalling.
  const PACE = 1024 * 1024;
  const send = (file: string, res: ServerResponse, paced: boolean, range?: { start: number; end: number }) => {
    const stream = fs.createReadStream(file, { ...range, highWaterMark: 64 * 1024 });
    if (!paced) return stream.pipe(res);
    res.on("close", () => stream.destroy());
    stream.on("error", () => res.destroy());
    stream.on("data", (chunk) => {
      stream.pause();
      res.write(chunk);
      setTimeout(() => stream.resume(), (chunk.length * 1000) / PACE);
    });
    stream.on("end", () => res.end());
  };
  return {
    name: "demo-e2e-files",
    configurePreviewServer(server) {
      server.middlewares.use((req, res, next) => {
        const m = /\/e2e\/(whole\/|paced\/)?((?:samples\/)?[\w.-]+)$/.exec((req.url ?? "").split("?")[0] ?? "");
        if (!m) return next();
        res.setHeader("Access-Control-Allow-Origin", "*");
        res.setHeader("Access-Control-Allow-Headers", "Range");
        res.setHeader("Access-Control-Expose-Headers", "Accept-Ranges, Content-Range, Content-Length");
        res.setHeader("Cache-Control", "no-store");
        if (req.method === "OPTIONS") return res.end();
        const file = path.join(dir, m[2]!);
        if (!fs.existsSync(file)) {
          res.statusCode = 404;
          return res.end();
        }
        const size = fs.statSync(file).size;
        res.setHeader("Content-Type", TYPES[path.extname(file)] ?? "application/octet-stream");
        const paced = m[1] === "paced/";
        const range = m[1] === "whole/" ? null : /^bytes=(\d*)-(\d*)$/.exec(req.headers.range ?? "");
        if (!range) {
          res.setHeader("Content-Length", size);
          return send(file, res, paced);
        }
        res.setHeader("Accept-Ranges", "bytes");
        const start = range[1] ? Number(range[1]) : Math.max(0, size - Number(range[2]));
        const end = range[1] && range[2] ? Math.min(size - 1, Number(range[2])) : size - 1;
        if (start >= size || end < start) {
          res.statusCode = 416;
          res.setHeader("Content-Range", `bytes */${size}`);
          return res.end();
        }
        res.statusCode = 206;
        res.setHeader("Content-Range", `bytes ${start}-${end}/${size}`);
        res.setHeader("Content-Length", end - start + 1);
        send(file, res, paced, { start, end });
      });
    },
  };
}

// DEMO_ORIGIN is where the demo is deployed; the default is `vite
// preview`'s, which the browser tests use.
const origin = process.env.DEMO_ORIGIN ?? "http://127.0.0.1:4317";

export default defineConfig({
  root: path.join(pkgDir, "demo"),
  base: process.env.DEMO_BASE ?? "/",
  resolve: { alias },
  esbuild: { jsx: "automatic" },
  define: { __DEMO_ORIGIN__: JSON.stringify(origin) },
  // The sandboxed frame at `${base}frame/`, served with its headers by `vite
  // preview`. It may play the demo's own media by URL and fetch from it.
  plugins: [exavViewer({ frameDir: "frame", frameOrigin: origin, mediaOrigins: [origin], connectOrigins: [origin] }), licences(), e2eFiles()],
  // Beside the docs site's 4321.
  server: { port: 4322, strictPort: true, host: true, fs: { allow: [pkgDir, nodeModules, unpackWasm] } },
  build: { outDir: "dist", emptyOutDir: true, target: "es2022" },
});
