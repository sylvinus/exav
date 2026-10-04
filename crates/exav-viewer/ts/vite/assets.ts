/**
 * The files engines fetch by name at runtime, which no bundler can follow
 * from an import: pdf.js's CMaps, standard fonts, ICC profiles and image
 * decoders. Collected from the host's own
 * node_modules, so the versions match the libraries it bundles, and laid out
 * under `<package>/<version>/` so `assetBase` can be served immutable.
 *
 * The engines this package ships itself (its wasm, workers and fonts) are not
 * here: they are reached with `new URL(..., import.meta.url)`, which the
 * host's bundler follows.
 */
import fs from "node:fs";
import path from "node:path";

import { fileURLToPath } from "node:url";

import type { AssetManifest } from "../core/assets.js";
import { FRAME_CSP, frameCsp, type FrameOrigins } from "../frame/policy.js";
import { PDFJS_ASSET_DIRS, pdfjsAssetDir, pdfjsWasmDir } from "../pdf/assets.js";

/**
 * pdf.js's decoders this package replaces: its OpenJPEG and PDFium builds and
 * their licences, left out of the copy.
 */
export const PDFJS_REPLACED = /^(openjpeg|jbig2)[._]|^LICENSE_(PDFJS_)?(OPENJPEG|JBIG2)$/;

// The package's root, from dist/vite/ (or ts/vite/).
const own = (file: string) => path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "..", file);

/**
 * What takes their place in pdf.js's `wasmUrl`. pdf.js first instantiates
 * `openjpeg.wasm` (or `jbig2.wasm`), and on failure imports the fallback
 * module beside it: the `.wasm` it is given is empty, so that it fails at
 * once, with one warning and no request answered 404.
 */
const PDF_DECODER_FILES: Record<string, string> = {
  "openjpeg.wasm": own("assets/pdfjs/absent.wasm"),
  "openjpeg_nowasm_fallback.js": own("wasm/openjpeg_nowasm_fallback.js"),
  "jbig2.wasm": own("assets/pdfjs/absent.wasm"),
  "jbig2_nowasm_fallback.js": own("wasm/jbig2_nowasm_fallback.js"),
};

export interface Asset {
  /** Absolute path of the file to copy. */
  source: string;
  /** Where it goes, relative to `assetBase`. */
  path: string;
}

/** The directory of an installed package, looked up from `root` as Node would. */
export function packageDir(name: string, root: string): string | null {
  let dir = path.resolve(root);
  for (;;) {
    const candidate = path.join(dir, "node_modules", name, "package.json");
    if (fs.existsSync(candidate)) return path.dirname(fs.realpathSync(candidate));
    const parent = path.dirname(dir);
    if (parent === dir) return null;
    dir = parent;
  }
}

const versionOf = (dir: string): string => JSON.parse(fs.readFileSync(path.join(dir, "package.json"), "utf8")).version;

function walk(dir: string): string[] {
  const out: string[] = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, entry.name);
    if (entry.isDirectory()) out.push(...walk(p));
    else out.push(p);
  }
  return out;
}

/** Everything to copy for the packages installed beside `root`, and the manifest describing it. */
export function collectAssets(root: string): { assets: Asset[]; manifest: AssetManifest } {
  const assets: Asset[] = [];
  const manifest: AssetManifest = { dirs: {}, files: {}, all: [] };

  const pdfjs = packageDir("pdfjs-dist", root);
  if (pdfjs) {
    // The layout the PDF engine reads at runtime, from `pdfjs.version`.
    const version = versionOf(pdfjs);
    const dir = pdfjsAssetDir("", version).slice(1);
    const wasmDir = pdfjsWasmDir("", version).slice(1);
    manifest.dirs.pdfjs = dir;
    for (const sub of PDFJS_ASSET_DIRS) {
      const from = path.join(pdfjs, sub);
      if (!fs.existsSync(from)) continue;
      for (const file of walk(from)) {
        const name = path.basename(file);
        // QuickJS is for pdf.js's scripting sandbox, which is never loaded.
        if (name.startsWith("quickjs")) continue;
        if (sub === "wasm" && PDFJS_REPLACED.test(name)) continue;
        const to = sub === "wasm" ? wasmDir : `${dir}${sub}/`;
        assets.push({ source: file, path: `${to}${path.relative(from, file).split(path.sep).join("/")}` });
      }
    }
    for (const [name, source] of Object.entries(PDF_DECODER_FILES)) assets.push({ source, path: `${wasmDir}${name}` });
  }

  manifest.all = assets.map((a) => a.path);
  return { assets, manifest };
}

/**
 * The sandboxed frame app's files (`dist/frame/app/`), relative to the
 * directory it is published in. Built with the package, not from the host's
 * node_modules: the frame carries its own engines.
 */
export function frameFiles(): Asset[] {
  const dir = own(path.join("dist", "frame", "app"));
  if (!fs.existsSync(dir)) throw new Error(`${dir} is missing: the package was built without its frame app`);
  return walk(dir).map((source) => ({ source, path: path.relative(dir, source).split(path.sep).join("/") }));
}

/**
 * A frame file's bytes as published. With `origin` (the frame's own, for
 * WebKit) or `origins` (what it may show or fetch besides; see `frameCsp`),
 * the page's meta policy names them.
 */
export function frameFileBytes(asset: Asset, origin?: string, origins: FrameOrigins = {}): Buffer {
  const bytes = fs.readFileSync(asset.source);
  if (asset.path !== "index.html" || (!origin && !origins.media?.length && !origins.connect?.length)) return bytes;
  const html = bytes.toString("utf8");
  const meta = `content="${FRAME_CSP}"`;
  if (!html.includes(meta)) throw new Error("the frame's index.html does not carry the policy this package expects");
  return Buffer.from(html.replace(meta, `content="${frameCsp(origin, origins)}"`));
}

const TYPES: Record<string, string> = {
  ".js": "text/javascript",
  ".mjs": "text/javascript",
  ".wasm": "application/wasm",
  ".json": "application/json",
  ".pfb": "application/octet-stream",
  ".ttf": "font/ttf",
  ".woff2": "font/woff2",
  ".bcmap": "application/octet-stream",
  ".icc": "application/vnd.iccprofile",
  ".html": "text/html; charset=utf-8",
  ".css": "text/css",
  ".txt": "text/plain; charset=utf-8",
};

export function contentType(file: string): string {
  return TYPES[path.extname(file).toLowerCase()] ?? "application/octet-stream";
}
