// Writes the size tables of the documentation from the build: the wasm
// modules (wasm/), and what a sandboxed frame published for each format weighs
// (dist/frame/), and what each peer dependency adds. The pages carry them
// between `<!-- sizes:wasm -->` and `<!-- /sizes:wasm -->`, and likewise for
// `sizes:peers` and `sizes:frame`.
//
//     node scripts/size-tables.mjs           # rewrite them
//     node scripts/size-tables.mjs --check   # fail when a page is not what a rewrite gives
//
// Run after `npm run build:wasm` and `npm run build`. Sizes are bytes; the
// compressed ones are what a server sends that compresses once, at brotli
// level 11 and gzip level 9. `--check` allows a few percent of drift, as another
// toolchain builds a slightly different module, and fails on any row that is
// not there or is new.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import zlib from "node:zlib";

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const PAGE = path.join(root, "..", "..", "www", "src", "content", "docs", "viewer", "integration.md");
const TOLERANCE = 0.05;

const { BUILTIN_ORDER } = await import(path.join(root, "dist", "core", "formats.js"));
const { frameSubset } = await import(path.join(root, "dist", "vite", "subset.js"));

/** What each module opens: every `wasm/*_bg.wasm` and the pdf.js fallbacks must be here. */
const MODULES = [
  ["exav_viewer_image_bg.wasm", "TIFF, BMP, ICO, PNM, QOI, DDS, farbfeld, HDR, JPEG 2000, JBIG2, JPEG XL, camera RAW"],
  ["exav_viewer_dwg_bg.wasm", "DWG, DXF"],
  ["exav_viewer_model_bg.wasm", "IFC, STL, OBJ, PLY, glTF"],
  ["exav_viewer_text_bg.wasm", "Markdown"],
  ["exav_viewer_sheets_bg.wasm", "XLS, ODS, FODS, Numbers, SpreadsheetML 2003, HTML tables, SYLK, to XLSX"],
  ["exav_viewer_slides_bg.wasm", "PPT, ODP, FODP, Keynote, ODG, Visio (VSDX), to PPTX"],
  ["exav_viewer_docs_bg.wasm", "DOC, ODT, FODT, RTF, to DOCX"],
  ["openjpeg_nowasm_fallback.js", "JPEG 2000 images in PDFs (pdf.js's JPXDecode), the module in base64"],
  ["jbig2_nowasm_fallback.js", "JBIG2 and CCITT fax images in PDFs, the module in base64"],
];

/** What a frame published for `formats` alone holds: a row of the frame table. */
const FRAMES = [
  ["PDF", ["pdf"]],
  ["Images: PNG, JPEG, WebP, GIF, SVG and the formats of the image module", ["image"]],
  ["DWG, DXF", ["dwg"]],
  ["IFC", ["ifc"]],
  ["STL, OBJ, PLY, glTF", ["stl"]],
  ["Word", ["docx"]],
  ["Excel, CSV", ["xlsx"]],
  ["PowerPoint", ["pptx"]],
  ["XLS, ODS, Numbers", ["xls"]],
  ["PPT, ODP, Keynote, ODG, Visio", ["ppt"]],
  ["DOC, ODT, RTF", ["rtf"]],
  ["Markdown, text", ["text"]],
  ["Archives", ["archive"]],
  ["Video, audio", ["video"]],
];

const compressed = new Map();
function sizes(file) {
  const hit = compressed.get(file);
  if (hit) return hit;
  const bytes = fs.readFileSync(file);
  const out = {
    raw: bytes.length,
    brotli: zlib.brotliCompressSync(bytes, { params: { [zlib.constants.BROTLI_PARAM_QUALITY]: 11, [zlib.constants.BROTLI_PARAM_LGWIN]: 24, [zlib.constants.BROTLI_PARAM_SIZE_HINT]: bytes.length } }).length,
    gzip: zlib.gzipSync(bytes, { level: 9 }).length,
  };
  compressed.set(file, out);
  return out;
}
const sum = (files) => files.map(sizes).reduce((a, b) => ({ raw: a.raw + b.raw, brotli: a.brotli + b.brotli, gzip: a.gzip + b.gzip }), { raw: 0, brotli: 0, gzip: 0 });
const n = (v) => v.toLocaleString("en-US");

function wasmTable() {
  const dir = path.join(root, "wasm");
  const listed = new Set(MODULES.map(([f]) => f));
  const built = fs.readdirSync(dir).filter((f) => f.endsWith("_bg.wasm") || f.endsWith("_nowasm_fallback.js"));
  const unknown = built.filter((f) => !listed.has(f));
  if (unknown.length) throw new Error(`scripts/size-tables.mjs does not say what ${unknown.join(", ")} opens`);
  const rows = MODULES.map(([file, opens]) => {
    if (!fs.existsSync(path.join(dir, file))) throw new Error(`wasm/${file} is missing: run npm run build:wasm`);
    const s = sizes(path.join(dir, file));
    return { key: file, opens, ...s };
  });
  return {
    head: ["Module", "Opens", "Size", "Brotli", "Gzip"],
    rows: rows.map((r) => ({ key: r.key, cells: [`\`${r.key.replace(/_bg\.wasm$/, "")}\``, r.opens, r.raw, r.brotli, r.gzip] })),
  };
}

function frameTable() {
  const listing = JSON.parse(fs.readFileSync(path.join(root, "dist", "frame", "files.json"), "utf8"));
  const app = path.join(root, "dist", "frame", "app");
  const of = (formats) => sum([...frameSubset(listing, formats).files].map((f) => path.join(app, f)));
  const rows = [
    ["The frame itself, in every one", [], true],
    ...FRAMES.map(([label, formats]) => [label, formats, false]),
    ["Every format", BUILTIN_ORDER, true],
  ].map(([label, formats, plain]) => {
    const s = of(formats);
    const shown = formats.length === 0 || formats.length === BUILTIN_ORDER.length ? "" : `\`${formats[0]}\``;
    return { key: label, cells: [label, plain ? "" : shown, s.raw, s.brotli, s.gzip] };
  });
  return { head: ["A frame for", "`formats`", "Size", "Brotli", "Gzip"], rows };
}

/** The peer dependencies, and the formats each is needed for. Every key of package.json's `peerDependencies` must be here. */
const PEERS = [
  [["pdfjs-dist"], "PDF"],
  [["@silurus/ooxml"], "Word, Excel, PowerPoint, CSV, and the formats converted to them: XLS, ODS, Numbers, PPT, ODP, Keynote, ODG, Visio, DOC, ODT, RTF"],
  [["three"], "IFC, STL, OBJ, PLY, glTF"],
  [["@exav/unpack-wasm"], "Archives"],
  [["react", "react-dom"], "The React components (`@exav/viewer/react`); the host's own React, not measured"],
];

// What each peer puts in a frame, from files.json: its share of every file it
// is bundled into (minified, as the frame's bundler gives it), and the files it
// brings whole (workers, wasm, pdf.js's runtime assets). A direct-mode host's
// bundler gives about the same, plus the runtime files the plugin copies.
function peerTable() {
  const listing = JSON.parse(fs.readFileSync(path.join(root, "dist", "frame", "files.json"), "utf8"));
  const app = path.join(root, "dist", "frame", "app");
  const meta = JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf8"));
  const declared = Object.keys(meta.peerDependencies ?? {});
  const listed = PEERS.flatMap(([names]) => names);
  const missing = declared.filter((d) => !listed.includes(d));
  if (missing.length) throw new Error(`scripts/size-tables.mjs does not say what ${missing.join(", ")} is needed for`);
  const extra = listed.filter((d) => !declared.includes(d));
  if (extra.length) throw new Error(`scripts/size-tables.mjs lists ${extra.join(", ")}, which package.json does not declare as a peer`);

  const rows = PEERS.map(([names, needed]) => {
    const name = names[0];
    const range = [...new Set(names.map((n) => meta.peerDependencies[n]))].join(", ");
    const built = listing.packages[name];
    if (!built && names.length === 1) throw new Error(`dist/frame/files.json has no bytes for ${name}: run npm run build`);
    let s = ["", "", ""];
    if (built) {
      const t = { raw: 0, brotli: 0, gzip: 0 };
      for (const [file, bytes] of Object.entries(built.files)) {
        const whole = sizes(path.join(app, file));
        const share = bytes / whole.raw;
        t.raw += bytes;
        t.brotli += Math.round(whole.brotli * share);
        t.gzip += Math.round(whole.gzip * share);
      }
      s = [t.raw, t.brotli, t.gzip];
    }
    return { key: names.join(", "), cells: [names.map((n) => `\`${n}\``).join(", "), `\`${range.replaceAll("|", "\\|")}\``, built ? built.version : "", needed, ...s] };
  });
  return { head: ["Peer", "Range", "Tested with", "Needed for", "Size", "Brotli", "Gzip"], rows };
}

function render({ head, rows }) {
  const line = (cells) => `| ${cells.join(" | ")} |`;
  return [line(head), line(head.map(() => "---")), ...rows.map((r) => line(r.cells.map((c) => (typeof c === "number" ? n(c) : c))))].join("\n");
}

const BLOCKS = { wasm: wasmTable, peers: peerTable, frame: frameTable };

const page = fs.readFileSync(PAGE, "utf8");
let next = page;
const problems = [];
for (const [name, make] of Object.entries(BLOCKS)) {
  const start = `<!-- sizes:${name} -->`;
  const end = `<!-- /sizes:${name} -->`;
  const from = next.indexOf(start);
  const to = next.indexOf(end);
  if (from < 0 || to < from) throw new Error(`${path.relative(root, PAGE)} has no ${start} ... ${end}`);
  const table = make();
  const old = next.slice(from + start.length, to);
  if (process.argv.includes("--check")) {
    // Row by row: the same rows, the numbers within the tolerance.
    const oldRows = old.trim().split("\n").slice(2).map((l) => l.split("|").slice(1, -1).map((c) => c.trim()));
    if (oldRows.length !== table.rows.length) problems.push(`${name}: the page has ${oldRows.length} rows, the build ${table.rows.length}`);
    table.rows.forEach((r, i) => {
      const o = oldRows[i];
      if (!o) return;
      r.cells.forEach((c, j) => {
        const text = typeof c === "number" ? c : String(c);
        if (typeof c !== "number") {
          if (o[j] !== text) problems.push(`${name}: row ${i + 1}, column ${j + 1} is "${o[j]}", the build says "${text}"`);
          return;
        }
        const was = Number(String(o[j]).replaceAll(",", ""));
        if (!(Math.abs(was - c) <= c * TOLERANCE)) problems.push(`${name}: ${r.key}, column ${table.head[j]}: the page says ${o[j]}, the build ${n(c)}`);
      });
    });
  } else {
    next = `${next.slice(0, from + start.length)}\n${render(table)}\n${next.slice(to)}`;
  }
}
if (process.argv.includes("--check")) {
  if (problems.length) {
    console.error(`${path.relative(root, PAGE)} is out of date (node scripts/size-tables.mjs):\n${problems.join("\n")}`);
    process.exit(1);
  }
  console.log("the size tables match the build");
} else if (next !== page) {
  fs.writeFileSync(PAGE, next);
  console.log(`${path.relative(root, PAGE)}: size tables written`);
} else console.log("size tables unchanged");
