#!/usr/bin/env node
// Checks that the viewer's own engines read every example, in Node, without a browser:
//
//     node demo/examples/verify-open.mjs [name-fragment ...]
//
// For each example (from demo/public/examples/ after `npm run demo:examples`, else
// the committed files/), it asks the viewer's detection (dist/core, from `npm run
// build`) which format claims it, and then reads it with the engine for that
// format: the wasm decoders and converters of wasm/ (`npm run build:wasm`),
// @exav/unpack-wasm for archives and pdf.js for PDF. A file of the `unsupported`
// group must fail; any other must open. Exit 1 on a surprise.
//
// What it does not check: that the picture drawn is right (it counts what the
// engine returns), and the browser-only formats (the browser draws PNG, JPEG,
// GIF, WebP and SVG; its media players play audio and video): those are checked
// by their signature.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const pkg = path.join(here, "..", "..");
const only = process.argv.slice(2);
const { examples } = JSON.parse(fs.readFileSync(path.join(here, "examples.json"), "utf8"));

const wasm = (name) => path.join(pkg, "wasm", name);
const need = (p) => {
  if (!fs.existsSync(p)) throw new Error(`${path.relative(pkg, p)} is missing: run npm run build:wasm and npm run build first`);
  return p;
};
const load = async (name) => {
  const mod = await import(pathToFileURL(need(wasm(`exav_viewer_${name}.js`))).href);
  mod.initSync({ module: fs.readFileSync(wasm(`exav_viewer_${name}_bg.wasm`)) });
  return mod;
};
const cache = {};
const engine = async (name) => (cache[name] ??= await load(name));

const formats = await import(pathToFileURL(need(path.join(pkg, "dist", "core", "formats.js"))).href);
const { createDetector } = await import(pathToFileURL(path.join(pkg, "dist", "core", "detect.js")).href);
const merge = (a, b) => ({ ...a, types: [...(a.types ?? []), ...(b.types ?? [])], extensions: [...(a.extensions ?? []), ...(b.extensions ?? [])], extensionOverrides: [...(a.extensionOverrides ?? []), ...(b.extensionOverrides ?? [])] });
const detector = createDetector(formats.BUILTIN_ORDER.map((id) => ({ id, match: id === "image" ? merge(formats.MATCHERS.image, formats.WASM_IMAGES) : formats.MATCHERS[id] })));

let unpack;
const archive = async () => {
  if (!unpack) {
    const dir = path.join(pkg, "..", "exav-unpack-wasm", "pkg");
    unpack = await import(pathToFileURL(need(path.join(dir, "exav_unpack_wasm.js"))).href);
    unpack.initSync({ module: fs.readFileSync(path.join(dir, "exav_unpack_wasm_bg.wasm")) });
  }
  return unpack;
};

let pdfjs;
const pdf = async () => (pdfjs ??= await import(pathToFileURL(path.join(pkg, "node_modules", "pdfjs-dist", "legacy", "build", "pdf.mjs")).href));

const ext = (name) => path.extname(name).slice(1).toLowerCase();
const GB = 1 << 30;

/** One check per detected format: returns a short description, or throws. */
const READ = {
  async image(name, bytes) {
    const e = ext(name);
    if (["png", "jpg", "jpeg", "gif", "webp"].includes(e)) {
      const type = detector.sniff(bytes.subarray(0, 512));
      if (!type.startsWith("image/")) throw new Error(`sniffed as "${type}"`);
      return `browser draws it (${type})`;
    }
    if (e === "svg") {
      if (!/<svg[\s>]/.test(new TextDecoder().decode(bytes.subarray(0, 4096)))) throw new Error("no <svg> element at the start");
      return "browser draws it (SVG)";
    }
    const m = await engine("image");
    const d = m.decodeImage(bytes, 1 << 29);
    const px = d.takeRgba();
    let sum = 0;
    for (let i = 0; i < px.length; i += 4) sum += px[i] + px[i + 1] + px[i + 2];
    if (px.length === 0 || sum === 0) throw new Error("decoded to nothing, or all black");
    return `${m.imageFormat(bytes.subarray(0, 512)) ?? "?"} ${d.width}x${d.height}`;
  },
  async dwg(name, bytes) {
    const m = await engine("dwg");
    const doc = m.parseDrawing(bytes, GB / 2);
    const layouts = JSON.parse(doc.layoutsJson());
    let best = 0;
    for (const l of layouts) {
      const d = doc.tessellate(l.name, new Uint8Array([255, 255, 255]), 50_000_000);
      best = Math.max(best, d.opaqueStrokes() + d.opaqueFills());
    }
    if (!best) throw new Error("nothing drawn");
    return `${layouts.length} layout(s), ${best} strokes and fills`;
  },
  async model(name, bytes, id) {
    const m = await engine("model");
    const model = { stl: m.parseStl, obj: m.parseObj, ply: m.parsePly, gltf: m.parseGltf, ifc: m.parseIfc }[id](bytes, 20_000_000);
    const meta = JSON.parse(model.metaJson());
    const tris = meta.batches.reduce((n, b) => n + b.indices / 3, 0);
    if (!tris) throw new Error("no triangles");
    return `${tris} triangles, ${meta.elements.length} element(s)`;
  },
  async ooxml(name, bytes, id) {
    const a = (await archive()).Archive.open(bytes);
    const names = a.list().map((e) => e.name);
    const part = { docx: "word/document.xml", xlsx: "xl/workbook.xml", pptx: "ppt/presentation.xml" }[id];
    if (!names.includes(part)) throw new Error(`no ${part}`);
    return `${names.length} parts`;
  },
  async docs(name, bytes) {
    const c = (await engine("docs")).convertDocs(bytes, ext(name), 1e6, GB);
    return `${c.paragraphs} paragraphs, ${c.takeDocx().length} bytes of DOCX`;
  },
  async sheets(name, bytes) {
    const c = (await engine("sheets")).convertSheets(bytes, ext(name), 1e7, GB);
    return `${c.takeXlsx().length} bytes of XLSX`;
  },
  async slides(name, bytes) {
    const c = (await engine("slides")).convertSlides(bytes, ext(name), 1e6, GB, Infinity);
    return `${c.slides} slide(s)`;
  },
  async pdf(name, bytes) {
    const lib = await pdf();
    const task = lib.getDocument({ data: new Uint8Array(bytes), useSystemFonts: false, isEvalSupported: false, verbosity: 0 });
    try {
      const doc = await task.promise;
      const outline = await doc.getOutline();
      const page = await doc.getPage(1);
      const annots = (await page.getAnnotations()).length;
      return `${doc.numPages} page(s), ${outline?.length ?? 0} outline entries, ${annots} annotations on page 1`;
    } finally {
      await task.destroy();
    }
  },
  async text(name, bytes) {
    const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    if (["json", "geojson"].includes(ext(name))) JSON.parse(text);
    if (["md", "markdown"].includes(ext(name))) {
      const doc = JSON.parse((await engine("text")).parseMarkdown(text));
      return `markdown, ${JSON.stringify(doc).length} bytes of tree`;
    }
    return `${text.split("\n").length} lines`;
  },
  async csv(name, bytes) {
    const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    const lines = text.split(/\r?\n/).filter(Boolean);
    if (lines.length < 2) throw new Error("fewer than two rows");
    return `${lines.length} lines`;
  },
  async archive(name, bytes) {
    const a = (await archive()).Archive.open(bytes);
    const list = a.list();
    if (!list.length) throw new Error("no members");
    return `${a.format()}, ${list.length} member(s)${list.some((m) => m.encrypted) ? ", encrypted" : ""}`;
  },
  async media(name, bytes) {
    // The browser's players decode them; here only that the head is a media container's or an MP3 frame's.
    const type = detector.sniff(bytes.subarray(0, 512));
    const mp3Frame = bytes[0] === 0xff && (bytes[1] & 0xe0) === 0xe0;
    if (!/^(audio|video|application\/ogg)/.test(type) && !mp3Frame) throw new Error(`sniffed as "${type}"`);
    return `plays in the browser (${type || "MP3 frames"})`;
  },
};

const ROUTE = {
  image: READ.image, dwg: READ.dwg, dxf: READ.dwg, ifc: (n, b) => READ.model(n, b, "ifc"), stl: (n, b) => READ.model(n, b, "stl"), obj: (n, b) => READ.model(n, b, "obj"),
  ply: (n, b) => READ.model(n, b, "ply"), gltf: (n, b) => READ.model(n, b, "gltf"), docx: (n, b) => READ.ooxml(n, b, "docx"), xlsx: (n, b) => READ.ooxml(n, b, "xlsx"),
  pptx: (n, b) => READ.ooxml(n, b, "pptx"), rtf: READ.docs, doc: READ.docs, odt: READ.docs, xls: READ.sheets, ods: READ.sheets, numbers: READ.sheets,
  ppt: READ.slides, odp: READ.slides, keynote: READ.slides, odg: READ.slides, visio: READ.slides, pdf: READ.pdf, text: READ.text, csv: READ.csv,
  archive: READ.archive, video: READ.media, audio: READ.media,
};

let surprises = 0;
let count = 0;
for (const e of examples) {
  if (only.length && !only.some((o) => e.file.includes(o))) continue;
  const served = path.join(pkg, "demo", "public", "examples", e.file);
  const file = fs.existsSync(served) ? served : e.path ? path.join(here, "files", e.path) : null;
  if (!file || !fs.existsSync(file)) {
    console.log(`skip ${e.file}: not downloaded`);
    continue;
  }
  count++;
  const bytes = new Uint8Array(fs.readFileSync(file));
  // As the demo does it: a file given by its address has a name and no type.
  const id = detector.detect({ type: "", name: e.file, path: e.file });
  const expectFail = e.group === "unsupported";
  let result;
  try {
    if (!id) throw new Error("no plugin claims it");
    if (["pages", "coreldraw", "publisher", "pagemaker", "freehand", "quarkxpress", "zonerdraw", "wpg"].includes(id)) throw new Error(`${id} needs an external converter`);
    if (!ROUTE[id]) throw new Error(`no check for ${id}`);
    result = { ok: true, text: `${id}: ${await ROUTE[id](e.file, bytes)}` };
  } catch (err) {
    result = { ok: false, text: `${id ?? "none"}: ${String(err.message ?? err).slice(0, 120)}` };
  }
  // The ODG converter is newer than some builds of wasm/: say so rather than fail.
  if (!result.ok && id === "odg" && /unsupported/.test(result.text) && !expectFail) {
    console.log(`warn ${e.file.padEnd(44)} ${result.text} (wasm/ may predate ODG: run npm run build:wasm)`);
    continue;
  }
  const fine = result.ok !== expectFail;
  if (!fine) surprises++;
  console.log(`${fine ? "ok  " : "FAIL"} ${e.file.padEnd(44)} ${expectFail ? "(unsupported on purpose) " : ""}${result.text}`);
}
console.log(`${count} examples read, ${surprises} surprise${surprises === 1 ? "" : "s"}`);
process.exit(surprises ? 1 : 0);
