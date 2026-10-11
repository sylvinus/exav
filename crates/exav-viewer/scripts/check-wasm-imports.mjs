// Fails when a shipped .wasm imports anything not on its list, or when one of
// this package's modules can grow past its memory cap. Every module the frame
// and the demo ship is covered: this package's (and the two embedded in
// pdf.js's decoder fallbacks, *_nowasm_fallback.js), @exav/unpack-wasm's,
// @silurus/ooxml's parsers and pdf.js's ICC engine.
//
// A module's imports are everything it can reach outside its own memory. A
// dependency that starts reaching for the network, a global, the clock or
// randomness shows up here as a new name, before it ships.
//
// Usage: node scripts/check-wasm-imports.mjs [--all] <dir>...
//   --all: every module listed must be found (the demo's full build).
import { readFileSync, readdirSync } from "node:fs";
import { basename, join } from "node:path";
import { fileURLToPath } from "node:url";

// wasm-bindgen's plumbing, names without their hash suffix: `__wbg_Error` is
// `new Error(message)`, which `JsError::new` makes; the rest is how it
// throws, passes strings and sets up its tables.
const BINDGEN = ["glue.__wbg_Error", "glue.__wbg___wbindgen_throw", "glue.__wbindgen_init_externref_table", "glue.__wbindgen_cast"];

/** Per module (file name without `.wasm` and a bundler's hash): what it may import, and why. */
export const LISTS = {
  // This package's: pure computation on the bytes handed in.
  exav_viewer_image_bg: { imports: BINDGEN, why: "exav-render's image decoders" },
  exav_viewer_dwg_bg: { imports: BINDGEN, why: "exav-render's DWG and DXF engine" },
  exav_viewer_model_bg: { imports: BINDGEN, why: "exav-render's IFC and STL meshes" },
  exav_viewer_pdf_jpx_bg: { imports: BINDGEN, why: "the JPEG 2000 decoder given to pdf.js" },
  exav_viewer_pdf_jbig2_bg: { imports: BINDGEN, why: "the JBIG2 and CCITT decoder given to pdf.js" },
  exav_unpack_wasm_bg: {
    imports: [
      ...BINDGEN,
      // Reading the archive: a Blob through FileReaderSync, or a reader
      // function the caller passes (`call`); building the arrays of members.
      "glue.__wbg_readAsArrayBuffer",
      "glue.__wbg_instanceof_Blob",
      "glue.__wbg_size",
      "glue.__wbg_slice",
      "glue.__wbg_call",
      "glue.__wbg_new",
      "glue.__wbg_new_from_slice",
      "glue.__wbg_length",
      "glue.__wbg_get",
      "glue.__wbg_get_unchecked",
      "glue.__wbg_set",
      "glue.__wbg_push",
      "glue.__wbg_isArray",
      "glue.__wbg_instanceof_Object",
      "glue.__wbg_instanceof_Uint8Array",
      "glue.__wbg_prototypesetcall",
      "glue.__wbindgen_object_drop_ref",
      "glue.__wbindgen_object_clone_ref",
      "glue.__wbg___wbindgen_is_null",
      "glue.__wbg___wbindgen_is_undefined",
      "glue.__wbg___wbindgen_is_function",
      "glue.__wbg___wbindgen_number_get",
      "glue.__wbg___wbindgen_string_get",
      "glue.__wbg___wbindgen_debug_string",
      "glue.__wbindgen_generic",
    ],
    why: "@exav/unpack-wasm: archives read from a Blob or a reader function, members returned as JS values",
  },
  // @silurus/ooxml's parsers: plumbing, and a panic's message and stack to
  // console.error (`new Error`, `stack`, `error`).
  docx_parser_bg: { imports: [...BINDGEN, "glue.__wbg_new", "glue.__wbg_stack", "glue.__wbg_error"], why: "@silurus/ooxml's Word parser" },
  pptx_parser_bg: { imports: [...BINDGEN, "glue.__wbg_new", "glue.__wbg_stack", "glue.__wbg_error"], why: "@silurus/ooxml's PowerPoint parser" },
  xlsx_parser_bg: { imports: [...BINDGEN, "glue.__wbg_new", "glue.__wbg_stack", "glue.__wbg_error"], why: "@silurus/ooxml's Excel parser" },
  // pdf.js's ICC engine: the converted colours are copied out by a callback.
  qcms_bg: { imports: [...BINDGEN, "glue.__wbg_copy_result"], why: "pdf.js's ICC engine (qcms)" },
};

/** The most pages (64 KiB) this package's modules may grow to: scripts/build-wasm.sh's caps. */
export const MEMORY_CAPS = {
  exav_viewer_image_bg: 16384,
  exav_viewer_dwg_bg: 32768,
  exav_viewer_model_bg: 49152,
  exav_viewer_pdf_jpx_bg: 16384,
  exav_viewer_pdf_jbig2_bg: 16384,
};

/** pdf.js's decoders this package replaces: shipped empty, so that they fail to compile. */
const EMPTY = new Set(["openjpeg.wasm", "jbig2.wasm"]);

const EMBEDDED = /^\/\/ the package's NOTICE\. Module: (\w+)\.wasm\.\nconst WASM = "([A-Za-z0-9+/=]*)";$/m;

function readLeb(bytes, at) {
  let value = 0;
  let shift = 0;
  for (;;) {
    const b = bytes[at++];
    value += (b & 0x7f) * 2 ** shift;
    shift += 7;
    if (!(b & 0x80)) return [value, at];
  }
}

/** The limits of the memory a module defines, in pages, or null when it defines none. */
export function memoryLimits(bytes) {
  let at = 8;
  while (at < bytes.length) {
    const id = bytes[at++];
    let size;
    [size, at] = readLeb(bytes, at);
    if (id === 5) {
      let count;
      let p;
      [count, p] = readLeb(bytes, at);
      if (count < 1) return null;
      const flags = bytes[p++];
      let min;
      [min, p] = readLeb(bytes, p);
      let max = null;
      if (flags & 1) [max] = readLeb(bytes, p);
      return { min, max };
    }
    at += size;
  }
  return null;
}

/** The module's list name: its file name without `.wasm` and a bundler's `-<hash>`. */
export function moduleName(file) {
  const name = basename(file).replace(/\.wasm$/, "");
  if (LISTS[name]) return name;
  const unhashed = name.replace(/-[A-Za-z0-9_-]{8}$/, "");
  return LISTS[unhashed] ? unhashed : name;
}

/** Problems with one module: imports not on its list, a memory cap missing or wrong. */
export function checkModule(name, bytes) {
  const list = LISTS[name];
  if (!list) return { name, problems: ["no import list for this module"] };
  const mod = new WebAssembly.Module(bytes);
  const problems = [];
  const seen = [
    ...new Set(
      WebAssembly.Module.imports(mod).map((i) => {
        const ns = i.module === `./${name}.js` || i.module === "wbg" ? "glue" : i.module;
        return `${ns}.${i.name.replace(/_[0-9a-f]{16}$/, "")}`;
      }),
    ),
  ];
  const unknown = seen.filter((n) => !list.imports.includes(n));
  if (unknown.length) problems.push(`imports not on its list: ${unknown.join(", ")}`);
  const memory = memoryLimits(bytes);
  if (MEMORY_CAPS[name] !== undefined && memory?.max !== MEMORY_CAPS[name]) {
    problems.push(`memory may grow to ${memory?.max == null ? "4 GiB" : `${memory.max} pages`}, not ${MEMORY_CAPS[name]} pages (scripts/build-wasm.sh)`);
  }
  return { name, problems, seen, memory };
}

/** Every module under `dir`: .wasm files, and the modules embedded in pdf.js's fallbacks. */
export function modulesIn(dir) {
  const out = [];
  const walk = (d) => {
    for (const e of readdirSync(d, { withFileTypes: true })) {
      const p = join(d, e.name);
      if (e.isDirectory()) walk(p);
      else if (e.name.endsWith(".wasm")) out.push({ label: p, file: e.name, bytes: readFileSync(p) });
      else if (e.name.endsWith("_nowasm_fallback.js")) {
        const found = EMBEDDED.exec(readFileSync(p, "utf8"));
        out.push({ label: `${p} (embedded)`, file: found ? `${found[1]}.wasm` : null, bytes: found ? Buffer.from(found[2], "base64") : null });
      }
    }
  };
  walk(dir);
  return out;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  const all = args.includes("--all");
  const dirs = args.filter((a) => a !== "--all");
  if (!dirs.length) dirs.push("wasm");
  let failed = false;
  const found = new Set();
  for (const dir of dirs) {
    for (const m of modulesIn(dir)) {
      if (!m.file || !m.bytes) {
        console.error(`${m.label}: no embedded module`);
        failed = true;
        continue;
      }
      if (EMPTY.has(m.file)) {
        if (m.bytes.length !== 0) {
          console.error(`${m.label}: pdf.js's own decoder is shipped`);
          failed = true;
        }
        continue;
      }
      const name = moduleName(m.file);
      const r = checkModule(name, m.bytes);
      found.add(name);
      if (r.problems.length) {
        console.error(`${m.label}: ${r.problems.join("; ")}`);
        failed = true;
      } else {
        const max = r.memory?.max == null ? "no maximum" : `at most ${(r.memory.max * 65536) / 2 ** 20} MiB`;
        console.log(`${m.label}: ${r.seen.length} imports, all listed; memory ${max}`);
      }
    }
  }
  if (all) {
    const missing = Object.keys(LISTS).filter((n) => !found.has(n));
    if (missing.length) {
      console.error(`listed but not found: ${missing.join(", ")}`);
      failed = true;
    }
  }
  if (failed) process.exitCode = 1;
}
