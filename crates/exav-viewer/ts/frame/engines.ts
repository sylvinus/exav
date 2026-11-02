/**
 * What the sandboxed frame is made of, by engine: which formats each opens,
 * which engines it needs besides its own, and which files of the frame app
 * (`dist/frame/app/`) are its. `scripts/build-frame.mjs` lays the app out
 * from this table and records the files of each engine in `dist/frame/files.json`;
 * a host that ships the frame for some formats only (`formats` of
 * `@exav/viewer/vite`, `--format` of `exav-viewer-assets`) gets the
 * files of those formats' engines and the core, and the frame itself
 * (`app/main.ts`) opens no other format.
 */
import type { BuiltinFormat } from "../core/types.js";

export interface Engine {
  /** The formats it opens. */
  formats: readonly BuiltinFormat[];
  /** The engines it cannot work without. */
  needs?: readonly string[];
  /**
   * The formats whose plugins the frame adds to the host's list when this
   * engine is in use: what it shows a file as.
   */
  shows?: readonly BuiltinFormat[];
  /** What it needs and shows besides when an external converter is set. */
  external?: { needs: readonly string[]; shows: readonly BuiltinFormat[] };
  /**
   * The entry modules of the engine's chunks, as paths from the package root
   * (a prefix): the dynamic imports of the frame's bundle that start there.
   * The chunks they share with other engines go with each of them.
   */
  entries?: readonly string[];
  /**
   * Its files beside the chunks, relative to the frame app: a name, or a
   * directory and `/**`.
   */
  files?: readonly string[];
  /** The packages whose licences it ships (`licenses/README.txt`). */
  notices?: readonly string[];
}

export const ENGINES: Readonly<Record<string, Engine>> = {
  pdf: {
    formats: ["pdf"],
    entries: ["ts/pdf/", "node_modules/pdfjs-dist/"],
    files: ["pdfjs.worker.js", "exav-viewer/pdfjs/**"],
    notices: ["pdfjs-dist"],
  },
  image: {
    formats: ["image"],
    entries: ["ts/image/"],
    files: ["decode.worker.js", "exav_viewer_image_bg.wasm"],
  },
  cad: {
    formats: ["dwg", "dxf"],
    entries: ["ts/cad/"],
    files: ["cad.worker.js", "exav_viewer_dwg_bg.wasm", "fonts/**", "licenses/fonts/**"],
  },
  media: { formats: ["video", "audio"] },
  three: { formats: [], entries: ["node_modules/three/"], notices: ["three"] },
  // The meshes of IFC, STL, OBJ, PLY and glTF are made in one worker.
  meshes: { formats: [], files: ["model.worker.js", "exav_viewer_model_bg.wasm"] },
  ifc: { formats: ["ifc"], needs: ["three", "meshes"], entries: ["ts/ifc/"] },
  model: { formats: ["stl", "obj", "ply", "gltf"], needs: ["three", "meshes"], entries: ["ts/model/"] },
  // The page the Office viewers share, and their licence.
  office: { formats: [], entries: ["ts/office/renderer.ts"], notices: ["@silurus/ooxml"] },
  docx: { formats: ["docx"], needs: ["office"], entries: ["node_modules/@silurus/ooxml/dist/docx.mjs"], files: ["docx_parser_bg.wasm"] },
  xlsx: { formats: ["xlsx", "csv"], needs: ["office"], entries: ["node_modules/@silurus/ooxml/dist/xlsx.mjs"], files: ["xlsx_parser_bg.wasm"] },
  pptx: { formats: ["pptx"], needs: ["office"], entries: ["node_modules/@silurus/ooxml/dist/pptx.mjs"], files: ["pptx_parser_bg.wasm"] },
  // A file the external converter converts is shown as a PDF or an XLSX, so
  // these two come with every converted format where one is set.
  convert: {
    formats: ["coreldraw", "publisher", "pagemaker", "freehand", "quarkxpress", "zonerdraw", "wpg"],
    external: { needs: ["pdf", "xlsx"], shows: ["pdf", "xlsx"] },
    entries: ["ts/office/convert.ts"],
  },
  sheets: { formats: ["xls", "ods", "numbers"], needs: ["convert", "xlsx"], shows: ["xlsx"], files: ["sheets.worker.js", "exav_viewer_sheets_bg.wasm"] },
  slides: { formats: ["ppt", "odp", "keynote", "odg", "visio"], needs: ["convert", "pptx"], shows: ["pptx"], files: ["slides.worker.js", "exav_viewer_slides_bg.wasm"] },
  docs: { formats: ["rtf", "doc", "odt"], needs: ["convert", "docx"], shows: ["docx"], files: ["docs.worker.js", "exav_viewer_docs_bg.wasm"] },
  text: { formats: ["text"], entries: ["ts/text/"], files: ["markdown.worker.js", "exav_viewer_text_bg.wasm"] },
  archive: {
    formats: ["archive"],
    entries: ["ts/archive/", "node_modules/@exav/unpack-wasm/", "../exav-unpack-wasm/"],
    files: ["worker.js", "ranges.worker.js", "exav_unpack_wasm_bg.wasm"],
    notices: ["@exav/unpack-wasm"],
  },
};

/** The engine that opens `format`. */
export function engineOf(format: BuiltinFormat): string {
  for (const [id, e] of Object.entries(ENGINES)) if (e.formats.includes(format)) return id;
  throw new Error(`no engine opens ${format}`);
}

/**
 * The engines that open `formats`, and those they need in turn; with
 * `external`, as many as an external converter makes them need.
 */
export function engineClosure(formats: readonly BuiltinFormat[], external = false): Set<string> {
  const seen = new Set<string>();
  const add = (id: string) => {
    if (seen.has(id)) return;
    seen.add(id);
    const e = ENGINES[id]!;
    for (const n of [...(e.needs ?? []), ...(external ? (e.external?.needs ?? []) : [])]) add(n);
  };
  for (const f of formats) add(engineOf(f));
  return seen;
}

/**
 * The formats whose plugins the frame builds for the host's `formats`: those,
 * and what a converted file is shown as.
 */
export function pluginFormats(formats: readonly BuiltinFormat[], external = false): BuiltinFormat[] {
  const out = [...formats];
  for (const id of engineClosure(formats, external)) {
    const e = ENGINES[id]!;
    for (const f of [...(e.shows ?? []), ...(external ? (e.external?.shows ?? []) : [])]) if (!out.includes(f)) out.push(f);
  }
  return out;
}

/** Every format the frame opens when it ships the engines of `formats`. */
export function shippedFormats(formats: readonly BuiltinFormat[], external = false): BuiltinFormat[] {
  return [...engineClosure(formats, external)].flatMap((id) => ENGINES[id]!.formats);
}

/** The name of the page's `<meta>` that lists the formats a frame was published for. */
export const FRAME_FORMATS_META = "exav-frame-formats";
