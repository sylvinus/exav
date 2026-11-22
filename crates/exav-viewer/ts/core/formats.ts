/**
 * How each built-in format claims a file. The plugins use these; they live in
 * the core so that the table can be read, tested and exported without
 * loading any plugin. The extensions and types are the registry's
 * (`formats.generated.ts`, from formats/registry.json); what is written here
 * is how a format claims them: the steps of `FormatMatcher`.
 */
import { REGISTERED } from "./formats.generated.js";
import type { BuiltinFormat, FormatMatcher } from "./types.js";

/** Types that say nothing: the extension decides. */
export const UNKNOWN_TYPES: readonly string[] = ["", "application/octet-stream", "binary/octet-stream"];

const ZIP_TYPES = ["application/zip", "application/x-zip-compressed"];

/**
 * What exav's detection says of a compound file (a Word, Excel or PowerPoint
 * document of 1997, a Visio or Publisher file, an installer). The name says
 * which.
 */
const OLE_TYPE = "application/x-ole-storage";

/**
 * The types of files that hold other files, and that a format may be stored
 * in: the extension answers over them for a format that lists "container" in
 * its `extensionOverrides` (every .docx is a zip, every .doc a compound
 * file).
 */
export const CONTAINER_TYPES: readonly string[] = [...ZIP_TYPES, OLE_TYPE];

interface Names {
  extensions: readonly string[];
  types: readonly string[];
}

/** What any text file may be typed as: it says nothing of which text, so no format is claimed by it. */
const PLAIN_TYPE = "text/plain";

/**
 * The extensions and types of the registry entries of `plugin` that `pick`
 * takes (all of them by default), `text/plain` left out. Throws when there
 * are none: a plugin the registry does not know, or a pick that is out of
 * date.
 */
function registered(plugin: BuiltinFormat, pick: (id: string) => boolean = () => true): Names {
  const mine = Object.entries(REGISTERED).filter(([id, e]) => e.plugin === plugin && pick(id));
  if (!mine.length) throw new Error(`formats: no registry entry for ${plugin}`);
  return {
    extensions: mine.flatMap(([, e]) => e.extensions),
    types: [...new Set(mine.flatMap(([, e]) => e.types))].filter((t) => t !== PLAIN_TYPE),
  };
}

/**
 * The matcher of `plugin`: the registry's extensions and types, and `rest`.
 * A registry type that `rest` gives as a container type is not claimed
 * outright, only after the extensions (a zip may be a .docx).
 */
function matcher(plugin: BuiltinFormat, rest: Pick<FormatMatcher, "containerTypes" | "extensionOverrides"> = {}, pick?: (id: string) => boolean): FormatMatcher {
  const { extensions, types } = registered(plugin, pick);
  return { types: types.filter((t) => !rest.containerTypes?.includes(t)), extensions, ...rest };
}

const only = (...ids: string[]) => (id: string) => ids.includes(id);

/**
 * The text formats and how each is shown: the registry's entries of the text
 * plugin, with the source code entry shown as plain text. Only these names
 * and types are claimed: a file with another name is not opened as text
 * because it happens to be. `.svg` is absent on purpose: it is an image;
 * HTML is shown as its source.
 */
export const TEXT_KINDS: Record<"plain" | "markdown" | "json" | "xml" | "html" | "diff", Names> = {
  markdown: registered("text", only("markdown")),
  json: registered("text", only("json")),
  xml: registered("text", only("xml")),
  html: registered("text", only("html")),
  diff: registered("text", only("diff")),
  plain: registered("text", only("text", "source")),
};

/** The registry entry of what every browser's `<img>` draws. */
const BROWSER_IMAGES = "image-web";

export const MATCHERS: Record<BuiltinFormat, FormatMatcher> = {
  pdf: matcher("pdf"),
  /**
   * What every browser's `<img>` draws. SVG in an `<img>` runs no script and
   * loads nothing. `WASM_IMAGES` adds what exav-render decodes.
   */
  image: matcher("image", {}, only(BROWSER_IMAGES)),
  dwg: matcher("dwg"),
  dxf: matcher("dxf"),
  /**
   * Open XML, macro-enabled twins included (nothing here runs a macro). Every
   * one is a zip, so the extension answers over a zip type. The 1997 binary
   * formats, RTF and OpenDocument are below: they are converted
   * (`CONVERTED_FORMATS`).
   */
  docx: matcher("docx", { extensionOverrides: ["container"] }),
  xlsx: matcher("xlsx", { extensionOverrides: ["container"] }),
  pptx: matcher("pptx", { extensionOverrides: ["container"] }),
  /**
   * A table saved as text. Windows types a .csv as the 1997 spreadsheet
   * (with Excel) or as plain text (without): there only the extension tells
   * it from an .xls or a note. `.txt` is not here: no separator can be
   * guessed for it.
   */
  csv: matcher("csv", { extensionOverrides: ["application/vnd.ms-excel", "text/plain"] }),
  /**
   * What `@exav/viewer/office` converts. Within each kind (text, presentation,
   * spreadsheet) the plugin reads what the bytes really are: Word saves RTF
   * under .doc, and an .xls is often an XLSX renamed. The OpenDocument ones
   * are zips, and the 1997 formats compound files, so the extension answers
   * over those types.
   */
  rtf: matcher("rtf", { extensionOverrides: ["text/plain"] }),
  /** Also what Windows types an .rtf as, with Word installed: the bytes then say RTF. */
  doc: matcher("doc", { extensionOverrides: ["container"] }),
  odt: matcher("odt", { extensionOverrides: ["container"] }),
  pages: matcher("pages", { extensionOverrides: ["container"] }),
  ppt: matcher("ppt", { extensionOverrides: ["container"] }),
  odp: matcher("odp", { extensionOverrides: ["container"] }),
  keynote: matcher("keynote", { extensionOverrides: ["container"] }),
  /**
   * The 1997 workbook's type is not claimed outright: Windows gives it to
   * every .csv when Excel is installed (`csv`). With the extension it is.
   */
  xls: matcher("xls", { extensionOverrides: ["application/vnd.ms-excel", "container"] }),
  ods: matcher("ods", { extensionOverrides: ["container"] }),
  numbers: matcher("numbers", { extensionOverrides: ["container"] }),
  odg: matcher("odg", { extensionOverrides: ["container"] }),
  visio: matcher("visio", { extensionOverrides: ["container"] }),
  coreldraw: matcher("coreldraw", { extensionOverrides: ["container"] }),
  publisher: matcher("publisher", { extensionOverrides: ["container"] }),
  pagemaker: matcher("pagemaker"),
  freehand: matcher("freehand"),
  quarkxpress: matcher("quarkxpress"),
  /** Zipped or not. */
  zonerdraw: matcher("zonerdraw", { extensionOverrides: ["container"] }),
  wpg: matcher("wpg"),
  /**
   * Text, by name or type (`TEXT_KINDS`). Browsers type source files as plain
   * text, as scripts or, for `.ts`, as MPEG transport streams, so the
   * extension answers over those; the bytes are checked when it is opened.
   */
  text: matcher("text", {
    extensionOverrides: ["text/plain", "text/javascript", "application/javascript", "text/css", "application/x-sh", "text/x-python", "video/mp2t"],
  }),
  /** What browsers play. Listing what they cannot decode buys a black rectangle. */
  video: matcher("video"),
  audio: matcher("audio"),
  /** `.ifczip` is an archive: its model opens as a member. */
  ifc: matcher("ifc"),
  stl: matcher("stl"),
  /**
   * Text with no signature: only the extension names it. `application/x-tgif`
   * is what older desktops type `.obj` as (and compiled object files are
   * `.obj` too: the reader refuses what is not Wavefront text).
   */
  obj: matcher("obj", { extensionOverrides: ["text/plain", "application/x-tgif"] }),
  ply: matcher("ply", { extensionOverrides: ["text/plain"] }),
  /** A `.gltf` document or a `.glb` container. */
  gltf: matcher("gltf", { extensionOverrides: ["text/plain"] }),
  /**
   * A zip is asked about after the extensions: an Open XML document is a zip
   * too. Documents that happen to be zips (OpenDocument, EPUB) and the
   * formats another reader opens (PDF, Office, email) are not here.
   */
  archive: matcher("archive", {
    containerTypes: ZIP_TYPES,
    // Types a desktop gives these extensions that are not an archive's: FreeArc
    // for `.arc`, the game consoles' disc images for `.iso`, `.pkg` as Newton's,
    // the OVF descriptor for `.ova`. (`.vhd`, VHDL source for a desktop, is not
    // here: a text file named so is a text file.)
    extensionOverrides: [
      "application/x-freearc",
      "application/x-sega-cd-rom",
      "application/x-sega-pico-rom",
      "application/x-saturn-rom",
      "application/x-dreamcast-rom",
      "application/x-wii-rom",
      "application/x-gamecube-rom",
      "application/x-newton-compatible-pkg",
      "application/ovf",
    ],
  }),
};

/**
 * The images exav-render decodes for browsers that cannot: the image plugin's
 * `wasmDecoders`. The rest of the image entries of the registry.
 */
export const WASM_IMAGES: FormatMatcher = matcher(
  "image",
  // Desktops type a Kodak .dcr as the Shockwave Director file it also is.
  { extensionOverrides: ["application/x-director"] },
  (id) => id !== BROWSER_IMAGES,
);

/** What `@exav/viewer/office` converts before showing it (`rtf()`, `doc()`...). */
export const CONVERTED_FORMATS: readonly BuiltinFormat[] = [
  "rtf",
  "doc",
  "odt",
  "pages",
  "ppt",
  "odp",
  "keynote",
  "xls",
  "ods",
  "numbers",
  "odg",
  "visio",
  "coreldraw",
  "publisher",
  "pagemaker",
  "freehand",
  "quarkxpress",
  "zonerdraw",
  "wpg",
];

/**
 * The built-in formats. Their order does not change an answer: no two of them
 * claim the same type or extension (asserted in the tests).
 */
export const BUILTIN_ORDER: readonly BuiltinFormat[] = [
  "pdf",
  "image",
  "dwg",
  "dxf",
  "video",
  "audio",
  "ifc",
  "stl",
  "obj",
  "ply",
  "gltf",
  "docx",
  "xlsx",
  "pptx",
  "csv",
  "rtf",
  "doc",
  "odt",
  "pages",
  "ppt",
  "odp",
  "keynote",
  "xls",
  "ods",
  "numbers",
  "odg",
  "visio",
  "coreldraw",
  "publisher",
  "pagemaker",
  "freehand",
  "quarkxpress",
  "zonerdraw",
  "wpg",
  "text",
  "archive",
];
