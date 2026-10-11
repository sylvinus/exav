/**
 * How each built-in format claims a file. The plugins use these; they live in
 * the core so that the table can be read, tested and exported without
 * loading any plugin.
 */
import type { BuiltinFormat, FormatMatcher, Signature } from "./types.js";

const ascii = (text: string) => [...text].map((c) => c.charCodeAt(0));

/**
 * What the first bytes prove, in order, first match wins. Formats with no
 * signature (DXF, CSV, STL) are told apart by their name alone.
 */
export const SIGNATURES: readonly Signature[] = [
  { type: "application/pdf", prefix: ascii("%PDF-") },
  { type: "image/png", prefix: [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a] },
  { type: "image/jpeg", prefix: [0xff, 0xd8, 0xff] },
  { type: "image/gif", prefix: ascii("GIF87a") },
  { type: "image/gif", prefix: ascii("GIF89a") },
  { type: "image/webp", prefix: ascii("RIFF"), also: ascii("WEBP"), alsoOffset: 8 },
  { type: "audio/wav", prefix: ascii("RIFF"), also: ascii("WAVE"), alsoOffset: 8 },
  { type: "image/tiff", prefix: [0x49, 0x49, 0x2a, 0x00] },
  { type: "image/tiff", prefix: [0x4d, 0x4d, 0x00, 0x2a] },
  { type: "image/bmp", prefix: ascii("BM") },
  // The JP2 signature box (JPX files open with it too), a bare JPEG 2000
  // codestream (SOC, SIZ), and the JBIG2 file header.
  { type: "image/jp2", prefix: [0, 0, 0, 0x0c, ...ascii("jP  "), 0x0d, 0x0a, 0x87, 0x0a] },
  { type: "image/j2c", prefix: [0xff, 0x4f, 0xff, 0x51] },
  { type: "image/x-jbig2", prefix: [0x97, ...ascii("JB2"), 0x0d, 0x0a, 0x1a, 0x0a] },
  // Named so that the MP4 catch-all below does not take a photograph for a
  // video. No plugin claims HEIC.
  { type: "image/heic", prefix: ascii("ftyp"), offset: 4, also: ascii("heic"), alsoOffset: 8 },
  { type: "image/heic", prefix: ascii("ftyp"), offset: 4, also: ascii("heix"), alsoOffset: 8 },
  { type: "image/heif", prefix: ascii("ftyp"), offset: 4, also: ascii("mif1"), alsoOffset: 8 },
  { type: "video/quicktime", prefix: ascii("ftyp"), offset: 4, also: ascii("qt  "), alsoOffset: 8 },
  // Every other ISO-BMFF brand (isom, mp42, avc1, M4V...) is an MP4 to a
  // `<video>`.
  { type: "video/mp4", prefix: ascii("ftyp"), offset: 4 },
  { type: "video/webm", prefix: [0x1a, 0x45, 0xdf, 0xa3] },
  { type: "audio/mpeg", prefix: ascii("ID3") },
  { type: "application/ogg", prefix: ascii("OggS") },
  { type: "image/vnd.dwg", prefix: ascii("AC10") },
  // A STEP file; the schema line, a few hundred bytes in, says whether it is
  // an IFC model (`ifc`'s `confirmSniff`).
  { type: "model/ifc", prefix: ascii("ISO-10303-21;") },
  { type: "application/zip", prefix: [0x50, 0x4b, 0x03, 0x04] },
  { type: "application/x-7z-compressed", prefix: [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c] },
  { type: "application/gzip", prefix: [0x1f, 0x8b] },
  { type: "application/x-rar-compressed", prefix: ascii("Rar!") },
];

/** Types that say nothing: the extension decides. */
export const UNKNOWN_TYPES: readonly string[] = ["", "application/octet-stream", "binary/octet-stream"];

const ZIP_TYPES = ["application/zip", "application/x-zip-compressed"];

/** A STEP file whose schema says IFC, or one named `.ifc`. */
function isIfc(head: Uint8Array, name: string): boolean {
  if (name.toLowerCase().endsWith(".ifc")) return true;
  const text = new TextDecoder("latin1").decode(head).toUpperCase();
  return text.includes("FILE_SCHEMA") && text.includes("IFC");
}

export const MATCHERS: Record<BuiltinFormat, FormatMatcher> = {
  pdf: { types: ["application/pdf"], extensions: [".pdf"] },
  /**
   * What every browser's `<img>` draws. SVG is deliberately absent: it has no
   * intrinsic size to fit, and it is a document that can carry scripts.
   * `WASM_IMAGES` adds what exav-render decodes.
   */
  image: {
    types: ["image/png", "image/jpeg", "image/webp", "image/gif"],
    extensions: [".png", ".jpg", ".jpeg", ".webp", ".gif"],
  },
  /** The registered type, and what CAD applications are seen sending. */
  dwg: {
    types: [
      "image/vnd.dwg",
      "image/x-dwg",
      "application/acad",
      "application/x-acad",
      "application/dwg",
      "application/x-dwg",
      "drawing/dwg",
    ],
    extensions: [".dwg"],
  },
  dxf: {
    types: ["image/vnd.dxf", "image/x-dxf", "application/dxf", "application/x-dxf", "drawing/x-dxf"],
    extensions: [".dxf"],
  },
  /**
   * Open XML, macro-enabled twins included (nothing here runs a macro). Every
   * one is a zip, so the extension answers over a zip type. The 1997 binary
   * formats are absent: no browser engine reads them.
   */
  docx: {
    types: [
      "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
      "application/vnd.ms-word.document.macroenabled.12",
    ],
    extensions: [".docx", ".docm"],
    extensionOverrides: ["container"],
  },
  xlsx: {
    types: [
      "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
      "application/vnd.ms-excel.sheet.macroenabled.12",
    ],
    extensions: [".xlsx", ".xlsm"],
    extensionOverrides: ["container"],
  },
  pptx: {
    types: [
      "application/vnd.openxmlformats-officedocument.presentationml.presentation",
      "application/vnd.ms-powerpoint.presentation.macroenabled.12",
    ],
    extensions: [".pptx", ".pptm"],
    extensionOverrides: ["container"],
  },
  /**
   * A table saved as text. Windows types a .csv as the 1997 spreadsheet
   * (with Excel) or as plain text (without): there only the extension tells
   * it from an .xls or a note. `.txt` is not here: no separator can be
   * guessed for it.
   */
  csv: {
    types: ["text/csv", "text/tab-separated-values"],
    extensions: [".csv", ".tsv"],
    extensionOverrides: ["application/vnd.ms-excel", "text/plain"],
  },
  /** What browsers play. Listing what they cannot decode buys a black rectangle. */
  video: {
    types: ["video/mp4", "video/quicktime", "video/webm", "video/ogg"],
    extensions: [".mp4", ".m4v", ".mov", ".webm", ".ogv"],
  },
  audio: {
    types: ["audio/mpeg", "audio/mp4", "audio/x-m4a", "audio/aac", "audio/wav", "audio/x-wav", "audio/ogg", "audio/webm"],
    extensions: [".mp3", ".m4a", ".aac", ".wav", ".ogg", ".oga", ".opus"],
  },
  /** `.ifczip` is an archive: its model opens as a member. */
  ifc: {
    types: ["model/ifc", "application/x-step", "application/ifc", "model/step"],
    extensions: [".ifc"],
    confirmSniff: isIfc,
  },
  /** `application/vnd.ms-pki.stl` is what Windows maps `.stl` to (a certificate trust list). */
  stl: {
    types: ["model/stl", "model/x.stl-binary", "model/x.stl-ascii", "application/sla", "application/vnd.ms-pki.stl", "application/x-navistyle"],
    extensions: [".stl"],
  },
  /** A zip is asked about after the extensions: an Open XML document is a zip too. */
  archive: {
    types: [
      "application/x-7z-compressed",
      "application/x-rar-compressed",
      "application/vnd.rar",
      "application/gzip",
      "application/x-gzip",
      "application/x-tar",
      "application/x-bzip2",
      "application/x-xz",
    ],
    containerTypes: ZIP_TYPES,
    extensions: [".zip", ".7z", ".rar", ".tar", ".gz", ".tgz", ".bz2", ".tbz2", ".xz", ".txz"],
  },
};

/** The images exav-render decodes for browsers that cannot: the image plugin's `wasmDecoders`. */
export const WASM_IMAGES: FormatMatcher = {
  types: [
    "image/tiff",
    "image/bmp",
    "image/x-ms-bmp",
    "image/x-icon",
    "image/vnd.microsoft.icon",
    "image/x-portable-anymap",
    "image/x-portable-bitmap",
    "image/x-portable-graymap",
    "image/x-portable-pixmap",
    "image/qoi",
    "image/vnd-ms.dds",
    "image/vnd.radiance",
    "image/jp2",
    "image/jpx",
    "image/j2c",
    "image/x-jbig2",
    "image/jbig2",
  ],
  extensions: [
    ".tif",
    ".tiff",
    ".bmp",
    ".ico",
    ".pbm",
    ".pgm",
    ".ppm",
    ".pnm",
    ".pam",
    ".qoi",
    ".dds",
    ".ff",
    ".hdr",
    ".jp2",
    ".jpf",
    ".jpx",
    ".j2k",
    ".j2c",
    ".jb2",
    ".jbig2",
  ],
};

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
  "docx",
  "xlsx",
  "pptx",
  "csv",
  "archive",
];
