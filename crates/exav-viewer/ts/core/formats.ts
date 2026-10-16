/**
 * How each built-in format claims a file. The plugins use these; they live in
 * the core so that the table can be read, tested and exported without
 * loading any plugin.
 */
import type { BuiltinFormat, FormatMatcher, Signature } from "./types.js";

const ascii = (text: string) => [...text].map((c) => c.charCodeAt(0));

/**
 * What the first bytes prove, in order, first match wins. Formats with no
 * signature (DXF, CSV, STL, OBJ, glTF) are told apart by their name alone.
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
  // JPEG XL: its signature box, and a bare codestream's two bytes.
  { type: "image/jxl", prefix: [0, 0, 0, 0x0c, ...ascii("JXL "), 0x0d, 0x0a, 0x87, 0x0a] },
  { type: "image/jxl", prefix: [0xff, 0x0a] },
  // Camera RAW files that are not TIFF underneath (the TIFF-structured ones,
  // DNG, CR2, NEF, ARW, PEF and the rest, sniff as `image/tiff`): Olympus
  // (IIRO, IIRS, MMOR), Panasonic, Fujifilm, Sigma, Canon CRW and Minolta.
  { type: "image/x-olympus-orf", prefix: ascii("IIRO") },
  { type: "image/x-olympus-orf", prefix: ascii("IIRS") },
  { type: "image/x-olympus-orf", prefix: ascii("MMOR") },
  { type: "image/x-panasonic-rw2", prefix: [0x49, 0x49, 0x55, 0x00] },
  { type: "image/x-fuji-raf", prefix: ascii("FUJIFILMCCD-RAW") },
  { type: "image/x-sigma-x3f", prefix: ascii("FOVb") },
  { type: "image/x-canon-crw", prefix: [0x49, 0x49, 0x1a, 0, 0, 0], also: ascii("HEAPCCDR"), alsoOffset: 6 },
  { type: "image/x-minolta-mrw", prefix: [0, ...ascii("MRM")] },
  // Canon CR3, an ISO-BMFF file: named before the MP4 catch-all below.
  { type: "image/x-canon-cr3", prefix: ascii("ftyp"), offset: 4, also: ascii("crx "), alsoOffset: 8 },
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
  { type: "audio/flac", prefix: ascii("fLaC") },
  { type: "application/ogg", prefix: ascii("OggS") },
  { type: "image/vnd.dwg", prefix: ascii("AC10") },
  // A STEP file; the schema line, a few hundred bytes in, says whether it is
  // an IFC model (`ifc`'s `confirmSniff`).
  { type: "model/ifc", prefix: ascii("ISO-10303-21;") },
  // A PLY header's first line (`ply`'s `confirmSniff` reads the second), and
  // a GLB's magic with its version 2.
  { type: "model/ply", prefix: ascii("ply\n") },
  { type: "model/ply", prefix: ascii("ply\r\n") },
  { type: "model/gltf-binary", prefix: ascii("glTF"), also: [2, 0, 0, 0], alsoOffset: 4 },
  { type: "application/zip", prefix: [0x50, 0x4b, 0x03, 0x04] },
  { type: "application/x-7z-compressed", prefix: [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c] },
  { type: "application/gzip", prefix: [0x1f, 0x8b] },
  { type: "application/x-rar-compressed", prefix: ascii("Rar!") },
  // The rest of what the archive plugin opens, for a member whose name says
  // nothing. A signature is only as long as it must be to leave text alone:
  // bzip2's is its "BZh" and the pi that opens its first block, a cabinet's
  // its zeroed reserved word. A tar says "ustar" at 257, an ISO 9660 image
  // "CD001" at 32769 (past the head read) and a disk image (dmg) at its end:
  // those are told by their names.
  { type: "application/x-bzip2", prefix: ascii("BZh"), also: ascii("1AY&SY"), alsoOffset: 4 },
  { type: "application/x-xz", prefix: [0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00] },
  { type: "application/zstd", prefix: [0x28, 0xb5, 0x2f, 0xfd] },
  { type: "application/x-lz4", prefix: [0x04, 0x22, 0x4d, 0x18] },
  { type: "application/x-lzip", prefix: ascii("LZIP"), also: [1], alsoOffset: 4 },
  { type: "application/x-compress", prefix: [0x1f, 0x9d] },
  { type: "application/x-tar", prefix: ascii("ustar"), offset: 257 },
  { type: "application/vnd.ms-cab-compressed", prefix: ascii("MSCF"), also: [0, 0, 0, 0], alsoOffset: 4 },
  { type: "application/vnd.ms-htmlhelp", prefix: ascii("ITSF"), also: [0, 0, 0], alsoOffset: 5 },
  { type: "application/x-lzh-compressed", prefix: ascii("-lh"), offset: 2 },
  { type: "application/x-lzh-compressed", prefix: ascii("-lz"), offset: 2 },
  { type: "application/x-arj", prefix: [0x60, 0xea] },
  { type: "application/x-archive", prefix: ascii("!<arch>\n") },
  { type: "application/x-cpio", prefix: ascii("070701") },
  { type: "application/x-cpio", prefix: ascii("070702") },
  { type: "application/x-cpio", prefix: ascii("070707") },
  { type: "application/x-xar", prefix: ascii("xar!"), also: [0], alsoOffset: 4 },
  { type: "application/x-ms-wim", prefix: ascii("MSWIM"), also: [0, 0, 0], alsoOffset: 5 },
  { type: "application/vnd.ms-tnef", prefix: [0x78, 0x9f, 0x3e, 0x22] },
  { type: "application/x-vhdx", prefix: ascii("vhdxfile") },
  { type: "application/x-vmdk", prefix: ascii("KDMV") },
  { type: "application/x-qemu-disk", prefix: [0x51, 0x46, 0x49, 0xfb] },
];

/** Types that say nothing: the extension decides. */
export const UNKNOWN_TYPES: readonly string[] = ["", "application/octet-stream", "binary/octet-stream"];

const ZIP_TYPES = ["application/zip", "application/x-zip-compressed"];

/** A file that says `ply` and then its format, or one named `.ply`. */
function isPly(head: Uint8Array, name: string): boolean {
  if (name.toLowerCase().endsWith(".ply")) return true;
  const text = new TextDecoder("latin1").decode(head.subarray(0, 64));
  return /^ply\r?\nformat (ascii|binary_little_endian|binary_big_endian) /.test(text);
}

/** A STEP file whose schema says IFC, or one named `.ifc`. */
function isIfc(head: Uint8Array, name: string): boolean {
  if (name.toLowerCase().endsWith(".ifc")) return true;
  const text = new TextDecoder("latin1").decode(head).toUpperCase();
  return text.includes("FILE_SCHEMA") && text.includes("IFC");
}

/**
 * The text formats and how each is shown. Only these names and types are
 * claimed: a file with another name is not opened as text because it happens
 * to be. `.svg` is absent on purpose: it is an image; HTML
 * is shown as its source.
 */
export const TEXT_KINDS: Record<"plain" | "markdown" | "json" | "xml" | "html" | "diff", { extensions: readonly string[]; types: readonly string[] }> = {
  markdown: { extensions: [".md", ".markdown"], types: ["text/markdown", "text/x-markdown"] },
  json: {
    extensions: [".json", ".geojson"],
    types: ["application/json", "text/json", "application/ld+json", "application/geo+json"],
  },
  xml: {
    extensions: [".xml", ".xsd", ".xsl", ".xslt", ".rss", ".atom", ".kml", ".gpx", ".rdf", ".wsdl", ".plist"],
    types: [
      "application/xml",
      "text/xml",
      "application/atom+xml",
      "application/rss+xml",
      "application/xslt+xml",
      "application/gpx+xml",
      "application/vnd.google-earth.kml+xml",
    ],
  },
  html: { extensions: [".html", ".htm", ".xhtml"], types: ["text/html", "application/xhtml+xml"] },
  diff: { extensions: [".diff", ".patch"], types: ["text/x-diff", "text/x-patch"] },
  plain: {
    extensions: [
      ".txt", ".text", ".log", ".jsonl", ".ndjson", ".srt", ".vtt", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf", ".properties",
      ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".mts", ".cts", ".css", ".scss", ".py", ".sh", ".bash", ".zsh", ".bat", ".ps1",
      ".c", ".h", ".cc", ".cpp", ".hpp", ".cs", ".rs", ".go", ".java", ".kt", ".swift", ".rb", ".php", ".pl", ".lua", ".sql",
    ],
    types: [
      "text/vtt",
      "application/x-subrip",
      "application/x-yaml",
      "application/yaml",
      "text/yaml",
      "text/x-yaml",
      "application/toml",
      "application/x-ndjson",
      "text/css",
      "text/javascript",
      "application/javascript",
      "application/x-sh",
      "text/x-python",
    ],
  },
};

const textKinds = Object.values(TEXT_KINDS);

export const MATCHERS: Record<BuiltinFormat, FormatMatcher> = {
  pdf: { types: ["application/pdf"], extensions: [".pdf"] },
  /**
   * What every browser's `<img>` draws. SVG in an `<img>` runs no script and
   * loads nothing. `WASM_IMAGES` adds what exav-render decodes.
   */
  image: {
    types: ["image/png", "image/jpeg", "image/webp", "image/gif", "image/svg+xml"],
    extensions: [".png", ".jpg", ".jpeg", ".webp", ".gif", ".svg"],
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
   * formats, RTF and OpenDocument are below: they are converted
   * (`CONVERTED_FORMATS`).
   */
  docx: {
    types: [
      "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
      "application/vnd.ms-word.document.macroenabled.12",
      "application/vnd.openxmlformats-officedocument.wordprocessingml.template",
    ],
    extensions: [".docx", ".docm", ".dotx"],
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
      "application/vnd.openxmlformats-officedocument.presentationml.slideshow",
      "application/vnd.openxmlformats-officedocument.presentationml.template",
    ],
    extensions: [".pptx", ".pptm", ".ppsx", ".potx"],
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
  /**
   * What `@exav/viewer/office` converts. Within each kind (text, presentation,
   * spreadsheet) the plugin reads what the bytes really are: Word saves RTF
   * under .doc, and an .xls is often an XLSX renamed. The OpenDocument ones
   * are zips, so the extension answers over a zip type.
   */
  rtf: { types: ["application/rtf", "text/rtf", "application/x-rtf"], extensions: [".rtf"], extensionOverrides: ["text/plain"] },
  /** Also what Windows types an .rtf as, with Word installed: the bytes then say RTF. Word 6.0 and 95 too. */
  doc: { types: ["application/msword"], extensions: [".doc", ".dot"] },
  /** With templates and flat XML (one XML file, not a zip). */
  odt: {
    types: ["application/vnd.oasis.opendocument.text", "application/vnd.oasis.opendocument.text-template", "application/vnd.oasis.opendocument.text-flat-xml"],
    extensions: [".odt", ".ott", ".fodt"],
    extensionOverrides: ["container"],
  },
  ppt: { types: ["application/vnd.ms-powerpoint"], extensions: [".ppt", ".pps", ".pot"] },
  odp: {
    types: [
      "application/vnd.oasis.opendocument.presentation",
      "application/vnd.oasis.opendocument.presentation-template",
      "application/vnd.oasis.opendocument.presentation-flat-xml",
    ],
    extensions: [".odp", ".otp", ".fodp"],
    extensionOverrides: ["container"],
  },
  /** Keynote 1 to 6, zipped (the 2013 format, and the XML one before it). */
  keynote: {
    types: ["application/vnd.apple.keynote", "application/x-iwork-keynote-sffkey"],
    extensions: [".key"],
    extensionOverrides: ["container"],
  },
  /**
   * The 1997 workbook's type is not claimed outright: Windows gives it to
   * every .csv when Excel is installed (`csv`). With the extension it is.
   * Excel 5.0/95 and 4.0 too.
   */
  xls: { types: ["application/x-msexcel", "application/x-excel"], extensions: [".xls", ".xlt"], extensionOverrides: ["application/vnd.ms-excel"] },
  ods: {
    types: [
      "application/vnd.oasis.opendocument.spreadsheet",
      "application/vnd.oasis.opendocument.spreadsheet-template",
      "application/vnd.oasis.opendocument.spreadsheet-flat-xml",
    ],
    extensions: [".ods", ".ots", ".fods"],
    extensionOverrides: ["container"],
  },
  /** Numbers, zipped. */
  numbers: {
    types: ["application/vnd.apple.numbers", "application/x-iwork-numbers-sffnumbers"],
    extensions: [".numbers"],
    extensionOverrides: ["container"],
  },
  /** Drawings, converted to PDF like the presentations. With templates and flat XML. */
  odg: {
    types: [
      "application/vnd.oasis.opendocument.graphics",
      "application/vnd.oasis.opendocument.graphics-template",
      "application/vnd.oasis.opendocument.graphics-flat-xml",
    ],
    extensions: [".odg", ".otg", ".fodg"],
    extensionOverrides: ["container"],
  },
  /** Visio: binary, XML (.vdx) and Open XML, with templates. */
  visio: {
    types: [
      "application/vnd.visio",
      "application/vnd.ms-visio.drawing",
      "application/vnd.ms-visio.drawing.main+xml",
      "application/vnd.ms-visio.drawing.macroenabled.main+xml",
      "application/vnd.ms-visio.template.main+xml",
      "application/vnd.ms-visio.template.macroenabled.main+xml",
    ],
    extensions: [".vsd", ".vst", ".vdx", ".vtx", ".vsdx", ".vsdm", ".vstx", ".vstm"],
    extensionOverrides: ["container"],
  },
  /** CorelDRAW, and its exchange format (.cmx). */
  coreldraw: {
    types: [
      "application/vnd.corel-draw",
      "application/cdr",
      "application/coreldraw",
      "application/x-cdr",
      "application/x-coreldraw",
      "image/cdr",
      "image/x-cdr",
      "image/x-cmx",
    ],
    extensions: [".cdr", ".cmx"],
    extensionOverrides: ["container"],
  },
  publisher: { types: ["application/vnd.ms-publisher", "application/x-mspublisher"], extensions: [".pub"] },
  /** PageMaker 6 to 7. */
  pagemaker: { types: ["application/x-pagemaker"], extensions: [".pmd", ".pm6", ".p65"] },
  /** FreeHand 3 to 11. */
  freehand: { types: ["image/x-freehand"], extensions: [".fh", ".fh3", ".fh4", ".fh5", ".fh7", ".fh8", ".fh9", ".fh10", ".fh11"] },
  /** QuarkXPress 3.1 to 4.1. */
  quarkxpress: { types: ["application/vnd.quark.quarkxpress"], extensions: [".qxd", ".qxt"] },
  /** Zoner Draw 4 and 5, zipped or not. */
  zonerdraw: { extensions: [".zmf"], extensionOverrides: ["container"] },
  /** WordPerfect Graphics 1 and 2. */
  wpg: { types: ["application/x-wpg", "image/x-wpg"], extensions: [".wpg"] },
  /**
   * Text, by name or type (`TEXT_KINDS`). Browsers type source files as plain
   * text, as scripts or, for `.ts`, as MPEG transport streams, so the
   * extension answers over those; the bytes are checked when it is opened.
   */
  text: {
    types: textKinds.flatMap((k) => k.types),
    extensions: textKinds.flatMap((k) => k.extensions),
    extensionOverrides: ["text/plain", "text/javascript", "application/javascript", "text/css", "application/x-sh", "text/x-python", "video/mp2t"],
  },
  /** What browsers play. Listing what they cannot decode buys a black rectangle. */
  video: {
    types: ["video/mp4", "video/quicktime", "video/webm", "video/ogg"],
    extensions: [".mp4", ".m4v", ".mov", ".webm", ".ogv"],
  },
  audio: {
    types: ["audio/mpeg", "audio/mp4", "audio/x-m4a", "audio/aac", "audio/wav", "audio/x-wav", "audio/ogg", "audio/webm", "audio/flac", "audio/x-flac"],
    extensions: [".mp3", ".m4a", ".aac", ".wav", ".ogg", ".oga", ".opus", ".flac"],
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
  /**
   * Text with no signature: only the extension names it. `application/x-tgif`
   * is what older desktops type `.obj` as (and compiled object files are
   * `.obj` too: the reader refuses what is not Wavefront text).
   */
  obj: {
    types: ["model/obj"],
    extensions: [".obj"],
    extensionOverrides: ["text/plain", "application/x-tgif"],
  },
  ply: {
    types: ["model/ply", "application/x-ply"],
    extensions: [".ply"],
    extensionOverrides: ["text/plain"],
    confirmSniff: isPly,
  },
  /** A `.gltf` document or a `.glb` container. */
  gltf: {
    types: ["model/gltf+json", "model/gltf-binary"],
    extensions: [".gltf", ".glb"],
    extensionOverrides: ["text/plain"],
  },
  /**
   * A zip is asked about after the extensions: an Open XML document is a zip
   * too. What is here is what a person opens to see the files inside: the
   * archives, the compressed streams, the packages that are zips (a jar, an
   * apk), the comic book archives, the installers' containers (a cabinet, a
   * pkg, a deb, a wim), the optical and virtual disk images, `winmail.dat`.
   * Documents that happen to be zips (OpenDocument, EPUB) and the formats
   * another reader opens (PDF, Office, email) are not.
   */
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
      "application/zstd",
      "application/x-zstd",
      "application/x-lz4",
      "application/x-lzip",
      "application/x-compress",
      "application/vnd.ms-cab-compressed",
      "application/x-cab",
      "application/vnd.ms-htmlhelp",
      "application/x-chm",
      "application/x-iso9660-image",
      "application/x-cd-image",
      "application/x-lzh-compressed",
      "application/x-lzh",
      "application/x-lha",
      "application/x-arj",
      "application/arj",
      "application/x-archive",
      "application/x-unix-archive",
      "application/vnd.debian.binary-package",
      "application/x-debian-package",
      "application/x-cpio",
      "application/x-xar",
      "application/x-apple-diskimage",
      "application/x-ms-wim",
      "application/vnd.ms-tnef",
      "application/x-vhd",
      "application/x-vhdx",
      "application/x-vmdk",
      "application/x-qemu-disk",
      "application/x-zoo",
      "application/x-arc",
      "application/x-alz",
      "application/java-archive",
      "application/x-java-archive",
      "application/vnd.android.package-archive",
      "application/x-xpinstall",
      "application/vnd.google-earth.kmz",
      "application/vnd.comicbook+zip",
      "application/vnd.comicbook-rar",
      "application/x-cbz",
      "application/x-cbr",
      "application/x-cb7",
      "application/x-cbt",
      // What a desktop gives a file by its extension: a tarball is its own
      // type there (shared-mime-info), and Windows has one for .tgz.
      "application/x-compressed-tar",
      "application/x-bzip-compressed-tar",
      "application/x-bzip1-compressed-tar",
      "application/x-bzip2-compressed-tar",
      "application/x-xz-compressed-tar",
      "application/x-zstd-compressed-tar",
      "application/x-lzma-compressed-tar",
      "application/x-lzip-compressed-tar",
      "application/x-tarz",
      "application/x-gtar",
      "application/x-compressed",
      "application/vnd.efi.iso",
      "application/x-vhd-disk",
      "application/x-vhdx-disk",
      "application/x-vmdk-disk",
    ],
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
    extensions: [
      ".zip", ".7z", ".rar", ".tar", ".gz", ".tgz", ".bz2", ".tbz", ".tbz2", ".xz", ".txz",
      ".zst", ".tzst", ".lz4", ".lz", ".tlz", ".z", ".taz",
      ".cab", ".chm", ".iso", ".lzh", ".lha", ".arj", ".ar", ".a", ".deb", ".udeb", ".cpio",
      ".xar", ".pkg", ".xip", ".dmg", ".wim", ".esd", "winmail.dat", ".tnef",
      ".vhd", ".vhdx", ".vmdk", ".qcow2", ".ova", ".zoo", ".arc", ".alz", ".egg",
      ".img",
      ".jar", ".war", ".ear", ".apk", ".apks", ".xapk", ".aab", ".ipa", ".xpi", ".whl", ".nupkg", ".vsix", ".kmz",
      ".appx", ".appxbundle", ".msix", ".msixbundle",
      ".cbz", ".cbr", ".cb7", ".cbt",
    ],
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
    "image/jxl",
    // Camera RAW files, shown by their embedded preview, under the names
    // desktops give them and the ones `SIGNATURES` sniffs.
    "image/x-adobe-dng",
    "image/dng",
    "image/x-canon-cr2",
    "image/x-canon-cr3",
    "image/x-canon-crw",
    "image/x-nikon-nef",
    "image/x-nikon-nrw",
    "image/x-sony-arw",
    "image/x-sony-sr2",
    "image/x-sony-srf",
    "image/x-olympus-orf",
    "image/x-panasonic-rw2",
    "image/x-panasonic-raw",
    "image/x-fuji-raf",
    "image/x-pentax-pef",
    "image/x-samsung-srw",
    "image/x-sigma-x3f",
    "image/x-minolta-mrw",
    "image/x-kodak-dcr",
    "image/x-kodak-kdc",
    "image/x-epson-erf",
    "image/x-mamiya-mef",
    "image/x-leaf-mos",
    "image/x-hasselblad-3fr",
    "image/x-phaseone-iiq",
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
    ".jxl",
    // Camera RAW: Adobe DNG (and GoPro's GPR), Canon, Nikon, Sony, Olympus,
    // Panasonic and Leica, Fujifilm, Pentax, Samsung, Hasselblad, Phase One,
    // Sigma, Minolta, Kodak, Epson, Mamiya, Leaf.
    ".dng",
    ".gpr",
    ".cr2",
    ".cr3",
    ".crw",
    ".nef",
    ".nrw",
    ".arw",
    ".sr2",
    ".srf",
    ".orf",
    ".ori",
    ".rw2",
    ".rwl",
    ".raw",
    ".raf",
    ".pef",
    ".srw",
    ".3fr",
    ".fff",
    ".iiq",
    ".x3f",
    ".mrw",
    ".dcr",
    ".kdc",
    ".erf",
    ".mef",
    ".mos",
  ],
  // Desktops type a Kodak .dcr as the Shockwave Director file it also is.
  extensionOverrides: ["application/x-director"],
};

/** What `@exav/viewer/office` converts before showing it (`rtf()`, `doc()`...). */
export const CONVERTED_FORMATS: readonly BuiltinFormat[] = [
  "rtf",
  "doc",
  "odt",
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
