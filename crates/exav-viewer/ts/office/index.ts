/**
 * `@exav/viewer/office`: Word, Excel, PowerPoint and CSV on `@silurus/ooxml`
 * (a peer dependency, MIT), whose engines parse Open XML in WebAssembly and
 * paint a canvas. One engine per format, each its own import: opening a
 * spreadsheet does not download the presentation engine.
 *
 * And the formats no browser engine reads (RTF, the 1997 Office formats,
 * OpenDocument, iWork, drawing and page layout formats), converted in the
 * browser. Spreadsheets (XLS, ODS, Numbers) are converted to XLSX, and
 * presentations and OpenDocument drawings (PPT, ODP, Keynote, ODG) to PPTX,
 * by exav-render, which this package ships; text documents (DOC, ODT, RTF) to
 * DOCX by it where no external converter is set. What no converter of the
 * package reads goes to an external converter, an ES module the host
 * installs and names (`externalConverter`, see `ExternalConverter`), which
 * resolves to a PDF, shown by `pdf()`, or an XLSX, shown by `xlsx()`: the host
 * registers those too. Without one, such a file ends in the "needs_converter"
 * error.
 *
 * Pictures and viewport (`controllers.pictures`, `controllers.viewport`),
 * regions in fractions of a page from its top left: a Word page, a slide, or
 * a sheet, which is its used area at 100 % without the headers the engine
 * draws around the cells (a CSV has one sheet). Page numbers are the viewer's
 * (hidden slides and sheets count). Drawn again at the size asked from a
 * second copy of the document, opened by the first picture or, for a sheet,
 * the first read of its viewport (`export.ts`), one picture at a time; the paper is opaque, so a transparent background is
 * refused. A region that needs a Word page or slide drawn past about 16
 * million pixels is refused as too large: the engines draw whole pages only.
 */
import { MATCHERS } from "../core/formats.js";
import type { Capability, FormatPlugin } from "../core/types.js";
import { docsFirst, slidesFirst } from "./route.js";

export interface OfficeOptions {
  /** Must stay false under a CSP without fonts.googleapis.com. Default false. */
  useGoogleFonts?: boolean;
  /**
   * Where the engines parse and paint: "main" (default) parses in a worker
   * made from an inline module and paints on the page; "worker" does both in
   * a worker started from a file, which is what the sandboxed frame can start.
   */
  mode?: "main" | "worker";
  /**
   * The most entries the ZIP of a document may list. Default 20000 (the
   * engines' own is 4096, which a deck of about a thousand slides with
   * pictures exceeds). The size a document may inflate to keeps its own
   * limit.
   */
  maxArchiveEntries?: number;
}

/** The entry limit used when `OfficeOptions.maxArchiveEntries` is not given. */
export const DEFAULT_MAX_ARCHIVE_ENTRIES = 20000;

/** For the converted formats. */
export interface ConversionOptions {
  /** A conversion still running after this long is stopped. Default 120000. */
  timeoutMs?: number;
  /**
   * The memory a conversion may take, in bytes, at most 4 GiB; past it, it
   * fails. exav-render's converters count their own, 1 GiB by default and at
   * most 1.5 GiB. Handed to the external converter as it is (absent when not
   * set).
   */
  maxMemory?: number;
  /**
   * What converts: "exav" is the converters this package ships (exav-render,
   * in WebAssembly), where there is one for the format; "external" is the
   * external converter alone, for every format.
   *
   * Spreadsheets (XLS, ODS, Numbers), presentations (PPT of any version, ODP,
   * Keynote of any version) and OpenDocument drawings (ODG, OTG, FODG) go to
   * the package's converters by default. A file one recognises and cannot
   * convert fails, its error's cause a `SheetConversionError`,
   * `SlideConversionError` or `DocConversionError` saying why; a file it does
   * not recognise (an HTML table saved as .xls, say) goes to the external
   * converter, or ends in a `NeedsConverterError` ("needs_converter") where
   * there is none.
   *
   * Text documents (DOC, ODT, RTF) go to the external converter when one is
   * set, and to the package's `docs` converter when not, or when this says
   * "exav". The other formats (CorelDRAW, Visio, Publisher and the like) go
   * to the external converter, and end in "needs_converter" without one.
   */
  converter?: "exav" | "external";
  /**
   * The external converter: the URL of an ES module (absolute, rooted, or
   * relative to the page), or the name of a package that
   * `@exav/viewer/vite` copied beside the assets (`externalConverter` of its
   * options, listed in the asset manifest). Default: none. See
   * `ExternalConverter` for what the module exports.
   */
  externalConverter?: string;
}

type Kind = "docx" | "xlsx" | "pptx" | "csv";

/** The formats `@exav/viewer/office` converts, by the viewer's name for them (the converter's `hint`). */
export type ConvertedFormat =
  | "rtf"
  | "doc"
  | "odt"
  | "ppt"
  | "odp"
  | "keynote"
  | "xls"
  | "ods"
  | "numbers"
  | "odg"
  | "visio"
  | "coreldraw"
  | "publisher"
  | "pagemaker"
  | "freehand"
  | "quarkxpress"
  | "zonerdraw"
  | "wpg";

const CAPABILITIES: Record<Kind, readonly Capability[]> = {
  docx: ["pages", "zoom", "pictures", "viewport"],
  xlsx: ["zoom", "sheets", "pictures", "viewport"],
  pptx: ["pages", "pictures", "viewport"],
  csv: ["zoom", "pictures", "viewport"],
};

/** What a converted file is shown with: the capabilities of `pdf()` and `xlsx()`. */
const AS_PDF: readonly Capability[] = ["pages", "zoom", "drag", "outline", "pictures", "viewport"];

const plugin = (kind: Kind, options: OfficeOptions): FormatPlugin<OfficeOptions> => ({
  id: kind,
  match: MATCHERS[kind],
  capabilities: CAPABILITIES[kind],
  options,
  load: () => import("./renderer.js").then((m) => m.rendererFor(kind)),
});

const converted = (kind: ConvertedFormat, options: ConversionOptions): FormatPlugin<ConversionOptions> => ({
  id: kind,
  match: MATCHERS[kind],
  capabilities:
    kind === "xls" || kind === "ods" || kind === "numbers"
      ? CAPABILITIES.xlsx
      : slidesFirst(kind, options)
        ? CAPABILITIES.pptx
        : docsFirst(kind, options)
          ? CAPABILITIES.docx
          : AS_PDF,
  options,
  load: () => import("./convert.js").then((m) => m.rendererFor(kind)),
  prefetch: (assetBase) => import("./convert.js").then((m) => m.prefetchUrls(kind, assetBase, options)),
});

export const docx = (options: OfficeOptions = {}) => plugin("docx", options);
export const xlsx = (options: OfficeOptions = {}) => plugin("xlsx", options);
export const pptx = (options: OfficeOptions = {}) => plugin("pptx", options);
/** The separator and the encoding are read off the bytes (`readingOf`). */
export const csv = (options: OfficeOptions = {}) => plugin("csv", options);

// Converted, templates and flat XML included. Within each kind (text,
// presentation, spreadsheet) the bytes decide: Word saves RTF under .doc, and
// an XLSX renamed .xls is shown as it is.
export const rtf = (options: ConversionOptions = {}) => converted("rtf", options);
/** Word 97 and later, 6.0 and 95. */
export const doc = (options: ConversionOptions = {}) => converted("doc", options);
export const odt = (options: ConversionOptions = {}) => converted("odt", options);
export const ppt = (options: ConversionOptions = {}) => converted("ppt", options);
export const odp = (options: ConversionOptions = {}) => converted("odp", options);
/** Keynote 1 to 6. */
export const keynote = (options: ConversionOptions = {}) => converted("keynote", options);
/** Excel 97 and later, 5.0/95 and 4.0. */
export const xls = (options: ConversionOptions = {}) => converted("xls", options);
export const ods = (options: ConversionOptions = {}) => converted("ods", options);
export const numbers = (options: ConversionOptions = {}) => converted("numbers", options);
// Drawings (ODG, OTG, FODG by the package, as slides) and page layouts (the external converter, to PDF).
export const odg = (options: ConversionOptions = {}) => converted("odg", options);
/** Visio: binary, XML and Open XML. */
export const visio = (options: ConversionOptions = {}) => converted("visio", options);
/** CorelDRAW and Corel Presentation Exchange. */
export const coreldraw = (options: ConversionOptions = {}) => converted("coreldraw", options);
export const publisher = (options: ConversionOptions = {}) => converted("publisher", options);
/** PageMaker 6 to 7. */
export const pagemaker = (options: ConversionOptions = {}) => converted("pagemaker", options);
/** FreeHand 3 to 11. */
export const freehand = (options: ConversionOptions = {}) => converted("freehand", options);
/** QuarkXPress 3.1 to 4.1. */
export const quarkxpress = (options: ConversionOptions = {}) => converted("quarkxpress", options);
/** Zoner Draw 4 and 5. */
export const zonerdraw = (options: ConversionOptions = {}) => converted("zonerdraw", options);
/** WordPerfect Graphics 1 and 2. */
export const wpg = (options: ConversionOptions = {}) => converted("wpg", options);

export { readingOf, type Reading } from "./delimited.js";
export { SheetConversionError, type SheetErrorKind, type SheetFormat } from "./sheets.js";
export { SlideConversionError, type SlideErrorKind, type SlideFormat } from "./slides.js";
export { DocConversionError, type DocErrorKind, type DocFormat } from "./docs.js";
export {
  ExternalConversionError,
  NeedsConverterError,
  type ConvertProgress,
  type ExternalConvertOptions,
  type ExternalConvertResult,
  type ExternalConverter,
} from "./external.js";
