/**
 * `@exav/viewer/office`: Word, Excel, PowerPoint and CSV on `@silurus/ooxml`
 * (a peer dependency, MIT), whose engines parse Open XML in WebAssembly and
 * paint a canvas. One engine per format, each its own import: opening a
 * spreadsheet does not download the presentation engine.
 */
import { MATCHERS } from "../core/formats.js";
import type { FormatPlugin } from "../core/types.js";

export interface OfficeOptions {
  /** Must stay false under a CSP without fonts.googleapis.com. Default false. */
  useGoogleFonts?: boolean;
  /**
   * Where the engines parse and paint: "main" (default) parses in a worker
   * made from an inline module and paints on the page; "worker" does both in
   * a worker started from a file, which is what the sandboxed frame can start.
   */
  mode?: "main" | "worker";
}

type Kind = "docx" | "xlsx" | "pptx" | "csv";

const plugin = (kind: Kind, options: OfficeOptions): FormatPlugin<OfficeOptions> => ({
  id: kind,
  match: MATCHERS[kind],
  capabilities: kind === "docx" || kind === "pptx" ? ["pages"] : [],
  options,
  load: () => import("./renderer.js").then((m) => m.rendererFor(kind)),
});

export const docx = (options: OfficeOptions = {}) => plugin("docx", options);
export const xlsx = (options: OfficeOptions = {}) => plugin("xlsx", options);
export const pptx = (options: OfficeOptions = {}) => plugin("pptx", options);
/** The separator and the encoding are read off the bytes (`readingOf`). */
export const csv = (options: OfficeOptions = {}) => plugin("csv", options);

export { readingOf, type Reading } from "./delimited.js";
