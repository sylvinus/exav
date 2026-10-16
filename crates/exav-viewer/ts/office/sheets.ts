/**
 * XLS, ODS, FODS, Numbers, and the text formats Excel opens from a .xls
 * file (XML Spreadsheet 2003, HTML tables, SYLK), converted to XLSX by
 * exav-render's `sheets` (exav_viewer_sheets.wasm), in a worker of its own for
 * this one file, terminated when it is done: a wasm instance's memory never
 * shrinks.
 */
import { createWorkerHost, type WorkerHost } from "../core/worker-host.js";

/** What the converter reads: "xml" is Excel's XML Spreadsheet 2003, "slk" SYLK. */
export type SheetFormat = "xls" | "ods" | "fods" | "numbers" | "xml" | "html" | "slk";

export interface SheetRequest {
  bytes: ArrayBuffer;
  format: SheetFormat;
  maxCells: number;
  maxMemory: number;
}

export interface SheetResult {
  xlsx: ArrayBuffer;
  warnings: string;
}

/**
 * Why a conversion failed: the converter's error kinds, "timeout" when it
 * did not answer in time, "crashed" when its module trapped.
 */
export type SheetErrorKind = "not-format" | "encrypted" | "unsupported" | "too-large" | "malformed" | "timeout" | "crashed";

const KINDS: readonly string[] = ["not-format", "encrypted", "unsupported", "too-large", "malformed"];

/** A spreadsheet exav-render's `sheets` recognised and could not convert. */
export class SheetConversionError extends Error {
  readonly kind: SheetErrorKind;
  constructor(
    readonly format: SheetFormat,
    cause: unknown,
  ) {
    const reason = cause instanceof Error ? cause.message : String(cause);
    const kind: SheetErrorKind = KINDS.includes(reason) ? (reason as SheetErrorKind) : /^no answer within/.test(reason) ? "timeout" : "crashed";
    super(`the ${format} file could not be converted: ${kind}`, { cause });
    this.name = "SheetConversionError";
    this.kind = kind;
  }
}

/** Cells and memory a conversion may take: the converter's defaults. */
export const SHEET_LIMITS = { maxCells: 4_000_000, maxMemory: 1 << 30 };

/** The module may grow to 2 GiB; the converter's own count leaves room for the file and the output. */
const MAX_MEMORY = 1.5 * 2 ** 30;

const ascii = (bytes: Uint8Array, at: number, text: string) => {
  if (at + text.length > bytes.length) return false;
  for (let i = 0; i < text.length; i++) if (bytes[at + i] !== text.charCodeAt(i)) return false;
  return true;
};

const contains = (bytes: Uint8Array, from: number, to: number, text: string) => {
  const first = text.charCodeAt(0);
  for (let i = Math.max(0, from); i <= Math.min(bytes.length, to) - text.length; i++) {
    if (bytes[i] === first && ascii(bytes, i, text)) return true;
  }
  return false;
};

/**
 * The start of a text document as ASCII, lower case: UTF-16 by its BOM
 * read a byte in two, a UTF-8 BOM and leading white space skipped.
 */
function textHead(bytes: Uint8Array, n = 4096): string {
  let step = 1;
  let at = 0;
  if ((bytes[0] === 0xff && bytes[1] === 0xfe) || (bytes[0] === 0xfe && bytes[1] === 0xff)) {
    step = 2;
    at = bytes[0] === 0xff ? 2 : 3;
  } else if (bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) at = 3;
  let s = "";
  for (let i = at; i < bytes.length && s.length < n; i += step) s += String.fromCharCode(bytes[i]! < 0x80 ? bytes[i]! : 0x3f);
  return s.trimStart().toLowerCase();
}

/**
 * What the bytes are: a spreadsheet the converter reads, an XLSX shown as
 * it is, or `null` for anything else (left to the external converter, which
 * may read more: CSV, DIF, dBase and the like saved as .xls).
 */
export function sniffSheet(bytes: Uint8Array): SheetFormat | "xlsx" | null {
  // A compound file, or a BIFF2 to BIFF4 worksheet's BOF record.
  if (bytes[0] === 0xd0 && bytes[1] === 0xcf && bytes[2] === 0x11 && bytes[3] === 0xe0) return "xls";
  if (bytes[0] === 0x09 && [0x00, 0x02, 0x04].includes(bytes[1]!) && bytes[2]! < 0x20 && bytes[3] === 0) return "xls";
  if (bytes[0] === 0x50 && bytes[1] === 0x4b) {
    // OpenDocument: the stored "mimetype" member first.
    // Stored, as the specification asks; a deflated one (some tools zip it
    // so) is told by the members below.
    const stored = bytes[8] === 0 && bytes[9] === 0;
    if (ascii(bytes, 30, "mimetype") && stored) return contains(bytes, 38, 120, "spreadsheet") ? "ods" : null;
    // The central directory, at the end, names the members.
    const from = bytes.length - (1 << 20);
    if (contains(bytes, from, bytes.length, "[Content_Types].xml") && contains(bytes, from, bytes.length, "xl/")) return "xlsx";
    if (contains(bytes, from, bytes.length, ".iwa") || contains(bytes, from, bytes.length, "Index.zip")) return "numbers";
    // Numbers '08 and '09: index.xml, or index.xml.gz.
    if (contains(bytes, from, bytes.length, "index.xml")) return "numbers";
    if (contains(bytes, from, bytes.length, "content.xml")) return "ods";
    return null;
  }
  // Flat OpenDocument, after a BOM and an XML declaration.
  if (contains(bytes, 0, 2048, "office:document") && contains(bytes, 0, 4096, "opendocument.spreadsheet")) return "fods";
  // The text formats Excel opens whatever their name says.
  const head = textHead(bytes);
  if (head.startsWith("id;")) return "slk";
  if (head.includes("urn:schemas-microsoft-com:office:spreadsheet") && head.includes("workbook") && !head.includes("<html")) return "xml";
  if (/<(html|table|!doctype html)[\s>]/.test(head)) return "html";
  return null;
}

/** Converts in a worker; `signal` (the session's) stops it at once. */
export async function convertSheet(
  bytes: Uint8Array,
  format: SheetFormat,
  options: { signal?: AbortSignal; timeoutMs?: number; maxMemory?: number } = {},
): Promise<SheetResult> {
  const host: WorkerHost<SheetRequest, SheetResult> = createWorkerHost(
    () => new Worker(new URL("./sheets.worker.js", import.meta.url), { type: "module" }),
  );
  const stop = () => host.destroy();
  options.signal?.addEventListener("abort", stop, { once: true });
  try {
    // A copy: the caller keeps its bytes.
    const copy = bytes.slice().buffer as ArrayBuffer;
    const maxMemory = Math.min(options.maxMemory ?? SHEET_LIMITS.maxMemory, MAX_MEMORY);
    return await host.call({ bytes: copy, format, maxCells: SHEET_LIMITS.maxCells, maxMemory }, [copy], options.timeoutMs ?? 120_000);
  } finally {
    options.signal?.removeEventListener("abort", stop);
    host.destroy();
  }
}
