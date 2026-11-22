/**
 * DOC, ODT, FODT, RTF, Word 2003 XML and Pages converted to DOCX by
 * exav-render's `docs` (exav_viewer_docs.wasm), in a worker of its own for this
 * one file, terminated when it is done: a wasm instance's memory never
 * shrinks.
 */
import { createWorkerHost, type WorkerHost } from "../core/worker-host.js";
import { isCompound, isZip } from "./zip.js";

/** What the converter reads. */
export type DocFormat = "doc" | "odt" | "fodt" | "rtf" | "wml2003" | "pages" | "html";

export interface DocRequest {
  bytes: ArrayBuffer;
  format: DocFormat;
  maxParagraphs: number;
  maxMemory: number;
}

export interface DocResult {
  docx: ArrayBuffer;
  paragraphs: number;
  warnings: string;
}

/** Why a conversion failed: the converter's error kinds, a timeout, or a crash of its module. */
export type DocErrorKind = "not-format" | "encrypted" | "unsupported" | "too-large" | "malformed" | "timeout" | "crashed";

const KINDS: readonly string[] = ["not-format", "encrypted", "unsupported", "too-large", "malformed"];

/** A document exav-render's `docs` recognised and could not convert. */
export class DocConversionError extends Error {
  readonly kind: DocErrorKind;
  constructor(
    readonly format: DocFormat,
    cause: unknown,
  ) {
    const reason = cause instanceof Error ? cause.message : String(cause);
    const kind: DocErrorKind = KINDS.includes(reason) ? (reason as DocErrorKind) : /^no answer within/.test(reason) ? "timeout" : "crashed";
    super(`the ${format} file could not be converted: ${kind}`, { cause });
    this.name = "DocConversionError";
    this.kind = kind;
  }
}

/** Paragraphs and memory a conversion may take: the converter's defaults. */
export const DOC_LIMITS = { maxParagraphs: 5_000_000, maxMemory: 1 << 30 };

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

const indexOf = (bytes: Uint8Array, from: number, to: number, text: string) => {
  for (let i = from; i <= to - text.length; i++) if (ascii(bytes, i, text)) return i;
  return -1;
};

/**
 * The name of an XML file's root element, from its first 4 KiB: after a byte
 * order mark, white space, the declaration, processing instructions, comments
 * and a document type. `null` when the bytes do not get there.
 */
export function xmlRoot(bytes: Uint8Array): string | null {
  const end = Math.min(bytes.length, 4096);
  let i = bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf ? 3 : 0;
  const space = (c: number | undefined) => c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d;
  while (i < end) {
    if (space(bytes[i])) {
      i++;
      continue;
    }
    if (bytes[i] !== 0x3c) return null;
    let close: string | null = null;
    if (ascii(bytes, i, "<?")) close = "?>";
    else if (ascii(bytes, i, "<!--")) close = "-->";
    else if (ascii(bytes, i, "<!")) {
      // A document type's internal subset, in brackets, holds `>` of its own.
      const bracket = indexOf(bytes, i, end, "[");
      close = bracket >= 0 && bracket < indexOf(bytes, i, end, ">") ? "]>" : ">";
    }
    if (close) {
      const at = indexOf(bytes, i + 2, end, close);
      if (at < 0) return null;
      i = at + close.length;
      continue;
    }
    let j = i + 1;
    while (j < end && !space(bytes[j]) && bytes[j] !== 0x3e && bytes[j] !== 0x2f) j++;
    return j > i + 1 ? String.fromCharCode(...bytes.subarray(i + 1, j)) : null;
  }
  return null;
}

/** The formats `sniffDocs` takes from `officeKinds`, in the order it prefers them. */
const FROM_KINDS = ["doc", "docx", "pages", "odt"] as const;

/**
 * What the bytes are: a document the converter reads, a DOCX shown as it is,
 * or `null` for anything else (the external converter gets those). `kinds`
 * are what the file's container says it may be (`officeKinds`): a compound
 * file or a ZIP is told by them alone.
 */
export function sniffDocs(bytes: Uint8Array, kinds: readonly string[] | null): DocFormat | "docx" | null {
  // A compound file too large to look into is taken as its name says.
  if (kinds === null) return isCompound(bytes) ? "doc" : null;
  if (isCompound(bytes) || isZip(bytes)) return FROM_KINDS.find((kind) => kinds.includes(kind)) ?? null;
  // RTF, after any white space or a byte order mark: `{\rt`, as exav-unpack's `is_rtf`.
  let at = 0;
  if (bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) at = 3;
  while (at < 16 && (bytes[at] === 0x20 || bytes[at] === 0x0a || bytes[at] === 0x0d || bytes[at] === 0x09)) at++;
  if (ascii(bytes, at, "{\\rt")) return "rtf";
  // Word's "Save as Web Page": an HTML page that declares Word's namespace,
  // alone or in the MIME message of "Single File Web Page". Before the XML
  // kinds, which look for the same namespace.
  const mime = ascii(bytes, at, "MIME-Version:") || ascii(bytes, at, "MIME-version:") || ascii(bytes, at, "Mime-Version:");
  const html = contains(bytes, 0, 4096, "<html") || contains(bytes, 0, 4096, "<HTML") || contains(bytes, 0, 4096, "<!DOCTYPE html") || contains(bytes, 0, 4096, "<!doctype html");
  if ((html || mime) && contains(bytes, 0, mime ? 16384 : 4096, "schemas-microsoft-com:office:word")) return "html";
  // XML: flat ODF text, or Word 2003 XML, told by its root element: a schema,
  // a stylesheet or a Word 2007 XML package (`pkg:package`, under the same
  // `mso-application` instruction) only mentions its namespace.
  if (contains(bytes, 0, 2048, "office:document") && contains(bytes, 0, 4096, "opendocument.text")) return "fodt";
  if (/^(?:[^:]+:)?wordDocument$/.test(xmlRoot(bytes) ?? "")) return "wml2003";
  return null;
}

/** Converts in a worker; `signal` (the session's) stops it at once. */
export async function convertDocs(
  bytes: Uint8Array,
  format: DocFormat,
  options: { signal?: AbortSignal; timeoutMs?: number; maxMemory?: number } = {},
): Promise<DocResult> {
  const host: WorkerHost<DocRequest, DocResult> = createWorkerHost(
    () => new Worker(new URL("./docs.worker.js", import.meta.url), { type: "module" }),
  );
  const stop = () => host.destroy();
  options.signal?.addEventListener("abort", stop, { once: true });
  try {
    // A copy: the caller keeps its bytes, for the external converter should this fail.
    const copy = bytes.slice().buffer as ArrayBuffer;
    const maxMemory = Math.min(options.maxMemory ?? DOC_LIMITS.maxMemory, MAX_MEMORY);
    return await host.call({ bytes: copy, format, maxParagraphs: DOC_LIMITS.maxParagraphs, maxMemory }, [copy], options.timeoutMs ?? 120_000);
  } finally {
    options.signal?.removeEventListener("abort", stop);
    host.destroy();
  }
}
