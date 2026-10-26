/**
 * DOC, ODT, FODT, RTF, Word 2003 XML and Pages converted to DOCX by
 * exav-render's `docs` (exav_viewer_docs.wasm), in a worker of its own for this
 * one file, terminated when it is done: a wasm instance's memory never
 * shrinks.
 */
import { createWorkerHost, type WorkerHost } from "../core/worker-host.js";

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

/**
 * Whether a compound file has a directory entry (stream or storage) called
 * `name`: its UTF-16LE name, padded to 64 bytes, then the name's length in
 * bytes with the terminator, then the entry's type (1 storage, 2 stream, 5
 * root).
 */
const hasEntry = (bytes: Uint8Array, name: string) => {
  const fold = (c: number) => (c >= 0x61 && c <= 0x7a ? c - 32 : c);
  for (let i = 0; i + 67 <= bytes.length; i += 2) {
    if (bytes[i + 1] !== 0 || fold(bytes[i]!) !== fold(name.charCodeAt(0))) continue;
    let k = 1;
    while (k < name.length && fold(bytes[i + 2 * k]!) === fold(name.charCodeAt(k)) && bytes[i + 2 * k + 1] === 0) k++;
    if (k !== name.length) continue;
    const size = (name.length + 1) * 2;
    if (bytes[i + 64] === size && bytes[i + 65] === 0 && [1, 2, 5].includes(bytes[i + 66]!)) return true;
  }
  return false;
};

/**
 * What the bytes are: a document the converter reads, a DOCX shown as it is,
 * or `null` for anything else (the external converter gets those).
 */
export function sniffDocs(bytes: Uint8Array): DocFormat | "docx" | null {
  // A compound file with a Word document stream (Word 6 to 2003).
  if (bytes[0] === 0xd0 && bytes[1] === 0xcf && bytes[2] === 0x11 && bytes[3] === 0xe0) {
    return hasEntry(bytes, "WordDocument") ? "doc" : null;
  }
  // RTF, after any white space or a byte order mark.
  let at = 0;
  if (bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) at = 3;
  while (at < 16 && (bytes[at] === 0x20 || bytes[at] === 0x0a || bytes[at] === 0x0d || bytes[at] === 0x09)) at++;
  if (ascii(bytes, at, "{\\rtf")) return "rtf";
  if (bytes[0] === 0x50 && bytes[1] === 0x4b) {
    // OpenDocument: the stored "mimetype" member first.
    if (ascii(bytes, 30, "mimetype")) return contains(bytes, 38, 120, "opendocument.text") ? "odt" : null;
    const from = bytes.length - (1 << 20);
    const has = (t: string) => contains(bytes, from, bytes.length, t);
    if (has("[Content_Types].xml") && has("word/")) return "docx";
    if (has("Index/Document.iwa") || has("Index.zip")) return has("Index/Tables/") || has("Slide") ? null : "pages";
    // A mimetype member that is not first or not stored: told by the members.
    if (has("content.xml") && has("styles.xml") && !has("ppt/") && !has("xl/")) return "odt";
    return null;
  }
  // Word's "Save as Web Page": an HTML page that declares Word's namespace,
  // alone or in the MIME message of "Single File Web Page". Before the XML
  // kinds, which look for the same namespace.
  const mime = ascii(bytes, at, "MIME-Version:") || ascii(bytes, at, "MIME-version:") || ascii(bytes, at, "Mime-Version:");
  const html = contains(bytes, 0, 4096, "<html") || contains(bytes, 0, 4096, "<HTML") || contains(bytes, 0, 4096, "<!DOCTYPE html") || contains(bytes, 0, 4096, "<!doctype html");
  if ((html || mime) && contains(bytes, 0, mime ? 16384 : 4096, "schemas-microsoft-com:office:word")) return "html";
  // XML: flat ODF text, or Word 2003 XML.
  if (contains(bytes, 0, 2048, "office:document") && contains(bytes, 0, 4096, "opendocument.text")) return "fodt";
  if (contains(bytes, 0, 4096, "w:wordDocument") || contains(bytes, 0, 4096, "schemas-microsoft-com:office:word")) return "wml2003";
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
