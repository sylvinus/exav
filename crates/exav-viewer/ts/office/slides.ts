/**
 * PPT, ODP, FODP and Keynote converted to PPTX by exav-render's `slides`
 * (exav_viewer_slides.wasm), and OpenDocument drawings (ODG, OTG, FODG), a
 * page to a slide, in a worker of its own for this one file, terminated when
 * it is done: a wasm instance's memory never shrinks.
 */
import { createWorkerHost, type WorkerHost } from "../core/worker-host.js";

/** What the converter reads. */
export type SlideFormat = "ppt" | "odp" | "fodp" | "key" | "odg" | "fodg" | "vsdx";

export interface SlideRequest {
  bytes: ArrayBuffer;
  format: SlideFormat;
  maxShapes: number;
  maxMemory: number;
}

export interface SlideResult {
  pptx: ArrayBuffer;
  slides: number;
  warnings: string;
}

/** Why a conversion failed: the converter's error kinds, a timeout, or a crash of its module. */
export type SlideErrorKind = "not-format" | "encrypted" | "unsupported" | "too-large" | "malformed" | "timeout" | "crashed";

const KINDS: readonly string[] = ["not-format", "encrypted", "unsupported", "too-large", "malformed"];

/** A presentation or drawing exav-render's `slides` recognised and could not convert. */
export class SlideConversionError extends Error {
  readonly kind: SlideErrorKind;
  constructor(
    readonly format: SlideFormat,
    cause: unknown,
  ) {
    const reason = cause instanceof Error ? cause.message : String(cause);
    const kind: SlideErrorKind = KINDS.includes(reason) ? (reason as SlideErrorKind) : /^no answer within/.test(reason) ? "timeout" : "crashed";
    super(`the ${format} file could not be converted: ${kind}`, { cause });
    this.name = "SlideConversionError";
    this.kind = kind;
  }
}

/** Shapes and memory a conversion may take: the converter's defaults. */
export const SLIDE_LIMITS = { maxShapes: 1_000_000, maxMemory: 1 << 30 };

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
const hasEntry = (bytes: Uint8Array, names: readonly string[]) => {
  // Names compare without regard to ASCII case, as in the file format.
  const fold = (c: number) => (c >= 0x61 && c <= 0x7a ? c - 32 : c);
  for (let i = 0; i + 67 <= bytes.length; i += 2) {
    if (bytes[i + 1] !== 0) continue;
    for (const name of names) {
      if (fold(bytes[i]!) !== fold(name.charCodeAt(0))) continue;
      let k = 1;
      while (k < name.length && fold(bytes[i + 2 * k]!) === fold(name.charCodeAt(k)) && bytes[i + 2 * k + 1] === 0) k++;
      if (k !== name.length) continue;
      // The length field follows the name's 64 bytes.
      const size = (name.length + 1) * 2;
      if (bytes[i + 64] === size && bytes[i + 65] === 0 && [1, 2, 5].includes(bytes[i + 66]!)) return true;
    }
  }
  return false;
};

/** BinHex 4.0's alphabet. */
const BINHEX = '!"#$%&\'()*+,-012345689@ABCDEFGHIJKLMNPQRSTUVXYZ[`abcdefhijklmpqr';

/**
 * The type and creator of the Macintosh file a BinHex 4.0 text holds, from
 * the header after its first colon (name, version, type, creator).
 */
function binhexHeader(bytes: Uint8Array): { type: string; creator: string } | null {
  const head = String.fromCharCode(...bytes.subarray(0, 1024));
  const at = head.indexOf(":");
  if (at < 0 || !head.startsWith("(This file must be converted with BinHex")) return null;
  const out: number[] = [];
  let bits = 0;
  let n = 0;
  for (const c of head.slice(at + 1)) {
    if (c === "\r" || c === "\n") continue;
    const v = BINHEX.indexOf(c);
    if (v < 0) break;
    bits = ((bits << 6) | v) & 0xffff;
    n += 6;
    if (n >= 8) {
      n -= 8;
      out.push((bits >> n) & 0xff);
    }
    if (out.length > 64) break;
  }
  // Length-prefixed name, version, type, creator.
  const p = 1 + (out[0] ?? 0);
  if (out.length < p + 9) return null;
  const text = (a: number, b: number) => String.fromCharCode(...out.slice(a, b));
  return { type: text(p + 1, p + 5), creator: text(p + 5, p + 9) };
}

/**
 * What the bytes are: a presentation the converter reads (or reports as one
 * it does not), a PPTX shown as it is, or `null` for anything else.
 *
 * Every version is recognised: PowerPoint 2 to 4 (a file starting with
 * 0xED 0xDE 0xAD 0x0B, or its Macintosh form, big endian, possibly as
 * BinHex text, or a compound file with a "PP40" stream), PowerPoint 95 and
 * 97 to 2003 (a "PowerPoint Document" stream), ODP, OTP and FODP, and
 * Keynote 1 to 6 (its XML or its IWA archives in a ZIP).
 */
export function sniffSlides(bytes: Uint8Array): SlideFormat | "pptx" | null {
  // A compound file holding a PowerPoint document stream.
  if (bytes[0] === 0xd0 && bytes[1] === 0xcf && bytes[2] === 0x11 && bytes[3] === 0xe0) {
    return hasEntry(bytes, ["PowerPoint Document", "PP40"]) ? "ppt" : null;
  }
  // PowerPoint 2 to 4, little endian (Windows) or big endian (Macintosh).
  if (
    (bytes[0] === 0xed && bytes[1] === 0xde && bytes[2] === 0xad && bytes[3] === 0x0b) ||
    (bytes[0] === 0x0b && bytes[1] === 0xad && bytes[2] === 0xde && bytes[3] === 0xed)
  ) {
    return "ppt";
  }
  if (bytes[0] === 0x28) {
    const h = binhexHeader(bytes);
    return h && (h.creator === "PPNT" || h.type.startsWith("SLD") || h.type.startsWith("PPT")) ? "ppt" : null;
  }
  if (bytes[0] === 0x50 && bytes[1] === 0x4b) {
    // OpenDocument: the stored "mimetype" member first.
    if (ascii(bytes, 30, "mimetype")) {
      if (contains(bytes, 38, 120, "presentation")) return "odp";
      // "graphics", and "drawing" in OpenOffice 1.x files.
      return contains(bytes, 38, 120, "graphics") || contains(bytes, 38, 120, "opendocument.drawing") ? "odg" : null;
    }
    // The central directory, at the end, names the members.
    const from = bytes.length - (1 << 20);
    const has = (t: string) => contains(bytes, from, bytes.length, t);
    if (has("[Content_Types].xml") && has("ppt/")) return "pptx";
    // Visio 2013 and later: an Open Packaging package with a visio/ directory.
    if (has("[Content_Types].xml") && has("visio/document.xml")) return "vsdx";
    if (has(".iwa") || has("Index.zip")) return has("Slide") || has("Index.zip") ? "key" : null;
    // Keynote 1 to 5: index.apxl, presentation.apxl, gzipped or not.
    if (has("index.apxl") || has("presentation.apxl")) return "key";
    if (has("content.xml")) return "odp";
    return null;
  }
  // Flat OpenDocument, after a BOM and an XML declaration.
  if (contains(bytes, 0, 2048, "office:document") && contains(bytes, 0, 4096, "opendocument.presentation")) return "fodp";
  if (contains(bytes, 0, 2048, "office:document") && (contains(bytes, 0, 4096, "opendocument.graphics") || contains(bytes, 0, 4096, "opendocument.drawing"))) return "fodg";
  return null;
}

/** Converts in a worker; `signal` (the session's) stops it at once. */
export async function convertSlides(
  bytes: Uint8Array,
  format: SlideFormat,
  options: { signal?: AbortSignal; timeoutMs?: number; maxMemory?: number } = {},
): Promise<SlideResult> {
  const host: WorkerHost<SlideRequest, SlideResult> = createWorkerHost(
    () => new Worker(new URL("./slides.worker.js", import.meta.url), { type: "module" }),
  );
  const stop = () => host.destroy();
  options.signal?.addEventListener("abort", stop, { once: true });
  try {
    // A copy: the caller keeps its bytes, for the external converter should this fail.
    const copy = bytes.slice().buffer as ArrayBuffer;
    const maxMemory = Math.min(options.maxMemory ?? SLIDE_LIMITS.maxMemory, MAX_MEMORY);
    return await host.call({ bytes: copy, format, maxShapes: SLIDE_LIMITS.maxShapes, maxMemory }, [copy], options.timeoutMs ?? 120_000);
  } finally {
    options.signal?.removeEventListener("abort", stop);
    host.destroy();
  }
}
