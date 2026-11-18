/**
 * PPT, ODP, FODP and Keynote converted to PPTX by exav-render's `slides`
 * (exav_viewer_slides.wasm), and OpenDocument drawings (ODG, OTG, FODG), a
 * page to a slide, in a worker of its own for this one file, terminated when
 * it is done: a wasm instance's memory never shrinks.
 */
import { createWorkerHost, type WorkerHost } from "../core/worker-host.js";
import { isCompound, isZip } from "./zip.js";

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

/** The formats `sniffSlides` takes from `officeKinds`, in the order it prefers them. */
const FROM_KINDS = ["ppt", "pptx", "vsdx", "key", "odp", "odg"] as const;

/**
 * What the bytes are: a presentation the converter reads (or reports as one
 * it does not), a PPTX shown as it is, or `null` for anything else.
 *
 * Every version is recognised: PowerPoint 2 to 4 (a file starting with
 * 0xED 0xDE 0xAD 0x0B, or its Macintosh form, big endian, possibly as
 * BinHex text, or a compound file with a "PP40" stream), PowerPoint 95 and
 * 97 to 2003 (a "PowerPoint Document" stream), ODP, OTP and FODP, and
 * Keynote 1 to 6 (its XML or its IWA archives in a ZIP). `kinds` are what the
 * file's container says it may be (`officeKinds`): a compound file or a ZIP
 * is told by them alone.
 */
export function sniffSlides(bytes: Uint8Array, kinds: readonly string[] | null): SlideFormat | "pptx" | null {
  // A compound file too large to look into is taken as its name says.
  if (kinds === null) return isCompound(bytes) ? "ppt" : null;
  if (isCompound(bytes) || isZip(bytes)) return FROM_KINDS.find((kind) => kinds.includes(kind)) ?? null;
  // PowerPoint 2 to 4, as a file or as BinHex text.
  if (kinds.includes("ppt")) return "ppt";
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
