/**
 * How a file's bytes reach the sandboxed frame, chosen per kind of file.
 *
 * - "blob": the host reads the whole file and transfers it.
 * - "ranges": the host reads what the frame asks for, by offset (HTTP range
 *   requests, or slices of a local file), and answers over the port. The
 *   frame never fetches; the host checks every request.
 * - "url": the frame is given the address. For video, audio and images an
 *   element shows it, unreadable to the frame's code; for PDF, pdf.js
 *   fetches it, and reads whatever that origin lets a CORS request read.
 *   Only origins the frame's policy names, so a refused URL is an error
 *   here rather than a request the policy blocks.
 */
import { createDetector } from "../core/detect.js";
import { MATCHERS } from "../core/formats.js";
import { readWhole } from "../core/source.js";
import type { BuiltinFormat, ByteRanges, FileSource, ViewerFile } from "../core/types.js";
import { isOrigin, type FrameOrigins } from "./policy.js";
import { READS } from "./protocol.js";

export interface Delivery {
  /** Video and audio. */
  media?: "url" | "blob";
  /** The images browsers decode themselves (PNG, JPEG, GIF, WebP). */
  images?: "url" | "blob";
  pdf?: "ranges" | "blob" | "url";
  archive?: "ranges" | "blob";
}

/** The kinds of file whose delivery is chosen; every other one goes as a Blob. */
type Kind = "media" | "images" | "pdf" | "archive";

const browserImages = createDetector([{ id: "image", match: MATCHERS.image }]);

export function kindOf(format: BuiltinFormat, file: Pick<ViewerFile, "name" | "type" | "path">): Kind | null {
  switch (format) {
    case "video":
    case "audio":
      return "media";
    case "image":
      // What only the frame's WebAssembly decoders draw is read whole.
      return browserImages.detect(file) === "image" ? "images" : null;
    case "pdf":
    case "archive":
      return format;
    default:
      return null;
  }
}

const MODES: { [K in Kind]: readonly string[] } = { media: ["url", "blob"], images: ["url", "blob"], pdf: ["ranges", "blob", "url"], archive: ["ranges", "blob"] };

/** Throws on a value the options do not take, or "url" with no origin to allow it. */
export function checkDelivery(delivery: Delivery = {}, origins: FrameOrigins = {}): void {
  for (const [key, value] of Object.entries(delivery)) {
    if (!Object.hasOwn(MODES, key)) throw new Error(`delivery: no kind of file named ${key}`);
    const modes = MODES[key as Kind];
    if (value !== undefined && !modes.includes(value)) throw new Error(`delivery.${key}: one of ${modes.join(", ")}, not ${String(value)}`);
  }
  for (const [name, list] of Object.entries(origins)) {
    if (name !== "media" && name !== "connect") throw new Error(`origins: media or connect, not ${name}`);
    for (const o of list ?? []) if (!isOrigin(o)) throw new Error(`origins.${name}: ${String(o)} is not an origin (scheme://host[:port], lower case, no path)`);
  }
  if ((delivery.media === "url" || delivery.images === "url") && !origins.media?.length) throw new Error('delivery "url" for media or images needs origins.media');
  if (delivery.pdf === "url" && !origins.connect?.length) throw new Error('delivery.pdf "url" needs origins.connect');
}

/**
 * Why `url` may not be given to the frame, or null. `allowed`: the origins
 * its policy names for this kind of file.
 */
export function urlRefusal(url: string, init: RequestInit | undefined, allowed: readonly string[], base?: string): string | null {
  let parsed: URL;
  try {
    parsed = new URL(url, base ?? (typeof location !== "undefined" ? location.href : undefined));
  } catch {
    return "not a URL";
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return `only http(s) URLs are given to the frame, not ${parsed.protocol}`;
  if (parsed.username || parsed.password) return "a URL with credentials in it is not given to the frame";
  if (init && Object.keys(init).length) return "the source has `init` (headers, credentials), which the frame's request would not carry";
  if (!allowed.includes(parsed.origin)) return `${parsed.origin} is not one of the origins the frame allows (${allowed.join(" ") || "none"})`;
  return null;
}

/**
 * Why the host refuses a read the frame asked for, or null. `outstanding`:
 * the frame's reads not answered yet. The message's shape is already checked
 * (`checkFrameMessage`): whole numbers.
 */
export function readRefusal(read: { offset: number; length: number }, size: number, outstanding: { count: number; bytes: number }): string | null {
  if (read.length < 1 || read.length > READS.maxLength) return `a read of ${read.length} bytes (1 to ${READS.maxLength})`;
  if (read.offset >= size || read.offset + read.length > size) return `bytes ${read.offset}-${read.offset + read.length - 1} of a file of ${size}`;
  if (outstanding.count >= READS.maxReads) return `more than ${READS.maxReads} reads at once`;
  if (outstanding.bytes + read.length > READS.maxBytes) return `more than ${READS.maxBytes} bytes asked at once`;
  return null;
}

/** A file read by ranges on the host's side; `head` is its first bytes, sent with it. */
export interface HostRanges extends ByteRanges {
  head: Uint8Array;
}

/**
 * `readWhole`: the file was to be read by ranges, and the server answers none
 * that can be used, so all of it was downloaded.
 */
export type Prepared = { kind: "blob"; blob: Blob; readWhole?: true } | { kind: "url"; url: string } | { kind: "ranges"; ranges: HostRanges };

/** A server whose range requests cannot be used: the file is read whole. */
const WHOLE = Symbol("whole");

type Resolved = { url: string; init?: RequestInit } | { blob: Blob } | { bytes: Uint8Array } | { ranges: ByteRanges };

const resolved = (r: string | Blob | Uint8Array): Resolved => (typeof r === "string" ? { url: r } : r instanceof Uint8Array ? { bytes: r } : { blob: r });

export interface PrepareOptions {
  delivery?: Delivery;
  origins?: FrameOrigins;
  signal: AbortSignal;
  /** Share of a whole download done, 0..1, when its size is known. */
  progress?: (share: number) => void;
}

/** Reads `source` as `format`'s delivery says, and what the frame is given. */
export async function prepare(source: FileSource, format: BuiltinFormat, file: Pick<ViewerFile, "name" | "type" | "path">, o: PrepareOptions): Promise<Prepared> {
  const kind = kindOf(format, file);
  const d = o.delivery ?? {};
  const origins = o.origins ?? {};
  const r = "resolve" in source ? resolved(await source.resolve(o.signal)) : source;
  const mode = kind === null ? "blob" : (d[kind] ?? (kind === "pdf" || kind === "archive" ? "ranges" : "auto"));

  if (mode === "url" || mode === "auto") {
    if ("url" in r) {
      const why = urlRefusal(r.url, r.init, kind === "pdf" ? (origins.connect ?? []) : (origins.media ?? []));
      if (!why) return { kind: "url", url: new URL(r.url, location.href).href };
      if (mode === "url") throw new Error(`${file.name}: ${why}`);
    }
    // A file the host holds has no address to give: it goes whole.
  } else if (mode === "ranges") {
    const ranges = await openRanges(r, "resolve" in source ? source.resolve : null, o);
    if (ranges instanceof Blob) return { kind: "blob", blob: ranges, readWhole: true };
    if (ranges === WHOLE) return { kind: "blob", blob: await readBlob(r, o), readWhole: true };
    if (ranges) return { kind: "ranges", ranges };
  }
  return { kind: "blob", blob: await readBlob(r, o) };
}

async function readBlob(r: Resolved, o: PrepareOptions): Promise<Blob> {
  if ("blob" in r) return r.blob;
  if ("bytes" in r) return new Blob([r.bytes as BlobPart]);
  if ("ranges" in r) return new Blob([(await readWhole(r.ranges, o.signal, (n) => o.progress?.(n / r.ranges.size))) as BlobPart]);
  const response = await fetch(r.url, { ...r.init, signal: o.signal });
  if (!response.ok) throw new Error(`HTTP ${response.status} for the file`);
  return readBody(response, o);
}

/** A response's body as a Blob, with progress when its length is known. */
async function readBody(response: Response, o: PrepareOptions): Promise<Blob> {
  const length = Number(response.headers.get("content-length"));
  const total = Number.isFinite(length) && length > 0 ? length : null;
  if (!response.body) return response.blob();
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let loaded = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
    loaded += value.length;
    if (total) o.progress?.(Math.min(1, loaded / total));
  }
  return new Blob(chunks as BlobPart[]);
}

/** `bytes start-end/total`, or null. */
export function contentRange(header: string | null): { start: number; end: number; total: number | null } | null {
  const m = /^bytes\s+(\d+)-(\d+)\/(\d+|\*)$/i.exec(header?.trim() ?? "");
  if (!m) return null;
  const start = Number(m[1]);
  const end = Number(m[2]);
  const total = m[3] === "*" ? null : Number(m[3]);
  if (!Number.isSafeInteger(start) || !Number.isSafeInteger(end) || end < start || (total !== null && (!Number.isSafeInteger(total) || end >= total))) return null;
  return { start, end, total };
}

const copy = (b: Uint8Array) => b.slice();

/**
 * `r` read by ranges; or the whole file, from a server that answered the
 * first range request with all of it; `WHOLE` for a server whose answer to
 * it cannot be used; or null when it is to be read whole (an empty file).
 */
async function openRanges(r: Resolved, resolve: ((signal: AbortSignal) => Promise<string | Blob | Uint8Array>) | null, o: PrepareOptions): Promise<HostRanges | Blob | typeof WHOLE | null> {
  const headOf = async (ranges: ByteRanges) => copy(await ranges.read(0, Math.min(ranges.size, READS.head), o.signal));
  if ("ranges" in r) return r.ranges.size > 0 ? { size: r.ranges.size, head: await headOf(r.ranges), read: (offset, length, signal) => r.ranges.read(offset, length, signal) } : null;
  if ("bytes" in r || "blob" in r) {
    const blob = "blob" in r ? r.blob : new Blob([r.bytes as BlobPart]);
    if (!blob.size) return null;
    const ranges: ByteRanges = { size: blob.size, read: async (offset, length) => new Uint8Array(await blob.slice(offset, offset + length).arrayBuffer()) };
    return { ...ranges, head: await headOf(ranges) };
  }
  return openUrlRanges(r, resolve, o);
}

/**
 * A URL read by HTTP range requests, with the source's `init`. A source
 * signed on demand is resolved again, once per request, when the server
 * answers 401 or 403: its URL may have expired.
 */
async function openUrlRanges(
  first: { url: string; init?: RequestInit },
  resolve: ((signal: AbortSignal) => Promise<string | Blob | Uint8Array>) | null,
  o: PrepareOptions,
): Promise<HostRanges | Blob | typeof WHOLE | null> {
  let current: Promise<{ url: string; init?: RequestInit }> = Promise.resolve(first);
  const resign = (stale: Promise<{ url: string; init?: RequestInit }>) => {
    // Requests that failed together resolve the source once.
    if (current === stale)
      current = resolve!(o.signal).then((r) => {
        if (typeof r !== "string") throw new Error("the source resolved again to bytes, not a URL");
        return { url: r, init: first.init };
      });
    return current;
  };
  const request = async (from: number, to: number, signal: AbortSignal): Promise<Response> => {
    let at = current;
    for (let attempt = 0; ; attempt++) {
      const { url, init } = await at;
      const headers: Record<string, string> = Object.fromEntries(new Headers(init?.headers).entries());
      headers.range = `bytes=${from}-${to}`;
      const response = await fetch(url, { ...init, headers, signal });
      if ((response.status === 401 || response.status === 403) && resolve && attempt === 0) {
        void response.body?.cancel();
        at = resign(at);
        continue;
      }
      return response;
    }
  };

  const probe = await request(0, READS.head - 1, o.signal);
  if (probe.status === 206) {
    const range = contentRange(probe.headers.get("content-range"));
    if (range && range.start === 0 && range.total) {
      const size = range.total;
      const head = new Uint8Array(await probe.arrayBuffer());
      if (head.length !== Math.min(size, READS.head)) throw new Error(`the server sent ${head.length} bytes for the first ${Math.min(size, READS.head)}`);
      return {
        size,
        head,
        async read(offset, length, signal) {
          const end = Math.min(size, offset + length) - 1;
          const response = await request(offset, end, signal);
          const got = contentRange(response.headers.get("content-range"));
          if (response.status !== 206 || !got || got.start !== offset || got.end !== end || got.total !== size) {
            void response.body?.cancel();
            throw new Error(`HTTP ${response.status} for bytes ${offset}-${end}`);
          }
          const bytes = new Uint8Array(await response.arrayBuffer());
          if (bytes.length !== end - offset + 1) throw new Error(`the server sent ${bytes.length} bytes for ${end - offset + 1}`);
          return bytes;
        },
      };
    }
    void probe.body?.cancel();
    console.warn("exav viewer: the server answered a range request without a readable Content-Range (cross-origin, it must be exposed): the whole file is downloaded");
    return WHOLE;
  }
  if (probe.status === 200) {
    console.warn("exav viewer: the server does not answer range requests: the whole file is downloaded");
    return readBody(probe, o);
  }
  if (probe.status !== 416) {
    void probe.body?.cancel();
    throw new Error(`HTTP ${probe.status} for the file`);
  }
  // 416: an empty file, read whole.
  return null;
}
