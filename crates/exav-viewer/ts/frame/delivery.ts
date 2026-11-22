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
import { bodyChunks, createFetcher, declaredLength, requestRange, type Fetcher } from "../core/http.js";
import { readWhole } from "../core/source.js";
import type { BuiltinFormat, ByteRanges, FileSource, ViewerFile } from "../core/types.js";
import { isOrigin, type FrameOrigins } from "./policy.js";
import { MAX_URL, READS } from "./protocol.js";

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
  // The frame refuses a longer one; read on this page, the file is shown.
  if (parsed.href.length > MAX_URL) return `a URL of more than ${MAX_URL} characters is not given to the frame`;
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

/** How a file of `kind` reaches the frame (`null`: every other kind of file, a Blob). */
function modeOf(kind: Kind | null, d: Delivery): "url" | "auto" | "ranges" | "blob" {
  return kind === null ? "blob" : (d[kind] ?? (kind === "pdf" || kind === "archive" ? "ranges" : "auto"));
}

/**
 * Whether `prepare` refuses the address of a file shown as `format`: delivery
 * "url" for it, and an origin the frame's policy does not name. It is an
 * error before any request, so the host does not ask that address for its
 * first bytes either.
 */
export function refusesAddress(address: { url: string; init?: RequestInit }, format: BuiltinFormat | null, file: Pick<ViewerFile, "name" | "type" | "path">, o: Pick<PrepareOptions, "delivery" | "origins">): boolean {
  const kind = format ? kindOf(format, file) : null;
  if (modeOf(kind, o.delivery ?? {}) !== "url") return false;
  const origins = o.origins ?? {};
  return urlRefusal(address.url, address.init, kind === "pdf" ? (origins.connect ?? []) : (origins.media ?? [])) !== null;
}

/**
 * The address `prepare` gives the frame for a file shown as `format`, or
 * null when this page reads the file itself; with whether the frame may
 * fetch it (an origin of `origins.connect`), as it does a PDF's, rather than
 * only show it in an element. Video and audio are never fetched by the frame.
 */
export function addressGiven(address: { url: string; init?: RequestInit }, format: BuiltinFormat | null, file: Pick<ViewerFile, "name" | "type" | "path">, o: Pick<PrepareOptions, "delivery" | "origins">): { url: string; fetchable: boolean } | null {
  const kind = format ? kindOf(format, file) : null;
  const mode = modeOf(kind, o.delivery ?? {});
  if (mode !== "url" && mode !== "auto") return null;
  const origins = o.origins ?? {};
  if (urlRefusal(address.url, address.init, kind === "pdf" ? (origins.connect ?? []) : (origins.media ?? [])) !== null) return null;
  const fetchable = kind !== "media" && urlRefusal(address.url, address.init, origins.connect ?? []) === null;
  return { url: new URL(address.url, location.href).href, fetchable };
}

/** Reads `source` as `format`'s delivery says, and what the frame is given. */
export async function prepare(source: FileSource, format: BuiltinFormat, file: Pick<ViewerFile, "name" | "type" | "path">, o: PrepareOptions): Promise<Prepared> {
  const kind = kindOf(format, file);
  const d = o.delivery ?? {};
  const origins = o.origins ?? {};
  const r = "resolve" in source ? resolved(await source.resolve(o.signal)) : source;
  const mode = modeOf(kind, d);
  const http = "url" in r ? createFetcher(r, "resolve" in source ? (s) => source.resolve(s) : null, o.signal) : null;

  if (mode === "url" || mode === "auto") {
    if ("url" in r) {
      const why = urlRefusal(r.url, r.init, kind === "pdf" ? (origins.connect ?? []) : (origins.media ?? []));
      if (!why) return { kind: "url", url: new URL(r.url, location.href).href };
      if (mode === "url") throw new Error(`${file.name}: ${why}`);
    }
    // A file the host holds has no address to give: it goes whole.
  } else if (mode === "ranges") {
    const ranges = await openRanges(r, http, o);
    if (ranges instanceof Response) return { kind: "blob", blob: await blobOf(ranges, o), readWhole: true };
    if (ranges === WHOLE) return { kind: "blob", blob: await readBlob(r, http, o), readWhole: true };
    if (ranges) return { kind: "ranges", ranges };
  }
  return { kind: "blob", blob: await readBlob(r, http, o) };
}

/** `http`: the requests to `r`, when it is an address. */
async function readBlob(r: Resolved, http: Fetcher | null, o: PrepareOptions): Promise<Blob> {
  if ("blob" in r) return r.blob;
  if ("bytes" in r) return new Blob([r.bytes as BlobPart]);
  if ("ranges" in r) return new Blob([(await readWhole(r.ranges, o.signal, (n) => o.progress?.(n / r.ranges.size))) as BlobPart]);
  const response = await http!.get(null, o.signal);
  if (!response.ok) throw new Error(`HTTP ${response.status} for the file`);
  return blobOf(response, o);
}

/** The whole file `response` holds, its progress said as it is read. */
async function blobOf(response: Response, o: PrepareOptions): Promise<Blob> {
  const total = declaredLength(response);
  const body = await bodyChunks(response, undefined, (loaded) => total && o.progress?.(Math.min(1, loaded / total)));
  return new Blob(body.chunks as BlobPart[]);
}

const copy = (b: Uint8Array) => b.slice();

/**
 * `r` read by ranges; the whole file's answer, unread, from a server that
 * ignores ranges; `WHOLE` for one whose answer to the first range request
 * cannot be used; or null when it is to be read whole (an empty file).
 */
async function openRanges(r: Resolved, http: Fetcher | null, o: PrepareOptions): Promise<HostRanges | Response | typeof WHOLE | null> {
  const headOf = async (ranges: ByteRanges) => copy(await ranges.read(0, Math.min(ranges.size, READS.head), o.signal));
  if ("ranges" in r) return r.ranges.size > 0 ? { size: r.ranges.size, head: await headOf(r.ranges), read: (offset, length, signal) => r.ranges.read(offset, length, signal) } : null;
  if ("bytes" in r || "blob" in r) {
    const blob = "blob" in r ? r.blob : new Blob([r.bytes as BlobPart]);
    if (!blob.size) return null;
    const ranges: ByteRanges = { size: blob.size, read: async (offset, length) => new Uint8Array(await blob.slice(offset, offset + length).arrayBuffer()) };
    return { ...ranges, head: await headOf(ranges) };
  }
  return openUrlRanges(http!, o);
}

/** A URL read by HTTP range requests. */
async function openUrlRanges(http: Fetcher, o: PrepareOptions): Promise<HostRanges | Response | typeof WHOLE | null> {
  const probe = await requestRange(http, { from: 0, to: READS.head - 1 }, o.signal, true);
  if (probe.kind === "empty") return null;
  if (probe.kind === "refused" && probe.status !== 206) throw new Error(`HTTP ${probe.status} for the file`);
  if (probe.kind === "whole") {
    console.warn("exav viewer: the server does not answer range requests: the whole file is downloaded");
    return probe.response;
  }
  if (probe.kind === "encoded") {
    console.warn("exav viewer: the server compresses its answers to range requests: the whole file is downloaded");
    return WHOLE;
  }
  if (probe.kind !== "part" || probe.total === null) {
    console.warn("exav viewer: the server's answer to a range request is not the bytes asked for, or has no readable Content-Range (cross-origin, it must be exposed): the whole file is downloaded");
    return WHOLE;
  }
  const size = probe.total;
  return {
    size,
    head: probe.bytes,
    async read(offset, length, signal) {
      const to = Math.min(size, offset + length) - 1;
      const a = await requestRange(http, { from: offset, to, total: size }, signal);
      if (a.kind === "part") return a.bytes;
      throw new Error(a.kind === "refused" ? a.why : `no usable answer for bytes ${offset}-${to}`);
    },
  };
}
