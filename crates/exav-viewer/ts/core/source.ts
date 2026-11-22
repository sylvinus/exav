import { bodyChunks, createFetcher, declaredLength, joinChunks, requestRange, type Address, type Fetcher, type Resolve } from "./http.js";
import { writable } from "./store.js";
import type { ByteRanges, FileSource, SourceReader } from "./types.js";

type Resolved = { url: string; init?: RequestInit } | { blob: Blob } | { bytes: Uint8Array } | { ranges: ByteRanges };

/** The size of each read when a file read by ranges is read whole. */
const WHOLE_PIECE = 4 * 1024 * 1024;

/** Every byte of `ranges`, a piece at a time. */
export async function readWhole(ranges: ByteRanges, signal: AbortSignal, progress?: (loaded: number) => void): Promise<Uint8Array> {
  const out = new Uint8Array(ranges.size);
  for (let at = 0; at < ranges.size; ) {
    const piece = await ranges.read(at, Math.min(WHOLE_PIECE, ranges.size - at), signal);
    if (!piece.length) throw new Error(`the file ended at ${at} of its ${ranges.size} bytes`);
    const n = Math.min(piece.length, ranges.size - at);
    out.set(piece.subarray(0, n), at);
    at += n;
    progress?.(Math.min(at, ranges.size));
  }
  return out;
}

/**
 * Whether two sources are the same bytes, as far as can be told without
 * reading them: what a host that builds a new object on each render must not
 * make a reload of. The same object, or two addresses with the same request
 * (`init` compared by its contents); anything else is another source.
 */
export function sameSource(a: FileSource | null, b: FileSource | null): boolean {
  if (a === b) return true;
  if (!a || !b) return false;
  if ("url" in a && "url" in b) {
    return a.url === b.url && (a.init === b.init || JSON.stringify(a.init ?? null) === JSON.stringify(b.init ?? null));
  }
  return false;
}

/** The size of a file read from an address whose server did not say it: past any size a file has. */
export const UNKNOWN_SIZE = Number.MAX_SAFE_INTEGER;

/** Some of a file's bytes, and its whole size. */
export interface FilePart {
  bytes: Uint8Array;
  size: number;
}

/** The first `length` bytes of a file and its size. Throws on an answer that is not usable. */
async function headOfUrl(http: Fetcher, length: number, signal: AbortSignal): Promise<FilePart> {
  const a = await requestRange(http, { from: 0, to: length - 1 }, signal);
  if (a.kind === "empty") return { bytes: new Uint8Array(), size: 0 };
  if (a.kind === "refused") throw new Error(a.why);
  if (a.kind === "encoded") throw new Error("the server compresses its answers to range requests");
  const total = a.kind === "part" ? a.total : null;
  return { bytes: a.bytes, size: total ?? (a.bytes.length < length ? a.bytes.length : UNKNOWN_SIZE) };
}

/** The last `length` bytes of a file and its size; null unless the server gave them as a range. */
async function tailOfUrl(http: Fetcher, length: number, signal: AbortSignal): Promise<FilePart | null> {
  const a = await requestRange(http, { suffix: length }, signal);
  if (a.kind === "empty") return { bytes: new Uint8Array(), size: 0 };
  return a.kind === "part" && a.total !== null ? { bytes: a.bytes, size: a.total } : null;
}

export interface OwnedSourceReader extends SourceReader {
  /**
   * The first `length` bytes of the file and its whole size (`UNKNOWN_SIZE`
   * when a server did not say it), or null when they cannot be had. For bytes,
   * a blob and ranges they cost no request; for an address, a range request
   * of its own. A server that ignores ranges is not downloaded from past
   * `length`; one that fails, or a network that does, gives null with a
   * warning, and the file is read when a plugin asks for it.
   */
  head(length: number): Promise<FilePart | null>;
  /**
   * The last `length` bytes of the file and its whole size, by the same
   * means as `head`; null for an address whose server answers no suffix range
   * request (nothing is downloaded to find out).
   */
  tail(length: number): Promise<FilePart | null>;
  /** Revokes the object URLs it made. The session calls it when it ends. */
  dispose(): void;
}

/**
 * Reads a source at most once: `url`, `blob` and `bytes` share one download,
 * aborted with `signal`. An object URL made for a blob or bytes belongs to the
 * reader and is revoked by `dispose`. A download stops past `maxBytes`, and
 * fails with a `RangeError`.
 */
export function createSourceReader(source: FileSource, signal: AbortSignal, maxBytes = Infinity): OwnedSourceReader {
  const progress = writable<{ loaded: number; total: number | null } | null>(null);
  const urls: string[] = [];
  let resolved: Promise<Resolved> | null = null;
  let downloaded: Promise<Uint8Array> | null = null;

  const resolve = (): Promise<Resolved> => {
    resolved ??= (async () => {
      if (!("resolve" in source)) return source;
      const r = await source.resolve(signal);
      if (typeof r === "string") return { url: r };
      if (r instanceof Uint8Array) return { bytes: r };
      return { blob: r };
    })();
    return resolved;
  };

  let fetcher: Fetcher | null = null;
  const resign: Resolve | null = "resolve" in source ? (s) => source.resolve(s) : null;
  const http = (address: Address): Fetcher => (fetcher ??= createFetcher(address, resign, signal));

  const download = (address: Address): Promise<Uint8Array> => {
    downloaded ??= (async () => {
      const response = await http(address).get(null, signal);
      if (!response.ok) throw new Error(`HTTP ${response.status} for the file`);
      const total = declaredLength(response);
      const over = () => new RangeError(`the file is larger than ${maxBytes} bytes`);
      if (total !== null && total > maxBytes) {
        void response.body?.cancel();
        throw over();
      }
      progress.set({ loaded: 0, total });
      const body = await bodyChunks(response, maxBytes + 1, (loaded) => progress.set({ loaded, total }));
      if (body.size > maxBytes) throw over();
      return joinChunks(body);
    })();
    return downloaded;
  };

  const own = (blob: Blob) => {
    const url = URL.createObjectURL(blob);
    urls.push(url);
    return url;
  };

  const whole = (ranges: ByteRanges): Promise<Uint8Array> => {
    downloaded ??= (async () => {
      progress.set({ loaded: 0, total: ranges.size });
      return readWhole(ranges, signal, (loaded) => progress.set({ loaded, total: ranges.size }));
    })();
    return downloaded;
  };

  return {
    progress,
    async url() {
      const r = await resolve();
      if ("url" in r) return (await http(r).address()).url;
      if ("ranges" in r) return own(new Blob([(await whole(r.ranges)) as BlobPart]));
      return own("blob" in r ? r.blob : new Blob([r.bytes as BlobPart]));
    },
    async blob() {
      const r = await resolve();
      if ("blob" in r) return r.blob;
      if ("bytes" in r) return new Blob([r.bytes as BlobPart]);
      if ("ranges" in r) return new Blob([(await whole(r.ranges)) as BlobPart]);
      return new Blob([(await download(r)) as BlobPart]);
    },
    async bytes() {
      const r = await resolve();
      if ("bytes" in r) return r.bytes;
      if ("blob" in r) return new Uint8Array(await r.blob.arrayBuffer());
      if ("ranges" in r) return whole(r.ranges);
      return download(r);
    },
    async head(length) {
      const r = await resolve();
      if ("bytes" in r) return { bytes: r.bytes.subarray(0, length), size: r.bytes.length };
      if ("blob" in r) return { bytes: new Uint8Array(await r.blob.slice(0, length).arrayBuffer()), size: r.blob.size };
      if ("ranges" in r) {
        const n = Math.min(length, r.ranges.size);
        return { bytes: n > 0 ? await r.ranges.read(0, n, signal) : new Uint8Array(), size: r.ranges.size };
      }
      try {
        return await headOfUrl(http(r), length, signal);
      } catch (error) {
        if (signal.aborted) throw error;
        console.warn("exav viewer: the first bytes of the file could not be read, its name and type decide", error);
        return null;
      }
    },
    async tail(length) {
      const r = await resolve();
      if ("bytes" in r) return { bytes: r.bytes.subarray(Math.max(0, r.bytes.length - length)), size: r.bytes.length };
      if ("blob" in r) return { bytes: new Uint8Array(await r.blob.slice(Math.max(0, r.blob.size - length)).arrayBuffer()), size: r.blob.size };
      if ("ranges" in r) {
        const n = Math.min(length, r.ranges.size);
        return { bytes: n > 0 ? await r.ranges.read(r.ranges.size - n, n, signal) : new Uint8Array(), size: r.ranges.size };
      }
      try {
        return await tailOfUrl(http(r), length, signal);
      } catch (error) {
        if (signal.aborted) throw error;
        return null;
      }
    },
    dispose() {
      for (const url of urls.splice(0)) URL.revokeObjectURL(url);
    },
  };
}

/**
 * Whether "open in a new tab" may be offered for a URL: an `http(s)` address,
 * absolute or relative to the page. `blob:` and `data:` die with the page and
 * render in its origin, `javascript:` runs in it. Parsed as the browser
 * would, so case, spaces and tabs in the scheme change nothing.
 */
export function canOpenInTab(url: string | null | undefined): boolean {
  if (!url) return false;
  try {
    const base = typeof location !== "undefined" ? location.href : "http://localhost/";
    const { protocol } = new URL(url, base);
    return protocol === "http:" || protocol === "https:";
  } catch {
    return false;
  }
}
