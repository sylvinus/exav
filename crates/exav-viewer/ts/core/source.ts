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

export interface OwnedSourceReader extends SourceReader {
  /** Revokes the object URLs it made. The session calls it when it ends. */
  dispose(): void;
}

/**
 * Reads a source at most once: `url`, `blob` and `bytes` share one download,
 * aborted with `signal`. An object URL made for a blob or bytes belongs to the
 * reader and is revoked by `dispose`.
 */
export function createSourceReader(source: FileSource, signal: AbortSignal): OwnedSourceReader {
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

  const download = (url: string, init?: RequestInit): Promise<Uint8Array> => {
    downloaded ??= (async () => {
      const response = await fetch(url, { ...init, signal });
      if (!response.ok) throw new Error(`HTTP ${response.status} for the file`);
      const length = Number(response.headers.get("content-length"));
      const total = Number.isFinite(length) && length > 0 ? length : null;
      if (!response.body) {
        const bytes = new Uint8Array(await response.arrayBuffer());
        progress.set({ loaded: bytes.length, total });
        return bytes;
      }
      const reader = response.body.getReader();
      const chunks: Uint8Array[] = [];
      let loaded = 0;
      progress.set({ loaded, total });
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        chunks.push(value);
        loaded += value.length;
        progress.set({ loaded, total });
      }
      const out = new Uint8Array(loaded);
      let at = 0;
      for (const c of chunks) {
        out.set(c, at);
        at += c.length;
      }
      return out;
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
      if ("url" in r) return r.url;
      if ("ranges" in r) return own(new Blob([(await whole(r.ranges)) as BlobPart]));
      return own("blob" in r ? r.blob : new Blob([r.bytes as BlobPart]));
    },
    async blob() {
      const r = await resolve();
      if ("blob" in r) return r.blob;
      if ("bytes" in r) return new Blob([r.bytes as BlobPart]);
      if ("ranges" in r) return new Blob([(await whole(r.ranges)) as BlobPart]);
      return new Blob([(await download(r.url, r.init)) as BlobPart]);
    },
    async bytes() {
      const r = await resolve();
      if ("bytes" in r) return r.bytes;
      if ("blob" in r) return new Uint8Array(await r.blob.arrayBuffer());
      if ("ranges" in r) return whole(r.ranges);
      return download(r.url, r.init);
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
