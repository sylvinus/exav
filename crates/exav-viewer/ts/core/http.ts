/**
 * Reading a file over HTTP, for the page's source reader and for the host
 * side of the sandboxed frame: one way to read a body, and one policy for a
 * range request (an expired address is signed again, the answer must be the
 * bytes asked for, a server that ignores the range is not downloaded from).
 */

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

/** The body's length as the response declares it, when it does. */
export function declaredLength(response: Response): number | null {
  const n = Number(response.headers.get("content-length"));
  return Number.isSafeInteger(n) && n > 0 ? n : null;
}

/** A response's body in pieces. `ended`: the body ended within `limit`. */
export interface Body {
  chunks: Uint8Array[];
  size: number;
  ended: boolean;
}

/**
 * The first `limit` bytes of a response's body (all of it by default); the
 * rest is cancelled, not read. `progress` gets the bytes read so far after
 * each piece.
 */
export async function bodyChunks(response: Response, limit = Infinity, progress?: (loaded: number) => void): Promise<Body> {
  const chunks: Uint8Array[] = [];
  let size = 0;
  let ended = false;
  const add = (chunk: Uint8Array) => {
    const part = chunk.subarray(0, limit - size);
    chunks.push(part);
    size += part.length;
  };
  if (!response.body) {
    const all = new Uint8Array(await response.arrayBuffer());
    add(all);
    progress?.(size);
    return { chunks, size, ended: all.length <= limit };
  }
  const reader = response.body.getReader();
  while (size < limit) {
    const { done, value } = await reader.read();
    if (done) {
      ended = true;
      break;
    }
    add(value);
    progress?.(size);
  }
  if (!ended) void reader.cancel().catch(() => undefined);
  return { chunks, size, ended };
}

/** The pieces of a body as one array of its own. */
export function joinChunks(body: Pick<Body, "chunks" | "size">): Uint8Array {
  const out = new Uint8Array(body.size);
  let at = 0;
  for (const c of body.chunks) {
    out.set(c, at);
    at += c.length;
  }
  return out;
}

/** Where a file is, and how to ask for it. */
export interface Address {
  url: string;
  init?: RequestInit;
}

/** Signs a source again: what a source's `resolve` gives. */
export type Resolve = (signal: AbortSignal) => Promise<string | Blob | Uint8Array>;

/**
 * Which bytes: `from` to `to` (inclusive), of a file of `total` bytes when
 * that is known, or the last `suffix` bytes.
 */
export type Span = { from: number; to: number; total?: number } | { suffix: number };

export interface Fetcher {
  /** The address requests go to now: the source's own, or the last one it was signed again to. */
  address(): Promise<Address>;
  /** One request, for `span` or the whole file (`null`). */
  get(span: Span | null, signal: AbortSignal): Promise<Response>;
}

const header = (span: Span) => ("from" in span ? `bytes=${span.from}-${span.to}` : `bytes=-${span.suffix}`);
const describe = (span: Span) => ("from" in span ? `bytes ${span.from}-${span.to}` : `the last ${span.suffix} bytes`);

/**
 * Requests to a file's address, with the source's `init`. When `resolve` is
 * given (a source signed on demand), the source is signed again, once per
 * request, when the server answers 401 or 403: its address may have expired.
 * Requests that fail together sign it once. `signal` ends the signing; each
 * request has its own.
 */
export function createFetcher(first: Address, resolve: Resolve | null, signal: AbortSignal): Fetcher {
  let current: Promise<Address> = Promise.resolve(first);
  const resign = (stale: Promise<Address>) => {
    if (current === stale)
      current = resolve!(signal).then((r) => {
        if (typeof r !== "string") throw new Error("the source resolved again to bytes, not a URL");
        return { url: r, init: first.init };
      });
    return current;
  };
  return {
    address: () => current,
    async get(span, requestSignal) {
      let at = current;
      for (let attempt = 0; ; attempt++) {
        const { url, init } = await at;
        const headers = span ? { ...Object.fromEntries(new Headers(init?.headers).entries()), range: header(span) } : init?.headers;
        const response = await fetch(url, { ...init, headers, signal: requestSignal });
        if ((response.status === 401 || response.status === 403) && resolve && attempt === 0) {
          void response.body?.cancel();
          at = resign(at);
          continue;
        }
        return response;
      }
    },
  };
}

/**
 * What a range request came to.
 * - `empty`: the file has no bytes (416, or a 200 with an empty body).
 * - `part`: the bytes asked for, and the file's size when the server said it.
 *   `ranged`: false when the server ignored the range and answered 200.
 * - `unreadable`: a 206 whose Content-Range the page cannot read (across
 *   origins it must be exposed); `bytes` are what the body began with.
 * - `refused`: any other answer, or one that is not the bytes asked for.
 */
export type Answer =
  | { kind: "empty" }
  | { kind: "part"; bytes: Uint8Array; total: number | null; ranged: boolean }
  | { kind: "unreadable"; bytes: Uint8Array }
  | { kind: "refused"; status: number; why: string };

/** A 200, handed back unread to a caller that asked to keep it. */
export type Whole = { kind: "whole"; response: Response };

/** Whether `got` is what `span` asks for: where it starts, where it ends, and the file's size if `span` says it. */
function answers(span: Span, got: { start: number; end: number; total: number | null }): boolean {
  if ("suffix" in span) return got.total !== null && got.end === got.total - 1 && got.start === Math.max(0, got.total - span.suffix);
  if (got.start !== span.from || (span.total !== undefined && got.total !== span.total)) return false;
  return got.total === null ? got.end <= span.to : got.end === Math.min(span.to, got.total - 1);
}

/**
 * The bytes of `span`, by a range request. The Content-Range of a 206 must
 * be exactly the span (a file shorter than it gives fewer bytes) and the body
 * as long as it says. A server that ignores the range answers 200 with the
 * whole file: for a span from the start its first bytes are taken and the
 * rest of the body is cancelled, so the file is not downloaded for this; any
 * other span is refused. With `keepWhole`, for a caller that reads the whole
 * file when ranges fail, the 200 is handed back unread instead, so the
 * server sends the file once.
 */
export async function requestRange(http: Fetcher, span: Span, signal: AbortSignal): Promise<Answer>;
export async function requestRange(http: Fetcher, span: Span, signal: AbortSignal, keepWhole: true): Promise<Answer | Whole>;
export async function requestRange(http: Fetcher, span: Span, signal: AbortSignal, keepWhole = false): Promise<Answer | Whole> {
  const response = await http.get(span, signal);
  const refuse = (why = `HTTP ${response.status} for ${describe(span)}`): Answer => {
    void response.body?.cancel();
    return { kind: "refused", status: response.status, why };
  };
  if (response.status === 416) {
    void response.body?.cancel();
    return { kind: "empty" };
  }
  if (response.status === 200) {
    if (keepWhole) return { kind: "whole", response };
    if (!("from" in span) || span.from !== 0) return refuse();
    const body = await bodyChunks(response, span.to + 1);
    if (!body.size) return { kind: "empty" };
    const declared = declaredLength(response);
    const total = body.ended ? body.size : declared !== null && declared >= body.size ? declared : null;
    if (!answers(span, { start: 0, end: body.size - 1, total })) return { kind: "refused", status: 200, why: `HTTP 200 for ${describe(span)}` };
    return { kind: "part", bytes: joinChunks(body), total, ranged: false };
  }
  if (response.status !== 206) return refuse();
  const got = contentRange(response.headers.get("content-range"));
  if (!got) {
    const body = await bodyChunks(response, "from" in span ? span.to - span.from + 1 : span.suffix);
    return { kind: "unreadable", bytes: joinChunks(body) };
  }
  if (!answers(span, got)) return refuse(`the server answered bytes ${got.start}-${got.end}/${got.total ?? "*"} for ${describe(span)}`);
  const count = got.end - got.start + 1;
  // One more than the header says shows a body that is longer.
  const body = await bodyChunks(response, count + 1);
  if (body.size !== count) return { kind: "refused", status: 206, why: `the server sent ${body.size < count ? body.size : `more than ${count}`} bytes for ${describe(span)}, not ${count}` };
  return { kind: "part", bytes: joinChunks(body), total: got.total, ranged: true };
}
