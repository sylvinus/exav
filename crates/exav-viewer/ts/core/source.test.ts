// How a source reader asks a server for a file's first bytes, last bytes and
// all of it, against a server played by the test.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { createSourceReader, UNKNOWN_SIZE } from "./source.js";

const FILE = Uint8Array.from({ length: 5000 }, (_, i) => (i * 7) & 0xff);

/** A server holding `FILE`: answers `bytes=a-b` and `bytes=-n`; `refuse` says which addresses it turns away with a status. */
function server(o: { refuse?: (url: string) => number | null; answer?: (range: string | null) => Response | null } = {}) {
  const requests: { url: string; range: string | null }[] = [];
  const fetch = vi.fn(async (url: string, init: RequestInit = {}) => {
    const range = new Headers(init.headers).get("range");
    requests.push({ url, range });
    const status = o.refuse?.(url);
    if (status) return new Response(null, { status });
    const custom = o.answer?.(range);
    if (custom) return custom;
    const m = /^bytes=(\d*)-(\d*)$/.exec(range ?? "");
    if (!m) return new Response(FILE.slice(), { headers: { "content-length": String(FILE.length) } });
    const start = m[1] ? Number(m[1]) : Math.max(0, FILE.length - Number(m[2]));
    const end = m[1] ? Math.min(FILE.length - 1, Number(m[2])) : FILE.length - 1;
    return new Response(FILE.slice(start, end + 1), { status: 206, headers: { "content-range": `bytes ${start}-${end}/${FILE.length}` } });
  });
  return { fetch, requests };
}

/** A source signed on demand: each resolution is a new address, and the first one has expired. */
function signed() {
  let n = 0;
  const resolve = vi.fn(async () => `https://files.test/f?sig=${++n}`);
  const refuse = (url: string) => (url.endsWith("sig=1") ? 403 : null);
  return { resolve, refuse };
}

const reader = (source: Parameters<typeof createSourceReader>[0]) => createSourceReader(source, new AbortController().signal);

beforeEach(() => vi.spyOn(console, "warn").mockImplementation(() => {}));
afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("a source signed on demand, when the server turns its address away", () => {
  it("is resolved again for the first bytes", async () => {
    const { resolve, refuse } = signed();
    const s = server({ refuse });
    vi.stubGlobal("fetch", s.fetch);
    const head = await reader({ resolve }).head(1024);
    expect(head).toEqual({ bytes: FILE.slice(0, 1024), size: FILE.length });
    expect(resolve).toHaveBeenCalledTimes(2);
    expect(s.requests.map((q) => q.url)).toEqual(["https://files.test/f?sig=1", "https://files.test/f?sig=2"]);
  });

  it("is resolved again for the last bytes", async () => {
    const { resolve, refuse } = signed();
    vi.stubGlobal("fetch", server({ refuse }).fetch);
    const tail = await reader({ resolve }).tail(100);
    expect(tail).toEqual({ bytes: FILE.slice(-100), size: FILE.length });
    expect(resolve).toHaveBeenCalledTimes(2);
  });

  it("is resolved again for the whole file", async () => {
    const { resolve, refuse } = signed();
    vi.stubGlobal("fetch", server({ refuse }).fetch);
    expect(await reader({ resolve }).bytes()).toEqual(FILE);
    expect(resolve).toHaveBeenCalledTimes(2);
  });

  it("is resolved again once, and the next request keeps the new address", async () => {
    const { resolve, refuse } = signed();
    const s = server({ refuse });
    vi.stubGlobal("fetch", s.fetch);
    const r = reader({ resolve });
    await r.head(1024);
    await r.tail(100);
    expect(await r.bytes()).toEqual(FILE);
    expect(resolve).toHaveBeenCalledTimes(2);
    expect(s.requests.map((q) => q.url.slice(-5))).toEqual(["sig=1", "sig=2", "sig=2", "sig=2"]);
    expect(await r.url()).toBe("https://files.test/f?sig=2");
  });

  it("is resolved again once per request: a second refusal is the answer", async () => {
    const resolve = vi.fn(async () => "https://files.test/f");
    const s = server({ refuse: () => 403 });
    vi.stubGlobal("fetch", s.fetch);
    const r = reader({ resolve });
    expect(await r.head(1024)).toBeNull();
    expect(resolve).toHaveBeenCalledTimes(2);
    expect(s.fetch).toHaveBeenCalledTimes(2);
  });

  it("is not resolved again for an answer other than 401 and 403", async () => {
    const { resolve } = signed();
    const s = server({ refuse: () => 500 });
    vi.stubGlobal("fetch", s.fetch);
    expect(await reader({ resolve }).head(1024)).toBeNull();
    expect(resolve).toHaveBeenCalledTimes(1);
  });
});

describe("an address with no way to be resolved again", () => {
  it("gets no second request when the server turns it away", async () => {
    const s = server({ refuse: () => 403 });
    vi.stubGlobal("fetch", s.fetch);
    const r = reader({ url: "https://files.test/f" });
    expect(await r.head(1024)).toBeNull();
    expect(await r.tail(100)).toBeNull();
    await expect(r.bytes()).rejects.toThrow("HTTP 403");
    expect(s.fetch).toHaveBeenCalledTimes(3);
  });
});

describe("the answer to a range request", () => {
  it("is the bytes asked for when the Content-Range says so", async () => {
    vi.stubGlobal("fetch", server().fetch);
    const r = reader({ url: "https://files.test/f" });
    expect(await r.head(100)).toEqual({ bytes: FILE.slice(0, 100), size: FILE.length });
    expect(await r.tail(100)).toEqual({ bytes: FILE.slice(-100), size: FILE.length });
    // A file shorter than the bytes asked for is given whole.
    expect(await r.head(FILE.length + 10)).toEqual({ bytes: FILE, size: FILE.length });
    expect(await r.tail(FILE.length + 10)).toEqual({ bytes: FILE, size: FILE.length });
  });

  it("is unusable for the last bytes when it is fewer than asked and the file is longer", async () => {
    const answer = () => new Response(FILE.slice(-50), { status: 206, headers: { "content-range": `bytes ${FILE.length - 50}-${FILE.length - 1}/${FILE.length}` } });
    vi.stubGlobal("fetch", server({ answer }).fetch);
    expect(await reader({ url: "https://files.test/f" }).tail(100)).toBeNull();
  });

  it("is unusable for the first bytes when it stops short of the end the file allows", async () => {
    const answer = () => new Response(FILE.slice(0, 10), { status: 206, headers: { "content-range": `bytes 0-9/${FILE.length}` } });
    vi.stubGlobal("fetch", server({ answer }).fetch);
    expect(await reader({ url: "https://files.test/f" }).head(100)).toBeNull();
  });

  it("is unusable for the first bytes when it does not start at the start", async () => {
    const answer = () => new Response(FILE.slice(10, 110), { status: 206, headers: { "content-range": `bytes 10-109/${FILE.length}` } });
    vi.stubGlobal("fetch", server({ answer }).fetch);
    expect(await reader({ url: "https://files.test/f" }).head(100)).toBeNull();
  });

  it("is unusable when its body is not as long as its Content-Range says", async () => {
    const answer = () => new Response(FILE.slice(0, 60), { status: 206, headers: { "content-range": `bytes 0-99/${FILE.length}` } });
    vi.stubGlobal("fetch", server({ answer }).fetch);
    const r = reader({ url: "https://files.test/f" });
    expect(await r.head(100)).toBeNull();
    expect(await r.tail(100)).toBeNull();
  });

  it("is taken as it comes for the first bytes when a cross-origin page cannot read its Content-Range", async () => {
    const answer = (range: string | null) => new Response(FILE.slice(0, Number(/-(\d+)$/.exec(range ?? "")![1]) + 1), { status: 206 });
    vi.stubGlobal("fetch", server({ answer }).fetch);
    const head = await reader({ url: "https://files.test/f" }).head(100);
    expect(head).toEqual({ bytes: FILE.slice(0, 100), size: UNKNOWN_SIZE });
  });

  it("is an empty file for a 416", async () => {
    vi.stubGlobal("fetch", server({ refuse: () => 416 }).fetch);
    const r = reader({ url: "https://files.test/f" });
    expect(await r.head(100)).toEqual({ bytes: new Uint8Array(), size: 0 });
    expect(await r.tail(100)).toEqual({ bytes: new Uint8Array(), size: 0 });
  });
});

describe("a server that answers 200 to a range request", () => {
  /** A body of 200 pieces of 512 bytes, which says how far it was read. */
  function endless() {
    const state = { pulled: 0, cancelled: false };
    const body = new ReadableStream<Uint8Array>({
      pull(controller) {
        state.pulled += 1;
        controller.enqueue(new Uint8Array(512).fill(state.pulled));
        if (state.pulled === 200) controller.close();
      },
      cancel: () => void (state.cancelled = true),
    });
    return { state, answer: () => new Response(body, { status: 200, headers: { "content-length": String(200 * 512) } }) };
  }

  it("gives the first bytes without the rest of the file", async () => {
    const e = endless();
    vi.stubGlobal("fetch", server({ answer: e.answer }).fetch);
    const head = await reader({ url: "https://files.test/f" }).head(1000);
    expect(head!.bytes.length).toBe(1000);
    expect(head!.size).toBe(200 * 512);
    expect(e.state.cancelled).toBe(true);
    expect(e.state.pulled).toBeLessThan(10);
  });

  it("gives no last bytes, and does not read the file to find them", async () => {
    const e = endless();
    vi.stubGlobal("fetch", server({ answer: e.answer }).fetch);
    expect(await reader({ url: "https://files.test/f" }).tail(1000)).toBeNull();
    expect(e.state.cancelled).toBe(true);
    expect(e.state.pulled).toBeLessThan(10);
  });
});
