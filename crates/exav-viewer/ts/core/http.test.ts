import { afterEach, describe, expect, it, vi } from "vitest";

import { bodyChunks, contentRange, createFetcher, declaredLength, joinChunks, requestRange, type Answer, type Span } from "./http.js";

const signal = new AbortController().signal;
const FILE = Uint8Array.from({ length: 1000 }, (_, i) => (i * 7) & 0xff);

afterEach(() => vi.unstubAllGlobals());

describe("Content-Range", () => {
  it("is read when it is whole and consistent", () => {
    expect(contentRange("bytes 0-9/100")).toEqual({ start: 0, end: 9, total: 100 });
    expect(contentRange("bytes 5-9/*")).toEqual({ start: 5, end: 9, total: null });
    for (const h of [null, "", "bytes 9-5/100", "bytes 0-100/100", "bytes */100", "items 0-9/100", "bytes 0-9/100, 20-29/100"]) expect(contentRange(h), String(h)).toBeNull();
  });
});

describe("a body", () => {
  /** A body of `n` pieces of 100 bytes, which says how far it was read. */
  function pieces(n: number) {
    const state = { pulled: 0, cancelled: false };
    const body = new ReadableStream<Uint8Array>({
      pull(controller) {
        state.pulled += 1;
        controller.enqueue(new Uint8Array(100).fill(state.pulled));
        if (state.pulled === n) controller.close();
      },
      cancel: () => void (state.cancelled = true),
    });
    return { state, response: new Response(body, { headers: { "content-length": String(100 * n) } }) };
  }

  it("is read to its end, with its progress", async () => {
    const { response } = pieces(3);
    const seen: number[] = [];
    const body = await bodyChunks(response, undefined, (n) => seen.push(n));
    expect(body).toMatchObject({ size: 300, ended: true });
    expect(seen).toEqual([100, 200, 300]);
    const bytes = joinChunks(body);
    expect([bytes.length, bytes[0], bytes[150], bytes[299]]).toEqual([300, 1, 2, 3]);
  });

  it("is read up to a limit, and the rest is cancelled", async () => {
    const { response, state } = pieces(100);
    const body = await bodyChunks(response, 250);
    expect(joinChunks(body).length).toBe(250);
    expect(body.ended).toBe(false);
    expect(state.cancelled).toBe(true);
    expect(state.pulled).toBeLessThan(10);
  });

  it("ends within a limit it is shorter than", async () => {
    const { response, state } = pieces(2);
    expect(await bodyChunks(response, 500)).toMatchObject({ size: 200, ended: true });
    expect(state.cancelled).toBe(false);
  });

  it("is read whole when the response has no stream", async () => {
    const seen: number[] = [];
    const response = { body: null, arrayBuffer: async () => FILE.slice().buffer } as unknown as Response;
    expect(await bodyChunks(response, undefined, (n) => seen.push(n))).toMatchObject({ size: 1000, ended: true });
    expect(seen).toEqual([1000]);
    const cut = await bodyChunks({ body: null, arrayBuffer: async () => FILE.slice().buffer } as unknown as Response, 10);
    expect(cut).toMatchObject({ size: 10, ended: false });
  });

  it("declares its length when the response does", () => {
    expect(declaredLength(new Response("", { headers: { "content-length": "12" } }))).toBe(12);
    for (const v of ["0", "-1", "x", "1.5"]) expect(declaredLength(new Response("", { headers: { "content-length": v } })), v).toBeNull();
    expect(declaredLength(new Response(""))).toBeNull();
  });
});

describe("a request", () => {
  it("carries the source's headers and the range, and no range for the whole file", async () => {
    const fetcher = vi.fn(async (_url: string, _init?: RequestInit) => new Response(null, { status: 200 }));
    vi.stubGlobal("fetch", fetcher);
    const http = createFetcher({ url: "https://files.test/f", init: { headers: { Authorization: "x" }, credentials: "include" } }, null, signal);
    await http.get({ from: 5, to: 9 }, signal);
    await http.get({ suffix: 7 }, signal);
    await http.get(null, signal);
    const sent = fetcher.mock.calls.map(([, init]) => [new Headers(init?.headers).get("range"), new Headers(init?.headers).get("authorization"), init?.credentials, init?.signal === signal]);
    expect(sent).toEqual([
      ["bytes=5-9", "x", "include", true],
      ["bytes=-7", "x", "include", true],
      [null, "x", "include", true],
    ]);
  });

  it("keeps a range's answer out of the browser's cache, which would join it to a later request for the whole file", async () => {
    const fetcher = vi.fn(async (_url: string, _init?: RequestInit) => new Response(null, { status: 200 }));
    vi.stubGlobal("fetch", fetcher);
    const http = createFetcher({ url: "https://files.test/f" }, null, signal);
    await http.get({ from: 0, to: 9 }, signal);
    await http.get({ suffix: 7 }, signal);
    await http.get(null, signal);
    expect(fetcher.mock.calls.map(([, init]) => init?.cache)).toEqual(["no-store", "no-store", undefined]);
  });

  it("signs a source again for requests that failed together, once", async () => {
    let signed = 0;
    const resolve = vi.fn(async () => `https://files.test/f?sig=${++signed}`);
    const fetcher = vi.fn(async (url: string) => new Response(null, { status: url.endsWith("sig=0") || url.endsWith("sig=1") ? 403 : 200 }));
    vi.stubGlobal("fetch", fetcher);
    const http = createFetcher({ url: "https://files.test/f?sig=0" }, resolve, signal);
    const answers = await Promise.all([http.get({ from: 0, to: 1 }, signal), http.get({ from: 2, to: 3 }, signal)]);
    expect(answers.map((r) => r.status)).toEqual([403, 403]);
    expect(resolve).toHaveBeenCalledTimes(1);
    expect((await http.address()).url).toBe("https://files.test/f?sig=1");
  });

  it("fails when the source is signed again to bytes", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response(null, { status: 401 })));
    const http = createFetcher({ url: "https://files.test/f" }, async () => new Uint8Array(1), signal);
    await expect(http.get(null, signal)).rejects.toThrow("not a URL");
  });
});

describe("the answer to a range request", () => {
  /** The server's answer to the one request, and the span it was asked for. */
  async function ask(response: Response, span: Span): Promise<Answer> {
    vi.stubGlobal("fetch", async () => response);
    return requestRange(createFetcher({ url: "https://files.test/f" }, null, signal), span, signal);
  }
  const part = (start: number, end: number, total: string | number = FILE.length) => new Response(FILE.slice(start, end + 1), { status: 206, headers: { "content-range": `bytes ${start}-${end}/${total}` } });

  it("is the bytes of the span, with the file's size", async () => {
    const a = await ask(part(10, 19), { from: 10, to: 19 });
    expect(a).toMatchObject({ kind: "part", total: 1000, ranged: true });
    expect(a.kind === "part" && [...a.bytes]).toEqual([...FILE.slice(10, 20)]);
    expect(await ask(part(990, 999), { suffix: 10 })).toMatchObject({ kind: "part", total: 1000 });
    expect(await ask(part(0, 999), { suffix: 5000 })).toMatchObject({ kind: "part", total: 1000 });
    expect(await ask(part(0, 999), { from: 0, to: 4999 })).toMatchObject({ kind: "part", total: 1000 });
  });

  it("is refused when it is not exactly the span", async () => {
    const cases: [string, Response, Span][] = [
      ["starts elsewhere", part(11, 20), { from: 10, to: 19 }],
      ["stops short", part(10, 18), { from: 10, to: 19 }],
      ["goes on", part(10, 20), { from: 10, to: 19 }],
      ["another size", part(10, 19, 1001), { from: 10, to: 19, total: 1000 }],
      ["no size", part(10, 19, "*"), { from: 10, to: 19, total: 1000 }],
      ["suffix, fewer", part(995, 999), { suffix: 10 }],
      ["suffix, not the end", part(980, 989), { suffix: 10 }],
      ["suffix, no size", part(990, 999, "*"), { suffix: 10 }],
      ["body shorter", new Response(FILE.slice(10, 15), { status: 206, headers: { "content-range": "bytes 10-19/1000" } }), { from: 10, to: 19 }],
      ["body longer", new Response(FILE.slice(10, 25), { status: 206, headers: { "content-range": "bytes 10-19/1000" } }), { from: 10, to: 19 }],
      ["other status", new Response(null, { status: 500 }), { from: 10, to: 19 }],
    ];
    for (const [name, response, span] of cases) expect(await ask(response, span), name).toMatchObject({ kind: "refused" });
  });

  it("is encoded when the server compressed it: its range is of the compressed bytes", async () => {
    const gzip = (headers: Record<string, string>) => new Response(FILE.slice(0, 20), { status: 206, headers: { "content-range": "bytes 0-19/1000", ...headers } });
    expect(await ask(gzip({ "content-encoding": "gzip" }), { from: 0, to: 19 })).toEqual({ kind: "encoded" });
    expect(await ask(gzip({ "content-encoding": " BR " }), { from: 0, to: 19 })).toEqual({ kind: "encoded" });
    expect(await ask(gzip({ "content-encoding": "identity" }), { from: 0, to: 19 })).toMatchObject({ kind: "part" });
  });

  it("is unreadable when a 206 has no Content-Range, whatever the body", async () => {
    const a = await ask(new Response(FILE.slice(0, 50), { status: 206 }), { from: 0, to: 19 });
    expect(a).toMatchObject({ kind: "unreadable" });
    expect(a.kind === "unreadable" && a.bytes.length).toBe(20);
  });

  it("is an empty file for a 416, or an empty 200", async () => {
    expect(await ask(new Response(null, { status: 416 }), { from: 0, to: 9 })).toEqual({ kind: "empty" });
    expect(await ask(new Response("", { status: 200 }), { from: 0, to: 9 })).toEqual({ kind: "empty" });
  });

  it("from a 200 is the start of the file, which is not read further than the span", async () => {
    let pulled = 0;
    let cancelled = false;
    const body = new ReadableStream<Uint8Array>({
      pull(controller) {
        pulled += 1;
        controller.enqueue(new Uint8Array(100));
      },
      cancel: () => void (cancelled = true),
    });
    const a = await ask(new Response(body, { status: 200, headers: { "content-length": "100000" } }), { from: 0, to: 149 });
    expect(a).toMatchObject({ kind: "part", total: 100000, ranged: false });
    expect(a.kind === "part" && a.bytes.length).toBe(150);
    expect(cancelled).toBe(true);
    expect(pulled).toBeLessThan(5);
  });

  it("from a 200 holds the whole file when it is within the span", async () => {
    expect(await ask(new Response(FILE.slice(), { status: 200 }), { from: 0, to: 4999 })).toMatchObject({ kind: "part", total: 1000, ranged: false });
  });

  it("from a 200 is refused for a span that does not start at 0, a suffix, or a file of another size", async () => {
    expect(await ask(new Response(FILE.slice(), { status: 200 }), { from: 1, to: 9 })).toMatchObject({ kind: "refused", status: 200 });
    expect(await ask(new Response(FILE.slice(), { status: 200 }), { suffix: 9 })).toMatchObject({ kind: "refused", status: 200 });
    expect(await ask(new Response(FILE.slice(), { status: 200, headers: { "content-length": "1000" } }), { from: 0, to: 9, total: 999 })).toMatchObject({ kind: "refused" });
    // Not known to be the size asked for.
    expect(await ask(new Response(FILE.slice(), { status: 200 }), { from: 0, to: 9, total: 1000 })).toMatchObject({ kind: "refused" });
  });

  it("from a 200 is handed back unread to a caller that keeps the whole file", async () => {
    const response = new Response(FILE.slice(), { status: 200 });
    vi.stubGlobal("fetch", async () => response);
    const a = await requestRange(createFetcher({ url: "https://files.test/f" }, null, signal), { from: 0, to: 9 }, signal, true);
    expect(a).toEqual({ kind: "whole", response });
    expect(response.bodyUsed).toBe(false);
  });
});
