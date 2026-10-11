// The host's side of a file's delivery to the frame: what it gives, what it
// refuses, and the HTTP it does for a file read by ranges, against a server
// played by the test.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import "../test/blob.js";
import { contentRange, kindOf, prepare, readRefusal, urlRefusal, type Prepared } from "./delivery.js";
import { READS } from "./protocol.js";

describe("an address the frame may be given", () => {
  const allowed = ["https://media.test"];
  it("is http(s), on an allowed origin, without credentials or `init`", () => {
    expect(urlRefusal("https://media.test/a.mp4", undefined, allowed)).toBeNull();
    expect(urlRefusal("https://media.test/a.mp4", {}, allowed)).toBeNull();
    expect(urlRefusal("/a.mp4", undefined, allowed, "https://media.test/page")).toBeNull();
    for (const [url, init] of [
      ["https://media.test.evil/a.mp4", undefined],
      ["https://media.test:8443/a.mp4", undefined],
      ["http://media.test/a.mp4", undefined],
      ["https://user:pw@media.test/a.mp4", undefined],
      ["https://media.test/a.mp4", { credentials: "include" }],
      ["data:video/mp4,x", undefined],
      ["javascript:alert(1)", undefined],
      ["/a.mp4", undefined],
    ] as [string, RequestInit | undefined][]) {
      expect(urlRefusal(url, init, allowed, "https://host.test/"), url).not.toBeNull();
    }
    expect(urlRefusal("https://media.test/a.mp4", undefined, [])).toMatch(/none/);
  });

  it("is given only for video, audio and the images browsers decode", () => {
    expect(kindOf("video", { name: "a.mp4" })).toBe("media");
    expect(kindOf("image", { name: "a.png" })).toBe("images");
    expect(kindOf("image", { name: "a.tif" })).toBeNull();
    expect(kindOf("pdf", { name: "a.pdf" })).toBe("pdf");
    expect(kindOf("docx", { name: "a.docx" })).toBeNull();
  });
});

describe("a read the frame asks for", () => {
  const none = { count: 0, bytes: 0 };
  it("is within the file, at most one read long, within what is outstanding", () => {
    expect(readRefusal({ offset: 0, length: 1 }, 10, none)).toBeNull();
    expect(readRefusal({ offset: 9, length: 1 }, 10, none)).toBeNull();
    expect(readRefusal({ offset: 9, length: 2 }, 10, none)).not.toBeNull();
    expect(readRefusal({ offset: 10, length: 1 }, 10, none)).not.toBeNull();
    expect(readRefusal({ offset: 0, length: 0 }, 10, none)).not.toBeNull();
    expect(readRefusal({ offset: 0, length: READS.maxLength }, 2 * READS.maxLength, none)).toBeNull();
    expect(readRefusal({ offset: 0, length: READS.maxLength + 1 }, 2 * READS.maxLength, none)).not.toBeNull();
    expect(readRefusal({ offset: 0, length: 1 }, 10, { count: READS.maxReads, bytes: 0 })).not.toBeNull();
    expect(readRefusal({ offset: 0, length: 2 }, 10, { count: 1, bytes: READS.maxBytes - 1 })).not.toBeNull();
  });
});

describe("Content-Range", () => {
  it("is read when it is whole and consistent", () => {
    expect(contentRange("bytes 0-9/100")).toEqual({ start: 0, end: 9, total: 100 });
    expect(contentRange("bytes 5-9/*")).toEqual({ start: 5, end: 9, total: null });
    for (const h of [null, "", "bytes 9-5/100", "bytes 0-100/100", "bytes */100", "items 0-9/100", "bytes 0-9/100, 20-29/100"]) expect(contentRange(h), String(h)).toBeNull();
  });
});

/** A server holding `file`: answers ranges unless `ranges` is false. */
function server(file: Uint8Array, o: { ranges?: boolean; status?: (url: string) => number | null } = {}) {
  const requests: { url: string; range: string | null; headers: Record<string, string> }[] = [];
  const fetch = vi.fn(async (url: string, init: RequestInit = {}) => {
    const headers = { ...(init.headers as Record<string, string> | undefined) };
    const range = headers.range ?? null;
    requests.push({ url, range, headers });
    const forced = o.status?.(url);
    if (forced) return new Response(null, { status: forced });
    const m = /^bytes=(\d+)-(\d+)$/.exec(range ?? "");
    if (!m || o.ranges === false) return new Response(file.slice(), { status: 200, headers: { "content-length": String(file.length) } });
    const start = Number(m[1]);
    const end = Math.min(file.length - 1, Number(m[2]));
    return new Response(file.slice(start, end + 1), { status: 206, headers: { "content-range": `bytes ${start}-${end}/${file.length}` } });
  });
  return { fetch, requests };
}

const FILE = Uint8Array.from({ length: 200_000 }, (_, i) => (i * 7) & 0xff);
const signal = new AbortController().signal;
const asRanges = (p: Prepared) => {
  if (p.kind !== "ranges") throw new Error(`delivered as ${p.kind}`);
  return p.ranges;
};

describe("a URL read by ranges", () => {
  beforeEach(() => vi.spyOn(console, "warn").mockImplementation(() => {}));
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("is read a range at a time, with the source's headers", async () => {
    const s = server(FILE);
    vi.stubGlobal("fetch", s.fetch);
    const r = asRanges(await prepare({ url: "https://files.test/a.pdf", init: { headers: { authorization: "Bearer t" } } }, "pdf", { name: "a.pdf" }, { signal }));
    expect(r.size).toBe(FILE.length);
    expect(Buffer.from(r.head).equals(FILE.subarray(0, READS.head))).toBe(true);
    expect(Buffer.from(await r.read(100_000, 10, signal)).equals(FILE.subarray(100_000, 100_010))).toBe(true);
    expect(Buffer.from(await r.read(FILE.length - 5, 10, signal)).equals(FILE.subarray(FILE.length - 5))).toBe(true);
    expect(s.requests.map((q) => q.range)).toEqual([`bytes=0-${READS.head - 1}`, "bytes=100000-100009", `bytes=${FILE.length - 5}-${FILE.length - 1}`]);
    expect(s.requests.every((q) => q.headers.authorization === "Bearer t")).toBe(true);
  });

  it("is read whole, and said so, from a server that answers no range request", async () => {
    const s = server(FILE, { ranges: false });
    vi.stubGlobal("fetch", s.fetch);
    const p = await prepare({ url: "https://files.test/a.pdf" }, "pdf", { name: "a.pdf" }, { signal });
    expect(p).toMatchObject({ kind: "blob", readWhole: true });
    expect(s.requests).toHaveLength(1);
    expect(console.warn).toHaveBeenCalledWith(expect.stringContaining("does not answer range requests"));
  });

  it("is read whole, and said so, when the server's range answers cannot be read", async () => {
    const s = server(FILE);
    // A partial answer whose Content-Range a cross-origin page cannot see.
    vi.stubGlobal("fetch", async (url: string, init: RequestInit) => {
      const r = await s.fetch(url, init);
      return r.status === 206 ? new Response(r.body, { status: 206 }) : r;
    });
    const p = await prepare({ url: "https://files.test/a.pdf" }, "pdf", { name: "a.pdf" }, { signal });
    expect(p).toMatchObject({ kind: "blob", readWhole: true });
    if (p.kind !== "blob") throw new Error(p.kind);
    expect(Buffer.from(await p.blob.arrayBuffer()).equals(FILE)).toBe(true);
  });

  it("from a server that answers ranges, is not said to be read whole", async () => {
    vi.stubGlobal("fetch", server(FILE).fetch);
    const p = await prepare({ url: "https://files.test/a.pdf" }, "pdf", { name: "a.pdf" }, { signal });
    expect(p.kind).toBe("ranges");
    expect(console.warn).not.toHaveBeenCalled();
  });

  it("fails a read the server answers with other bytes than asked", async () => {
    let lie = false;
    const s = server(FILE);
    vi.stubGlobal("fetch", async (url: string, init: RequestInit) => {
      const r = await s.fetch(url, init);
      if (!lie) return r;
      return new Response(FILE.slice(0, 10), { status: 206, headers: { "content-range": `bytes 0-9/${FILE.length}` } });
    });
    const r = asRanges(await prepare({ url: "https://files.test/a.pdf" }, "pdf", { name: "a.pdf" }, { signal }));
    lie = true;
    await expect(r.read(100_000, 10, signal)).rejects.toThrow();
  });

  it("resolves a source signed on demand again when its URL is refused, once", async () => {
    let signed = 0;
    const resolve = vi.fn(async () => `https://files.test/a.pdf?sig=${++signed}`);
    const s = server(FILE, { status: (url) => (url.endsWith("sig=1") && signed > 0 && expired ? 403 : null) });
    let expired = false;
    vi.stubGlobal("fetch", s.fetch);
    const r = asRanges(await prepare({ resolve }, "pdf", { name: "a.pdf" }, { signal }));
    expect(resolve).toHaveBeenCalledTimes(1);
    expired = true;
    expect(Buffer.from(await r.read(70_000, 4, signal)).equals(FILE.subarray(70_000, 70_004))).toBe(true);
    expect(resolve).toHaveBeenCalledTimes(2);
    expect(s.requests.slice(-2).map((q) => q.url)).toEqual(["https://files.test/a.pdf?sig=1", "https://files.test/a.pdf?sig=2"]);
  });

  it("reads a local file by slices", async () => {
    const r = asRanges(await prepare({ blob: new Blob([FILE]) }, "archive", { name: "a.zip" }, { signal }));
    expect(r.size).toBe(FILE.length);
    expect(r.head.length).toBe(READS.head);
  });
});
