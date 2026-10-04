// The host's side of the sandboxed frame, against a frame played by the test:
// what reaches the stores is what the protocol allows, and nothing else.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import "../test/blob.js";
import type { ByteRanges, Controllers, FileSource, Session } from "../core/types.js";
import { builtinTranslate } from "../react/messages.js";
import { createSandboxedViewer, type SandboxConfig } from "./index.js";
import { frameCsp, readPolicy, type FramePolicy } from "./policy.js";
import { HELLO, PROTOCOL, READS } from "./protocol.js";

const tick = (ms = 0) => new Promise((r) => setTimeout(r, ms));

interface Frame {
  session: Session;
  iframe: HTMLIFrameElement;
  /** What the host sent over the port. */
  received: any[];
  send(message: unknown): Promise<void>;
  controllers(): Controllers;
}

let hosts: HTMLElement[] = [];
afterEach(() => {
  for (const h of hosts) h.remove();
  hosts = [];
  vi.restoreAllMocks();
});
beforeEach(() => {
  vi.spyOn(console, "warn").mockImplementation(() => {});
});

/** Mounts a file and plays the frame up to its `ready`, reporting `policy`. */
async function mount(
  config: Partial<SandboxConfig> = {},
  name = "plan.dwg",
  ready = true,
  source: FileSource = { bytes: new Uint8Array([1, 2, 3]) },
  policy: FramePolicy | null = null,
): Promise<Frame> {
  const viewer = createSandboxedViewer({ url: "https://frame.test/index.html", ...config });
  const host = document.createElement("div");
  document.body.append(host);
  hosts.push(host);
  const session = viewer.mount(host, { id: "f1", name, source });
  const iframe = host.querySelector("iframe")!;
  const hello: { message: any; target: string; transfer: MessagePort[] }[] = [];
  iframe.contentWindow!.postMessage = ((message: unknown, target: string, transfer: MessagePort[]) => hello.push({ message, target, transfer })) as never;
  iframe.dispatchEvent(new Event("load"));
  expect(hello).toHaveLength(1);
  const port = hello[0]!.transfer[0]!;
  const received: any[] = [];
  port.onmessage = (e: MessageEvent) => received.push(e.data);
  const frame: Frame = {
    session,
    iframe,
    received,
    async send(message) {
      port.postMessage(message);
      await tick(5);
    },
    controllers: () => session.controllers.get(),
  };
  if (ready) await frame.send({ type: "ready", protocol: PROTOCOL, policy });
  await tick(5);
  return frame;
}

const LAYERS = { kind: "layers", items: [{ id: "WALLS", name: "WALLS", color: "rgb(255 0 0)", visible: true }] };

describe("the frame element", () => {
  it("is sandboxed to scripts, with no features and no referrer, and gets the port alone", async () => {
    const viewer = createSandboxedViewer({ url: "https://frame.test/index.html" });
    const host = document.createElement("div");
    document.body.append(host);
    hosts.push(host);
    viewer.mount(host, { id: "x", name: "a.pdf", source: { bytes: new Uint8Array(1) } });
    const iframe = host.querySelector("iframe")!;
    expect(iframe.getAttribute("sandbox")).toBe("allow-scripts");
    expect(iframe.getAttribute("allow")).toBe("");
    expect(iframe.getAttribute("referrerpolicy")).toBe("no-referrer");
    expect(iframe.getAttribute("src")).toBe("https://frame.test/index.html");
    const sent: unknown[][] = [];
    iframe.contentWindow!.postMessage = ((...a: unknown[]) => sent.push(a)) as never;
    iframe.dispatchEvent(new Event("load"));
    expect(sent).toHaveLength(1);
    const [message, target, transfer] = sent[0] as [unknown, string, unknown[]];
    expect(message).toEqual({ type: HELLO, protocol: PROTOCOL });
    expect(target).toBe("*");
    expect(transfer).toHaveLength(1);
  });

  it("is given the file once it is ready, with the formats it may use", async () => {
    const f = await mount({ formats: ["pdf", "dwg"] });
    const open = f.received.find((m) => m.type === "open");
    expect(open).toMatchObject({ type: "open", formats: ["pdf", "dwg"], file: { name: "plan.dwg", type: "", path: "plan.dwg", format: "dwg" } });
  });

  it("is not made for a file of a format it was not given", async () => {
    const viewer = createSandboxedViewer({ url: "https://frame.test/", formats: ["pdf"] });
    const host = document.createElement("div");
    hosts.push(host);
    const s = viewer.mount(host, { id: "x", name: "plan.dwg", source: { bytes: new Uint8Array(1) } });
    expect(host.querySelector("iframe")).toBeNull();
    // As in the page: no plugin claims it.
    expect(s.status.get()).toEqual({ phase: "error", error: { code: "file" } });
  });

  it("is dropped when it loads a second time: it navigated away", async () => {
    const f = await mount();
    f.iframe.dispatchEvent(new Event("load"));
    expect(f.session.status.get().phase).toBe("error");
    expect(f.iframe.isConnected).toBe(false);
  });

  it("is dropped when it speaks another protocol, or does not start", async () => {
    const f = await mount({}, "plan.dwg", false);
    await f.send({ type: "ready", protocol: PROTOCOL + 1, policy: null });
    expect(f.session.status.get().phase).toBe("error");
    expect(f.received.find((m) => m.type === "open")).toBeUndefined();

    const viewer = createSandboxedViewer({ url: "https://frame.test/", startTimeoutMs: 20 });
    const host = document.createElement("div");
    hosts.push(host);
    const s = viewer.mount(host, { id: "x", name: "a.pdf", source: { bytes: new Uint8Array(1) } });
    await tick(60);
    expect(s.status.get()).toMatchObject({ phase: "error", error: { code: "pdf" } });
  });

  it("goes with the session", async () => {
    const f = await mount();
    f.session.destroy();
    expect(f.iframe.isConnected).toBe(false);
  });
});

describe("what the frame sends", () => {
  it("reaches the stores when it has the protocol's shape", async () => {
    const f = await mount();
    await f.send({ type: "status", session: 0, status: { phase: "ready" } });
    expect(f.session.status.get()).toEqual({ phase: "ready" });
    await f.send({ type: "controllers", session: 0, values: { layers: LAYERS, ground: "light" }, statics: { ground: { light: "#ffffff", dark: "#000000" } } });
    expect(f.controllers().layers?.get()).toEqual(LAYERS);
    expect(f.controllers().ground?.colors).toEqual({ light: "#ffffff", dark: "#000000" });
    await f.send({ type: "state", session: 0, key: "ground", value: "dark" });
    expect(f.controllers().ground?.get()).toBe("dark");
  });

  it("is dropped whole when any part of it is not", async () => {
    const f = await mount();
    const bad = [
      // A colour that would make the host fetch a URL the frame chose.
      { type: "controllers", session: 0, values: { layers: { kind: "layers", items: [{ id: "a", name: "a", color: "url(https://x.test/?leak)", visible: true }] } }, statics: {} },
      { type: "controllers", session: 0, values: { layers: LAYERS }, statics: { ground: { light: "#fff", dark: "red; background: url(x)" } } },
      // A controller the protocol does not have.
      { type: "controllers", session: 0, values: { layers: LAYERS, image: {} }, statics: {} },
      // A string past its limit.
      { type: "controllers", session: 0, values: { layers: { kind: "layers", items: [{ id: "a", name: "x".repeat(2000), color: "#000", visible: true }] } }, statics: {} },
      { type: "status", session: 0, status: { phase: "error", code: "<b>" } },
      { type: "status", session: 0, status: { phase: "converting", progress: 7 } },
      { type: "nonsense" },
      "ready",
      null,
    ];
    for (const m of bad) await f.send(m);
    expect(f.controllers()).toEqual({});
    expect(f.session.status.get()).toEqual({ phase: "loading" });
  });

  it("keeps a store's value when an update does not check", async () => {
    const f = await mount();
    await f.send({ type: "controllers", session: 0, values: { zoom: { scale: 1, min: 0, max: Infinity } }, statics: {} });
    await f.send({ type: "state", session: 0, key: "zoom", value: { scale: "big", min: 0, max: 1 } });
    await f.send({ type: "state", session: 0, key: "zoom", value: { scale: Number.NaN, min: 0, max: 1 } });
    expect(f.controllers().zoom?.get()).toEqual({ scale: 1, min: 0, max: Infinity });
  });

  it("keeps a drag mode the checks accept, and drops one they do not", async () => {
    const f = await mount();
    await f.send({ type: "controllers", session: 0, values: { drag: { mode: "pan", available: true } }, statics: {} });
    expect(f.controllers().drag?.get()).toEqual({ mode: "pan", available: true });
    await f.send({ type: "state", session: 0, key: "drag", value: { mode: "<b>", available: true } });
    await f.send({ type: "state", session: 0, key: "drag", value: { mode: "select", available: "yes" } });
    expect(f.controllers().drag?.get()).toEqual({ mode: "pan", available: true });
    await f.send({ type: "state", session: 0, key: "drag", value: { mode: "select", available: true } });
    expect(f.controllers().drag?.get()).toEqual({ mode: "select", available: true });
  });

  it("is ignored for a session the frame never announced", async () => {
    const f = await mount();
    await f.send({ type: "status", session: 7, status: { phase: "ready" } });
    await f.send({ type: "controllers", session: 7, values: { layers: LAYERS }, statics: {} });
    expect(f.session.status.get()).toEqual({ phase: "loading" });
    expect(f.controllers()).toEqual({});
  });
});

describe("the controllers the host gets", () => {
  it("send a drag choice to the frame, and show it at once only where there is a choice", async () => {
    const f = await mount();
    await f.send({ type: "controllers", session: 0, values: { drag: { mode: "pan", available: true } }, statics: {} });
    f.controllers().drag!.choose("select");
    expect(f.controllers().drag!.get()).toEqual({ mode: "select", available: true });
    await tick(5);
    await f.send({ type: "done", call: f.received.filter((m) => m.type === "command")[0].call, ok: true });
    await f.send({ type: "state", session: 0, key: "drag", value: { mode: "select", available: false } });
    f.controllers().drag!.choose("pan");
    // Nothing to choose: the frame keeps selecting, and so does what is shown.
    expect(f.controllers().drag!.get()).toEqual({ mode: "select", available: false });
    await tick(5);
    const commands = f.received.filter((m) => m.type === "command");
    expect(commands.map(({ target, action, args }) => [target, action, args])).toEqual([
      ["drag", "choose", ["select"]],
      ["drag", "choose", ["pan"]],
    ]);
  });

  it("send their commands to the frame, and show toggles at once", async () => {
    const f = await mount();
    await f.send({
      type: "controllers",
      session: 0,
      values: { layers: LAYERS, layouts: { items: [{ id: "", name: "Model", isModel: true }], current: "" }, pages: { unit: "page", current: 1, total: 3 } },
      statics: { pages: { goTo: true, step: false } },
    });
    const c = f.controllers();
    c.layers!.setVisible("WALLS", false);
    expect(c.layers!.get().items[0]!.visible).toBe(false);
    c.pages!.goTo!(2);
    expect(c.pages!.next).toBeUndefined();
    let selected = false;
    void c.layouts!.select("A3").then(() => (selected = true));
    await tick(5);
    const commands = f.received.filter((m) => m.type === "command");
    expect(commands.map(({ target, action, args }) => [target, action, args])).toEqual([
      ["layers", "setVisible", ["WALLS", false]],
      ["pages", "goTo", [2]],
      ["layouts", "select", ["A3"]],
    ]);
    expect(selected).toBe(false);
    await f.send({ type: "done", call: commands[2].call, ok: true });
    expect(selected).toBe(true);
  });

  it("show an archive's member as a session of its own", async () => {
    const f = await mount({}, "delivery.zip");
    const member = { index: 2, name: "a/plan.dxf", uncompressedSize: 10, encrypted: false };
    const archive = (opened: unknown) => ({ members: [member], opening: null, opened, refused: null });
    await f.send({ type: "controllers", session: 0, values: { archive: archive(null) }, statics: {} });
    await f.send({ type: "state", session: 0, key: "archive", value: archive({ member, name: "a/plan.dxf", format: "dxf", session: 1 }) });
    const opened = f.controllers().archive!.get().opened!;
    expect(opened.member).toEqual(member);
    expect(opened.session.format).toBe("dxf");
    await f.send({ type: "status", session: 1, status: { phase: "ready" } });
    expect(opened.session.status.get()).toEqual({ phase: "ready" });
    // Back to the list: the member's session is forgotten.
    await f.send({ type: "state", session: 0, key: "archive", value: archive(null) });
    await f.send({ type: "status", session: 1, status: { phase: "empty" } });
    expect(opened.session.status.get()).toEqual({ phase: "ready" });
    // A number already in use is not a member.
    await f.send({ type: "state", session: 0, key: "archive", value: archive({ member, name: "x", format: null, session: 0 }) });
    expect(f.controllers().archive!.get().opened).toBeNull();
  });
});

describe("links", () => {
  it("open, after the host's question, only when absolute http(s), one question at a time", async () => {
    let answer: (yes: boolean) => void = () => {};
    const confirmLink = vi.fn((_url: string) => new Promise<boolean>((resolve) => (answer = resolve)));
    const open = vi.spyOn(window, "open").mockImplementation(() => null);
    const f = await mount({ confirmLink });
    for (const url of ["javascript:alert(1)", "/relative", "data:text/html,x", "file:///etc/passwd", "x".repeat(3000)]) await f.send({ type: "link", url });
    expect(confirmLink).not.toHaveBeenCalled();
    await f.send({ type: "link", url: "https://example.com/a" });
    await f.send({ type: "link", url: "https://example.com/b" });
    expect(confirmLink).toHaveBeenCalledTimes(1);
    expect(confirmLink.mock.calls[0]![0]).toBe("https://example.com/a");
    answer(true);
    await tick(5);
    expect(open).toHaveBeenCalledWith("https://example.com/a", "_blank", "noopener,noreferrer");
    await f.send({ type: "link", url: "https://example.com/c" });
    answer(false);
    await tick(5);
    expect(open).toHaveBeenCalledTimes(1);
  });
});

/** Byte `i` of these files is `i & 0xff`. */
function pattern(offset: number, length: number): Uint8Array {
  const out = new Uint8Array(length);
  for (let i = 0; i < length; i++) out[i] = (offset + i) & 0xff;
  return out;
}

/** A file read by ranges whose reads, past its first bytes, wait until the test lets them go. */
function heldRanges(size: number) {
  const reads: { offset: number; length: number; signal: AbortSignal; release: () => void }[] = [];
  const ranges: ByteRanges = {
    size,
    read(offset, length, signal) {
      if (offset === 0 && length <= READS.head) return Promise.resolve(pattern(offset, length));
      return new Promise((resolve, reject) => {
        reads.push({ offset, length, signal, release: () => resolve(pattern(offset, length)) });
        signal.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError")));
      });
    },
  };
  return { ranges, reads };
}

const answer = (f: Frame, id: number) => f.received.find((m) => m.type === "bytes" && m.id === id);

describe("a file read by ranges", () => {
  it("gives the frame its size and first bytes, then what it asks within the file and the limits", async () => {
    const size = 100 * 1024 * 1024;
    const held = heldRanges(size);
    const f = await mount({}, "big.pdf", true, { ranges: held.ranges });
    const open = f.received.find((m) => m.type === "open");
    expect(open.source.kind).toBe("ranges");
    expect(open.source.size).toBe(size);
    const same = (a: ArrayBuffer, b: Uint8Array) => Buffer.from(a).equals(b);
    expect(same(open.source.head, pattern(0, READS.head))).toBe(true);

    // Outside the file, empty, or longer than one read may be: refused, and not read.
    const refusals: [number, number, number][] = [
      [1, size - 10, 11],
      [2, size, 1],
      [3, 0, 0],
      [4, 0, READS.maxLength + 1],
    ];
    for (const [id, offset, length] of refusals) await f.send({ type: "read", id, offset, length });
    for (const [id] of refusals) expect(answer(f, id), String(id)).toEqual({ type: "bytes", id, error: "refused" });
    expect(held.reads).toHaveLength(0);

    // As many bytes at once as the limit: the next is refused until one is answered.
    const big = READS.maxBytes / READS.maxLength;
    for (let i = 0; i < big; i++) await f.send({ type: "read", id: 10 + i, offset: (i + 1) * READS.maxLength, length: READS.maxLength });
    expect(held.reads).toHaveLength(big);
    await f.send({ type: "read", id: 20, offset: 0, length: 1 });
    expect(answer(f, 20)).toEqual({ type: "bytes", id: 20, error: "refused" });
    held.reads[0]!.release();
    await tick(5);
    expect(same(answer(f, 10).data, pattern(READS.maxLength, READS.maxLength))).toBe(true);
    // As many reads at once as the limit.
    for (let i = 0; i < READS.maxReads - (big - 1); i++) await f.send({ type: "read", id: 30 + i, offset: 1000 + i, length: 1 });
    await f.send({ type: "read", id: 40, offset: 0, length: 1 });
    expect(answer(f, 40)).toEqual({ type: "bytes", id: 40, error: "refused" });
    // An id in use is not read twice.
    await f.send({ type: "read", id: 30, offset: 5, length: 1 });
    expect(held.reads.filter((r) => r.offset === 5)).toHaveLength(0);

    // A cancelled read stops, and is answered.
    await f.send({ type: "cancel", id: 11 });
    expect(held.reads[1]!.signal.aborted).toBe(true);
    expect(answer(f, 11)).toEqual({ type: "bytes", id: 11, error: "failed" });
    // The session's end stops the rest.
    f.session.destroy();
    expect(held.reads.every((r) => r.signal.aborted)).toBe(true);
  });

  it("is the only file a read is answered for", async () => {
    const f = await mount();
    expect(f.received.find((m) => m.type === "open").source.kind).toBe("blob");
    await f.send({ type: "read", id: 1, offset: 0, length: 1 });
    expect(answer(f, 1)).toEqual({ type: "bytes", id: 1, error: "refused" });
  });
});

describe("delivery by URL", () => {
  const MEDIA = "https://media.test";
  const policy = (origins: { media?: string[]; connect?: string[] }) => readPolicy(frameCsp(undefined, origins));
  let fetched: string[] = [];
  beforeEach(() => {
    fetched = [];
    vi.stubGlobal("fetch", async (url: string) => {
      fetched.push(String(url));
      return new Response(new Uint8Array([1, 2, 3]));
    });
  });
  afterEach(() => vi.unstubAllGlobals());

  it("gives the frame a video's address on a media origin, and reads anything else itself", async () => {
    const origins = { media: [MEDIA] };
    let f = await mount({ origins }, "clip.mp4", true, { url: `${MEDIA}/v/clip.mp4` }, policy(origins));
    expect(f.received.find((m) => m.type === "open").source).toEqual({ kind: "url", url: `${MEDIA}/v/clip.mp4` });
    expect(fetched).toEqual([]);
    // Another origin, a URL with `init`, an image only the frame's decoders draw: read whole by the host.
    for (const [name, source] of [
      ["clip.mp4", { url: "https://other.test/clip.mp4" }],
      ["clip.mp4", { url: `${MEDIA}/clip.mp4`, init: { headers: { authorization: "x" } } }],
      ["scan.tif", { url: `${MEDIA}/scan.tif` }],
    ] as [string, FileSource][]) {
      f = await mount({ origins }, name, true, source, policy(origins));
      expect(f.received.find((m) => m.type === "open").source.kind, name).toBe("blob");
    }
  });

  it('refuses, without a request, an address it may not give when "url" is asked for', async () => {
    const origins = { media: [MEDIA], connect: ["https://files.test"] };
    for (const [config, name, url] of [
      [{ origins, delivery: { media: "url" } }, "clip.mp4", "https://other.test/clip.mp4"],
      [{ origins, delivery: { media: "url" } }, "clip.mp4", "ftp://media.test/clip.mp4"],
      [{ origins, delivery: { pdf: "url" } }, "a.pdf", `${MEDIA}/a.pdf`],
    ] as [Partial<SandboxConfig>, string, string][]) {
      const f = await mount(config, name, true, { url }, policy(origins));
      expect(f.session.status.get().phase, url).toBe("error");
      expect(f.iframe.isConnected).toBe(false);
      expect(f.received.find((m) => m.type === "open")).toBeUndefined();
    }
    expect(fetched).toEqual([]);
    const f = await mount({ origins, delivery: { pdf: "url" } }, "a.pdf", true, { url: "https://files.test/a.pdf" }, policy(origins));
    expect(f.received.find((m) => m.type === "open").source).toEqual({ kind: "url", url: "https://files.test/a.pdf" });
  });

  it("goes only to a frame whose policy allows exactly the origins it is configured with", async () => {
    const origins = { media: [MEDIA] };
    for (const [config, reported] of [
      [{ origins }, null],
      [{ origins }, policy({})],
      [{ origins }, policy({ media: [MEDIA], connect: ["https://files.test"] })],
      [{}, policy(origins)],
    ] as [Partial<SandboxConfig>, FramePolicy | null][]) {
      const f = await mount(config, "plan.dwg", true, undefined, reported);
      expect(f.session.status.get().phase).toBe("error");
      expect(f.received.find((m) => m.type === "open")).toBeUndefined();
    }
    // Its own origin, written for WebKit, is its own.
    const f = await mount({ origins }, "plan.dwg", true, undefined, readPolicy(frameCsp("https://frame.test", origins)));
    expect(f.received.find((m) => m.type === "open")).toBeDefined();
  });

  it("is configured with known kinds, modes and origins", () => {
    for (const config of [
      { delivery: { pdf: "stream" } },
      { delivery: { office: "url" } },
      { delivery: { media: "url" } },
      { delivery: { pdf: "url" }, origins: { media: [MEDIA] } },
      { origins: { media: ["https://media.test/"] } },
      { origins: { media: ["*"] } },
      { origins: { other: [MEDIA] } },
    ]) {
      expect(() => createSandboxedViewer({ url: "https://frame.test/", ...(config as Partial<SandboxConfig>) }), JSON.stringify(config)).toThrow();
    }
    expect(() => createSandboxedViewer({ url: "https://frame.test/", delivery: { media: "url", pdf: "url" }, origins: { media: [MEDIA], connect: [MEDIA] } })).not.toThrow();
  });
});

describe("a file to be read by ranges", () => {
  const FILE = Uint8Array.from({ length: 100_000 }, (_, i) => i & 0xff);
  /** A server that answers range requests, or sends the whole file to every request. */
  const serve = (ranges: boolean) =>
    vi.stubGlobal("fetch", async (_url: string, init: RequestInit = {}) => {
      const m = /^bytes=(\d+)-(\d+)$/.exec((init.headers as Record<string, string> | undefined)?.range ?? "");
      if (!ranges || !m) return new Response(FILE.slice(), { status: 200 });
      const start = Number(m[1]);
      const end = Math.min(FILE.length - 1, Number(m[2]));
      return new Response(FILE.slice(start, end + 1), { status: 206, headers: { "content-range": `bytes ${start}-${end}/${FILE.length}` } });
    });
  afterEach(() => vi.unstubAllGlobals());

  it("from a server that sends it whole, goes whole, and the warnings say so beside the frame's", async () => {
    serve(false);
    const f = await mount({}, "a.pdf", true, { url: "https://files.test/a.pdf" });
    expect(f.received.find((m) => m.type === "open").source.kind).toBe("blob");
    const said = { key: "source_read_whole", count: 1 };
    expect(f.controllers().warnings?.get()).toEqual([said]);
    const frames = { key: "external_references", count: 2 };
    await f.send({ type: "controllers", session: 0, values: { warnings: [frames] }, statics: {} });
    expect(f.controllers().warnings?.get()).toEqual([frames, said]);
    await f.send({ type: "state", session: 0, key: "warnings", value: [] });
    expect(f.controllers().warnings?.get()).toEqual([said]);
    // A new set of controllers without warnings keeps it.
    await f.send({ type: "controllers", session: 0, values: { archive: { members: [], opening: null, opened: null, refused: null } }, statics: {} });
    expect(f.controllers().warnings?.get()).toEqual([said]);
    for (const lang of ["en", "fr"]) expect(builtinTranslate(lang)("warning_source_read_whole"), lang).not.toBe("warning_source_read_whole");
  });

  it("from a server that answers ranges, goes by ranges, with no warning", async () => {
    serve(true);
    const f = await mount({}, "a.pdf", true, { url: "https://files.test/a.pdf" });
    expect(f.received.find((m) => m.type === "open").source.kind).toBe("ranges");
    await f.send({ type: "controllers", session: 0, values: {}, statics: {} });
    expect(f.controllers().warnings).toBeUndefined();
  });
});
