// The host's side of the sandboxed frame, against a frame played by the test:
// what reaches the stores is what the protocol allows, and nothing else.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import "../test/blob.js";
import type { ByteRanges, Controllers, FileSource, Session } from "../core/types.js";
import { builtinTranslate } from "../react/messages.js";
import type { FrameTheme } from "../core/theme.js";
import { createSandboxedViewer, KEY_RATE, type SandboxConfig, type SandboxedViewer } from "./index.js";
import { frameCsp, readPolicy, type FramePolicy } from "./policy.js";
import { HELLO, MAX_DRAWS, PROTOCOL, READS } from "./protocol.js";

const tick = (ms = 0) => new Promise((r) => setTimeout(r, ms));

interface Frame {
  session: Session;
  iframe: HTMLIFrameElement;
  /** What the host sent over the port. */
  received: any[];
  send(message: unknown): Promise<void>;
  /** As `send`, but handed to the host as it is: a port clones a message, which a bitmap cannot survive here. */
  inject(message: unknown): Promise<void>;
  controllers(): Controllers;
}

let hosts: HTMLElement[] = [];
afterEach(() => {
  for (const h of hosts) h.remove();
  hosts = [];
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
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
  return mountWith(createSandboxedViewer({ url: "https://frame.test/index.html", ...config }), name, ready, source, policy);
}

async function mountWith(
  viewer: SandboxedViewer,
  name = "plan.dwg",
  ready = true,
  source: FileSource = { bytes: new Uint8Array([1, 2, 3]) },
  policy: FramePolicy | null = null,
): Promise<Frame> {
  const host = document.createElement("div");
  document.body.append(host);
  hosts.push(host);
  const session = viewer.mount(host, { id: "f1", name, source });
  const iframe = host.querySelector("iframe")!;
  const hello: { message: any; target: string; transfer: MessagePort[] }[] = [];
  iframe.contentWindow!.postMessage = ((message: unknown, target: string, transfer: MessagePort[]) => hello.push({ message, target, transfer })) as never;
  const Channel = globalThis.MessageChannel;
  const channels: MessageChannel[] = [];
  vi.stubGlobal(
    "MessageChannel",
    class extends Channel {
      constructor() {
        super();
        channels.push(this);
      }
    },
  );
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
    async inject(message) {
      channels[0]!.port1.onmessage?.({ data: message } as MessageEvent);
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
  it("is sandboxed to scripts, with no feature but autoplay and isolation and no referrer, and gets the port alone", async () => {
    const viewer = createSandboxedViewer({ url: "https://frame.test/index.html" });
    const host = document.createElement("div");
    document.body.append(host);
    hosts.push(host);
    viewer.mount(host, { id: "x", name: "a.pdf", source: { bytes: new Uint8Array(1) } });
    const iframe = host.querySelector("iframe")!;
    expect(iframe.getAttribute("sandbox")).toBe("allow-scripts");
    expect(iframe.getAttribute("allow")).toBe("autoplay");
    // It fills its host without the stylesheet.
    expect([iframe.style.width, iframe.style.height, iframe.style.display]).toEqual(["100%", "100%", "block"]);
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

  const MEDIA = { kind: "video", paused: true, ended: false, currentTime: 0, duration: 12.5, buffered: 3, volume: 1, muted: false, rate: 1, waiting: false, blocked: false };

  it("drive a player: its state from the frame, its commands to it", async () => {
    const f = await mount({}, "clip.mp4");
    await f.send({ type: "controllers", session: 0, values: { media: MEDIA }, statics: {} });
    const media = f.controllers().media!;
    expect(media.get()).toEqual(MEDIA);
    let played = false;
    void media.play().then(() => (played = true));
    media.seek(4);
    media.setVolume(0.5);
    media.setMuted(true);
    media.setRate(2);
    media.pause();
    await tick(5);
    const commands = f.received.filter((m) => m.type === "command");
    expect(commands.map(({ target, action, args }) => [target, action, args])).toEqual([
      ["media", "play", []],
      ["media", "seek", [4]],
      ["media", "setVolume", [0.5]],
      ["media", "setMuted", [true]],
      ["media", "setRate", [2]],
      ["media", "pause", []],
    ]);
    // `play` resolves once the frame has tried.
    expect(played).toBe(false);
    await f.send({ type: "done", call: commands[0].call, ok: true });
    expect(played).toBe(true);
    await f.send({ type: "state", session: 0, key: "media", value: { ...MEDIA, paused: false, currentTime: 4 } });
    expect(media.get()).toMatchObject({ paused: false, currentTime: 4 });
    // A volume past 1 is no state of a player.
    await f.send({ type: "state", session: 0, key: "media", value: { ...MEDIA, volume: 3 } });
    expect(media.get()).toMatchObject({ paused: false, volume: 1 });
  });

  it("switch sheets through the frame", async () => {
    const f = await mount({}, "book.xlsx");
    const sheets = { items: [{ index: 0, name: "Data" }, { index: 1, name: "Chart" }], current: 0 };
    await f.send({ type: "controllers", session: 0, values: { sheets }, statics: {} });
    const c = f.controllers().sheets!;
    expect(c.get()).toEqual(sheets);
    void c.select(1);
    await tick(5);
    expect(f.received.filter((m) => m.type === "command").map(({ target, action, args }) => [target, action, args])).toEqual([["sheets", "select", [1]]]);
    await f.send({ type: "state", session: 0, key: "sheets", value: { ...sheets, current: 1 } });
    expect(c.get().current).toBe(1);
  });
});

describe("pictures of pages", () => {
  const PAGE = { count: 3, space: "page" };
  const RECT = { x: 0, y: 0, width: 1, height: 1 };
  const asked = (f: Frame) => f.received.filter((m) => m.type === "raster");

  /** A bitmap as the frame sends one: only its size is read. */
  class FakeBitmap {
    closed = false;
    constructor(
      public width: number,
      public height: number,
    ) {}
    close() {
      this.closed = true;
    }
  }
  beforeEach(() => void vi.stubGlobal("ImageBitmap", FakeBitmap));
  afterEach(() => void vi.unstubAllGlobals());
  const done = (id: number, bitmap: FakeBitmap, extra: Record<string, unknown> = {}) => ({
    type: "rastered",
    id,
    result: { ok: true, bitmap, width: bitmap.width, height: bitmap.height, page: 2, space: "page", region: RECT, ...extra },
  });

  it("are asked of the frame with their options, and come back with the region drawn", async () => {
    const f = await mount({}, "report.pdf");
    await f.send({ type: "controllers", session: 0, values: { pictures: PAGE }, statics: {} });
    const pictures = f.controllers().pictures!;
    expect(pictures.get()).toEqual(PAGE);
    const region = { x: 0.1, y: 0.1, width: 0.5, height: 0.5 };
    const drawn = pictures.raster(2, { width: 40, height: 20, region, fit: "cover", background: "transparent" });
    await tick(5);
    const [m] = asked(f);
    expect(m).toMatchObject({ type: "raster", session: 0, page: 2, options: { width: 40, height: 20, region, fit: "cover", background: "transparent" } });
    // An answer to nothing asked is dropped (and its bitmap freed); the one asked for resolves.
    const stray = new FakeBitmap(40, 20);
    await f.inject(done(m.id + 100, stray));
    expect(stray.closed).toBe(true);
    const bitmap = new FakeBitmap(40, 20);
    await f.inject(done(m.id, bitmap, { region: { x: 0.1, y: 0.2, width: 0.5, height: 0.25 } }));
    expect(await drawn).toEqual({ bitmap, width: 40, height: 20, page: 2, space: "page", region: { x: 0.1, y: 0.2, width: 0.5, height: 0.25 } });
    expect(bitmap.closed).toBe(false);
  });

  it("render a page by its longest side, and are null where a raster is an error", async () => {
    const f = await mount({}, "report.pdf");
    await f.send({ type: "controllers", session: 0, values: { pictures: PAGE }, statics: {} });
    const pictures = f.controllers().pictures!;
    const drawn = pictures.render(2, 300);
    await tick(5);
    expect(asked(f)[0]).toMatchObject({ page: 2, options: { longEdge: 300 } });
    await f.send({ type: "rastered", id: asked(f)[0].id, result: { ok: false, code: "failed" } });
    expect(await drawn).toBeNull();
  });

  it("fail with the frame's own code, or as failed for a picture that is not the one asked for", async () => {
    const f = await mount({}, "report.pdf");
    await f.send({ type: "controllers", session: 0, values: { pictures: PAGE }, statics: {} });
    const pictures = f.controllers().pictures!;
    const code = async (options: Parameters<typeof pictures.raster>[1], answer: (id: number) => unknown) => {
      const p = pictures.raster(1, options).then(
        () => "drawn",
        (e) => (e as { code: string }).code,
      );
      await tick(5);
      await f.inject(answer(asked(f).at(-1).id));
      return p;
    };
    expect(await code({ longEdge: 10 }, (id) => ({ type: "rastered", id, result: { ok: false, code: "too-large" } }))).toBe("too-large");
    expect(await code({ longEdge: 10 }, (id) => ({ type: "rastered", id, result: { ok: false, code: "nonsense" } }))).toBe("failed");
    // Not the size asked for, the wrong space, past the long edge asked: freed, and failed.
    for (const [options, bitmap, extra] of [
      [{ width: 40, height: 20 }, new FakeBitmap(41, 20), {}],
      [{ width: 40 }, new FakeBitmap(39, 20), {}],
      [{ height: 20 }, new FakeBitmap(40, 21), {}],
      [{ longEdge: 30 }, new FakeBitmap(31, 10), {}],
      [{ longEdge: 30 }, new FakeBitmap(30, 10), { space: "drawing" }],
    ] as const) {
      expect(await code(options, (id) => done(id, bitmap, extra)), JSON.stringify([options, extra])).toBe("failed");
      expect(bitmap.closed).toBe(true);
    }
    const good = new FakeBitmap(30, 10);
    expect(await code({ longEdge: 30 }, (id) => done(id, good))).toBe("drawn");
    expect(good.closed).toBe(false);
  });

  it("are stopped by the signal at once, the frame told, and a bitmap that comes later is freed", async () => {
    const f = await mount({}, "report.pdf");
    await f.send({ type: "controllers", session: 0, values: { pictures: PAGE }, statics: {} });
    const pictures = f.controllers().pictures!;
    const abort = new AbortController();
    const drawn = pictures.raster(1, { longEdge: 100, signal: abort.signal }).catch((e) => e.code);
    await tick(5);
    const id = asked(f)[0].id;
    abort.abort();
    expect(await drawn).toBe("aborted");
    await tick(5);
    expect(f.received.filter((m) => m.type === "unraster")).toEqual([{ type: "unraster", id }]);
    const late = new FakeBitmap(100, 50);
    await f.inject(done(id, late));
    expect(late.closed).toBe(true);
    // Already aborted: nothing is sent.
    expect(await pictures.raster(1, { longEdge: 100, signal: abort.signal }).catch((e) => e.code)).toBe("aborted");
    expect(asked(f)).toHaveLength(1);
  });

  it("are not asked beyond the limit, nor for what is no page, and end with the frame", async () => {
    const f = await mount({}, "report.pdf");
    await f.send({ type: "controllers", session: 0, values: { pictures: { count: 99, space: "page" } }, statics: {} });
    const pictures = f.controllers().pictures!;
    expect(await pictures.render(0, 300)).toBeNull();
    expect(await pictures.render(1.5, 300)).toBeNull();
    expect(await pictures.raster(100, { longEdge: 300 }).catch((e) => e.code)).toBe("invalid");
    const waiting = Array.from({ length: MAX_DRAWS }, (_, i) => pictures.raster(i + 1, { longEdge: 100 }).catch((e) => e.code));
    expect(await pictures.raster(50, { longEdge: 100 }).catch((e) => e.message)).toMatch(/more than 8 pictures/);
    await tick(5);
    expect(asked(f)).toHaveLength(MAX_DRAWS);
    f.session.destroy();
    expect(await Promise.all(waiting)).toEqual(Array(MAX_DRAWS).fill("aborted"));
  });

  it("are encoded by this page, from the bitmap the frame drew", async () => {
    const f = await mount({}, "report.pdf");
    await f.send({ type: "controllers", session: 0, values: { pictures: PAGE }, statics: {} });
    const pictures = f.controllers().pictures!;
    // A type or a quality that is none is refused before the frame is asked.
    expect(await pictures.toBlob(1, { longEdge: 10, type: "gif" as never }).catch((e) => e.code)).toBe("invalid");
    expect(await pictures.toBlob(1, { longEdge: 10, quality: 2 }).catch((e) => e.code)).toBe("invalid");
    expect(asked(f)).toHaveLength(0);
    // jsdom has no canvas, so the encoding fails; the frame's bitmap is closed all the same.
    const blob = pictures.toBlob(1, { longEdge: 10 }).catch((e) => e.code);
    await tick(5);
    const bitmap = new FakeBitmap(10, 5);
    await f.inject(done(asked(f)[0].id, bitmap, { page: 1 }));
    expect(await blob).toBe("too-large");
    expect(bitmap.closed).toBe(true);
  });

  it("follow the viewport the frame reports, read-only", async () => {
    const f = await mount({}, "report.pdf");
    const viewport = { space: "page", page: 2, region: { x: 0, y: 0.5, width: 1, height: 0.5 } };
    await f.send({ type: "controllers", session: 0, values: { pictures: PAGE, viewport: null }, statics: {} });
    const store = f.controllers().viewport!;
    expect(store.get()).toBeNull();
    await f.send({ type: "state", session: 0, key: "viewport", value: viewport });
    expect(store.get()).toEqual(viewport);
    await f.send({ type: "state", session: 0, key: "viewport", value: { ...viewport, space: "camera" } });
    expect(store.get()).toEqual(viewport);
    expect("set" in store).toBe(false);
  });

  it("fail as invalid where the frame refuses the request", async () => {
    const f = await mount({}, "report.pdf");
    await f.send({ type: "controllers", session: 0, values: { pictures: PAGE }, statics: {} });
    const pictures = f.controllers().pictures!;
    const drawn = pictures.raster(1, { longEdge: 100 }).then(
      () => "drawn",
      (e) => e,
    );
    await tick(5);
    await f.send({ type: "rastered", id: asked(f)[0].id, result: { ok: false, code: "invalid" } });
    const error = await drawn;
    expect(error).toMatchObject({ name: "RasterError", code: "invalid" });
  });
});

describe("the viewport", () => {
  const VIEW = { space: "page", page: 2, region: { x: 0, y: 0.5, width: 1, height: 0.5 } };
  const told = (f: Frame) => f.received.filter((m) => m.type === "watch" || m.type === "unwatch");

  async function withViewport() {
    const f = await mount({}, "report.pdf");
    await f.send({ type: "controllers", session: 0, values: { pictures: { count: 3, space: "page" }, viewport: null }, statics: {} });
    return f;
  }

  it("is not asked of the frame by a session that does not use it", async () => {
    const f = await withViewport();
    expect(f.controllers().viewport).toBeDefined();
    await f.send({ type: "state", session: 0, key: "zoom", value: { scale: 1, min: 0.5, max: 4 } });
    expect(told(f)).toEqual([]);
  });

  it("is watched from the first listener to the last", async () => {
    const f = await withViewport();
    const store = f.controllers().viewport!;
    const seen: unknown[] = [];
    const a = store.subscribe((v) => seen.push(v));
    await tick(5);
    expect(told(f)).toEqual([{ type: "watch", session: 0, key: "viewport" }]);
    const b = store.subscribe(() => {});
    await f.send({ type: "state", session: 0, key: "viewport", value: VIEW });
    expect(seen).toEqual([VIEW]);
    a();
    a();
    await tick(5);
    expect(told(f)).toHaveLength(1);
    b();
    await tick(5);
    expect(told(f)).toEqual([
      { type: "watch", session: 0, key: "viewport" },
      { type: "unwatch", session: 0, key: "viewport" },
    ]);
    // Followed again later: watched again.
    store.subscribe(() => {})();
    await tick(5);
    expect(told(f).map((m) => m.type)).toEqual(["watch", "unwatch", "watch", "unwatch"]);
  });

  it("is asked for once by a read with no listener, which has the last value the frame reported", async () => {
    const f = await withViewport();
    const store = f.controllers().viewport!;
    expect(store.get()).toBeNull();
    await tick(5);
    expect(told(f).map((m) => m.type)).toEqual(["watch", "unwatch"]);
    await f.send({ type: "state", session: 0, key: "viewport", value: VIEW });
    expect(store.get()).toEqual(VIEW);
    await tick(5);
    expect(told(f)).toHaveLength(4);
    // While it is followed, a read asks for nothing more.
    const stop = store.subscribe(() => {});
    store.get();
    store.get();
    await tick(5);
    expect(told(f)).toHaveLength(5);
    stop();
  });

  it("stays watched when the frame sends its controllers again, until the last listener of any of them leaves", async () => {
    const f = await withViewport();
    const first = f.controllers().viewport!;
    const stopFirst = first.subscribe(() => {});
    await f.send({ type: "controllers", session: 0, values: { pictures: { count: 3, space: "page" }, viewport: null }, statics: {} });
    const second = f.controllers().viewport!;
    expect(second).not.toBe(first);
    // The new listener comes before the old one leaves.
    const stopSecond = second.subscribe(() => {});
    stopFirst();
    await tick(5);
    expect(told(f).map((m) => m.type)).toEqual(["watch"]);
    stopSecond();
    await tick(5);
    expect(told(f).map((m) => m.type)).toEqual(["watch", "unwatch"]);
  });

  it("tells the frame nothing once the session has ended", async () => {
    const f = await withViewport();
    const store = f.controllers().viewport!;
    const stop = store.subscribe(() => {});
    await tick(5);
    f.session.destroy();
    stop();
    store.get();
    store.subscribe(() => {})();
    await tick(5);
    expect(told(f).map((m) => m.type)).toEqual(["watch"]);
  });
});

describe("keys from the frame", () => {
  const pressed = (f: Frame) => {
    const keys: string[] = [];
    f.iframe.ownerDocument.addEventListener("keydown", (e) => keys.push(`${e.key}${e.shiftKey ? "+shift" : ""}${e.target === f.iframe ? "" : "?"}`));
    return keys;
  };

  it("reach this page's listeners from the frame element, when they are navigation keys", async () => {
    const f = await mount();
    const keys = pressed(f);
    await f.send({ type: "key", key: "ArrowRight", shift: false, repeat: false });
    await f.send({ type: "key", key: "Escape", shift: true, repeat: false });
    // What could type or press a shortcut does not pass the check.
    await f.send({ type: "key", key: "Delete", shift: false, repeat: false });
    await f.send({ type: "key", key: "a", shift: false, repeat: false });
    await f.send({ type: "key", key: "ArrowLeft" });
    expect(keys).toEqual(["ArrowRight", "Escape+shift"]);
  });

  it(`are taken at most ${KEY_RATE} a second`, async () => {
    const f = await mount();
    const keys = pressed(f);
    for (let i = 0; i < KEY_RATE + 10; i++) await f.send({ type: "key", key: "ArrowDown", shift: false, repeat: true });
    expect(keys).toHaveLength(KEY_RATE);
  });

  it("are only those the host lists, or none", async () => {
    const some = await mount({ keys: ["Escape"] });
    const someKeys = pressed(some);
    await some.send({ type: "key", key: "ArrowRight", shift: false, repeat: false });
    await some.send({ type: "key", key: "Escape", shift: false, repeat: false });
    expect(someKeys).toEqual(["Escape"]);
    const none = await mount({ keys: false });
    const noneKeys = pressed(none);
    await none.send({ type: "key", key: "Escape", shift: false, repeat: false });
    expect(noneKeys).toEqual([]);
  });
});

describe("the theme", () => {
  it("goes with the file, checked, and again on restyle", async () => {
    const theme = { tokens: { "--exav-viewer-text": "#123456", "--exav-viewer-panel": "url(https://x.test/)", "--exav-viewer-radius": "4px" }, scheme: "dark" } as unknown as FrameTheme;
    const viewer = createSandboxedViewer({ url: "https://frame.test/index.html", theme });
    const f = await mountWith(viewer);
    const open = f.received.find((m) => m.type === "open");
    expect(open.theme).toEqual({ tokens: { "--exav-viewer-text": "#123456", "--exav-viewer-radius": "4px" }, scheme: "dark" });
    viewer.restyle();
    await tick(5);
    expect(f.received.filter((m) => m.type === "theme")).toEqual([{ type: "theme", theme: open.theme }]);
    // A frame that has ended is not restyled.
    f.session.destroy();
    viewer.restyle();
    await tick(5);
    expect(f.received.filter((m) => m.type === "theme")).toHaveLength(1);
  });

  it("is none with null", async () => {
    const f = await mount({ theme: null });
    expect(f.received.find((m) => m.type === "open").theme).toEqual({ tokens: {}, scheme: null });
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
    for (const [id, offset, length] of refusals) await f.send({ type: "read", id, generation: 0, offset, length });
    for (const [id] of refusals) expect(answer(f, id), String(id)).toEqual({ type: "bytes", id, error: "refused" });
    expect(held.reads).toHaveLength(0);

    // As many bytes at once as the limit: the next is refused until one is answered.
    const big = READS.maxBytes / READS.maxLength;
    for (let i = 0; i < big; i++) await f.send({ type: "read", id: 10 + i, generation: 0, offset: (i + 1) * READS.maxLength, length: READS.maxLength });
    expect(held.reads).toHaveLength(big);
    await f.send({ type: "read", id: 20, generation: 0, offset: 0, length: 1 });
    expect(answer(f, 20)).toEqual({ type: "bytes", id: 20, error: "refused" });
    held.reads[0]!.release();
    await tick(5);
    expect(same(answer(f, 10).data, pattern(READS.maxLength, READS.maxLength))).toBe(true);
    // As many reads at once as the limit.
    for (let i = 0; i < READS.maxReads - (big - 1); i++) await f.send({ type: "read", id: 30 + i, generation: 0, offset: 1000 + i, length: 1 });
    await f.send({ type: "read", id: 40, generation: 0, offset: 0, length: 1 });
    expect(answer(f, 40)).toEqual({ type: "bytes", id: 40, error: "refused" });
    // An id in use is not read twice.
    await f.send({ type: "read", id: 30, generation: 0, offset: 5, length: 1 });
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
    await f.send({ type: "read", id: 1, generation: 0, offset: 0, length: 1 });
    expect(answer(f, 1)).toEqual({ type: "bytes", id: 1, error: "refused" });
  });

  it("is read for the document it names: after a replacement the old one's reads are refused, and the new one's answered from its bytes", async () => {
    const size = 100 * 1024 * 1024;
    const first = heldRanges(size);
    const second = heldRanges(size + 1);
    const f = await mount({}, "big.pdf", true, { ranges: first.ranges });
    const replacing = f.session.replace({ id: "f1", name: "big.pdf", source: { ranges: second.ranges } });
    await tick(5);
    const message = f.received.find((m) => m.type === "replace");
    expect(message).toMatchObject({ type: "replace", generation: 1, file: { name: "big.pdf", format: "pdf" }, source: { kind: "ranges", size: size + 1 } });
    // Both alive until the frame answers: the document being replaced is still drawn from its own bytes.
    await f.send({ type: "read", id: 1, generation: 0, offset: size - 5, length: 5 });
    await f.send({ type: "read", id: 2, generation: 1, offset: size, length: 1 });
    expect(first.reads.map((r) => r.offset)).toEqual([size - 5]);
    expect(second.reads.map((r) => r.offset)).toEqual([size]);
    await f.send({ type: "replaced", call: message.call, ok: true });
    expect(await replacing).toBe(true);
    // Now only the new one: the old generation, and one that was never given, are refused.
    await f.send({ type: "read", id: 3, generation: 0, offset: 0, length: 1 });
    await f.send({ type: "read", id: 4, generation: 7, offset: 0, length: 1 });
    expect(answer(f, 3)).toEqual({ type: "bytes", id: 3, error: "refused" });
    expect(answer(f, 4)).toEqual({ type: "bytes", id: 4, error: "refused" });
    await f.send({ type: "read", id: 5, generation: 1, offset: size, length: 1 });
    expect(second.reads.map((r) => r.offset)).toEqual([size, size]);
    expect(first.reads.every((r) => r.signal.aborted === false)).toBe(true);
  });
});

describe("replacing the document in the frame", () => {
  const replacements = (f: Frame) => f.received.filter((m) => m.type === "replace");
  const next = (name = "plan.dwg", bytes = [4, 5, 6]) => ({ id: "f1", name, source: { bytes: new Uint8Array(bytes) } });

  it("sends the next file, and resolves true once the frame has shown it, with the file on the session", async () => {
    const f = await mount();
    const first = f.session.file;
    const done = f.session.replace({ ...next(), type: "image/vnd.dwg" });
    await tick(5);
    const [m] = replacements(f);
    expect(m).toMatchObject({ type: "replace", generation: 1, file: { name: "plan.dwg", type: "image/vnd.dwg", path: "plan.dwg", format: "dwg" }, source: { kind: "blob" } });
    // Not the session's file until the frame has taken it.
    expect(f.session.file).toBe(first);
    await f.send({ type: "replaced", call: m.call, ok: true });
    expect(await done).toBe(true);
    expect(f.session.file.type).toBe("image/vnd.dwg");
  });

  it("resolves false and changes nothing when the frame cannot, and for what is no replacement", async () => {
    const f = await mount();
    const first = f.session.file;
    const refused = f.session.replace(next());
    await tick(5);
    await f.send({ type: "replaced", call: replacements(f)[0].call, ok: false });
    expect(await refused).toBe(false);
    expect(f.session.file).toBe(first);
    // Another format, or no bytes: the caller starts over, and the frame is not asked.
    expect(await f.session.replace({ id: "f1", name: "report.pdf", source: { bytes: new Uint8Array(1) } })).toBe(false);
    expect(await f.session.replace({ id: "f1", name: "plan.dwg", source: null })).toBe(false);
    expect(replacements(f)).toHaveLength(1);
  });

  it("is refused before the frame has the first file, and after the session ended", async () => {
    const early = await mount({}, "plan.dwg", false);
    expect(await early.session.replace(next())).toBe(false);
    const f = await mount();
    const pending = f.session.replace(next());
    await tick(5);
    f.session.destroy();
    expect(await pending).toBe(false);
    expect(await f.session.replace(next())).toBe(false);
  });

  it("is one at a time: a newer call supersedes one still being read, and waits for one the frame has", async () => {
    const f = await mount();
    const one = f.session.replace(next("plan.dwg", [1]));
    await tick(5);
    expect(replacements(f)).toHaveLength(1);
    // Two more while the first is with the frame: only the last is sent after it.
    const two = f.session.replace(next("plan.dwg", [2]));
    const three = f.session.replace(next("plan.dwg", [3]));
    await tick(5);
    expect(replacements(f)).toHaveLength(1);
    await f.send({ type: "replaced", call: replacements(f)[0].call, ok: true });
    await tick(5);
    expect(replacements(f)).toHaveLength(2);
    await f.send({ type: "replaced", call: replacements(f)[1].call, ok: true });
    expect(await Promise.all([one, two, three])).toEqual([true, true, true]);
    expect(replacements(f).map((m) => m.generation)).toEqual([1, 2]);
  });

  it("is not sent a delivery the frame was not made for: an image first given by URL stays a URL", async () => {
    const origins = { media: ["https://media.test"] };
    const viewer = createSandboxedViewer({ url: "https://frame.test/index.html", delivery: { images: "url" }, origins });
    const f = await mountWith(viewer, "a.png", true, { url: "https://media.test/a.png" }, readPolicy(frameCsp(undefined, origins)));
    expect(f.received.find((m) => m.type === "open").source.kind).toBe("url");
    const blob = f.session.replace({ id: "f1", name: "a.png", source: { bytes: new Uint8Array([1]) } });
    expect(await blob).toBe(false);
    expect(replacements(f)).toHaveLength(0);
    const url = f.session.replace({ id: "f1", name: "a.png", source: { url: "https://media.test/b.png" } });
    await tick(5);
    expect(replacements(f)[0]).toMatchObject({ source: { kind: "url", url: "https://media.test/b.png" } });
    await f.send({ type: "replaced", call: replacements(f)[0].call, ok: true });
    expect(await url).toBe(true);
  });

  it("is shown as an error, the old document staying, when the next one cannot be read", async () => {
    const f = await mount();
    const failing: FileSource = { resolve: async () => Promise.reject(new Error("offline")) };
    expect(await f.session.replace({ id: "f1", name: "plan.dwg", source: failing })).toBe(true);
    expect(f.session.status.get()).toMatchObject({ phase: "error", error: { code: "drawing" } });
    expect(replacements(f)).toHaveLength(0);
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
