// The host's side of the sandboxed frame, against a frame played by the test:
// what reaches the stores is what the protocol allows, and nothing else.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import "../test/blob.js";
import type { BuiltinFormat, ByteRanges, Controllers, FileSource, FileTree, Session, ViewerFile } from "../core/types.js";
import { builtinTranslate } from "../react/messages.js";
import type { FrameTheme } from "../core/theme.js";
import { createSniffer } from "../core/sniff-engine.js";
import { sniffInWorker } from "../test/sniff.js";
import { sniffed } from "./app/sniff.js";
import { createSandboxedViewer, KEY_RATE, LINK_QUIET_MS, type SandboxConfig, type SandboxedViewer } from "./index.js";
import { frameCsp, readPolicy, type FramePolicy } from "./policy.js";
import { HELLO, MAX_DRAWS, PROTOCOL, READS, TREE, type SniffMessage } from "./protocol.js";

// The detection runs in this process (the page has it in a worker; jsdom has none).
vi.mock("../core/sniff-engine.js", async () => {
  const real = await import("../test/sniff.js");
  return { createSniffer: vi.fn(() => real.sniffInWorker), createInspector: vi.fn(() => real.inspectInWorker), createOfficer: vi.fn(() => real.officeInWorker) };
});

const tick = (ms = 0) => new Promise((r) => setTimeout(r, ms));

/** Waits for what a test expects to have happened, as long as it takes up to a limit well under the test's. */
const until = <T>(check: () => T): Promise<T> => vi.waitFor(check, { timeout: 2000, interval: 2 });

/**
 * A set wait, for a step that must NOT happen: no condition can be waited
 * for, so it gives the step time to (wrongly) happen. Used only after a step
 * that must have happened is waited for.
 */
const quiet = (ms = 5) => tick(ms);

interface Frame {
  session: Session;
  iframe: HTMLIFrameElement;
  /** What the host sent over the port. */
  received: any[];
  /** Hands a message to the host, and returns once the host has handled it (or has ended). What the host then sends back arrives later: wait for it with `got` or `until`. */
  send(message: unknown): Promise<void>;
  /** As `send`, but handed to the host as it is: a port clones a message, which a bitmap cannot survive here. */
  inject(message: unknown): Promise<void>;
  /** Waits until the host has sent `count` messages of this type, and returns all of them. */
  got(type: string, count?: number): Promise<any[]>;
  controllers(): Controllers;
}

/** What the played frame answers a `sniff`: what the frame app would, a format of the test's, or nothing. */
let sniffAnswer: "auto" | "silent" | BuiltinFormat | null = "auto";

let hosts: HTMLElement[] = [];
afterEach(() => {
  sniffAnswer = "auto";
  for (const h of hosts) h.remove();
  hosts = [];
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  vi.useRealTimers();
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
  tree?: FileTree,
  extra: Partial<ViewerFile> = {},
): Promise<Frame> {
  const host = document.createElement("div");
  document.body.append(host);
  hosts.push(host);
  const session = viewer.mount(host, { id: "f1", name, source, ...(tree && { tree }), ...extra });
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
  /** The `sniffed` answers being made. */
  const answering: Promise<unknown>[] = [];
  port.onmessage = (e: MessageEvent) => {
    received.push(e.data);
    // As the frame app answers, unless the test says what. Not checked
    // (protocol.test does it): this port's buffers are of another realm.
    if (e.data?.type !== "sniff") return;
    const asked = e.data as SniffMessage;
    const answer = sniffAnswer === "auto" ? sniffed(asked, sniffInWorker, null) : Promise.resolve(sniffAnswer);
    answering.push(answer.then((format) => format !== "silent" && port.postMessage({ type: "sniffed", call: asked.call, format })));
  };
  const frame: Frame = {
    session,
    iframe,
    received,
    async send(message) {
      const hostPort = channels[0]!.port1;
      let stop = () => {};
      const handled = new Promise<void>((resolve) => {
        // The host's listener was added first, so it has run when this one does.
        hostPort.addEventListener("message", () => resolve(), { once: true });
        // A host that has ended has closed its port, and handles nothing more.
        const watch = setInterval(() => iframe.isConnected || resolve(), 5);
        stop = () => clearInterval(watch);
      });
      port.postMessage(message);
      await handled;
      stop();
    },
    async inject(message) {
      channels[0]!.port1.onmessage?.({ data: message } as MessageEvent);
    },
    async got(type, count = 1) {
      return until(() => {
        const messages = received.filter((m) => m.type === type);
        expect(messages.length, `messages of type ${type}`).toBeGreaterThanOrEqual(count);
        return messages;
      });
    },
    controllers: () => session.controllers.get(),
  };
  if (ready) {
    await frame.send({ type: "ready", protocol: PROTOCOL, policy, formats: null });
    // The host asks what the file is, or opens it, or ends in an error.
    const over = () => received.some((m) => m.type === "open") || session.status.get().phase === "error";
    await until(() => expect(over() || received.some((m) => m.type === "sniff")).toBe(true));
    while (answering.length) await Promise.all(answering.splice(0));
    // A frame that never answers leaves the host to its timeout: the test goes on at once.
    if (sniffAnswer !== "silent" && received.some((m) => m.type === "sniff")) await until(() => expect(over()).toBe(true));
  }
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

  it("is not made for a file of a format it was not given, when its bytes are not read", async () => {
    const viewer = createSandboxedViewer({ url: "https://frame.test/", formats: ["pdf"], sniffBytes: 0 });
    const host = document.createElement("div");
    hosts.push(host);
    const s = viewer.mount(host, { id: "x", name: "plan.dwg", source: { bytes: new Uint8Array(1) } });
    expect(host.querySelector("iframe")).toBeNull();
    expect(s.status.get()).toEqual({ phase: "error", error: { code: "file" } });
  });

  it("is made to ask what the bytes of a file of a format it was not given are, and dropped when they say none it opens", async () => {
    const f = await mount({ formats: ["pdf"] }, "plan.dwg");
    expect(f.received.find((m) => m.type === "sniff")).toMatchObject({ formats: ["pdf"], file: { name: "plan.dwg" } });
    expect(f.iframe.isConnected).toBe(false);
    expect(f.session.status.get()).toEqual({ phase: "error", error: { code: "file" } });
  });

  it("is given the file once, however many times it says it is ready", async () => {
    const f = await mount();
    await f.send({ type: "ready", protocol: PROTOCOL, policy: null, formats: null });
    await quiet();
    expect(f.received.filter((m) => m.type === "open")).toHaveLength(1);
  });

  it("is dropped when it loads a second time: it navigated away", async () => {
    const f = await mount();
    f.iframe.dispatchEvent(new Event("load"));
    expect(f.session.status.get().phase).toBe("error");
    expect(f.iframe.isConnected).toBe(false);
  });

  it("is dropped when it speaks another protocol, or does not start", async () => {
    const f = await mount({}, "plan.dwg", false);
    await f.send({ type: "ready", protocol: PROTOCOL + 1, policy: null, formats: null });
    expect(f.session.status.get().phase).toBe("error");
    await quiet();
    expect(f.received.find((m) => m.type === "open")).toBeUndefined();

    const viewer = createSandboxedViewer({ url: "https://frame.test/", startTimeoutMs: 20 });
    const host = document.createElement("div");
    hosts.push(host);
    const s = viewer.mount(host, { id: "x", name: "a.pdf", source: { bytes: new Uint8Array(1) } });
    await until(() => expect(s.status.get()).toMatchObject({ phase: "error", error: { code: "pdf" } }));
  });

  it("is dropped when it was published without the format of the file, and says so", async () => {
    const f = await mount({}, "plan.dwg", false);
    await f.send({ type: "ready", protocol: PROTOCOL, policy: null, formats: ["pdf", "image"] });
    await until(() => expect(f.session.status.get()).toMatchObject({ phase: "error", error: { code: "drawing" } }));
    await quiet();
    expect(f.received.find((m) => m.type === "open")).toBeUndefined();
    expect(f.session.status.get()).toMatchObject({ error: { cause: { message: expect.stringContaining("published without dwg") } } });

    // One that was published with it, or for all of them, is given the file.
    for (const formats of [["dwg", "dxf"] as const, null]) {
      const g = await mount({}, "plan.dwg", false);
      await g.send({ type: "ready", protocol: PROTOCOL, policy: null, formats });
      await until(() => expect(g.received.find((m) => m.type === "open")).toBeDefined());
    }
  });

  it("goes with the session", async () => {
    const f = await mount();
    f.session.destroy();
    expect(f.iframe.isConnected).toBe(false);
  });

  it("is pinged a third of frameTimeoutMs apart, and dropped when a ping stays unanswered that long", async () => {
    const f = await mount({ frameTimeoutMs: 240 });
    // The next ping is sent once the last is answered.
    await f.got("ping");
    await f.send({ type: "pong" });
    await f.got("ping", 2);
    await quiet(30);
    expect(f.session.status.get().phase).not.toBe("error");
    // The second stays unanswered.
    await until(() => expect(f.session.status.get()).toMatchObject({ phase: "error", error: { cause: { message: "the frame did not answer in 240 ms" } } }));
    expect(f.iframe.isConnected).toBe(false);
  });

  it("is not dropped for a late tick: the gap is not counted, the ping is sent again and the wait starts over", async () => {
    // Only the interval is played; the clock the host reads is the test's.
    vi.useFakeTimers({ toFake: ["setInterval", "clearInterval"] });
    let clock = 0;
    vi.spyOn(performance, "now").mockImplementation(() => clock);
    const f = await mount({ frameTimeoutMs: 240 });
    const tick = (ms: number) => {
      clock += ms;
      vi.advanceTimersByTime(80);
    };
    tick(80);
    await f.got("ping");
    tick(80);
    expect(f.session.status.get().phase).not.toBe("error");
    // A tick a second after the one before, the ping still unanswered.
    tick(1000);
    await f.got("ping", 2);
    expect(f.session.status.get().phase).not.toBe("error");
    // Ticks on time: the new wait is 240 ms, so the third of them ends it.
    tick(80);
    tick(80);
    expect(f.session.status.get().phase).not.toBe("error");
    tick(80);
    expect(f.session.status.get()).toMatchObject({ phase: "error", error: { cause: { message: "the frame did not answer in 240 ms" } } });
  });

  it("is not pinged with frameTimeoutMs 0", async () => {
    const f = await mount({ frameTimeoutMs: 0 });
    await quiet(100);
    expect(f.received.filter((m) => m.type === "ping")).toEqual([]);
    expect(() => createSandboxedViewer({ url: "https://frame.test/", frameTimeoutMs: -1 })).toThrow(RangeError);
  });

  it("is pinged no more once its session is destroyed", async () => {
    const set = vi.spyOn(globalThis, "setInterval");
    const clear = vi.spyOn(globalThis, "clearInterval");
    const f = await mount({ frameTimeoutMs: 240 });
    const pinger = set.mock.results.find((r, i) => set.mock.calls[i]![1] === 80)!.value;
    f.session.destroy();
    expect(clear).toHaveBeenCalledWith(pinger);
  });

  it("is dropped when the page's policy refuses it, and not for a report only, another address or another directive", async () => {
    const f = await mount({}, "plan.dwg", false);
    const violation = (init: object) => document.dispatchEvent(Object.assign(new Event("securitypolicyviolation"), { effectiveDirective: "frame-src", disposition: "enforce", ...init }));
    violation({ blockedURI: "https://other.test/index.html" });
    violation({ blockedURI: "https://frame.test/index.html", disposition: "report" });
    violation({ blockedURI: "https://frame.test/index.html", effectiveDirective: "img-src" });
    expect(f.session.status.get().phase).not.toBe("error");
    violation({ blockedURI: "https://frame.test/index.html" });
    expect(f.session.status.get()).toMatchObject({ phase: "error", error: { cause: { message: "the page's Content-Security-Policy blocks the frame: add https://frame.test to its frame-src (to its child-src or default-src when it has no frame-src)" } } });
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
    const [first] = await f.got("command");
    await f.send({ type: "done", call: first.call, ok: true });
    await f.send({ type: "state", session: 0, key: "drag", value: { mode: "select", available: false } });
    f.controllers().drag!.choose("pan");
    // Nothing to choose: the frame keeps selecting, and so does what is shown.
    expect(f.controllers().drag!.get()).toEqual({ mode: "select", available: false });
    const commands = await f.got("command", 2);
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
    const commands = await f.got("command", 3);
    expect(commands.map(({ target, action, args }) => [target, action, args])).toEqual([
      ["layers", "setVisible", ["WALLS", false]],
      ["pages", "goTo", [2]],
      ["layouts", "select", ["A3"]],
    ]);
    expect(selected).toBe(false);
    await f.send({ type: "done", call: commands[2].call, ok: true });
    await until(() => expect(selected).toBe(true));
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
    const commands = await f.got("command", 6);
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
    await until(() => expect(played).toBe(true));
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
    const commands = await f.got("command");
    expect(commands.map(({ target, action, args }) => [target, action, args])).toEqual([["sheets", "select", [1]]]);
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
    const [m] = await f.got("raster");
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
    await f.got("raster");
    expect(asked(f)[0]).toMatchObject({ page: 2, options: { longEdge: 300 } });
    await f.send({ type: "rastered", id: asked(f)[0].id, result: { ok: false, code: "failed" } });
    expect(await drawn).toBeNull();
  });

  it("fail with the frame's own code, or as failed for a picture that is not the one asked for", async () => {
    const f = await mount({}, "report.pdf");
    await f.send({ type: "controllers", session: 0, values: { pictures: PAGE }, statics: {} });
    const pictures = f.controllers().pictures!;
    const code = async (options: Parameters<typeof pictures.raster>[1], answer: (id: number) => unknown) => {
      const before = asked(f).length;
      const p = pictures.raster(1, options).then(
        () => "drawn",
        (e) => (e as { code: string }).code,
      );
      await f.got("raster", before + 1);
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
    const [{ id }] = await f.got("raster");
    abort.abort();
    expect(await drawn).toBe("aborted");
    await f.got("unraster");
    // Told once: a second would arrive after the first.
    await quiet();
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
    await f.got("raster", MAX_DRAWS);
    // The ninth, refused, would arrive after the eighth.
    await quiet();
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
    await f.got("raster");
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
    await f.got("raster");
    await f.send({ type: "rastered", id: asked(f)[0].id, result: { ok: false, code: "invalid" } });
    const error = await drawn;
    expect(error).toMatchObject({ name: "RasterError", code: "invalid" });
  });
});

describe("the viewport", () => {
  const VIEW = { space: "page", page: 2, region: { x: 0, y: 0.5, width: 1, height: 0.5 } };
  const told = (f: Frame) => f.received.filter((m) => m.type === "watch" || m.type === "unwatch");
  const toldTimes = (f: Frame, count: number) => until(() => expect(told(f), `${count} messages of watch or unwatch`).toHaveLength(count));

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
    await toldTimes(f, 1);
    expect(told(f)).toEqual([{ type: "watch", session: 0, key: "viewport" }]);
    const b = store.subscribe(() => {});
    await f.send({ type: "state", session: 0, key: "viewport", value: VIEW });
    expect(seen).toEqual([VIEW]);
    a();
    a();
    // One listener is left: nothing is told.
    await quiet();
    expect(told(f)).toHaveLength(1);
    b();
    await toldTimes(f, 2);
    expect(told(f)).toEqual([
      { type: "watch", session: 0, key: "viewport" },
      { type: "unwatch", session: 0, key: "viewport" },
    ]);
    // Followed again later: watched again.
    store.subscribe(() => {})();
    await toldTimes(f, 4);
    expect(told(f).map((m) => m.type)).toEqual(["watch", "unwatch", "watch", "unwatch"]);
  });

  it("is asked for once by a read with no listener, which has the last value the frame reported", async () => {
    const f = await withViewport();
    const store = f.controllers().viewport!;
    expect(store.get()).toBeNull();
    await toldTimes(f, 2);
    expect(told(f).map((m) => m.type)).toEqual(["watch", "unwatch"]);
    await f.send({ type: "state", session: 0, key: "viewport", value: VIEW });
    expect(store.get()).toEqual(VIEW);
    await toldTimes(f, 4);
    // While it is followed, a read asks for nothing more.
    const stop = store.subscribe(() => {});
    store.get();
    store.get();
    await toldTimes(f, 5);
    await quiet();
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
    await toldTimes(f, 1);
    // The first listener left with the second there: no unwatch.
    await quiet();
    expect(told(f).map((m) => m.type)).toEqual(["watch"]);
    stopSecond();
    await toldTimes(f, 2);
    expect(told(f).map((m) => m.type)).toEqual(["watch", "unwatch"]);
  });

  it("tells the frame nothing once the session has ended", async () => {
    const f = await withViewport();
    const store = f.controllers().viewport!;
    const stop = store.subscribe(() => {});
    await toldTimes(f, 1);
    f.session.destroy();
    stop();
    store.get();
    store.subscribe(() => {})();
    // Nothing more is told: a message would arrive after the first.
    await quiet();
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
    expect(await f.got("theme")).toEqual([{ type: "theme", theme: open.theme }]);
    // A frame that has ended is not restyled.
    f.session.destroy();
    viewer.restyle();
    await quiet();
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
    // The question would be asked a step after the link is handled.
    await quiet();
    expect(confirmLink).not.toHaveBeenCalled();
    await f.send({ type: "link", url: "https://example.com/a" });
    await until(() => expect(confirmLink).toHaveBeenCalledTimes(1));
    await f.send({ type: "link", url: "https://example.com/b" });
    await quiet();
    expect(confirmLink).toHaveBeenCalledTimes(1);
    expect(confirmLink.mock.calls[0]![0]).toBe("https://example.com/a");
    answer(true);
    await until(() => expect(open).toHaveBeenCalledWith("https://example.com/a", "_blank", "noopener,noreferrer"));
    await f.send({ type: "link", url: "https://example.com/c" });
    answer(false);
    await quiet();
    expect(open).toHaveBeenCalledTimes(1);
  });

  it("to an email address open the mail program after the host's question", async () => {
    const confirmLink = vi.fn(async (_url: string) => true);
    const open = vi.spyOn(window, "open").mockImplementation(() => null);
    const f = await mount({ confirmLink });
    await f.send({ type: "link", url: "mailto:someone@example.com" });
    await until(() => expect(open).toHaveBeenCalledWith("mailto:someone@example.com", "_blank", "noopener,noreferrer"));
    expect(confirmLink.mock.calls[0]![0]).toBe("mailto:someone@example.com");
  });

  it("are asked about with the file on screen, the one the last replacement showed", async () => {
    const confirmLink = vi.fn(async (_url: string, _file: ViewerFile) => false);
    const f = await mount({ confirmLink });
    const replaced = f.session.replace({ id: "f1", name: "next.dwg", source: { bytes: new Uint8Array([4, 5, 6]) } });
    const [replacement] = await f.got("replace");
    await f.send({ type: "replaced", call: replacement.call, ok: true });
    expect(await replaced).toBe(true);
    await f.send({ type: "link", url: "https://example.com/a" });
    await until(() => expect(confirmLink).toHaveBeenCalledTimes(1));
    expect(confirmLink.mock.calls[0]![1].name).toBe("next.dwg");
  });

  it("are dropped for a moment after each answer, so that a frame cannot ask again at once", async () => {
    let now = 1000;
    vi.spyOn(performance, "now").mockImplementation(() => now);
    const confirmLink = vi.fn(async (_url: string) => false);
    const f = await mount({ confirmLink });
    await f.send({ type: "link", url: "https://example.com/a" });
    await until(() => expect(confirmLink).toHaveBeenCalledTimes(1));
    await f.send({ type: "link", url: "https://example.com/b" });
    now += LINK_QUIET_MS - 1;
    await f.send({ type: "link", url: "https://example.com/c" });
    // The question would be asked a step after the link is handled.
    await quiet();
    expect(confirmLink).toHaveBeenCalledTimes(1);
    now += 1;
    await f.send({ type: "link", url: "https://example.com/d" });
    await until(() => expect(confirmLink).toHaveBeenCalledTimes(2));
    expect(confirmLink.mock.calls[1]![0]).toBe("https://example.com/d");
  });

  it("with linkQuietMs 0 are asked about again as soon as the question is answered", async () => {
    vi.spyOn(performance, "now").mockImplementation(() => 1000);
    const confirmLink = vi.fn(async (_url: string) => false);
    const f = await mount({ confirmLink, linkQuietMs: 0 });
    await f.send({ type: "link", url: "https://example.com/a" });
    await until(() => expect(confirmLink).toHaveBeenCalledTimes(1));
    await f.send({ type: "link", url: "https://example.com/b" });
    await until(() => expect(confirmLink).toHaveBeenCalledTimes(2));
  });

  it("are dropped with no question unless the user just clicked or pressed a key", async () => {
    const activation = { isActive: false };
    Object.defineProperty(navigator, "userActivation", { value: activation, configurable: true });
    try {
      const confirmLink = vi.fn(async (_url: string) => false);
      const f = await mount({ confirmLink, linkQuietMs: 0 });
      await f.send({ type: "link", url: "https://example.com/a" });
      // The question would be asked a step after the link is handled.
      await quiet();
      expect(confirmLink).not.toHaveBeenCalled();
      activation.isActive = true;
      await f.send({ type: "link", url: "https://example.com/b" });
      await until(() => expect(confirmLink).toHaveBeenCalledTimes(1));
      expect(confirmLink.mock.calls[0]![0]).toBe("https://example.com/b");
    } finally {
      Reflect.deleteProperty(navigator, "userActivation");
    }
  });

  it("with credentials in them are not asked about", async () => {
    const confirmLink = vi.fn(async (_url: string) => false);
    const f = await mount({ confirmLink });
    await f.send({ type: "link", url: "https://bank.example@evil.example/" });
    // The question would be asked a step after the link is handled.
    await quiet();
    expect(confirmLink).not.toHaveBeenCalled();
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

describe("the files around the one shown", () => {
  const files: Record<string, Uint8Array> = { "site/title.dwg": new Uint8Array([7, 8, 9]), "site/big.bin": new Uint8Array(TREE.maxFileBytes + 1) };
  const opened: string[] = [];
  const tree = (): FileTree => ({
    path: "site/plan.dwg",
    paths: ["site/plan.dwg", ...Object.keys(files), "site/gone.dwg"],
    async open(path) {
      opened.push(path);
      const bytes = files[path];
      if (!bytes) throw new Error("gone");
      return { bytes };
    },
  });
  const mountTree = () => mountWith(createSandboxedViewer({ url: "https://frame.test/index.html" }), "plan.dwg", true, { bytes: new Uint8Array([1]) }, null, tree());

  it("are listed to the frame with the file", async () => {
    const f = await mountTree();
    expect(f.received.find((m) => m.type === "open").tree).toEqual({ path: "site/plan.dwg", paths: ["site/plan.dwg", "site/title.dwg", "site/big.bin", "site/gone.dwg"] });
    const alone = await mount();
    expect("tree" in alone.received.find((m) => m.type === "open")).toBe(false);
  });

  it("are given whole when the frame asks for one it was told of, and for no other", async () => {
    opened.length = 0;
    const f = await mountTree();
    await f.send({ type: "fetch", id: 1, path: "site/title.dwg" });
    await until(() => expect([...new Uint8Array(answer(f, 1).data)]).toEqual([7, 8, 9]));
    // Not in the list, and not a path of the list in another spelling: never opened.
    await f.send({ type: "fetch", id: 2, path: "site/secret.dwg" });
    await f.send({ type: "fetch", id: 3, path: "SITE/TITLE.DWG" });
    await until(() => expect(answer(f, 2)).toEqual({ type: "bytes", id: 2, error: "refused" }));
    await until(() => expect(answer(f, 3)).toEqual({ type: "bytes", id: 3, error: "refused" }));
    expect(opened).toEqual(["site/title.dwg"]);
    // Listed and unreadable, or past the size the host reads for the frame.
    await f.send({ type: "fetch", id: 4, path: "site/gone.dwg" });
    await f.send({ type: "fetch", id: 5, path: "site/big.bin" });
    await until(() => expect(answer(f, 4)).toEqual({ type: "bytes", id: 4, error: "failed" }));
    await until(() => expect(answer(f, 5)).toEqual({ type: "bytes", id: 5, error: "refused" }));
  });

  it("are judged by the size they state before they are read, all fetches together", async () => {
    const read = vi.fn((_offset: number, _length: number) => new Promise<Uint8Array>(() => undefined));
    const half = Math.floor(TREE.maxFileBytes / 2) + 1;
    const sized: FileTree = {
      path: "a.dwg",
      paths: ["a.dwg", "huge.bin", "b.bin", "c.bin"],
      open: async (path) => ({ ranges: { size: path === "huge.bin" ? TREE.maxFileBytes + 1 : half, read } }),
    };
    const f = await mountWith(createSandboxedViewer({ url: "https://frame.test/index.html" }), "a.dwg", true, { bytes: new Uint8Array([1]) }, null, sized);
    // Past the limit: refused without a byte read.
    await f.send({ type: "fetch", id: 1, path: "huge.bin" });
    await until(() => expect(answer(f, 1)).toEqual({ type: "bytes", id: 1, error: "refused" }));
    expect(read).not.toHaveBeenCalled();
    // Within it, read; another that would take the fetches together past it, refused while the first is read.
    await f.send({ type: "fetch", id: 2, path: "b.bin" });
    await until(() => expect(read).toHaveBeenCalledTimes(1));
    await f.send({ type: "fetch", id: 3, path: "c.bin" });
    await until(() => expect(answer(f, 3)).toEqual({ type: "bytes", id: 3, error: "refused" }));
    expect(read).toHaveBeenCalledTimes(1);
  });

  it("are read up to the limit when they state no size, all fetches together, and refused past it", async () => {
    const MiB = 1024 * 1024;
    const chunk = new Uint8Array(MiB);
    const pulled: Record<string, number> = {};
    // A file at an address with no Content-Length: endless, or of `size` MiB.
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string) => {
        const name = new URL(url).pathname.slice(1);
        const size = name === "endless.bin" ? Infinity : 150;
        pulled[name] = 0;
        const body = new ReadableStream<Uint8Array>({
          async pull(c) {
            // Slow enough for two downloads to overlap.
            await tick(1);
            if (pulled[name]! >= size) return c.close();
            pulled[name]! += 1;
            c.enqueue(chunk);
          },
        });
        return new Response(body, { status: 200 });
      }),
    );
    const at: FileTree = { path: "a.dwg", paths: ["a.dwg", "endless.bin", "b.bin", "c.bin"], open: async (path) => ({ url: `https://files.test/${path}` }) };
    const f = await mountWith(createSandboxedViewer({ url: "https://frame.test/index.html" }), "a.dwg", true, { bytes: new Uint8Array([1]) }, null, at);
    await f.send({ type: "fetch", id: 1, path: "endless.bin" });
    await until(() => expect(answer(f, 1)).toEqual({ type: "bytes", id: 1, error: "refused" }));
    expect(pulled["endless.bin"]).toBeLessThan(TREE.maxFileBytes / MiB + 4);
    // Two of 150 MiB: the second passes the limit with the first's bytes.
    await f.send({ type: "fetch", id: 2, path: "b.bin" });
    await f.send({ type: "fetch", id: 3, path: "c.bin" });
    await until(() => expect([answer(f, 2), answer(f, 3)].every(Boolean)).toBe(true));
    expect([answer(f, 2), answer(f, 3)].filter((m) => m.error === "refused")).toHaveLength(1);
  });

  it("are refused to a file that has none", async () => {
    const f = await mount();
    await f.send({ type: "fetch", id: 1, path: "site/title.dwg" });
    await until(() => expect(answer(f, 1)).toEqual({ type: "bytes", id: 1, error: "refused" }));
  });

  it("are read once for an id in use, and no more once the fetch is cancelled", async () => {
    const signals: AbortSignal[] = [];
    const slow: FileTree = { path: "a.dwg", paths: ["a.dwg", "b.dwg"], open: (_p, s) => (signals.push(s), new Promise(() => undefined)) };
    const f = await mountWith(createSandboxedViewer({ url: "https://frame.test/index.html" }), "a.dwg", true, { bytes: new Uint8Array([1]) }, null, slow);
    await f.send({ type: "fetch", id: 9, path: "b.dwg" });
    await until(() => expect(signals).toHaveLength(1));
    await f.send({ type: "fetch", id: 9, path: "b.dwg" });
    // A second read of the id would start a step after it is handled.
    await quiet();
    expect(signals).toHaveLength(1);
    await f.send({ type: "cancel", id: 9 });
    expect(signals[0]!.aborted).toBe(true);
    // The ones that stay open are limited as reads are.
    for (let i = 0; i < READS.maxReads; i++) await f.send({ type: "fetch", id: 100 + i, path: "b.dwg" });
    await f.send({ type: "fetch", id: 200, path: "b.dwg" });
    await until(() => expect(answer(f, 200)).toEqual({ type: "bytes", id: 200, error: "refused" }));
  });
});

describe("a file read by ranges", () => {
  it("answers a read with a copy, so a buffer the host keeps is not taken from it", async () => {
    const kept = pattern(0, 200_000);
    // The host's own buffer for a read of all of it.
    const ranges: ByteRanges = {
      size: kept.length,
      read: async (offset, length) => (offset === 0 && length === kept.length ? kept : kept.slice(offset, offset + length)),
    };
    const f = await mount({}, "big.pdf", true, { ranges });
    await f.send({ type: "read", id: 1, generation: 0, offset: 0, length: kept.length });
    await until(() => expect(answer(f, 1)).toBeTruthy());
    expect(kept.byteLength).toBe(200_000);
  });

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
    for (const [id] of refusals) await until(() => expect(answer(f, id), String(id)).toEqual({ type: "bytes", id, error: "refused" }));
    expect(held.reads).toHaveLength(0);

    // As many bytes at once as the limit: the next is refused until one is answered.
    const big = READS.maxBytes / READS.maxLength;
    for (let i = 0; i < big; i++) await f.send({ type: "read", id: 10 + i, generation: 0, offset: (i + 1) * READS.maxLength, length: READS.maxLength });
    await until(() => expect(held.reads).toHaveLength(big));
    await f.send({ type: "read", id: 20, generation: 0, offset: 0, length: 1 });
    await until(() => expect(answer(f, 20)).toEqual({ type: "bytes", id: 20, error: "refused" }));
    held.reads[0]!.release();
    await until(() => expect(same(answer(f, 10).data, pattern(READS.maxLength, READS.maxLength))).toBe(true));
    // As many reads at once as the limit.
    for (let i = 0; i < READS.maxReads - (big - 1); i++) await f.send({ type: "read", id: 30 + i, generation: 0, offset: 1000 + i, length: 1 });
    await f.send({ type: "read", id: 40, generation: 0, offset: 0, length: 1 });
    await until(() => expect(answer(f, 40)).toEqual({ type: "bytes", id: 40, error: "refused" }));
    // An id in use is not read twice.
    await f.send({ type: "read", id: 30, generation: 0, offset: 5, length: 1 });
    // A second read would start a step after the message is handled.
    await quiet();
    expect(held.reads.filter((r) => r.offset === 5)).toHaveLength(0);

    // A cancelled read stops, and is answered.
    await f.send({ type: "cancel", id: 11 });
    expect(held.reads[1]!.signal.aborted).toBe(true);
    await until(() => expect(answer(f, 11)).toEqual({ type: "bytes", id: 11, error: "failed" }));
    // The session's end stops the rest: every read not answered yet.
    f.session.destroy();
    expect(held.reads.slice(1).every((r) => r.signal.aborted)).toBe(true);
  });

  it("is read in a browser without AbortSignal.any, and its reads still end with the session", async () => {
    const any = AbortSignal.any;
    (AbortSignal as { any?: unknown }).any = undefined;
    try {
      const held = heldRanges(100 * 1024 * 1024);
      const f = await mount({}, "big.pdf", true, { ranges: held.ranges });
      await f.send({ type: "read", id: 1, generation: 0, offset: 10, length: 5 });
      await f.send({ type: "read", id: 2, generation: 0, offset: 20, length: 5 });
      await until(() => expect(held.reads).toHaveLength(2));
      held.reads[0]!.release();
      await until(() => expect(answer(f, 1).data.byteLength).toBe(5));
      f.session.destroy();
      expect(held.reads[1]!.signal.aborted).toBe(true);
    } finally {
      AbortSignal.any = any;
    }
  });

  it("is the only file a read is answered for", async () => {
    const f = await mount();
    expect(f.received.find((m) => m.type === "open").source.kind).toBe("blob");
    await f.send({ type: "read", id: 1, generation: 0, offset: 0, length: 1 });
    await until(() => expect(answer(f, 1)).toEqual({ type: "bytes", id: 1, error: "refused" }));
  });

  it("is read for the document it names: after a replacement the old one's reads are refused, and the new one's answered from its bytes", async () => {
    const size = 100 * 1024 * 1024;
    const first = heldRanges(size);
    const second = heldRanges(size + 1);
    const f = await mount({}, "big.pdf", true, { ranges: first.ranges });
    const replacing = f.session.replace({ id: "f1", name: "big.pdf", source: { ranges: second.ranges } });
    const [message] = await f.got("replace");
    expect(message).toMatchObject({ type: "replace", generation: 1, file: { name: "big.pdf", format: "pdf" }, source: { kind: "ranges", size: size + 1 } });
    // Both alive until the frame answers: the document being replaced is still drawn from its own bytes.
    await f.send({ type: "read", id: 1, generation: 0, offset: size - 5, length: 5 });
    await f.send({ type: "read", id: 2, generation: 1, offset: size, length: 1 });
    await until(() => expect(first.reads.map((r) => r.offset)).toEqual([size - 5]));
    await until(() => expect(second.reads.map((r) => r.offset)).toEqual([size]));
    await f.send({ type: "replaced", call: message.call, ok: true });
    expect(await replacing).toBe(true);
    // Now only the new one: the old generation, and one that was never given, are refused.
    await f.send({ type: "read", id: 3, generation: 0, offset: 0, length: 1 });
    await f.send({ type: "read", id: 4, generation: 7, offset: 0, length: 1 });
    await until(() => expect(answer(f, 3)).toEqual({ type: "bytes", id: 3, error: "refused" }));
    await until(() => expect(answer(f, 4)).toEqual({ type: "bytes", id: 4, error: "refused" }));
    await f.send({ type: "read", id: 5, generation: 1, offset: size, length: 1 });
    await until(() => expect(second.reads.map((r) => r.offset)).toEqual([size, size]));
    expect(first.reads.every((r) => r.signal.aborted === false)).toBe(true);
  });
});

describe("highlights in the frame", () => {
  const box = { x: 0.1, y: 0.2, width: 0.3, height: 0.05 };
  const open = (extra: Partial<ViewerFile>) =>
    mountWith(createSandboxedViewer({ url: "https://frame.test/index.html" }), "offre.pdf", true, { bytes: new Uint8Array([1]) }, null, undefined, extra);

  it("go to the frame with the file, each with its id", async () => {
    const f = await open({ highlights: [{ text: "prix", label: "Prix" }, { id: "b", page: 2, rects: [box] }], focusHighlight: "b" });
    const message = f.received.find((m) => m.type === "open");
    expect(message.highlights).toEqual([
      { id: "0", text: "prix", label: "Prix" },
      { id: "b", page: 2, rects: [box] },
    ]);
    expect(message.focusHighlight).toBe("b");
  });

  it("are placed where the frame says, with the host's own labels, colours and quotes, never the frame's", async () => {
    const f = await open({ highlights: [{ id: "a", text: "prix", label: "Prix", color: "#ff0000" }] });
    const item = { id: "a", state: "shown", page: 3, rects: [box], label: "<img src=x>", color: "url(https://x.test/leak)", text: "not this" };
    await f.send({ type: "controllers", session: 0, values: { highlights: { items: [item], current: "a" } }, statics: {} });
    expect(f.controllers().highlights?.get()).toEqual({ items: [{ id: "a", state: "shown", page: 3, rects: [box], label: "Prix", color: "#ff0000", text: "prix" }], current: "a" });
    // A box off the page fails the message.
    await f.send({ type: "state", session: 0, key: "highlights", value: { items: [{ ...item, rects: [{ ...box, x: 2 }] }], current: null } });
    expect(f.controllers().highlights?.get().items[0]!.page).toBe(3);
  });

  it("send set and goTo to the frame, and take the labels of the list set", async () => {
    const f = await open({});
    await f.send({ type: "controllers", session: 0, values: { highlights: { items: [], current: null } }, statics: {} });
    f.controllers().highlights!.set([{ text: "délai", label: "Délai" }]);
    f.controllers().highlights!.goTo("0");
    const commands = await f.got("command", 2);
    expect(commands.map(({ target, action, args }) => [target, action, args])).toEqual([
      ["highlights", "set", [[{ id: "0", text: "délai", label: "Délai" }]]],
      ["highlights", "goTo", ["0"]],
    ]);
    await f.send({ type: "state", session: 0, key: "highlights", value: { items: [{ id: "0", state: "missing", page: null, rects: [] }], current: null } });
    expect(f.controllers().highlights?.get().items[0]).toEqual({ id: "0", state: "missing", page: null, rects: [], label: "Délai", text: "délai" });
  });
});

describe("replacing the document in the frame", () => {
  const replacements = (f: Frame) => f.received.filter((m) => m.type === "replace");
  const next = (name = "plan.dwg", bytes = [4, 5, 6]) => ({ id: "f1", name, source: { bytes: new Uint8Array(bytes) } });

  it("sends the next file, and resolves true once the frame has shown it, with the file on the session", async () => {
    const f = await mount();
    const first = f.session.file;
    const done = f.session.replace({ ...next(), type: "image/vnd.dwg" });
    const [m] = await f.got("replace");
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
    const [message] = await f.got("replace");
    await f.send({ type: "replaced", call: message.call, ok: false });
    expect(await refused).toBe(false);
    expect(f.session.file).toBe(first);
    // Another format, or no bytes: the caller starts over, and the frame is not asked.
    expect(await f.session.replace({ id: "f1", name: "report.pdf", source: { bytes: new Uint8Array(1) } })).toBe(false);
    expect(await f.session.replace({ id: "f1", name: "plan.dwg", source: null })).toBe(false);
    await quiet();
    expect(replacements(f)).toHaveLength(1);
  });

  it("is refused before the frame has the first file, and after the session ended", async () => {
    const early = await mount({}, "plan.dwg", false);
    expect(await early.session.replace(next())).toBe(false);
    const f = await mount();
    const pending = f.session.replace(next());
    await f.got("replace");
    f.session.destroy();
    expect(await pending).toBe(false);
    expect(await f.session.replace(next())).toBe(false);
  });

  it("is one at a time: a newer call supersedes one still being read, and waits for one the frame has", async () => {
    const f = await mount();
    const one = f.session.replace(next("plan.dwg", [1]));
    await f.got("replace");
    expect(replacements(f)).toHaveLength(1);
    // Two more while the first is with the frame: only the last is sent after it.
    const two = f.session.replace(next("plan.dwg", [2]));
    const three = f.session.replace(next("plan.dwg", [3]));
    // A send of either would come a step after the file is read.
    await quiet();
    expect(replacements(f)).toHaveLength(1);
    await f.send({ type: "replaced", call: replacements(f)[0].call, ok: true });
    await f.got("replace", 2);
    expect(replacements(f)).toHaveLength(2);
    await f.send({ type: "replaced", call: replacements(f)[1].call, ok: true });
    expect(await Promise.all([one, two, three])).toEqual([true, true, true]);
    expect(replacements(f).map((m) => m.generation)).toEqual([1, 2]);
  });

  it("is not sent a delivery the frame was not made for: an image first given by URL stays a URL", async () => {
    const origins = { media: ["https://media.test"] };
    // The address is asked for its first bytes.
    vi.stubGlobal("fetch", async () => new Response(new Uint8Array(4)));
    const viewer = createSandboxedViewer({ url: "https://frame.test/index.html", delivery: { images: "url" }, origins });
    const f = await mountWith(viewer, "a.png", true, { url: "https://media.test/a.png" }, readPolicy(frameCsp(undefined, origins)));
    expect(f.received.find((m) => m.type === "open").source.kind).toBe("url");
    const blob = f.session.replace({ id: "f1", name: "a.png", source: { bytes: new Uint8Array([1]) } });
    expect(await blob).toBe(false);
    await quiet();
    expect(replacements(f)).toHaveLength(0);
    const url = f.session.replace({ id: "f1", name: "a.png", source: { url: "https://media.test/b.png" } });
    await f.got("replace");
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
    vi.stubGlobal("fetch", async (url: string, init?: RequestInit) => {
      fetched.push(`${String(url)} ${new Headers(init?.headers).get("range") ?? ""}`.trim());
      return new Response(new Uint8Array([1, 2, 3]));
    });
  });
  afterEach(() => vi.unstubAllGlobals());

  it("gives the frame a video's address on a media origin, and reads anything else itself", async () => {
    const origins = { media: [MEDIA] };
    let f = await mount({ origins }, "clip.mp4", true, { url: `${MEDIA}/v/clip.mp4` }, policy(origins));
    expect(f.received.find((m) => m.type === "open").source).toEqual({ kind: "url", url: `${MEDIA}/v/clip.mp4` });
    // The page asked for nothing: a video given by its address is told by its name and type.
    expect(fetched).toEqual([]);
    expect(f.received.some((m) => m.type === "sniff")).toBe(false);
    // Another origin, a URL with `init`, an image only the frame's decoders
    // draw, an address longer than the frame takes (a long signed URL): read
    // whole by the host.
    for (const [name, source] of [
      ["clip.mp4", { url: "https://other.test/clip.mp4" }],
      ["clip.mp4", { url: `${MEDIA}/clip.mp4`, init: { headers: { authorization: "x" } } }],
      ["scan.tif", { url: `${MEDIA}/scan.tif` }],
      ["clip.mp4", { url: `${MEDIA}/clip.mp4?sig=${"s".repeat(3000)}` }],
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

describe("a file whose bytes say one format and whose name says another", () => {
  const pdf = new Uint8Array([...'%PDF-1.7\n%'].map((c) => c.charCodeAt(0)).concat([0xe2, 0xe3, 0xcf, 0xd3, 10]));
  const png = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 13, 0x49, 0x48, 0x44, 0x52, 0, 0, 0, 1]);

  it("is given to the frame as what its bytes are: a PDF named .png is a PDF", async () => {
    const f = await mount({}, "plan.png", true, { bytes: pdf });
    const open = f.received.find((m) => m.type === "open");
    expect(open).toMatchObject({ file: { name: "plan.png", format: "pdf" }, source: { kind: "ranges" } });
    expect(f.session.format).toBe("pdf");
  });

  it("starts its frame to ask what the bytes are when the name says no format the frame opens", async () => {
    const f = await mount({}, "plan.bin", true, { bytes: pdf });
    expect(f.received.find((m) => m.type === "sniff")).toMatchObject({ file: { name: "plan.bin" }, source: { kind: "head", size: pdf.length } });
    expect(f.received.find((m) => m.type === "open")).toMatchObject({ file: { name: "plan.bin", format: "pdf" } });
    expect(f.session.format).toBe("pdf");
  });

  it("takes from the frame only a format it was published for: for another, the name and the type decide", async () => {
    sniffAnswer = "pdf";
    const f = await mount({}, "plan.dwg", false);
    await f.send({ type: "ready", protocol: PROTOCOL, policy: null, formats: ["dwg"] });
    await until(() => expect(f.received.find((m) => m.type === "open")).toMatchObject({ file: { name: "plan.dwg", format: "dwg" } }));
    expect(f.session.format).toBe("dwg");
  });

  it("is judged by its bytes when it replaces the document", async () => {
    const f = await mount({}, "a.pdf", true, { bytes: pdf });
    const replacements = () => f.received.filter((m) => m.type === "replace");
    const same = f.session.replace({ id: "f1", name: "b.png", source: { bytes: pdf } });
    // The detection runs in a worker: wait for its answer, not a set time.
    await until(() => expect(replacements()[0]).toMatchObject({ file: { name: "b.png", format: "pdf" } }));
    await f.send({ type: "replaced", call: replacements()[0].call, ok: true });
    expect(await same).toBe(true);
    // A picture named .pdf is another format than the document on show.
    expect(await f.session.replace({ id: "f1", name: "c.pdf", source: { bytes: png } })).toBe(false);
    expect(replacements()).toHaveLength(1);
  });

  it("sends the frame plain options and the detection's timeout and size, to use in its own", async () => {
    const evil = JSON.parse('{"__proto__":{"x":1},"constructor":{"x":1},"pdf":{"maxZoom":3,"prototype":{"x":1}}}');
    evil.image = { maxScale: () => 1 };
    const f = await mount({ options: evil, sniffTimeoutMs: 0, sniffBytes: 4096 }, "a.pdf", true, { bytes: pdf });
    const options = f.received.find((m) => m.type === "open").options;
    expect(options).toEqual({
      pdf: { maxZoom: 3 },
      image: {},
      sniff: { timeoutMs: 0, bytes: 4096 },
      limits: { maxExtractedBytes: 512 * 1024 * 1024, maxMembers: 20_000, maxCompressionRatio: 1000 },
    });
    expect(Object.hasOwn(options, "__proto__") || Object.hasOwn(options, "constructor")).toBe(false);
  });

  it("asks the frame within sniffTimeoutMs, the name and the type deciding past it, and runs no detection of its own", async () => {
    sniffAnswer = "silent";
    // Long enough that a stalled process does not pass it before the check
    // that no `open` came yet.
    const f = await mount({ sniffTimeoutMs: 200 }, "plan.png", true, { bytes: pdf });
    expect(f.received.find((m) => m.type === "sniff").sniff).toEqual({ timeoutMs: 200, bytes: 65536 });
    expect(f.received.some((m) => m.type === "open")).toBe(false);
    await until(() => expect(f.received.find((m) => m.type === "open")).toMatchObject({ file: { name: "plan.png", format: "image" } }));
    expect(createSniffer).not.toHaveBeenCalled();
  });
});
