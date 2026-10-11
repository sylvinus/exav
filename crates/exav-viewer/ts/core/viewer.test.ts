import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { canOpenInTab, createSourceReader } from "./source.js";
import type { FormatPlugin, RenderContext, RendererHandle, Status } from "./types.js";
import { createViewer } from "./viewer.js";

const tick = () => new Promise((r) => setTimeout(r, 0));

/** A plugin whose engine records what happened to it. */
function fakePlugin(id = "fake", over: Partial<FormatPlugin> = {}) {
  const log: string[] = [];
  let ctx: RenderContext | null = null;
  const plugin: FormatPlugin = {
    id,
    match: { extensions: [`.${id}`] },
    capabilities: [],
    options: {},
    load: async () => ({
      mount(host: HTMLElement, c: RenderContext): RendererHandle {
        ctx = c;
        log.push(`mount ${c.file.id}`);
        host.textContent = c.file.id;
        c.status({ phase: "ready" });
        return { controllers: {}, destroy: () => log.push(`destroy ${c.file.id}`) };
      },
    }),
    ...over,
  };
  return { plugin, log, ctx: () => ctx };
}

let created: string[];
let revoked: string[];
beforeEach(() => {
  created = [];
  revoked = [];
  // jsdom has no object URLs.
  URL.createObjectURL = vi.fn(() => {
    const u = `blob:test/${created.length}`;
    created.push(u);
    return u;
  });
  URL.revokeObjectURL = vi.fn((u: string) => void revoked.push(u));
});
afterEach(() => vi.restoreAllMocks());

describe("a session", () => {
  it("renders the file, and frees the engine, the signal and its object URLs when it ends", async () => {
    const f = fakePlugin();
    const viewer = createViewer({ plugins: [f.plugin] });
    const host = document.createElement("div");
    const s = viewer.mount(host, { id: "a", name: "a.fake", source: { bytes: new Uint8Array([1, 2]) } });
    await tick();
    expect(s.format).toBe("fake");
    expect(s.status.get()).toEqual({ phase: "ready" });
    expect(host.textContent).toBe("a");
    const url = await f.ctx()!.source.url();
    expect(url).toBe(created[0]);
    s.destroy();
    expect(f.log).toEqual(["mount a", "destroy a"]);
    expect(f.ctx()!.signal.aborted).toBe(true);
    expect(revoked).toEqual([url]);
    // A second destroy is harmless.
    s.destroy();
    expect(f.log).toEqual(["mount a", "destroy a"]);
  });

  it("closing before the engine has mounted frees it as soon as it does, and logs nothing", async () => {
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    const f = fakePlugin();
    const slow = { ...f.plugin, load: async () => (await gate, f.plugin.load()) };
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const s = createViewer({ plugins: [slow] }).mount(document.createElement("div"), {
      id: "a",
      name: "a.fake",
      source: { bytes: new Uint8Array() },
    });
    s.destroy();
    release();
    await tick();
    await tick();
    expect(f.log).toEqual([]);
    expect(warn).not.toHaveBeenCalled();
  });

  it("forgets an engine that failed to load, so the next file tries again", async () => {
    let calls = 0;
    const f = fakePlugin();
    const flaky: FormatPlugin = {
      ...f.plugin,
      load: () => (++calls === 1 ? Promise.reject(new Error("offline")) : f.plugin.load()),
    };
    vi.spyOn(console, "warn").mockImplementation(() => {});
    const viewer = createViewer({ plugins: [flaky] });
    const first = viewer.mount(document.createElement("div"), { id: "a", name: "a.fake", source: { bytes: new Uint8Array() } });
    await tick();
    // A host plugin's error is a file's, not a PDF's.
    expect(first.status.get()).toMatchObject({ phase: "error", error: { code: "file" } });
    const second = viewer.mount(document.createElement("div"), { id: "b", name: "b.fake", source: { bytes: new Uint8Array() } });
    await tick();
    expect(second.status.get()).toEqual({ phase: "ready" });
    expect(calls).toBe(2);
  });

  it("reports an engine error under its format's code, and logs it", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const broken: FormatPlugin = {
      id: "dwg",
      match: {},
      capabilities: [],
      options: {},
      load: async () => ({
        mount() {
          throw new Error("bad drawing");
        },
      }),
    };
    const s = createViewer({ plugins: [broken] }).mount(document.createElement("div"), {
      id: "a",
      name: "a",
      format: "dwg",
      source: { bytes: new Uint8Array() },
    });
    await tick();
    expect((s.status.get() as Extract<Status, { phase: "error" }>).error.code).toBe("drawing");
    expect(warn).toHaveBeenCalledWith("dwg: could not render", expect.any(Error));
  });

  it("mounts nothing for a file with no source yet, and errors for one nothing opens", async () => {
    const f = fakePlugin();
    const viewer = createViewer({ plugins: [f.plugin] });
    const pending = viewer.mount(document.createElement("div"), { id: "a", name: "a.fake", source: null, placeholder: { state: "pending" } });
    await tick();
    expect(f.log).toEqual([]);
    expect(pending.status.get()).toEqual({ phase: "loading" });
    const unknown = viewer.mount(document.createElement("div"), { id: "b", name: "b.zzz", source: { bytes: new Uint8Array() } });
    expect(unknown.format).toBeNull();
    expect(unknown.status.get().phase).toBe("error");
  });

  it("ends the nested sessions with their parent", async () => {
    const f = fakePlugin();
    const viewer = createViewer({ plugins: [f.plugin] });
    const outer = viewer.mount(document.createElement("div"), { id: "zip", name: "a.fake", source: { bytes: new Uint8Array() } });
    await tick();
    f.ctx()!.mountNested(document.createElement("div"), { id: "zip:0", name: "m.fake", source: { bytes: new Uint8Array() } });
    await tick();
    outer.destroy();
    expect(f.log).toContain("destroy zip:0");
  });
});

describe("replacing a session's document", () => {
  /** An engine that can show another document, and says what it was given. */
  function replaceable(fail?: () => boolean) {
    const log: string[] = [];
    const seen: { file: string; aborted: () => boolean; url: () => Promise<string> }[] = [];
    let first: RenderContext | null = null;
    const plugin: FormatPlugin = {
      id: "fake",
      match: { extensions: [".fake"] },
      capabilities: [],
      options: {},
      load: async () => ({
        mount(_host: HTMLElement, c: RenderContext): RendererHandle {
          first = c;
          c.status({ phase: "ready" });
          return {
            controllers: {},
            async replace(next) {
              log.push(`replace ${next.file.name}`);
              seen.push({ file: next.file.name, aborted: () => next.signal.aborted, url: () => next.source.url() });
              if (fail?.()) throw new Error("unreadable");
            },
            destroy: () => log.push("destroy"),
          };
        },
      }),
    };
    return { plugin, log, seen, first: () => first! };
  }
  const file = (id: string, bytes = [1]) => ({ id: "doc", name: `${id}.fake`, source: { bytes: new Uint8Array(bytes) } });

  it("hands the next document to the engine, which keeps its own state, and frees the old one's reads", async () => {
    const r = replaceable();
    const s = createViewer({ plugins: [r.plugin] }).mount(document.createElement("div"), file("one"));
    await tick();
    const old = await r.first().source.url();
    expect(await s.replace(file("two", [2]))).toBe(true);
    expect(r.log).toEqual(["replace two.fake"]);
    expect(s.file.name).toBe("two.fake");
    // The engine was not remounted, the first document's object URL is revoked, the second's is live.
    expect(revoked).toEqual([old]);
    expect(r.seen[0]!.aborted()).toBe(false);
    expect(r.first().signal.aborted).toBe(true);
    const fresh = await r.seen[0]!.url();
    s.destroy();
    expect(revoked).toEqual([old, fresh]);
  });

  it("says false when the engine cannot, or has not mounted, and changes nothing", async () => {
    const f = fakePlugin();
    const s = createViewer({ plugins: [f.plugin] }).mount(document.createElement("div"), file("one"));
    // Not mounted yet.
    expect(await s.replace(file("two"))).toBe(false);
    await tick();
    expect(await s.replace(file("two"))).toBe(false);
    expect(s.file.name).toBe("one.fake");
    expect(f.log).toEqual(["mount doc"]);
    // Nor with nothing to show.
    const r = replaceable();
    const t = createViewer({ plugins: [r.plugin] }).mount(document.createElement("div"), file("one"));
    await tick();
    expect(await t.replace({ id: "doc", name: "x.fake", source: null })).toBe(false);
  });

  it("keeps the old document under an error status when the new one cannot be shown", async () => {
    vi.spyOn(console, "warn").mockImplementation(() => {});
    let bad = true;
    const r = replaceable(() => bad);
    const s = createViewer({ plugins: [r.plugin] }).mount(document.createElement("div"), file("one"));
    await tick();
    expect(await s.replace(file("two"))).toBe(true);
    expect(s.status.get().phase).toBe("error");
    expect(s.file.name).toBe("one.fake");
    bad = false;
    expect(await s.replace(file("three"))).toBe(true);
    expect(s.file.name).toBe("three.fake");
  });

  it("lets a newer replacement supersede one still being shown", async () => {
    let release: () => void = () => {};
    const gate = new Promise<void>((r) => (release = r));
    const seen: string[] = [];
    const plugin: FormatPlugin = {
      id: "fake",
      match: { extensions: [".fake"] },
      capabilities: [],
      options: {},
      load: async () => ({
        mount(_h: HTMLElement, c: RenderContext): RendererHandle {
          c.status({ phase: "ready" });
          return {
            controllers: {},
            async replace(next) {
              if (next.file.name === "slow.fake") await gate;
              seen.push(`${next.file.name}${next.signal.aborted ? " (superseded)" : ""}`);
            },
            destroy() {},
          };
        },
      }),
    };
    const s = createViewer({ plugins: [plugin] }).mount(document.createElement("div"), file("one"));
    await tick();
    const slow = s.replace(file("slow"));
    await tick();
    const fast = s.replace(file("fast"));
    release();
    expect(await Promise.all([slow, fast])).toEqual([true, true]);
    expect(seen).toEqual(["fast.fake", "slow.fake (superseded)"]);
    expect(s.file.name).toBe("fast.fake");
  });
});

describe("a plugin that shows another file", () => {
  const inner: FormatPlugin = {
    id: "inner",
    match: { extensions: [".inner"] },
    capabilities: [],
    options: {},
    load: async () => ({
      async mount(_h: HTMLElement, c: RenderContext): Promise<RendererHandle> {
        c.status({ phase: "converting", progress: 0.5 });
        const zoom = { get: () => ({ scale: 1, min: 1, max: 2 }), subscribe: () => () => {}, setScale() {}, fit() {} };
        c.controllers({ zoom });
        await tick();
        c.status({ phase: "ready" });
        return { controllers: { zoom }, destroy() {} };
      },
    }),
  };
  const wrapper = (forward: boolean): FormatPlugin => ({
    id: "wrap",
    match: { extensions: [".wrap"] },
    capabilities: [],
    options: {},
    load: async () => ({
      async mount(host: HTMLElement, c: RenderContext): Promise<RendererHandle> {
        const s = c.mountNested(host, { id: "w:1", name: "m.inner", source: { bytes: new Uint8Array([1]) } }, forward ? { forward: true } : undefined);
        return { controllers: {}, destroy: () => s.destroy() };
      },
    }),
  });

  it("with forward, takes its status and controllers from the nested session as they change", async () => {
    const s = createViewer({ plugins: [wrapper(true), inner] }).mount(document.createElement("div"), { id: "w", name: "a.wrap", source: { bytes: new Uint8Array([1]) } });
    await tick();
    expect(s.status.get()).toEqual({ phase: "converting", progress: 0.5 });
    expect(Object.keys(s.controllers.get())).toEqual(["zoom"]);
    await tick();
    await tick();
    expect(s.status.get()).toEqual({ phase: "ready" });
    // Its own empty controllers do not clear the nested ones.
    expect(Object.keys(s.controllers.get())).toEqual(["zoom"]);
  });

  it("without it, wires nothing", async () => {
    const s = createViewer({ plugins: [wrapper(false), inner] }).mount(document.createElement("div"), { id: "w", name: "a.wrap", source: { bytes: new Uint8Array([1]) } });
    await tick();
    await tick();
    await tick();
    expect(s.status.get()).toEqual({ phase: "loading" });
    expect(s.controllers.get()).toEqual({});
  });
});

describe("a source", () => {
  it("is downloaded once whatever is asked of it, and reports its progress", async () => {
    const body = new Uint8Array([1, 2, 3, 4, 5]);
    const fetcher = vi.fn(async () => new Response(body, { headers: { "content-length": "5" } }));
    vi.stubGlobal("fetch", fetcher);
    const r = createSourceReader({ url: "https://example.test/f" }, new AbortController().signal);
    const [a, b] = await Promise.all([r.bytes(), r.blob()]);
    expect([...a]).toEqual([1, 2, 3, 4, 5]);
    expect(b.size).toBe(5);
    expect(await r.url()).toBe("https://example.test/f");
    expect(fetcher).toHaveBeenCalledTimes(1);
    expect(r.progress.get()).toEqual({ loaded: 5, total: 5 });
    vi.unstubAllGlobals();
  });

  it("fails on an HTTP error rather than handing an error page to an engine", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response("<!doctype html>", { status: 404 })));
    const r = createSourceReader({ url: "/missing.pdf" }, new AbortController().signal);
    await expect(r.bytes()).rejects.toThrow("HTTP 404");
    vi.unstubAllGlobals();
  });

  it("read by ranges is read whole, once, in pieces, for an engine that needs it all", async () => {
    const size = 9 * 1024 * 1024 + 3;
    const asked: [number, number][] = [];
    const read = vi.fn(async (offset: number, length: number) => {
      asked.push([offset, length]);
      return new Uint8Array(Math.min(length, size - offset)).fill(offset >> 20);
    });
    const r = createSourceReader({ ranges: { size, read } }, new AbortController().signal);
    const [a, b] = await Promise.all([r.bytes(), r.blob()]);
    expect(a.length).toBe(size);
    expect([a[0], a[4 * 1024 * 1024], a[size - 1]]).toEqual([0, 4, 8]);
    expect(b.size).toBe(size);
    expect(asked).toEqual([
      [0, 4 * 1024 * 1024],
      [4 * 1024 * 1024, 4 * 1024 * 1024],
      [8 * 1024 * 1024, 1024 * 1024 + 3],
    ]);
    expect(r.progress.get()).toEqual({ loaded: size, total: size });
  });

  it("resolves a URL signed at open time only once", async () => {
    const resolve = vi.fn(async () => new Uint8Array([9]));
    const r = createSourceReader({ resolve }, new AbortController().signal);
    await r.bytes();
    await r.blob();
    expect(resolve).toHaveBeenCalledTimes(1);
  });
});

describe("what a second tab can be given", () => {
  it("a tab for anything with an address of its own", () => {
    expect(canOpenInTab("https://storage.example/bucket/x.pdf?sig=1")).toBe(true);
    expect(canOpenInTab("/media/documents/x.png")).toBe(true);
  });

  it("none for a URL that dies with this page, or no URL", () => {
    expect(canOpenInTab("blob:http://localhost:5180/2b6f")).toBe(false);
    expect(canOpenInTab("data:image/png;base64,iVBORw0KGgo=")).toBe(false);
    expect(canOpenInTab(null)).toBe(false);
    expect(canOpenInTab(undefined)).toBe(false);
    expect(canOpenInTab("")).toBe(false);
  });

  it("none for a scheme that runs or renders in the page's origin, however it is spelled", () => {
    for (const url of ["javascript:alert(1)", "JavaScript:alert(1)", " javascript:alert(1)", "java\tscript:alert(1)", "BLOB:http://localhost/x", " data:text/html,<p>", "vbscript:x", "file:///etc/passwd"]) {
      expect(canOpenInTab(url), url).toBe(false);
    }
    expect(canOpenInTab("HTTPS://storage.example/x.pdf")).toBe(true);
  });
});

describe("prefetch", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("fetches a format's assets once, and again after one of them failed", async () => {
    const asked: string[] = [];
    let missing = "/a/2";
    vi.stubGlobal("fetch", (u: string) => {
      asked.push(u);
      return Promise.resolve(new Response(u === missing ? null : "x", { status: u === missing ? 404 : 200 }));
    });
    const f = fakePlugin("fake", { prefetch: async () => ["/a/1", "/a/2", "/a/3"] });
    const viewer = createViewer({ plugins: [f.plugin] });

    await viewer.prefetch(["fake"]);
    expect(asked).toEqual(["/a/1", "/a/2", "/a/3"]);
    // A 404 is a failure: the next call fetches again.
    missing = "";
    await viewer.prefetch(["fake"]);
    expect(asked).toHaveLength(6);
    // Once everything arrived, it is done.
    await viewer.prefetch(["fake"]);
    expect(asked).toHaveLength(6);
  });
});
