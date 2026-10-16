import { afterEach, beforeAll, expect, it, vi } from "vitest";

import type { Controllers, RenderContext, Status } from "../core/types.js";
import { decodeInWorker as decode } from "./decode.js";
import type { ImageOptions } from "./index.js";
import { renderer } from "./renderer.js";

// The WebAssembly decoder runs in a worker: its answers are the test's.
vi.mock("./decode.js", () => ({ decodeInWorker: vi.fn(), toCanvas: vi.fn() }));
const decodeInWorker = vi.mocked(decode);

beforeAll(() => {
  globalThis.ResizeObserver ??= class {
    observe() {}
    unobserve() {}
    disconnect() {}
  };
});
afterEach(() => vi.unstubAllGlobals());

/** Every `<img>` made loads at once, its size read off its address: "wide" is 40 by 30, "tall" 30 by 40. */
function stubImages() {
  vi.stubGlobal("Image", function () {
    const img = document.createElement("img");
    let src = "";
    Object.defineProperty(img, "naturalWidth", { get: () => (src.includes("tall") ? 30 : 40) });
    Object.defineProperty(img, "naturalHeight", { get: () => (src.includes("tall") ? 40 : 30) });
    Object.defineProperty(img, "src", {
      get: () => src,
      set: (value: string) => {
        src = value;
        if (value) queueMicrotask(() => img.onload?.(new Event("load")));
      },
    });
    return img;
  });
}

it("shows the next document of the session in place of the first, keeping the zoom while the shape stays, and gives the host's overlay and detail the new file", async () => {
  stubImages();
  const events: string[] = [];
  const options: ImageOptions<{ marks: string }> = {
    overlay: (file) => ({
      mount: () => {
        events.push(`overlay ${file.meta?.marks}`);
        return { destroy: () => events.push(`overlay gone ${file.meta?.marks}`) };
      },
    }),
    detail: (file) => {
      events.push(`detail ${file.meta?.marks}`);
      return async () => null;
    },
  };
  const source = (url: string) => ({ url: async () => url }) as unknown as RenderContext["source"];
  const file = (url: string, marks: string) => ({ id: "a", name: url, source: { url }, meta: { marks } });
  const host = document.createElement("div");
  const signal = new AbortController().signal;
  const handle = await renderer.mount(host, {
    options,
    file: file("wide-1.png", "one"),
    source: source("wide-1.png"),
    signal,
    status() {},
    controllers() {},
  } as unknown as RenderContext<ImageOptions>);
  const root = host.querySelector<HTMLElement>(".exav-viewer-image")!;
  Object.defineProperty(root, "clientWidth", { value: 200 });
  Object.defineProperty(root, "clientHeight", { value: 200 });
  handle.resize!();
  const surface = handle.controllers.image!;
  handle.controllers.zoom!.setScale(3, { x: 20, y: 20 });
  const first = host.querySelector(".exav-viewer-image-picture");

  await handle.replace!({ file: file("wide-2.png", "two"), source: source("wide-2.png"), signal });
  const second = host.querySelector<HTMLImageElement>(".exav-viewer-image-picture")!;
  expect(second).not.toBe(first);
  expect(second.src).toBe("wide-2.png");
  expect(host.querySelectorAll(".exav-viewer-image-picture")).toHaveLength(1);
  expect(surface.get().scale).toBe(3);
  expect(events).toEqual(["detail one", "overlay one", "detail two", "overlay gone one", "overlay two"]);

  // A picture of another shape is fitted.
  await handle.replace!({ file: file("tall-3.png", "three"), source: source("tall-3.png"), signal });
  expect(surface.get().scale).toBe(1);
  handle.destroy();
});

it("leaves the picture as it was when the next one cannot be read", async () => {
  stubImages();
  const host = document.createElement("div");
  const signal = new AbortController().signal;
  const source = (url: string) => ({ url: async () => url }) as unknown as RenderContext["source"];
  const handle = await renderer.mount(host, {
    options: {},
    file: { id: "a", name: "a", source: { url: "wide-1.png" } },
    source: source("wide-1.png"),
    signal,
    status() {},
    controllers() {},
  } as unknown as RenderContext<ImageOptions>);
  const shown = host.querySelector(".exav-viewer-image-picture");
  const gone = new AbortController();
  gone.abort();
  await expect(handle.replace!({ file: { id: "a", name: "b", source: { url: "wide-2.png" } }, source: source("wide-2.png"), signal: gone.signal })).rejects.toThrow();
  expect(host.querySelector(".exav-viewer-image-picture")).toBe(shown);
  handle.destroy();
});

// A plugin that shows an image in a nested session follows the controllers
// from the status: they have to be there by the time it says "ready".
it("publishes its controllers before it says ready", async () => {
  // A real element, loaded as soon as it has an address.
  vi.stubGlobal("Image", function () {
    const img = document.createElement("img");
    Object.defineProperty(img, "naturalWidth", { value: 40 });
    Object.defineProperty(img, "naturalHeight", { value: 30 });
    Object.defineProperty(img, "src", {
      get: () => "",
      set: (value: string) => {
        if (value) queueMicrotask(() => img.onload?.(new Event("load")));
      },
    });
    return img;
  });
  const events: string[] = [];
  let published: Controllers | null = null;
  const ctx = {
    options: {},
    file: { id: "a", name: "a.png", source: { url: "a.png" } },
    source: { url: async () => "a.png" },
    signal: new AbortController().signal,
    status: (s: Status) => events.push(`status:${s.phase}`),
    controllers: (c: Controllers) => {
      published = c;
      events.push("controllers");
    },
  } as unknown as RenderContext<ImageOptions>;
  const host = document.createElement("div");
  const handle = await renderer.mount(host, ctx);
  expect(events).toEqual(["status:loading", "controllers", "status:ready"]);
  expect(Object.keys(published ?? {}).sort()).toEqual(["image", "pictures", "viewport", "zoom"]);
  expect(published!.pictures!.get()).toEqual({ count: 1, space: "pixels" });
  // One page: no other is drawn.
  expect(await published!.pictures!.render(2, 100)).toBeNull();
  await expect(published!.pictures!.raster(2, { longEdge: 100 })).rejects.toMatchObject({ code: "invalid" });
  handle.destroy();
});

/** A file the browser does not draw, so that exav-render's decoder is asked, and answers with `reason`. */
async function mountUndrawable(reason: string) {
  vi.stubGlobal("Image", function () {
    const img = document.createElement("img");
    Object.defineProperty(img, "src", {
      get: () => "",
      set: (value: string) => {
        if (value) queueMicrotask(() => img.onerror?.(new Event("error")));
      },
    });
    return img;
  });
  decodeInWorker.mockRejectedValue(new Error(reason));
  const statuses: Status[] = [];
  const ctx = {
    options: { wasmDecoders: true },
    file: { id: "a", name: "IMG_0001.CR3", source: { url: "a.cr3" } },
    source: { url: async () => "a.cr3", bytes: async () => new Uint8Array([1, 2, 3]) },
    signal: new AbortController().signal,
    status: (s: Status) => statuses.push(s),
    controllers() {},
  } as unknown as RenderContext<ImageOptions>;
  try {
    return { statuses, handle: await renderer.mount(document.createElement("div"), ctx), error: undefined };
  } catch (error) {
    return { statuses, handle: undefined, error };
  }
}

it("says a camera RAW file with no preview holds none, in a status of its own", async () => {
  const { statuses, handle } = await mountUndrawable("no-preview");
  expect(handle).toBeDefined();
  expect(statuses).toEqual([{ phase: "loading" }, { phase: "error", error: { code: "image_no_preview", cause: expect.any(Error) } }]);
});

it("leaves every other decoder failure to the viewer's own error for an image", async () => {
  for (const reason of ["undecodable", "too-large", "unsupported"]) {
    const { statuses, error } = await mountUndrawable(reason);
    expect(error, reason).toEqual(new Error(reason));
    expect(statuses, reason).toEqual([{ phase: "loading" }]);
  }
});
