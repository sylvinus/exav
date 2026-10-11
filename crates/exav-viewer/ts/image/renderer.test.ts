import { afterEach, beforeAll, expect, it, vi } from "vitest";

import type { Controllers, RenderContext, Status } from "../core/types.js";
import type { ImageOptions } from "./index.js";
import { renderer } from "./renderer.js";

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
  const root = host.querySelector<HTMLElement>(".exv-image")!;
  Object.defineProperty(root, "clientWidth", { value: 200 });
  Object.defineProperty(root, "clientHeight", { value: 200 });
  handle.resize!();
  const surface = handle.controllers.image!;
  handle.controllers.zoom!.setScale(3, { x: 20, y: 20 });
  const first = host.querySelector(".exv-image-picture");

  await handle.replace!({ file: file("wide-2.png", "two"), source: source("wide-2.png"), signal });
  const second = host.querySelector<HTMLImageElement>(".exv-image-picture")!;
  expect(second).not.toBe(first);
  expect(second.src).toBe("wide-2.png");
  expect(host.querySelectorAll(".exv-image-picture")).toHaveLength(1);
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
  const shown = host.querySelector(".exv-image-picture");
  const gone = new AbortController();
  gone.abort();
  await expect(handle.replace!({ file: { id: "a", name: "b", source: { url: "wide-2.png" } }, source: source("wide-2.png"), signal: gone.signal })).rejects.toThrow();
  expect(host.querySelector(".exv-image-picture")).toBe(shown);
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
  expect(Object.keys(published ?? {}).sort()).toEqual(["image", "zoom"]);
  handle.destroy();
});
