/** What the office viewers give for pictures and the viewport, over fake engines and a fake second document. */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { Raster, RasterOptions, RenderContext } from "../core/types.js";
import { docx, xlsx, csv, pptx, rtf, xls } from "./index.js";
import type { Current, Exporter, SheetExporter } from "./export.js";
import type { Grid } from "./raster.js";

type Options = Record<string, unknown>;
const viewers: { engine: string; options: Options; canvas?: HTMLElement }[] = [];

/** What the fake second document was asked. */
const exported = {
  rasters: [] as { kind: string; page: number; options: RasterOptions; current: Current }[],
  disposed: [] as string[],
  measured: [] as number[],
  sources: [] as (() => Promise<ArrayBuffer>)[],
  grid: null as Grid | null,
  /** Measures wait for it: a test holds them to have one in flight. */
  gate: Promise.resolve() as Promise<void>,
};

vi.mock("./export.js", () => {
  const make = (kind: string, load: () => Promise<ArrayBuffer>): Exporter => {
    exported.sources.push(load);
    return {
      raster: async (page, options, current) => {
        exported.rasters.push({ kind, page, options, current });
        return { bitmap: {} as ImageBitmap, width: 1, height: 1, page, space: "page" } as Raster;
      },
      dispose: async () => void exported.disposed.push(kind),
    };
  };
  return {
    docxExporter: (load: () => Promise<ArrayBuffer>) => make("docx", load),
    pptxExporter: (load: () => Promise<ArrayBuffer>) => make("pptx", load),
    sheetExporter: (load: () => Promise<ArrayBuffer>): SheetExporter => ({
      ...make("sheet", load),
      measure: async (page, fn) => {
        exported.measured.push(page);
        await exported.gate;
        return fn(exported.grid!);
      },
    }),
  };
});

vi.mock("@silurus/ooxml/docx", () => ({
  DocxScrollViewer: class {
    constructor(_root: HTMLElement, options: Options) {
      viewers.push({ engine: "docx", options });
    }
    async load() {}
    getScale() {
      return 1;
    }
    destroy() {}
  },
}));
vi.mock("@silurus/ooxml/pptx", () => ({
  PptxViewer: class {
    constructor(canvas: HTMLElement, options: Options) {
      viewers.push({ engine: "pptx", options, canvas });
    }
    async load() {}
    async fitPage() {}
    getScale() {
      return 1;
    }
    destroy() {}
  },
}));
let sheetNames = ["Quote", "Notes"];
let current = 0;
let corner: { x: number; y: number } | null = { x: 50, y: 22 };
vi.mock("@silurus/ooxml/xlsx", () => ({
  XlsxSheetViewer: class {
    sheetNames = sheetNames;
    get sheetIndex() {
      return current;
    }
    constructor(_canvas: HTMLElement, options: Options) {
      viewers.push({ engine: "xlsx", options });
    }
    async load() {}
    getScale() {
      return 1;
    }
    getCellViewportRect() {
      return corner && { ...corner, width: 100, height: 20 };
    }
    async goToSheet() {}
    destroy() {}
  },
}));

beforeEach(() => {
  vi.stubGlobal("ResizeObserver", class { observe() {} disconnect() {} });
  vi.spyOn(console, "warn").mockImplementation(() => {});
  exported.grid = { header: { width: 50, height: 22 }, cols: 2, rows: 2, colEdge: (c) => (c - 1) * 100, rowEdge: (r) => (r - 1) * 20 };
  current = 0;
  corner = { x: 50, y: 22 };
  // A canvas of 300 x 200 CSS px in the viewer.
  Object.defineProperty(HTMLCanvasElement.prototype, "clientWidth", { configurable: true, get: () => 300 });
  Object.defineProperty(HTMLCanvasElement.prototype, "clientHeight", { configurable: true, get: () => 200 });
});
afterEach(() => {
  // A session left open keeps watching, into the next test.
  for (const m of open.splice(0)) m.destroy();
  delete (HTMLCanvasElement.prototype as { clientWidth?: number }).clientWidth;
  delete (HTMLCanvasElement.prototype as { clientHeight?: number }).clientHeight;
  viewers.length = 0;
  Object.assign(exported, { rasters: [], disposed: [], measured: [], sources: [], gate: Promise.resolve() });
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

const open: { destroy(): void }[] = [];

async function mount(plugin: ReturnType<typeof docx>, bytes = new Uint8Array([1, 2, 3])) {
  const host = document.createElement("div");
  document.body.append(host);
  const ctx = { options: {}, source: { bytes: async () => bytes }, signal: new AbortController().signal, status: () => {} } as unknown as RenderContext<Record<string, never>>;
  const renderer = await plugin.load();
  const mounted = await renderer.mount(host, ctx as never);
  open.push(mounted);
  return { host, mounted };
}

describe("what the office plugins offer", () => {
  it("lists pictures and viewport for every format that draws, converted ones included", () => {
    for (const p of [docx(), xlsx(), pptx(), csv(), xls(), rtf({ converter: "exav" })]) {
      expect(p.capabilities, p.id).toEqual(expect.arrayContaining(["pictures", "viewport"]));
    }
  });
});

const rectOf = (r: [number, number, number, number]) => () => ({ left: r[0], top: r[1], width: r[2], height: r[3], right: r[0] + r[2], bottom: r[1] + r[3], x: r[0], y: r[1] }) as DOMRect;
const later = (ms = 60) => new Promise((r) => setTimeout(r, ms));

describe("a Word document", () => {
  /** The scroll viewer's DOM as the engine lays it out: one page in a 600 x 400 scroller; `measured` counts the boxes read. */
  function laidOut(host: HTMLElement) {
    const root = host.querySelector<HTMLElement>(".exav-viewer-office")!;
    const scroller = document.createElement("div");
    scroller.getBoundingClientRect = rectOf([0, 0, 600, 400]);
    Object.defineProperty(scroller, "clientWidth", { value: 600 });
    Object.defineProperty(scroller, "clientHeight", { value: 400 });
    const slot = document.createElement("div");
    const layer = document.createElement("div");
    layer.dataset.overlay = "text";
    layer.dataset.pageIndex = "0";
    const measured = vi.fn(rectOf([0, -100, 600, 1000]));
    layer.getBoundingClientRect = measured;
    slot.append(layer);
    scroller.append(slot);
    root.append(scroller);
    return { root, measured };
  }
  const seen = { space: "page", page: 1, region: { x: 0, y: 0.1, width: 1, height: 0.4 } };

  it("measures no view in a session that does not use the viewport", async () => {
    const { mounted, host } = await mount(docx());
    const { root, measured } = laidOut(host);
    (viewers[0]!.options.onVisiblePageChange as (a: number, b: number, c: boolean) => void)(0, 2, true);
    (viewers[0]!.options.onScaleChange as (s: number) => void)(1.5);
    root.dispatchEvent(new Event("scroll"));
    await later();
    expect(measured).not.toHaveBeenCalled();
    expect(mounted.controllers.pictures!.get().count).toBe(2);
  });

  it("measures the view while the viewport is followed, and stops when the last listener leaves", async () => {
    const { mounted, host } = await mount(docx());
    const { root, measured } = laidOut(host);
    const store = mounted.controllers.viewport!;
    const stop = store.subscribe(() => {});
    expect(store.get()).toEqual(seen);
    const after = measured.mock.calls.length;
    expect(after).toBeGreaterThan(0);
    root.dispatchEvent(new Event("scroll"));
    await vi.waitFor(() => expect(measured.mock.calls.length).toBeGreaterThan(after));
    stop();
    await later();
    const stopped = measured.mock.calls.length;
    root.dispatchEvent(new Event("scroll"));
    (viewers[0]!.options.onVisiblePageChange as (a: number, b: number, c: boolean) => void)(0, 2, true);
    await later();
    expect(measured.mock.calls.length).toBe(stopped);
  });

  it("measures the view once for a read with no listener, which has the current view", async () => {
    const { mounted, host } = await mount(docx());
    const { measured } = laidOut(host);
    const store = mounted.controllers.viewport!;
    expect(store.get()).toEqual(seen);
    const once = measured.mock.calls.length;
    expect(once).toBeGreaterThan(0);
    expect(store.get()).toEqual(seen);
    expect(measured.mock.calls.length).toBe(2 * once);
  });

  it("has pictures and a viewport, the page count following the pages the viewer lays out", async () => {
    const { mounted } = await mount(docx());
    const c = mounted.controllers;
    expect(c.pictures!.get()).toEqual({ count: 0, space: "page" });
    (viewers[0]!.options.onVisiblePageChange as (a: number, b: number, c: boolean) => void)(0, 3, true);
    expect(c.pictures!.get()).toEqual({ count: 3, space: "page" });
    expect(c.viewport!.get()).toBeNull();
    // Nothing of the second document is opened by mounting, or by asking its count.
    expect(exported.rasters).toEqual([]);
  });

  it("draws through the second document, handing it the viewer's view for region current", async () => {
    const { mounted } = await mount(docx());
    (viewers[0]!.options.onVisiblePageChange as (a: number, b: number, c: boolean) => void)(0, 2, true);
    await mounted.controllers.pictures!.raster(2, { width: 100, region: "current" });
    const call = exported.rasters[0]!;
    expect([call.kind, call.page, call.options.width]).toEqual(["docx", 2, 100]);
    // No page laid out in this DOM: nothing in view.
    expect(call.current(2, null)).toBeNull();
  });

  it("refuses a page the document has not", async () => {
    const { mounted } = await mount(docx());
    await expect(mounted.controllers.pictures!.raster(1, { width: 10 })).rejects.toMatchObject({ code: "invalid" });
    expect(exported.rasters).toEqual([]);
  });

  it("gives the second document the same bytes, fresh each time", async () => {
    const { mounted } = await mount(docx());
    const [a, b] = [await exported.sources[0]!(), await exported.sources[0]!()];
    expect(a).not.toBe(b);
    expect(new Uint8Array(a).length).toBeGreaterThan(0);
    mounted.destroy();
  });

  it("closes the second document with the session", async () => {
    const { mounted } = await mount(docx());
    mounted.destroy();
    expect(exported.disposed).toEqual(["docx"]);
  });
});

describe("a deck", () => {
  it("counts slides from the viewer and says the slide shown whole", async () => {
    const { mounted, host } = await mount(pptx());
    const stage = host.querySelector(".exav-viewer-office-stage") as HTMLElement;
    const slide = viewers[0]!.canvas!;
    const rect = (r: [number, number, number, number]) => () => ({ left: r[0], top: r[1], width: r[2], height: r[3], right: r[0] + r[2], bottom: r[1] + r[3], x: r[0], y: r[1] }) as DOMRect;
    stage.getBoundingClientRect = rect([0, 0, 800, 600]);
    slide.getBoundingClientRect = rect([100, 0, 600, 600]);
    (viewers[0]!.options.onSlideChange as (i: number, n: number) => void)(1, 5);
    expect(mounted.controllers.pictures!.get()).toEqual({ count: 5, space: "page" });
    await vi.waitFor(() => expect(mounted.controllers.viewport!.get()).toEqual({ space: "page", page: 2, region: { x: 0, y: 0, width: 1, height: 1 } }));
  });

  /** A deck whose stage and slide count the times they are measured. */
  async function measuredDeck() {
    const { mounted, host } = await mount(pptx());
    const stage = host.querySelector(".exav-viewer-office-stage") as HTMLElement;
    const measured = vi.fn(rectOf([0, 0, 800, 600]));
    stage.getBoundingClientRect = measured;
    viewers[0]!.canvas!.getBoundingClientRect = rectOf([100, 0, 600, 600]);
    const change = (slide: number) => (viewers[0]!.options.onSlideChange as (i: number, n: number) => void)(slide, 5);
    return { mounted, measured, change };
  }

  it("measures no view in a session that does not use the viewport", async () => {
    const { mounted, measured, change } = await measuredDeck();
    change(1);
    change(2);
    await later();
    expect(measured).not.toHaveBeenCalled();
    expect(mounted.controllers.pictures!.get().count).toBe(5);
  });

  it("measures the view while the viewport is followed, and stops when the last listener leaves", async () => {
    const { mounted, measured, change } = await measuredDeck();
    const store = mounted.controllers.viewport!;
    const seen: unknown[] = [];
    change(1);
    const stop = store.subscribe((v) => seen.push(v));
    expect(measured).toHaveBeenCalled();
    change(2);
    await vi.waitFor(() => expect(seen).toEqual([{ space: "page", page: 3, region: { x: 0, y: 0, width: 1, height: 1 } }]));
    stop();
    await later();
    const stopped = measured.mock.calls.length;
    change(3);
    await later();
    expect(measured.mock.calls.length).toBe(stopped);
    expect(seen).toHaveLength(1);
  });

  it("measures the view for a read with no listener, which has the current slide", async () => {
    const { mounted, change } = await measuredDeck();
    change(3);
    expect(mounted.controllers.viewport!.get()).toEqual({ space: "page", page: 4, region: { x: 0, y: 0, width: 1, height: 1 } });
    change(0);
    expect(mounted.controllers.viewport!.get()?.page).toBe(1);
  });
});

describe("a spreadsheet", () => {
  it("counts its sheets, hidden ones included, as the sheets controller lists them", async () => {
    sheetNames = ["Quote", "Notes", "Hidden"];
    const { mounted } = await mount(xlsx());
    expect(mounted.controllers.sheets!.get().items).toHaveLength(3);
    expect(mounted.controllers.pictures!.get()).toEqual({ count: 3, space: "page" });
    sheetNames = ["Quote", "Notes"];
  });

  it("measures its viewport only once someone asks for it, then keeps it up to date", async () => {
    const { mounted } = await mount(xlsx());
    await new Promise((r) => setTimeout(r, 50));
    expect(exported.measured).toEqual([]);
    const seen = vi.fn();
    mounted.controllers.viewport!.subscribe(seen);
    await vi.waitFor(() => expect(exported.measured).toEqual([1]));
    await vi.waitFor(() => expect(mounted.controllers.viewport!.get()?.page).toBe(1));
    // The viewer scrolls.
    corner = { x: -50, y: 22 };
    (viewers[0]!.options.onViewportChange as () => void)();
    await vi.waitFor(() => expect(exported.measured.length).toBeGreaterThan(1));
  });

  it("measures nothing in a session that does not use the viewport", async () => {
    const { mounted } = await mount(xlsx());
    (viewers[0]!.options.onViewportChange as () => void)();
    (viewers[0]!.options.onScaleChange as (s: number) => void)(2);
    (viewers[0]!.options.onSheetChange as (i: number) => void)(1);
    await later();
    expect(exported.measured).toEqual([]);
    expect(mounted.controllers.sheets!.get().current).toBe(1);
  });

  it("stops measuring when the last listener leaves, and starts again with the next", async () => {
    const { mounted } = await mount(xlsx());
    const store = mounted.controllers.viewport!;
    const a = store.subscribe(() => {});
    const b = store.subscribe(() => {});
    await vi.waitFor(() => expect(exported.measured).toEqual([1]));
    const scroll = () => (viewers[0]!.options.onViewportChange as () => void)();
    a();
    scroll();
    await vi.waitFor(() => expect(exported.measured).toEqual([1, 1]));
    b();
    await later();
    scroll();
    (viewers[0]!.options.onScaleChange as (s: number) => void)(2);
    await later();
    expect(exported.measured).toEqual([1, 1]);
    store.subscribe(() => {});
    await vi.waitFor(() => expect(exported.measured).toEqual([1, 1, 1]));
  });

  it("does not measure again for a change that came while it measured, once the last listener has left", async () => {
    let release = () => {};
    exported.gate = new Promise<void>((resolve) => (release = resolve));
    const { mounted } = await mount(xlsx());
    const stop = mounted.controllers.viewport!.subscribe(() => {});
    await vi.waitFor(() => expect(exported.measured).toEqual([1]));
    // The viewer scrolls while the measure is out: one more is due.
    (viewers[0]!.options.onViewportChange as () => void)();
    await later();
    stop();
    release();
    await later();
    expect(exported.measured).toEqual([1]);
  });

  it("measures for a read with no listener, which has the last measure, without following the viewer", async () => {
    const { mounted } = await mount(xlsx());
    const store = mounted.controllers.viewport!;
    const x = () => (store.get()!.region as { x: number }).x;
    expect(store.get()).toBeNull();
    await later();
    expect(exported.measured).toEqual([1]);
    const before = x();
    await later();
    expect(exported.measured).toEqual([1, 1]);
    // The viewer scrolls: not followed, so the next read has the old view and starts the measure of the new one.
    corner = { x: -50, y: 22 };
    (viewers[0]!.options.onViewportChange as () => void)();
    await later();
    expect(exported.measured).toEqual([1, 1]);
    expect(x()).toBe(before);
    await later();
    expect(x()).toBeGreaterThan(before);
    expect(exported.measured).toEqual([1, 1, 1, 1]);
  });

  it("is the sheet shown, by its number", async () => {
    const { mounted } = await mount(xlsx());
    current = 1;
    (viewers[0]!.options.onSheetChange as (i: number) => void)(1);
    mounted.controllers.viewport!.subscribe(() => {});
    await vi.waitFor(() => expect(exported.measured).toContain(2));
    await vi.waitFor(() => expect(mounted.controllers.viewport!.get()?.page).toBe(2));
  });

  it("draws region current only for the sheet shown", async () => {
    const { mounted } = await mount(xlsx());
    await mounted.controllers.pictures!.raster(1, { width: 10, region: "current" });
    const { current: view } = exported.rasters[0]!;
    expect(view(1, exported.grid)).toEqual({ x: 0, y: 0, width: 1, height: 1 });
    expect(view(2, exported.grid)).toBeNull();
  });

  it("closes the second document with the session, and stops measuring", async () => {
    const { mounted } = await mount(xlsx());
    mounted.controllers.viewport!.subscribe(() => {});
    await vi.waitFor(() => expect(exported.measured.length).toBe(1));
    mounted.destroy();
    expect(exported.disposed).toEqual(["sheet"]);
    const before = exported.measured.length;
    (viewers[0]!.options.onViewportChange as () => void)();
    await new Promise((r) => setTimeout(r, 50));
    expect(exported.measured.length).toBe(before);
  });
});

describe("a CSV", () => {
  it("has one sheet, drawn from its table as a workbook", async () => {
    const { mounted } = await mount(csv(), new TextEncoder().encode("a;b\n1;2\n"));
    expect(mounted.controllers.pictures!.get()).toEqual({ count: 1, space: "page" });
    const workbook = new Uint8Array(await exported.sources[0]!());
    // A ZIP: the second copy is a workbook made of the table.
    expect([...workbook.slice(0, 4)]).toEqual([0x50, 0x4b, 0x03, 0x04]);
    expect(mounted.controllers.sheets).toBeUndefined();
  });
});
