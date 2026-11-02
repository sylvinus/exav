import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { RasterError } from "../core/pictures.js";
import type { RasterOptions } from "../core/types.js";
import { FakeBitmap, FakeCanvas, stubCanvas } from "../test/fake-canvas.js";
import {
  cellName,
  ENGINE_PIXELS,
  engineError,
  indexAt,
  lazy,
  pageInView,
  rasterPage,
  rasterSheet,
  sameRegion,
  serial,
  sheetView,
  sheetWindow,
  usedArea,
  visibleRegion,
  type Grid,
  type PageEngine,
  type SheetEngine,
} from "./raster.js";

beforeEach(stubCanvas);
afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

const code = async (p: Promise<unknown>) => p.then(() => "none", (e) => (e instanceof RasterError ? e.code : `other: ${String(e)}`));

/** A page 200 by 100 (units), drawn at any width. */
function pages() {
  const drawn: FakeBitmap[] = [];
  const widths: number[] = [];
  const engine: PageEngine = {
    size: () => ({ width: 200, height: 100 }),
    async draw(_page, width) {
      widths.push(width);
      const b = new FakeBitmap(width, Math.round(width / 2));
      drawn.push(b);
      return b as unknown as ImageBitmap;
    },
  };
  return { engine, drawn, widths };
}

describe("a page drawn as a picture", () => {
  it("is the whole page at the width asked, on white", async () => {
    const { engine, drawn, widths } = pages();
    const r = await rasterPage(engine, 1, { width: 400 }, null);
    expect(widths).toEqual([400]);
    expect([r.width, r.height, r.space, r.page]).toEqual([400, 200, "page", 1]);
    expect(r.region).toEqual({ x: 0, y: 0, width: 1, height: 1 });
    const out = FakeCanvas.made[0]!;
    expect(out.fills).toEqual([["#ffffff", 0, 0, 400, 200]]);
    expect(out.draws).toEqual([[drawn[0], -0, -0]]);
    // The whole-page bitmap is closed once copied.
    expect(drawn[0]!.closed).toBe(true);
  });

  it("draws a region from the page drawn at the scale the region needs", async () => {
    const { engine, widths } = pages();
    // The right half, 300 px wide: the page at 600.
    const r = await rasterPage(engine, 1, { width: 300, region: { x: 0.5, y: 0.25, width: 0.5, height: 0.5 } }, null);
    expect(widths).toEqual([600]);
    expect([r.width, r.height]).toEqual([300, 150]);
    expect(FakeCanvas.made[0]!.draws[0]!.slice(1)).toEqual([-300, -75]);
    expect(r.region).toEqual({ x: 0.5, y: 0.25, width: 0.5, height: 0.5 });
  });

  it("reports the region drawn, to the pixel", async () => {
    const { engine } = pages();
    // A third of the width is 133.33 px of a 400 px page: cut at whole pixels.
    const r = await rasterPage(engine, 1, { width: 100, region: { x: 1 / 3, y: 0, width: 0.25, height: 0.25 } }, null);
    expect(r.region).toEqual({ x: 133 / 400, y: 0, width: 100 / 400, height: 50 / 200 });
  });

  it("widens the region to the shape asked (contain) or narrows it (cover), the page shape being 2:1", async () => {
    const { engine } = pages();
    const contain = await rasterPage(engine, 1, { width: 100, height: 100 }, null);
    expect(contain.region).toMatchObject({ x: 0, width: 1 });
    expect((contain.region as { y: number }).y).toBeCloseTo(-0.5);
    expect((contain.region as { height: number }).height).toBeCloseTo(2);
    const cover = await rasterPage(engine, 1, { width: 100, height: 100, fit: "cover" }, null);
    expect(cover.region).toMatchObject({ y: 0, height: 1 });
    expect((cover.region as { width: number }).width).toBeCloseTo(0.5);
  });

  it("shows the background beyond the page and nothing else of it", async () => {
    const { engine } = pages();
    await rasterPage(engine, 1, { width: 100, height: 100, background: "#336699" }, null);
    const out = FakeCanvas.made[0]!;
    expect(out.fills[0]).toEqual(["#336699", 0, 0, 100, 100]);
    // Contain: the page 100 px wide sits in the middle, 25 px down.
    expect(out.draws[0]!.slice(1)).toEqual([-0, 25]);
  });

  it("refuses a transparent ground, as its pages are paper", async () => {
    const { engine, widths } = pages();
    expect(await code(rasterPage(engine, 1, { width: 100, background: "transparent" }, null))).toBe("unsupported");
    expect(widths).toEqual([]);
  });

  it("refuses, before drawing, a region whose whole page is past what the engine draws", async () => {
    const { engine, widths } = pages();
    // The page would be drawn at 40000 px wide.
    expect(await code(rasterPage(engine, 1, { width: 400, region: { x: 0, y: 0, width: 0.01, height: 0.01 } }, null))).toBe("too-large");
    expect(widths).toEqual([]);
    const limit = Math.floor(Math.sqrt(ENGINE_PIXELS * 2));
    expect(await code(rasterPage(engine, 1, { width: limit + 100 }, null))).toBe("too-large");
    expect(widths).toEqual([]);
    expect(await code(rasterPage(engine, 1, { width: limit - 100 }, null))).toBe("none");
  });

  it("refuses a bitmap the engine quietly drew smaller, and closes it", async () => {
    const small = new FakeBitmap(300, 150);
    const engine: PageEngine = { size: () => ({ width: 200, height: 100 }), draw: async () => small as unknown as ImageBitmap };
    expect(await code(rasterPage(engine, 1, { width: 400 }, null))).toBe("too-large");
    expect(small.closed).toBe(true);
    expect(FakeCanvas.made).toHaveLength(0);
  });

  it("draws what the viewport says for region current, and refuses when nothing is in view", async () => {
    const { engine, widths } = pages();
    const r = await rasterPage(engine, 1, { width: 100, region: "current" }, { x: 0, y: 0.5, width: 1, height: 0.5 });
    expect(widths).toEqual([100]);
    expect(r.region).toEqual({ x: 0, y: 0.5, width: 1, height: 0.5 });
    expect(await code(rasterPage(engine, 1, { width: 100, region: "current" }, null))).toBe("invalid");
  });

  it("frees the whole-page bitmap and the picture's canvas when the copy fails", async () => {
    const { engine, drawn } = pages();
    vi.spyOn(FakeCanvas.prototype, "transferToImageBitmap").mockImplementation(() => {
      throw new Error("no memory");
    });
    await expect(rasterPage(engine, 1, { width: 100 }, null)).rejects.toThrow("no memory");
    expect(drawn[0]!.closed).toBe(true);
    expect([FakeCanvas.made[0]!.width, FakeCanvas.made[0]!.height]).toEqual([0, 0]);
  });

  it("validates before drawing", async () => {
    const { engine, widths } = pages();
    for (const options of [{}, { width: -1 }, { longEdge: 10, width: 10 }, { width: 10, fit: "stretch" }, { width: 10, background: "url(x)" }] as RasterOptions[]) {
      expect(await code(rasterPage(engine, 1, options, null))).toBe("invalid");
    }
    expect(widths).toEqual([]);
  });
});

describe("the queue", () => {
  const gate = () => {
    let open!: () => void;
    const promise = new Promise<void>((r) => (open = r));
    return { promise, open };
  };

  it("runs tasks one at a time, in order", async () => {
    const run = serial();
    const log: string[] = [];
    const g = gate();
    const a = run(async () => {
      log.push("a start");
      await g.promise;
      log.push("a end");
      return 1;
    });
    const b = run(async () => {
      log.push("b");
      return 2;
    });
    await Promise.resolve();
    expect(log).toEqual(["a start"]);
    g.open();
    expect(await Promise.all([a, b])).toEqual([1, 2]);
    expect(log).toEqual(["a start", "a end", "b"]);
  });

  it("never starts a task whose signal aborted while it waited", async () => {
    const run = serial();
    const g = gate();
    const first = run(() => g.promise.then(() => 1));
    const abort = new AbortController();
    const task = vi.fn(async () => 2);
    const second = run(task, abort.signal);
    abort.abort();
    expect(await code(second)).toBe("aborted");
    g.open();
    await first;
    expect(task).not.toHaveBeenCalled();
  });

  it("rejects at once when a running task is aborted, frees its late result, and keeps the next waiting for it", async () => {
    const run = serial();
    const g = gate();
    const abort = new AbortController();
    const disposed: number[] = [];
    const running = run(async () => (await g.promise, 7), abort.signal, (v) => disposed.push(v));
    await Promise.resolve();
    const next = vi.fn(async () => 8);
    const after = run(next);
    abort.abort();
    expect(await code(running)).toBe("aborted");
    // The abandoned drawing is still going: the next one has not started.
    await Promise.resolve();
    expect(next).not.toHaveBeenCalled();
    g.open();
    expect(await after).toBe(8);
    expect(disposed).toEqual([7]);
  });

  it("rejects at once for a signal already aborted, without running anything", async () => {
    const run = serial();
    const task = vi.fn(async () => 1);
    const abort = new AbortController();
    abort.abort();
    expect(await code(run(task, abort.signal))).toBe("aborted");
    expect(task).not.toHaveBeenCalled();
  });

  it("carries on after a task fails", async () => {
    const run = serial();
    await expect(run(async () => Promise.reject(new Error("boom")))).rejects.toThrow("boom");
    expect(await run(async () => 3)).toBe(3);
  });
});

describe("the second document", () => {
  it("is opened once, on first use, and closed with the session", async () => {
    const open = vi.fn(async () => ({ id: 1 }));
    const close = vi.fn();
    const doc = lazy(open, close);
    expect(open).not.toHaveBeenCalled();
    expect(doc.started).toBe(false);
    const [a, b] = await Promise.all([doc.get(), doc.get()]);
    expect(a).toBe(b);
    expect(open).toHaveBeenCalledTimes(1);
    await doc.dispose();
    expect(close).toHaveBeenCalledWith({ id: 1 });
    expect(await code(doc.get())).toBe("failed");
  });

  it("is opened again after a failed open", async () => {
    const open = vi.fn().mockRejectedValueOnce(new Error("bad")).mockResolvedValueOnce("ok");
    const doc = lazy(open, () => {});
    await expect(doc.get()).rejects.toThrow("bad");
    expect(await doc.get()).toBe("ok");
  });

  it("is closed when the session ends while it is still opening, and not otherwise", async () => {
    let finish!: (v: string) => void;
    const close = vi.fn();
    const doc = lazy(() => new Promise<string>((r) => (finish = r)), close);
    const got = doc.get();
    const ended = doc.dispose();
    finish("late");
    await ended;
    await got;
    expect(close).toHaveBeenCalledWith("late");
    // Nothing to close for a document never opened.
    const unused = lazy(async () => "x", close);
    await unused.dispose();
    expect(close).toHaveBeenCalledTimes(1);
  });
});

describe("what an engine throws", () => {
  it("is too-large for its resource limits, the message kept", () => {
    const limit = Object.assign(new Error("archive entries 5000 > 4096"), { name: "OoxmlResourceLimitError" });
    const e = engineError(limit) as RasterError;
    expect([e.code, e.message]).toEqual(["too-large", "archive entries 5000 > 4096"]);
    expect((engineError(Object.assign(new Error("x"), { name: "OoxmlDecodedImageLimitError" })) as RasterError).code).toBe("too-large");
    const other = new Error("other");
    expect(engineError(other)).toBe(other);
  });
});

describe("what is in view", () => {
  const box = (left: number, top: number, width: number, height: number) => ({ left, top, width, height });

  it("is the part of a box inside the view, as fractions of the box", () => {
    expect(visibleRegion(box(0, -100, 200, 400), box(0, 0, 200, 150))).toEqual({ x: 0, y: 0.25, width: 1, height: 0.375 });
    expect(visibleRegion(box(50, 0, 100, 100), box(0, 0, 100, 100))).toEqual({ x: 0, y: 0, width: 0.5, height: 1 });
    expect(visibleRegion(box(0, 200, 100, 100), box(0, 0, 100, 100))).toBeNull();
    expect(visibleRegion(box(0, 0, 0, 100), box(0, 0, 100, 100))).toBeNull();
  });

  it("is the page with the most of it showing, the first on a tie", () => {
    const view = box(0, 0, 100, 100);
    // Page 0 shows 20 of 100 high, page 1 shows 80.
    const boxes = [
      { index: 0, box: box(0, -80, 100, 100) },
      { index: 1, box: box(0, 20, 100, 100) },
    ];
    expect(pageInView(boxes, view)).toEqual({ index: 1, region: { x: 0, y: 0, width: 1, height: 0.8 } });
    const tie = [
      { index: 4, box: box(0, -50, 100, 100) },
      { index: 5, box: box(0, 50, 100, 100) },
    ];
    expect(pageInView(tie, view)!.index).toBe(4);
    expect(pageInView([{ index: 0, box: box(0, 500, 100, 100) }], view)).toBeNull();
  });

  it("compares regions to a ten-thousandth", () => {
    const r = { x: 0.1, y: 0.2, width: 0.3, height: 0.4 };
    expect(sameRegion(r, { ...r, x: 0.10005 })).toBe(true);
    expect(sameRegion(r, { ...r, x: 0.1002 })).toBe(false);
    expect(sameRegion(undefined, r)).toBe(false);
  });
});

/** Columns of 100, 50 and a hidden one, then 100; rows of 20 and a hidden one. The headers are 50 by 22. */
const grid = (): Grid => {
  const widths = [100, 50, 0, 100];
  const heights = [20, 20, 0, 20];
  const edges = (sizes: number[]) => (n: number) => sizes.slice(0, n - 1).reduce((a, b) => a + b, 0);
  return { header: { width: 50, height: 22 }, cols: 4, rows: 4, colEdge: edges(widths), rowEdge: edges(heights) };
};

describe("a sheet's cells", () => {
  it("finds the cell holding a position, the visible one after hidden ones", () => {
    const g = grid();
    expect([0, 99.9, 100, 149, 150, 249.9].map((p) => indexAt(g.colEdge, g.cols, p))).toEqual([1, 1, 2, 2, 4, 4]);
    expect(indexAt(g.colEdge, g.cols, -5)).toBe(1);
  });

  it("is the page's size from the used area, hidden columns taking none", () => {
    const g = grid();
    expect([g.colEdge(5), g.rowEdge(5)]).toEqual([250, 60]);
  });

  it("works out the cells a region covers, and how far into the first one it starts", () => {
    const g = grid();
    // x 110..230 of 250, y 10..50 of 60.
    const w = sheetWindow(g, { x: 110 / 250, y: 10 / 60, width: 120 / 250, height: 40 / 60 })!;
    // The hidden column and row are in the window: they take no room.
    expect(w).toMatchObject({ col: 2, cols: 3, row: 1, rows: 4 });
    expect(w.offsetX).toBeCloseTo(10);
    expect(w.offsetY).toBeCloseTo(10);
    expect([w.x0, w.x1]).toEqual([110, 230].map((v) => expect.closeTo(v, 6)));
  });

  it("ends a window on a cell edge in the cell before it", () => {
    const w = sheetWindow(grid(), { x: 0, y: 0, width: 100 / 250, height: 20 / 60 })!;
    expect([w.col, w.cols, w.row, w.rows]).toEqual([1, 1, 1, 1]);
  });

  it("cuts a region reaching past the page to the page, and is null when none of it is on it", () => {
    const g = grid();
    const w = sheetWindow(g, { x: -0.5, y: 0.5, width: 2, height: 2 })!;
    expect([w.x0, w.x1, w.y0, w.y1]).toEqual([0, 250, 30, 60]);
    expect(sheetWindow(g, { x: 1, y: 0, width: 1, height: 1 })).toBeNull();
    expect(sheetWindow(g, { x: -2, y: 0, width: 1, height: 1 })).toBeNull();
  });

  it("names cells", () => {
    expect([cellName(1, 1), cellName(26, 5), cellName(27, 1), cellName(702, 9), cellName(703, 2), cellName(16384, 1)]).toEqual(["A1", "Z5", "AA1", "ZZ9", "AAA2", "XFD1"]);
  });

  it("takes the used area from values, styles, merges and anchors, at least A1", () => {
    expect(usedArea({ rows: [] })).toEqual({ rows: 1, cols: 1 });
    const cell = (col: number, type = "text", styleIndex?: number) => ({ col, value: { type }, ...(styleIndex !== undefined && { styleIndex }) });
    expect(usedArea({ rows: [{ index: 3, cells: [cell(2)] }, { index: 7, cells: [cell(9, "empty")] }, { index: 5, cells: [cell(4, "number")] }] })).toEqual({ rows: 5, cols: 4 });
    // An empty cell with a style (a fill) is drawn.
    expect(usedArea({ rows: [{ index: 6, cells: [cell(3, "empty", 2)] }] })).toEqual({ rows: 6, cols: 3 });
    expect(usedArea({ rows: [], mergeCells: [{ bottom: 8, right: 5 }], anchors: [{ toRow: 11, toCol: 6 }] })).toEqual({ rows: 12, cols: 7 });
    expect(usedArea({ rows: [{ index: 5_000_000, cells: [cell(99_999)] }] })).toEqual({ rows: 1_048_576, cols: 16_384 });
  });
});

/** A sheet engine over `grid()`: each drawing is a bitmap of the size asked. */
function sheets() {
  const drawn: { page: number; window: unknown; size: { width: number; height: number; scale: number }; bitmap: FakeBitmap }[] = [];
  const engine: SheetEngine = {
    measure: async (_page, fn) => fn(grid()),
    async draw(page, window, size) {
      const bitmap = new FakeBitmap(size.width, size.height);
      drawn.push({ page, window, size, bitmap });
      return bitmap as unknown as ImageBitmap;
    },
  };
  return { engine, drawn };
}

describe("a sheet drawn as a picture", () => {
  it("is the used area, without the headers, at the scale of the width asked", async () => {
    const { engine, drawn } = sheets();
    const r = await rasterSheet(engine, 1, { width: 500 }, () => null);
    // 250 x 60 at 100 %: twice that.
    expect([r.width, r.height]).toEqual([500, 120]);
    expect(drawn[0]!.size).toEqual({ width: 100 + 500, height: 44 + 120, scale: 2 });
    expect(drawn[0]!.window).toMatchObject({ row: 1, col: 1, rows: 4, cols: 4, offsetX: 0, offsetY: 0 });
    const out = FakeCanvas.made[0]!;
    expect(out.fills[0]).toEqual(["#ffffff", 0, 0, 500, 120]);
    expect(out.draws[0]!.slice(1)).toEqual([100, 44, 500, 120, 0, 0, 500, 120]);
    expect(r.region).toEqual({ x: 0, y: 0, width: 1, height: 1 });
    expect(drawn[0]!.bitmap.closed).toBe(true);
  });

  it("draws a region as the cells it covers, scrolled to its start", async () => {
    const { engine, drawn } = sheets();
    // x 110..230, y 10..50: 120 x 40 at 100 %, drawn 3 times as large.
    await rasterSheet(engine, 1, { width: 360, region: { x: 110 / 250, y: 10 / 60, width: 120 / 250, height: 40 / 60 } }, () => null);
    expect(drawn[0]!.window).toMatchObject({ row: 1, col: 2, rows: 4, cols: 3 });
    expect((drawn[0]!.window as { offsetX: number }).offsetX).toBeCloseTo(10);
    expect(drawn[0]!.size).toEqual({ width: 50 * 3 + 360, height: 22 * 3 + 120, scale: 3 });
  });

  it("leaves the background where the region is off the used area, and draws nothing when all of it is", async () => {
    const { engine, drawn } = sheets();
    await rasterSheet(engine, 1, { width: 250, region: { x: 0.5, y: 0, width: 1, height: 1 }, background: "#eeeeee" }, () => null);
    const out = FakeCanvas.made[0]!;
    expect(out.fills[0]![0]).toBe("#eeeeee");
    // Half the picture is cells: the left 125 px of the 250.
    expect(out.draws[0]!.slice(5)).toEqual([0, 0, 125, 60]);
    await rasterSheet(engine, 1, { width: 100, region: { x: 3, y: 3, width: 1, height: 1 } }, () => null);
    expect(drawn).toHaveLength(1);
    expect(FakeCanvas.made[1]!.draws).toEqual([]);
  });

  it("draws at the smallest scale the engine does and scales down below it, the region unchanged", async () => {
    const { engine, drawn } = sheets();
    const r = await rasterSheet(engine, 1, { width: 50 }, () => null);
    expect(drawn[0]!.size.scale).toBe(0.5);
    expect(drawn[0]!.size).toEqual({ width: 25 + 125, height: 11 + 30, scale: 0.5 });
    // 125 x 30 drawn into 50 x 12.
    expect(FakeCanvas.made[0]!.draws[0]!.slice(1)).toEqual([25, 11, 125, 30, 0, 0, 50, 12]);
    expect(FakeCanvas.made[0]!.imageSmoothingQuality).toBe("high");
    expect(r.region).toEqual({ x: 0, y: 0, width: 1, height: 1 });
  });

  it("refuses a transparent ground before drawing", async () => {
    const { engine, drawn } = sheets();
    expect(await code(rasterSheet(engine, 1, { width: 100, background: "transparent" }, () => null))).toBe("unsupported");
    expect(drawn).toHaveLength(0);
  });

  it("refuses what the engine would draw smaller, before drawing", async () => {
    const { engine, drawn } = sheets();
    expect(await code(rasterSheet(engine, 1, { width: 16000, height: 4000 }, () => null))).toBe("too-large");
    expect(drawn).toHaveLength(0);
  });

  it("refuses a bitmap the engine drew at another size, and closes it", async () => {
    const small = new FakeBitmap(10, 10);
    const engine: SheetEngine = { measure: async (_p, fn) => fn(grid()), draw: async () => small as unknown as ImageBitmap };
    expect(await code(rasterSheet(engine, 1, { width: 500 }, () => null))).toBe("too-large");
    expect(small.closed).toBe(true);
    expect([FakeCanvas.made[0]!.width, FakeCanvas.made[0]!.height]).toEqual([0, 0]);
  });

  it("takes region current from the viewer, with the grid it is measured against", async () => {
    const { engine, drawn } = sheets();
    const seen: Grid[] = [];
    await rasterSheet(engine, 1, { width: 100, region: "current" }, (g) => (seen.push(g), { x: 0, y: 0, width: 0.4, height: 1 }));
    expect(seen).toHaveLength(1);
    expect(drawn[0]!.window).toMatchObject({ col: 1, cols: 1 });
    expect(await code(rasterSheet(engine, 1, { width: 100, region: "current" }, () => null))).toBe("invalid");
  });

  it("says where the viewer is in the page", () => {
    const g = grid();
    // At 100 %, scrolled 30 px right and 10 down, in a 150 x 80 canvas: the cells in view are x 30..130, y 10..68, cut to the page's 60.
    const v = sheetView(g, { x: 50 - 30, y: 22 - 10 }, 1, { width: 150, height: 80 })!;
    expect(v.x).toBeCloseTo(30 / 250);
    expect(v.width).toBeCloseTo(100 / 250);
    expect(v.y).toBeCloseTo(10 / 60);
    expect(v.height).toBeCloseTo(50 / 60);
    // Zoomed 2x, nothing scrolled, a 250 x 144 canvas shows 75 x 50 of the page.
    const z = sheetView(g, { x: 100, y: 44 }, 2, { width: 250, height: 144 })!;
    expect(z).toEqual({ x: 0, y: 0, width: expect.closeTo(75 / 250, 6), height: expect.closeTo(50 / 60, 6) });
    // Scrolled past the used area: none of it shows.
    expect(sheetView(g, { x: -400, y: 22 }, 1, { width: 150, height: 80 })).toBeNull();
    expect(sheetView(g, { x: 0, y: 0 }, 0, { width: 1, height: 1 })).toBeNull();
  });
});
