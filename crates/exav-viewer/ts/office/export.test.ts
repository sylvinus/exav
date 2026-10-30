/** The second document the pictures are drawn from, over fake engines. */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { RasterError } from "../core/pictures.js";
import { FakeBitmap, FakeCanvas, stubCanvas } from "../test/fake-canvas.js";
import { docxExporter, pptxExporter, sheetExporter } from "./export.js";

/** What the fake engines saw. */
const seen = {
  loads: [] as { source: unknown; options: unknown }[],
  destroyed: [] as string[],
  draws: [] as { engine: string; args: unknown[] }[],
  inFlight: 0,
  mostInFlight: 0,
  bitmaps: [] as FakeBitmap[],
  /** Holds the next drawing until released. */
  hold: null as null | Promise<void>,
  /** Holds the document's opening until released. */
  holdLoad: null as null | Promise<void>,
  failure: null as null | Error,
  layout: [] as string[],
};

async function drawn(engine: string, args: unknown[], width: number, height: number) {
  seen.draws.push({ engine, args });
  seen.inFlight++;
  seen.mostInFlight = Math.max(seen.mostInFlight, seen.inFlight);
  try {
    if (seen.hold) await seen.hold;
    if (seen.failure) throw seen.failure;
    const b = new FakeBitmap(width, height);
    seen.bitmaps.push(b);
    return b as unknown as ImageBitmap;
  } finally {
    seen.inFlight--;
  }
}

vi.mock("@silurus/ooxml/docx", () => ({
  DocxDocument: {
    async load(source: unknown, options: unknown) {
      seen.loads.push({ source, options });
      if (seen.holdLoad) await seen.holdLoad;
      return {
        waitUntilLayoutComplete: async () => void seen.layout.push("docx layout"),
        pageSize: () => ({ widthPt: 200, heightPt: 100 }),
        renderPageToBitmap: (index: number, o: { width: number }) => drawn("docx", [index, o], o.width, Math.round(o.width / 2)),
        destroy: () => seen.destroyed.push("docx"),
      };
    },
  },
}));

vi.mock("@silurus/ooxml/pptx", () => ({
  PptxPresentation: {
    async load(source: unknown, options: unknown) {
      seen.loads.push({ source, options });
      return {
        slideWidth: 9144000,
        slideHeight: 6858000,
        waitUntilLayoutComplete: async () => void seen.layout.push("pptx layout"),
        renderSlideToBitmap: (index: number, o: { width: number }) => drawn("pptx", [index, o], o.width, Math.round((o.width * 3) / 4)),
        destroy: () => seen.destroyed.push("pptx"),
      };
    },
  },
}));

/** Columns 100, 60 and 100 wide and rows 20 high, the headers 50 by 22, as the viewer over a workbook reports them. */
const sheetMeter = () => {
  const visited: number[] = [];
  const widths = [100, 60, 100];
  const meter = {
    goToSheet: async (i: number) => void visited.push(i),
    getScale: () => 1,
    getViewportOffset: () => ({ x: 0, y: 0 }),
    getCellViewportRect: (name: string) => {
      const m = /^([A-Z]+)(\d+)$/.exec(name)!;
      const col = m[1]!.split("").reduce((n, c) => n * 26 + c.charCodeAt(0) - 64, 0);
      const row = Number(m[2]);
      const w = widths[col - 1] ?? 70;
      return { x: 50 + widths.slice(0, col - 1).reduce((a, b) => a + b, 0), y: 22 + (row - 1) * 20, width: w, height: 20 };
    },
    destroy: () => seen.destroyed.push("meter"),
  };
  return { meter, visited };
};
let meters: ReturnType<typeof sheetMeter>;

vi.mock("@silurus/ooxml/xlsx", () => ({
  XlsxWorkbook: {
    async load(source: unknown, options: unknown) {
      seen.loads.push({ source, options });
      return {
        getWorksheet: async (i: number) => ({
          rows: [{ index: 2 + i, cells: [{ col: 3, value: { type: "text" } }] }],
          mergeCells: [],
          images: [],
          charts: [],
        }),
        renderViewportToBitmap: (index: number, viewport: unknown, o: { width: number; height: number }) => drawn("xlsx", [index, viewport, o], o.width, o.height),
        destroy: () => seen.destroyed.push("xlsx"),
      };
    },
  },
  XlsxSheetViewer: { fromWorkbook: () => meters.meter },
}));

const bytes = () => async () => new ArrayBuffer(8);
const never = () => null;
const code = async (p: Promise<unknown>) => p.then(() => "none", (e) => (e instanceof RasterError ? e.code : `other: ${String(e)}`));

beforeEach(() => {
  stubCanvas();
  Object.assign(seen, { loads: [], destroyed: [], draws: [], inFlight: 0, mostInFlight: 0, bitmaps: [], hold: null, holdLoad: null, failure: null, layout: [] });
  meters = sheetMeter();
});
afterEach(() => vi.unstubAllGlobals());

describe("pictures of a Word document", () => {
  it("opens a second copy on the first picture only, with the viewer's options, and keeps it", async () => {
    const options = { useGoogleFonts: false, resourceLimits: { maxArchiveEntries: 5 }, mode: "worker" };
    const e = docxExporter(bytes(), options);
    expect(seen.loads).toHaveLength(0);
    await e.raster(1, { width: 200 }, never);
    await e.raster(2, { width: 100 }, never);
    expect(seen.loads).toHaveLength(1);
    expect(seen.loads[0]!.options).toBe(options);
    expect(seen.layout).toEqual(["docx layout"]);
    // Each page at the width, one device pixel to a CSS one, page numbers from 0 for the engine.
    expect(seen.draws.map((d) => d.args)).toEqual([
      [0, { width: 200, dpr: 1 }],
      [1, { width: 100, dpr: 1 }],
    ]);
  });

  it("destroys the copy with the session, and never opens one that nobody asked for", async () => {
    const unused = docxExporter(bytes(), {});
    await unused.dispose();
    expect(seen.loads).toHaveLength(0);
    const e = docxExporter(bytes(), {});
    await e.raster(1, { width: 50 }, never);
    await e.dispose();
    expect(seen.destroyed).toEqual(["docx"]);
    expect(await code(e.raster(1, { width: 50 }, never))).toBe("failed");
  });

  it("draws one picture at a time", async () => {
    const e = docxExporter(bytes(), {});
    await Promise.all([1, 2, 1].map((p) => e.raster(p, { width: 100 }, never)));
    expect(seen.draws).toHaveLength(3);
    expect(seen.mostInFlight).toBe(1);
  });

  it("stops waiting for a drawing at once when aborted, closes its late bitmap, and the next one still draws", async () => {
    let release!: () => void;
    seen.hold = new Promise((r) => (release = r));
    const e = docxExporter(bytes(), {});
    const abort = new AbortController();
    const first = e.raster(1, { width: 100, signal: abort.signal }, never);
    await vi.waitFor(() => expect(seen.draws).toHaveLength(1));
    const second = e.raster(1, { width: 60 }, never);
    abort.abort();
    expect(await code(first)).toBe("aborted");
    // The second waits for the abandoned drawing, which cannot be stopped.
    expect(seen.draws).toHaveLength(1);
    seen.hold = null;
    release();
    const r = await second;
    expect(r.width).toBe(60);
    // The abandoned picture, drawn after nobody waited for it, is closed; the second's is the caller's.
    expect(FakeCanvas.made[0]!.bitmaps[0]!.closed).toBe(true);
    expect(FakeCanvas.made[1]!.bitmaps[0]!.closed).toBe(false);
  });

  it("never draws for a signal aborted while the document was opening", async () => {
    let open!: () => void;
    seen.holdLoad = new Promise((r) => (open = r));
    const e = docxExporter(bytes(), {});
    const abort = new AbortController();
    const p = e.raster(1, { width: 100, signal: abort.signal }, never);
    await vi.waitFor(() => expect(seen.loads).toHaveLength(1));
    abort.abort();
    expect(await code(p)).toBe("aborted");
    seen.holdLoad = null;
    open();
    // The document is kept for the next picture, which is drawn.
    expect((await e.raster(1, { width: 40 }, never)).width).toBe(40);
    expect(seen.loads).toHaveLength(1);
    expect(seen.draws).toHaveLength(1);
  });

  it("says too-large for the engine's resource limits, and failed for its other errors", async () => {
    const e = docxExporter(bytes(), {});
    seen.failure = Object.assign(new Error("image pixels over the limit"), { name: "OoxmlDecodedImageLimitError" });
    const limit = await e.raster(1, { width: 100 }, never).catch((x: RasterError) => x);
    expect([(limit as RasterError).code, (limit as RasterError).message]).toEqual(["too-large", "image pixels over the limit"]);
    seen.failure = new Error("broken");
    expect(await code(e.raster(1, { width: 100 }, never))).toBe("other: Error: broken");
  });

  it("hands the viewport to region current, for the page asked", async () => {
    const e = docxExporter(bytes(), {});
    const current = vi.fn((page: number) => (page === 1 ? { x: 0, y: 0.5, width: 1, height: 0.5 } : null));
    const r = await e.raster(1, { width: 100, region: "current" }, current);
    expect(r.region).toEqual({ x: 0, y: 0.5, width: 1, height: 0.5 });
    expect(current).toHaveBeenCalledWith(1, null);
    expect(await code(e.raster(2, { width: 100, region: "current" }, current))).toBe("invalid");
    // Not asked for unless wanted.
    current.mockClear();
    await e.raster(1, { width: 100 }, current);
    expect(current).not.toHaveBeenCalled();
  });
});

describe("pictures of a PowerPoint deck", () => {
  it("draws a slide by its shape, from the second copy", async () => {
    const e = pptxExporter(bytes(), {});
    const r = await e.raster(2, { width: 400 }, never);
    expect([r.width, r.height]).toEqual([400, 300]);
    expect(seen.draws[0]!.args).toEqual([1, { width: 400, dpr: 1 }]);
    await e.dispose();
    expect(seen.destroyed).toEqual(["pptx"]);
  });
});

describe("pictures of a sheet", () => {
  it("is measured by a viewer over the second copy, which the cells are asked of by name", async () => {
    const e = sheetExporter(bytes(), {});
    const grid = await e.measure(1, (g) => ({ header: g.header, rows: g.rows, cols: g.cols, edges: [1, 2, 3, 4].map(g.colEdge), rowEdges: [1, 2, 3].map(g.rowEdge) }));
    // The cell at row 2, column 3 is the last with a value: the page is A1:C2.
    expect(grid).toEqual({ header: { width: 50, height: 22 }, rows: 2, cols: 3, edges: [0, 100, 160, 260], rowEdges: [0, 20, 40] });
    expect(meters.visited).toEqual([0]);
    await e.measure(1, () => 0);
    expect(meters.visited).toEqual([0]);
    await e.measure(2, () => 0);
    expect(meters.visited).toEqual([0, 1]);
    expect(seen.loads).toHaveLength(1);
  });

  it("draws the cells of the region at the scale, with the viewer's own offsets", async () => {
    const e = sheetExporter(bytes(), {});
    // The page is 260 x 40 at 100 %: the right half of it, 130 px wide, is x 130..260, at 2x.
    const r = await e.raster(1, { width: 260, region: { x: 0.5, y: 0, width: 0.5, height: 1 } }, never);
    expect([r.width, r.height]).toEqual([260, 80]);
    const [index, viewport, size] = seen.draws[0]!.args as [number, Record<string, number>, Record<string, number>];
    expect(index).toBe(0);
    expect(viewport).toEqual({ row: 1, col: 2, rows: 2, cols: 2 });
    expect(size).toMatchObject({ width: 100 + 260, height: 44 + 80, dpr: 1, cellScale: 2, scrollOffsetX: 30, scrollOffsetY: 0 });
    expect(FakeCanvas.made.length).toBeGreaterThan(0);
  });

  it("takes region current from the viewer with the grid, only for the sheet shown", async () => {
    const e = sheetExporter(bytes(), {});
    const current = vi.fn((page: number, grid: unknown) => (page === 1 && grid ? { x: 0, y: 0, width: 0.5, height: 1 } : null));
    const r = await e.raster(1, { width: 130, region: "current" }, current);
    expect(r.region).toEqual({ x: 0, y: 0, width: 0.5, height: 1 });
    expect(await code(e.raster(2, { width: 130, region: "current" }, current))).toBe("invalid");
  });

  it("destroys the viewer and the workbook with the session", async () => {
    const e = sheetExporter(bytes(), {});
    await e.measure(1, () => 0);
    await e.dispose();
    expect(seen.destroyed.sort()).toEqual(["meter", "xlsx"]);
  });

  it("refuses a transparent background", async () => {
    const e = sheetExporter(bytes(), {});
    expect(await code(e.raster(1, { width: 100, background: "transparent" }, never))).toBe("unsupported");
    expect(seen.draws).toHaveLength(0);
  });
});
