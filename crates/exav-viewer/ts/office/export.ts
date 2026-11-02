/**
 * The engine side of office pictures: a second copy of the document, opened
 * the first time a picture is asked of it (or its viewport is wanted, for a
 * sheet), kept for the next and destroyed with the session. The viewers own
 * their own copy and nothing here touches their canvases; every drawing is on
 * a canvas made here.
 *
 * Sharing the viewer's copy was not chosen: the engines take a borrowed
 * document only for a viewer built over it (`fromDocument`, `fromPresentation`,
 * `fromWorkbook`, the last of which draws nothing until a sheet is gone to),
 * which would change how every office file is opened, and a delimited text
 * has no document of its own to borrow. The price is that the file is
 * parsed twice for as long as the session lives once a picture has been asked.
 */
import { RasterError, throwIfAborted } from "../core/pictures.js";
import type { Raster, RasterOptions, RasterRect } from "../core/types.js";
import {
  cellName,
  engineError,
  lazy,
  rasterPage,
  rasterSheet,
  serial,
  usedArea,
  type Grid,
  type PageEngine,
  type SheetEngine,
  type SheetWindow,
} from "./raster.js";

/**
 * What the viewport is for `region: "current"`: the region of page `page` in
 * view, or null when that page is not the one in view. A sheet's needs its
 * grid to be turned into fractions of the used area.
 */
export type Current = (page: number, grid: Grid | null) => RasterRect | null;

/** What a format's pictures are drawn from, and how they are asked for. */
export interface Exporter {
  raster(page: number, options: RasterOptions, current: Current): Promise<Raster>;
  dispose(): Promise<void>;
}

/** The options the viewers load a document with, given to the second copy too. */
type Common = Record<string, unknown>;

const close = (r: Raster) => r.bitmap.close();

/** Runs `draw` in the queue, once the document is open. */
function queued<D>(run: ReturnType<typeof serial>, document: { get(): Promise<D> }, draw: (d: D, page: number, options: RasterOptions, current: Current) => Promise<Raster>) {
  return (page: number, options: RasterOptions, current: Current) =>
    run(
      async () => {
        try {
          const d = await document.get();
          throwIfAborted(options.signal);
          return await draw(d, page, options, current);
        } catch (error) {
          throw engineError(error);
        }
      },
      options.signal,
      close,
    );
}

export function docxExporter(load: () => Promise<ArrayBuffer>, common: Common): Exporter {
  const document = lazy(
    async () => {
      const { DocxDocument } = await import("@silurus/ooxml/docx");
      const d = await DocxDocument.load(await load(), common);
      try {
        await d.waitUntilLayoutComplete();
      } catch (error) {
        d.destroy();
        throw error;
      }
      return d;
    },
    (d) => d.destroy(),
  );
  const run = serial();
  return {
    raster: queued(run, document, (d, page, options, current) => {
      const engine: PageEngine = {
        size: (p) => {
          const s = d.pageSize(p - 1);
          return { width: s.widthPt, height: s.heightPt };
        },
        draw: (p, width) => d.renderPageToBitmap(p - 1, { width, dpr: 1 }),
      };
      return rasterPage(engine, page, options, options.region === "current" ? current(page, null) : null);
    }),
    dispose: () => document.dispose(),
  };
}

export function pptxExporter(load: () => Promise<ArrayBuffer>, common: Common): Exporter {
  const document = lazy(
    async () => {
      const { PptxPresentation } = await import("@silurus/ooxml/pptx");
      const p = await PptxPresentation.load(await load(), common);
      try {
        await p.waitUntilLayoutComplete();
      } catch (error) {
        p.destroy();
        throw error;
      }
      return p;
    },
    (p) => p.destroy(),
  );
  const run = serial();
  return {
    raster: queued(run, document, (p, page, options, current) => {
      const engine: PageEngine = {
        size: () => ({ width: p.slideWidth, height: p.slideHeight }),
        draw: (s, width) => p.renderSlideToBitmap(s - 1, { width, dpr: 1 }),
      };
      return rasterPage(engine, page, options, options.region === "current" ? current(page, null) : null);
    }),
    dispose: () => document.dispose(),
  };
}

/** A sheet exporter also tells where the viewer's cells are (the viewport of a sheet needs the used area). */
export interface SheetExporter extends Exporter {
  /** Runs `fn` with the grid of sheet `page` (1-based), the grid valid only inside it. */
  measure<T>(page: number, fn: (grid: Grid) => T): Promise<T>;
}

export function sheetExporter(load: () => Promise<ArrayBuffer>, common: Common): SheetExporter {
  const open = lazy(
    async () => {
      const { XlsxWorkbook, XlsxSheetViewer } = await import("@silurus/ooxml/xlsx");
      const wb = await XlsxWorkbook.load(await load(), common);
      // A viewer over the workbook that draws nowhere, to ask where its cells are.
      const meter = XlsxSheetViewer.fromWorkbook(document.createElement("canvas"), wb, {});
      return { wb, meter, on: -1 };
    },
    (m) => {
      m.meter.destroy();
      m.wb.destroy();
    },
  );
  const areas = new Map<number, { rows: number; cols: number }>();
  const lock = serial();
  const run = serial();

  const measure = <T>(page: number, fn: (grid: Grid) => T): Promise<T> =>
    lock(async () => {
      const m = await open.get();
      const index = page - 1;
      let area = areas.get(index);
      if (!area) {
        const ws = await m.wb.getWorksheet(index);
        area = usedArea({ rows: ws.rows, mergeCells: ws.mergeCells, anchors: [...ws.images, ...ws.charts, ...(ws.shapeGroups ?? []), ...(ws.slicers ?? [])] });
        areas.set(index, area);
      }
      if (m.on !== index) {
        await m.meter.goToSheet(index);
        m.on = index;
      }
      const rect = (col: number, row: number) => {
        const r = m.meter.getCellViewportRect(cellName(col, row));
        if (!r) throw new RasterError("failed", "the sheet's cells could not be measured");
        return r;
      };
      const scale = m.meter.getScale();
      const offset = m.meter.getViewportOffset();
      const origin = rect(1, 1);
      const { rows, cols } = area;
      const edge = (at: (n: number) => { start: number; size: number }, count: number) => (n: number) => {
        if (n <= count) return at(n).start;
        const last = at(count);
        return last.start + last.size;
      };
      const grid: Grid = {
        header: { width: (origin.x + offset.x) / scale, height: (origin.y + offset.y) / scale },
        rows,
        cols,
        colEdge: edge((c) => ({ start: (rect(c, 1).x - origin.x) / scale, size: rect(c, 1).width / scale }), cols),
        rowEdge: edge((r) => ({ start: (rect(1, r).y - origin.y) / scale, size: rect(1, r).height / scale }), rows),
      };
      return fn(grid);
    });

  const engine: SheetEngine & { measure: typeof measure } = {
    measure,
    draw: async (page, window: Pick<SheetWindow, "row" | "col" | "rows" | "cols" | "offsetX" | "offsetY">, size) => {
      const m = await open.get();
      return m.wb.renderViewportToBitmap(
        page - 1,
        { row: window.row, col: window.col, rows: window.rows, cols: window.cols },
        { width: size.width, height: size.height, dpr: 1, cellScale: size.scale, scrollOffsetX: window.offsetX, scrollOffsetY: window.offsetY },
      );
    },
  };

  return {
    measure,
    raster: queued(run, open, (_m, page, options, current) => rasterSheet(engine, page, options, (grid) => current(page, grid))),
    dispose: () => open.dispose(),
  };
}
