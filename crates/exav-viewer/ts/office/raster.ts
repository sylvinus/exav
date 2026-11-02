/**
 * Pictures of office pages and sheets, over what the engines can draw: a
 * whole page at a width (Word, PowerPoint) or a cell range at a scale
 * (spreadsheets), always on a canvas made here. No engine import: the
 * engines are given as small interfaces.
 *
 * The engines have no way to stop a drawing and no sub-rectangle of a page,
 * and they quietly draw a smaller bitmap than asked past a pixel budget
 * (`ENGINE_PIXELS`). So a region of a page is cut out of a drawing of the
 * whole page at the scale the region needs, and a request whose whole page
 * would be past that budget is refused ("too-large") instead of coming
 * back blurred. A sheet is drawn by cell range, so only the range the
 * region covers is drawn.
 */
import { MAX_PICTURE_EDGE, planRect, RasterError } from "../core/pictures.js";
import { bitmapOf, createCanvas, release } from "../core/raster.js";
import type { Raster, RasterOptions, RasterRect } from "../core/types.js";

/** The most pixels the engines draw in one bitmap: past it they return a smaller one. */
export const ENGINE_PIXELS = 2 ** 24;

/** The smallest cell scale a sheet is drawn at; a smaller picture is drawn at this and scaled down. */
export const MIN_SHEET_SCALE = 0.5;

const WHOLE: RasterRect = { x: 0, y: 0, width: 1, height: 1 };

/** The `RasterError` for what an engine threw: its resource limits are "too-large". */
export function engineError(error: unknown): unknown {
  if (error instanceof RasterError) return error;
  const name = (error as { name?: unknown } | null)?.name;
  if (name === "OoxmlResourceLimitError" || name === "OoxmlDecodedImageLimitError") {
    return new RasterError("too-large", error instanceof Error ? error.message : "past the engine's limits", { cause: error });
  }
  return error;
}

// ── Queue ────────────────────────────────────────────────────────────────────

/**
 * Runs tasks one at a time, in order. A task whose signal aborts rejects at
 * once with "aborted"; if it had started, it is left to end (an engine's
 * drawing cannot be stopped), its result passed to `dispose`, and the next
 * task waits for it, so abandoned work never piles up.
 */
export function serial() {
  let tail: Promise<unknown> = Promise.resolve();
  return function run<T>(task: () => Promise<T>, signal?: AbortSignal, dispose?: (value: T) => void): Promise<T> {
    return new Promise<T>((resolve, reject) => {
      let settled = false;
      const abort = () => {
        if (settled) return;
        settled = true;
        reject(new RasterError("aborted", "aborted"));
      };
      if (signal?.aborted) return abort();
      signal?.addEventListener("abort", abort, { once: true });
      tail = tail
        .then(async () => {
          if (settled) return;
          try {
            const value = await task();
            if (settled) dispose?.(value);
            else {
              settled = true;
              resolve(value);
            }
          } catch (error) {
            if (settled) return;
            settled = true;
            reject(error);
          }
        })
        .finally(() => signal?.removeEventListener("abort", abort));
    });
  };
}

// ── The second document ──────────────────────────────────────────────────────

/**
 * A resource opened on first use (the second copy of a document the pictures
 * are drawn from), kept for the next, and closed with the session. A failed
 * open is tried again by the next use.
 */
export function lazy<D>(make: () => Promise<D>, close: (resource: D) => void) {
  let current: Promise<D> | null = null;
  let closed = false;
  return {
    get(): Promise<D> {
      if (closed) return Promise.reject(new RasterError("failed", "the session is closed"));
      current ??= make().catch((error) => {
        current = null;
        throw error;
      });
      return current;
    },
    /** Whether `get` has been called and not failed. */
    get started() {
      return current !== null;
    },
    async dispose(): Promise<void> {
      closed = true;
      const pending = current;
      current = null;
      if (!pending) return;
      try {
        close(await pending);
      } catch {
        // It never opened: nothing to close.
      }
    },
  };
}

// ── A page drawn whole (Word, PowerPoint) ────────────────────────────────────

export interface PageEngine {
  /** The page's shape: width and height in any one unit. */
  size(page: number): { width: number; height: number };
  /** The whole page `width` px wide. The caller closes the bitmap. */
  draw(page: number, width: number): Promise<ImageBitmap>;
}

/** What a transparent ground is refused with: the pages are opaque paper. */
export const NO_TRANSPARENT = "this format draws its pages on opaque paper: a transparent background is not available";

/**
 * Page `page` as a picture. `region` is a rectangle of fractions of the page
 * (top left origin); `current` is the viewport's, for `region: "current"`.
 * The page is drawn whole at the width the region needs, and the region cut
 * out of it (so a region cut out is exactly the pixels a full page at that
 * width shows). What is outside the page is the background. The region
 * returned is the one drawn, to the pixel.
 */
export async function rasterPage(engine: PageEngine, page: number, options: RasterOptions, current: RasterRect | null): Promise<Raster> {
  const shape = engine.size(page);
  const plan = planRect(options, WHOLE, { x: shape.width, y: shape.height }, current);
  if (plan.background === "transparent") throw new RasterError("unsupported", NO_TRANSPARENT);
  const width = Math.max(1, Math.round(plan.width / plan.region.width));
  const height = Math.max(1, Math.round((width * shape.height) / shape.width));
  if (!(width <= MAX_PICTURE_EDGE && height <= MAX_PICTURE_EDGE && width * height <= ENGINE_PIXELS)) {
    throw new RasterError("too-large", `this region needs the whole page drawn at ${width} x ${height} px, past the ${ENGINE_PIXELS} px a page can be drawn at`);
  }
  const full = await engine.draw(page, width);
  try {
    if (Math.abs(full.width - width) > 1 || Math.abs(full.height - height) > 1) {
      throw new RasterError("too-large", `the page was drawn at ${full.width} x ${full.height} px, not ${width} x ${height}`);
    }
    const x = Math.round(plan.region.x * full.width);
    const y = Math.round(plan.region.y * full.height);
    const { canvas, ctx } = createCanvas(plan.width, plan.height);
    try {
      ctx.fillStyle = plan.background;
      ctx.fillRect(0, 0, plan.width, plan.height);
      ctx.drawImage(full, -x, -y);
      const bitmap = await bitmapOf(canvas);
      return {
        bitmap,
        width: plan.width,
        height: plan.height,
        page,
        space: "page",
        region: { x: x / full.width, y: y / full.height, width: plan.width / full.width, height: plan.height / full.height },
      };
    } catch (error) {
      release(canvas);
      throw error;
    }
  } finally {
    full.close();
  }
}

// ── A box in view ────────────────────────────────────────────────────────────

export interface Box {
  left: number;
  top: number;
  width: number;
  height: number;
}

/** The part of `box` inside `view`, as fractions of `box`; null when none of it is. */
export function visibleRegion(box: Box, view: Box): RasterRect | null {
  if (!(box.width > 0 && box.height > 0)) return null;
  const left = Math.max(box.left, view.left);
  const top = Math.max(box.top, view.top);
  const right = Math.min(box.left + box.width, view.left + view.width);
  const bottom = Math.min(box.top + box.height, view.top + view.height);
  if (!(right > left && bottom > top)) return null;
  return { x: (left - box.left) / box.width, y: (top - box.top) / box.height, width: (right - left) / box.width, height: (bottom - top) / box.height };
}

/**
 * The page most in view of `boxes` (index and the visible region): the one
 * with the most of its area inside `view`, the first on a tie. Null when
 * none shows.
 */
export function pageInView(boxes: readonly { index: number; box: Box }[], view: Box): { index: number; region: RasterRect } | null {
  let best: { index: number; region: RasterRect; area: number } | null = null;
  for (const { index, box } of boxes) {
    const region = visibleRegion(box, view);
    if (!region) continue;
    const area = region.width * region.height * box.width * box.height;
    if (!best || area > best.area + 1e-6 || (Math.abs(area - best.area) <= 1e-6 && index < best.index)) best = { index, region, area };
  }
  return best && { index: best.index, region: best.region };
}

/** Whether two regions are the same to a ten-thousandth of the page. */
export function sameRegion(a: RasterRect | undefined, b: RasterRect | undefined): boolean {
  return !!a && !!b && (["x", "y", "width", "height"] as const).every((k) => Math.abs(a[k] - b[k]) < 1e-4);
}

// ── A sheet ──────────────────────────────────────────────────────────────────

/**
 * The geometry of a sheet at 100 %, in px, from the top left of cell A1.
 * Its page is the used area: columns 1..`cols` and rows 1..`rows`.
 */
export interface Grid {
  /** The column and row headers the engine draws around the cells. */
  header: { width: number; height: number };
  cols: number;
  rows: number;
  /** The left edge of column `c` (1-based); `cols + 1` is the right edge of the page. */
  colEdge(c: number): number;
  /** The top edge of row `r`; `rows + 1` is the bottom edge of the page. */
  rowEdge(r: number): number;
}

/** The page's size at 100 %. */
export const pageSize = (grid: Grid) => ({ width: grid.colEdge(grid.cols + 1), height: grid.rowEdge(grid.rows + 1) });

/** The last index in 1..`count` whose edge is at or before `at` (the cell holding it); 1 when none. */
export function indexAt(edge: (index: number) => number, count: number, at: number): number {
  let low = 1;
  let high = count;
  while (low < high) {
    const middle = Math.ceil((low + high) / 2);
    if (edge(middle) <= at) low = middle;
    else high = middle - 1;
  }
  return low;
}

/** What to ask the engine for to draw part of a sheet. */
export interface SheetWindow {
  row: number;
  col: number;
  rows: number;
  cols: number;
  /** How far into the first column and row the window starts, at 100 %. */
  offsetX: number;
  offsetY: number;
  /** The window in the page, at 100 % (the part of the region that is on the page). */
  x0: number;
  y0: number;
  x1: number;
  y1: number;
}

/** The cells of `grid` that region `region` (fractions of the page) covers, or null when it is all off the page. */
export function sheetWindow(grid: Grid, region: RasterRect): SheetWindow | null {
  const page = pageSize(grid);
  const x0 = Math.max(0, region.x * page.width);
  const y0 = Math.max(0, region.y * page.height);
  const x1 = Math.min(page.width, (region.x + region.width) * page.width);
  const y1 = Math.min(page.height, (region.y + region.height) * page.height);
  if (!(x1 > x0 && y1 > y0)) return null;
  const col = indexAt(grid.colEdge, grid.cols, x0);
  const row = indexAt(grid.rowEdge, grid.rows, y0);
  const lastCol = indexAt(grid.colEdge, grid.cols, x1 - 1e-7);
  const lastRow = indexAt(grid.rowEdge, grid.rows, y1 - 1e-7);
  return { row, col, rows: lastRow - row + 1, cols: lastCol - col + 1, offsetX: x0 - grid.colEdge(col), offsetY: y0 - grid.rowEdge(row), x0, y0, x1, y1 };
}

export interface SheetEngine {
  /** Runs `fn` with the grid of sheet `page` (1-based); the grid is good inside `fn` only. */
  measure<T>(page: number, fn: (grid: Grid) => T): Promise<T>;
  /**
   * The cells of `window` with the headers, `width` by `height` px, the cells
   * `scale` times their size at 100 % and scrolled `offsetX`, `offsetY`
   * (100 % px) into the first cell. The caller closes the bitmap.
   */
  draw(page: number, window: Pick<SheetWindow, "row" | "col" | "rows" | "cols" | "offsetX" | "offsetY">, size: { width: number; height: number; scale: number }): Promise<ImageBitmap>;
}

/**
 * Sheet `page` as a picture. The page is the sheet's used area at 100 %, and
 * `region` fractions of it from the top left of cell A1; the headers the
 * engine draws are not part of it. Where the region is off the used area is
 * the background. The scale is the picture's width over the region's width
 * at 100 %; the region is drawn exactly, to a pixel.
 */
export async function rasterSheet(engine: SheetEngine, page: number, options: RasterOptions, current: (grid: Grid) => RasterRect | null): Promise<Raster> {
  const { full, header, plan, window } = await engine.measure(page, (grid) => {
    const full = pageSize(grid);
    const plan = planRect(options, WHOLE, { x: full.width, y: full.height }, options.region === "current" ? current(grid) : null);
    if (plan.background === "transparent") throw new RasterError("unsupported", "a sheet is drawn on its own white cells: a transparent background is not available");
    return { full, header: grid.header, plan, window: sheetWindow(grid, plan.region) };
  });
  const scale = plan.width / (plan.region.width * full.width);
  const drawn = Math.max(scale, MIN_SHEET_SCALE);
  const { canvas, ctx } = createCanvas(plan.width, plan.height);
  try {
    ctx.fillStyle = plan.background;
    ctx.fillRect(0, 0, plan.width, plan.height);
    if (window) {
      // The engine's headers; the cells start where the viewer's do.
      const headerX = Math.round(header.width * drawn);
      const headerY = Math.round(header.height * drawn);
      const cellsX = Math.max(1, Math.round((window.x1 - window.x0) * drawn));
      const cellsY = Math.max(1, Math.round((window.y1 - window.y0) * drawn));
      const width = headerX + cellsX;
      const height = headerY + cellsY;
      if (!(width <= MAX_PICTURE_EDGE && height <= MAX_PICTURE_EDGE && width * height <= ENGINE_PIXELS)) {
        throw new RasterError("too-large", `this region needs ${width} x ${height} px drawn, past the ${ENGINE_PIXELS} px a sheet can be drawn at`);
      }
      const bitmap = await engine.draw(page, window, { width, height, scale: drawn });
      try {
        if (bitmap.width !== width || bitmap.height !== height) {
          throw new RasterError("too-large", `the sheet was drawn at ${bitmap.width} x ${bitmap.height} px, not ${width} x ${height}`);
        }
        const dx = Math.round((window.x0 - plan.region.x * full.width) * scale);
        const dy = Math.round((window.y0 - plan.region.y * full.height) * scale);
        const dw = Math.max(1, Math.round((window.x1 - window.x0) * scale));
        const dh = Math.max(1, Math.round((window.y1 - window.y0) * scale));
        ctx.imageSmoothingQuality = "high";
        ctx.drawImage(bitmap, headerX, headerY, cellsX, cellsY, dx, dy, dw, dh);
      } finally {
        bitmap.close();
      }
    }
    const bitmap = await bitmapOf(canvas);
    return { bitmap, width: plan.width, height: plan.height, page, space: "page", region: plan.region };
  } catch (error) {
    release(canvas);
    throw error;
  }
}

/**
 * The part of a sheet in view, as fractions of its page: `corner` is where
 * cell A1's top left is in the viewer (CSS px, negative when scrolled), `scale`
 * the viewer's zoom, `canvas` its size in CSS px. Null when none of the used
 * area shows.
 */
export function sheetView(grid: Grid, corner: { x: number; y: number }, scale: number, canvas: { width: number; height: number }): RasterRect | null {
  if (!(scale > 0)) return null;
  const page = pageSize(grid);
  const left = grid.header.width - corner.x / scale;
  const top = grid.header.height - corner.y / scale;
  const right = left + canvas.width / scale - grid.header.width;
  const bottom = top + canvas.height / scale - grid.header.height;
  return visibleRegion({ left: 0, top: 0, width: page.width, height: page.height }, { left, top, width: right - left, height: bottom - top });
}

// ── Used area ────────────────────────────────────────────────────────────────

/** The parts of a worksheet that give its used area. */
export interface Extent {
  rows: { index: number; cells: { col: number; styleIndex?: number; value: { type: string } }[] }[];
  mergeCells?: { bottom: number; right: number }[];
  /** Drawings and charts anchored to cells, 0-based. */
  anchors?: { toRow: number; toCol: number }[];
}

const MAX_ROWS = 1_048_576;
const MAX_COLS = 16_384;

/** The used area of a worksheet: its last row and column that hold a value, a style, a merge or a drawing (at least A1). */
export function usedArea(sheet: Extent): { rows: number; cols: number } {
  let rows = 1;
  let cols = 1;
  for (const row of sheet.rows) {
    for (const cell of row.cells) {
      if (cell.value.type === "empty" && cell.styleIndex === undefined) continue;
      rows = Math.max(rows, row.index);
      cols = Math.max(cols, cell.col);
    }
  }
  for (const m of sheet.mergeCells ?? []) {
    rows = Math.max(rows, m.bottom);
    cols = Math.max(cols, m.right);
  }
  for (const a of sheet.anchors ?? []) {
    rows = Math.max(rows, a.toRow + 1);
    cols = Math.max(cols, a.toCol + 1);
  }
  return { rows: Math.min(MAX_ROWS, rows), cols: Math.min(MAX_COLS, cols) };
}

/** A column's letters ("A", "AB"), 1-based. */
export function columnName(col: number): string {
  let name = "";
  for (let c = col; c > 0; c = Math.floor((c - 1) / 26)) name = String.fromCharCode(65 + ((c - 1) % 26)) + name;
  return name;
}

/** A cell's name ("A1"), 1-based. */
export const cellName = (col: number, row: number) => columnName(col) + row;
