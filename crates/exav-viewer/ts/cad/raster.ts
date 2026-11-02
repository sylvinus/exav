/**
 * The arithmetic of a drawing's pictures (`pictures.raster`) and of its
 * viewport: no DOM, no GL.
 *
 * Regions are rectangles in drawing units, y up: the file's own coordinates
 * in model space, the sheet's in a paper layout. A layout is its own space:
 * the model, the sheet and each viewport (a window onto the model, scaled and
 * clipped) do not share coordinates. The buffers and the camera work in
 * "local" coordinates, the drawing's `origin` less; the functions here take
 * and give drawing units unless they say otherwise.
 */
import { planRect, RasterError, type RectPlan, type Tile } from "../core/pictures.js";
import type { RasterOptions, RasterRect, Viewport } from "../core/types.js";
import { FIT_MARGIN } from "./renderer/camera.js";

/** The tiles a picture is cut in unless the plugin says otherwise, and the most it may say (px a side). */
export const DEFAULT_TILE = 2048;
export const MAX_TILE = 4096;

/** What the GPU holds: the smallest of these is the largest drawing buffer. */
export interface GpuLimits {
  texture: number;
  renderbuffer: number;
  viewport: readonly [number, number];
}

/**
 * The side, in pixels, of the tiles a picture is drawn in: `forced` (the
 * plugin's `rasterTile`) when it is a whole number of pixels, else
 * `DEFAULT_TILE`, never past `MAX_TILE` or what the GPU holds.
 */
export function tileEdge(limits: GpuLimits, forced?: number): number {
  const gpu = Math.min(limits.texture, limits.renderbuffer, limits.viewport[0], limits.viewport[1]);
  const wanted = Number.isSafeInteger(forced) && (forced as number) >= 1 ? (forced as number) : DEFAULT_TILE;
  return Math.max(1, Math.min(wanted, MAX_TILE, gpu));
}

/** Where a layout is drawn, and which pages are which layouts. */
export interface LayoutRef {
  id: string;
  name: string;
  isModel: boolean;
}

/**
 * The layout a request is for and its page. `options.layout` (an id of the
 * layouts controller: "" is model space) wins over `page`, which is the
 * layout's place in that list plus one.
 */
export function layoutFor(layouts: readonly LayoutRef[], page: number, options: Pick<RasterOptions, "layout">): { id: string; page: number } {
  if (options.layout !== undefined) {
    const i = typeof options.layout === "string" ? layouts.findIndex((l) => l.id === options.layout) : -1;
    if (i < 0) throw new RasterError("invalid", `no layout ${JSON.stringify(options.layout)}`);
    return { id: layouts[i]!.id, page: i + 1 };
  }
  const found = layouts[page - 1];
  if (!found) throw new RasterError("invalid", `no page ${String(page)}`);
  return { id: found.id, page };
}

/** The viewport's rectangle when it is that of layout `id`, else null. */
export function currentFor(viewport: Viewport | null, id: string): RasterRect | null {
  if (!viewport || viewport.space !== "drawing" || viewport.layout !== id) return null;
  const r = viewport.region;
  return "width" in r ? { x: r.x, y: r.y, width: r.width, height: r.height } : null;
}

/**
 * What the drawing shows when no region is asked: its extents (`[minX, minY,
 * maxX, maxY]` relative to `origin`) with the margin the viewer's fit leaves.
 * A line has no height, nor a point any size: a side is at least a hundredth
 * of the longer one, and an empty layout is one unit wide.
 */
export function defaultRegion(extents: readonly [number, number, number, number], origin: readonly [number, number]): RasterRect {
  const [minX, minY, maxX, maxY] = extents;
  let w = maxX - minX;
  let h = maxY - minY;
  const longest = Math.max(w, h);
  if (!(longest > 0) || !Number.isFinite(longest)) {
    w = h = 1;
  } else {
    w = Math.max(w, longest / 100);
    h = Math.max(h, longest / 100);
  }
  const width = w * (1 + 2 * FIT_MARGIN);
  const height = h * (1 + 2 * FIT_MARGIN);
  const cx = origin[0] + (minX + maxX) / 2;
  const cy = origin[1] + (minY + maxY) / 2;
  return { x: cx - width / 2, y: cy - height / 2, width, height };
}

/**
 * The size, region and ground of a picture; null while the region is not
 * known (no region asked, and the layout's extents not read yet): then
 * `full` is needed.
 */
export function planExport(options: RasterOptions, full: RasterRect | null, current: RasterRect | null, ground: string): RectPlan | null {
  if (options.lineweight !== undefined && options.lineweight !== "screen" && options.lineweight !== "scaled") {
    throw new RasterError("invalid", "lineweight is screen or scaled");
  }
  if (options.region === undefined && !full) return null;
  return planRect(options, full ?? { x: 0, y: 0, width: 1, height: 1 }, { x: 1, y: 1 }, current, ground);
}

/** What is drawn: the plan's region as the picture's pixels make it. */
export interface ExportView {
  /** The rectangle the picture shows, exactly: `width` and `height` pixels of `scale` units each. */
  region: RasterRect;
  /** Its centre. */
  cx: number;
  cy: number;
  /** Drawing units per pixel, the same along both axes. */
  scale: number;
}

/**
 * The view of a picture of `width` by `height` px that shows the plan's
 * region. A picture rounded to whole pixels is a hair off the region's
 * shape, and the renderer has one scale: the region is widened by that hair
 * (about its centre), and the result is what `Raster.region` reports.
 */
export function exportView(plan: Pick<RectPlan, "width" | "height" | "region">): ExportView {
  const { width, height, region } = plan;
  const scale = Math.max(region.width / width, region.height / height);
  if (!(scale > 0) || !Number.isFinite(scale)) throw new RasterError("invalid", "the region has no size");
  const cx = region.x + region.width / 2;
  const cy = region.y + region.height / 2;
  return { region: { x: cx - (width * scale) / 2, y: cy - (height * scale) / 2, width: width * scale, height: height * scale }, cx, cy, scale };
}

/**
 * How near the picture may be to the drawing: past a few f32 steps of its
 * coordinates per pixel (the viewer's own zoom limit) vertices snap and lines
 * wobble. `extents` and the view are in local coordinates' units.
 */
export function minScaleFor(extents: readonly [number, number, number, number]): number {
  const [minX, minY, maxX, maxY] = extents;
  const size = Math.max(maxX - minX, maxY - minY, 1e-9);
  const reach = Math.max(Math.abs(minX), Math.abs(minY), Math.abs(maxX), Math.abs(maxY), size);
  return reach * 2 ** -21;
}

/** Refuses a picture closer than the f32 coordinates can place. */
export function checkScale(scale: number, extents: readonly [number, number, number, number]): void {
  const min = minScaleFor(extents);
  if (scale < min) throw new RasterError("invalid", `the region is too small for the drawing's precision (${scale} units per pixel, at least ${min})`);
}

/** A tile as GL counts pixels: from the picture's bottom left. */
export function glTile(size: { height: number }, tile: Tile): Tile {
  return { x: tile.x, y: size.height - tile.y - tile.height, width: tile.width, height: tile.height };
}

/**
 * The camera that shows a tile of a picture, given the camera of the whole
 * picture (centre and scale in local units, size in pixels) and the tile in
 * GL pixels (`glTile`): the same scale, centred where the tile is.
 */
export function tileCamera(
  whole: { cx: number; cy: number; scale: number; width: number; height: number },
  tile: Tile,
): { cx: number; cy: number; scale: number; width: number; height: number } {
  return {
    cx: whole.cx + (tile.x + tile.width / 2 - whole.width / 2) * whole.scale,
    cy: whole.cy + (tile.y + tile.height / 2 - whole.height / 2) * whole.scale,
    scale: whole.scale,
    width: tile.width,
    height: tile.height,
  };
}

/**
 * The viewer's canvas, in device pixels, that "scaled" line weights are
 * measured against; a canvas not laid out (hidden, a pixel wide) is taken as
 * an ordinary screen.
 */
export function referenceCanvas(canvas: { width: number; height: number }): { width: number; height: number } {
  return canvas.width >= 64 && canvas.height >= 64 ? { width: canvas.width, height: canvas.height } : { width: 1024, height: 768 };
}

/**
 * How line widths are drawn in a picture, as two factors on the viewer's own:
 * `pixel` on the widths that are in pixels (model space, and every line's
 * minimum of one pixel), `paper` on the widths that are on the sheet (a
 * layout's lineweights, drawing units per hundredth of a millimetre).
 *
 * "screen" (default): lines are as many pixels wide as the viewer draws them
 * when its canvas shows `region` (the zoom that fits the region in the
 * canvas), whatever the picture's size. "scaled": as if the viewer's zoom were
 * raised from there until the region filled the picture, which is `k` times
 * the pixels per unit, `k = fit scale / scale` (the units per pixel the
 * viewer has when it fits `region`, over the picture's): every width in
 * pixels grows `k` times, and a sheet's lineweights keep their real width on
 * the page. With `region: "current"` at the canvas's size `k` is 1, and the
 * two are the same.
 */
export function lineweightFactors(
  mode: "screen" | "scaled" | undefined,
  region: RasterRect,
  scale: number,
  canvas: { width: number; height: number },
): { pixel: number; paper: number } {
  const ref = referenceCanvas(canvas);
  const fit = Math.max(region.width / ref.width, region.height / ref.height);
  const k = fit / scale;
  return mode === "scaled" ? { pixel: k, paper: 1 } : { pixel: 1, paper: 1 / k };
}

/**
 * The region a camera shows, in drawing units: its centre and scale are in
 * local coordinates, `origin` is added back.
 */
export function viewportRegion(camera: { cx: number; cy: number; scale: number; width: number; height: number }, origin: readonly [number, number]): RasterRect {
  const width = camera.width * camera.scale;
  const height = camera.height * camera.scale;
  return { x: origin[0] + camera.cx - width / 2, y: origin[1] + camera.cy - height / 2, width, height };
}

const nothing = () => {};

/**
 * `promise`, or a `RasterError` "aborted" as soon as `signal` aborts: the
 * work behind the promise goes on until it can stop (a worker's tessellation
 * cannot be interrupted), its result dropped.
 */
export function abortable<T>(promise: Promise<T>, signal: AbortSignal | undefined): Promise<T> {
  if (!signal) return promise;
  if (signal.aborted) {
    promise.catch(nothing);
    return Promise.reject(new RasterError("aborted", "aborted"));
  }
  return new Promise<T>((resolve, reject) => {
    const abort = () => reject(new RasterError("aborted", "aborted"));
    signal.addEventListener("abort", abort, { once: true });
    promise.then(resolve, reject).finally(() => signal.removeEventListener("abort", abort));
  });
}

/**
 * A queue that runs its jobs one at a time, in order: one picture at a time
 * per session, whatever the number asked for. A job aborted while it waits
 * is rejected at once and never runs; one aborted while it runs is rejected
 * at once too, and the next job starts when it has let go of what it holds.
 */
export function serial(): <T>(signal: AbortSignal | undefined, job: () => Promise<T>) => Promise<T> {
  let tail: Promise<unknown> = Promise.resolve();
  return (signal, job) => {
    const run = tail.then(() => {
      if (signal?.aborted) throw new RasterError("aborted", "aborted");
      return job();
    });
    tail = run.then(nothing, nothing);
    return abortable(run, signal);
  };
}

/** A signal that aborts when any of `signals` does; `dispose` detaches it from them. */
export function linked(signals: readonly (AbortSignal | undefined)[]): { signal: AbortSignal; dispose(): void } {
  const control = new AbortController();
  const hooks: [AbortSignal, () => void][] = [];
  for (const s of signals) {
    if (!s) continue;
    if (s.aborted) control.abort();
    else {
      const abort = () => control.abort();
      s.addEventListener("abort", abort, { once: true });
      hooks.push([s, abort]);
    }
  }
  return { signal: control.signal, dispose: () => hooks.forEach(([s, abort]) => s.removeEventListener("abort", abort)) };
}

export function sameRect(a: RasterRect, b: RasterRect): boolean {
  return a.x === b.x && a.y === b.y && a.width === b.width && a.height === b.height;
}
