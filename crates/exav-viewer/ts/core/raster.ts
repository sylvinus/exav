/**
 * The canvas side of pictures: a surface to draw tiles on, encoding to a
 * file, and the controller every plugin's `raster` is wrapped in.
 */
import {
  asRasterError,
  checkRasterOptions,
  isPage,
  MAX_PICTURE_EDGE,
  MAX_PICTURE_PIXELS,
  RasterError,
  tilePlan,
  throwIfAborted,
  type Tile,
} from "./pictures.js";
import { writable, type Store } from "./store.js";
import type { EncodeOptions, PicturesController, Raster, RasterBlob, RasterOptions, RasterType, RegionSpace } from "./types.js";

type Surface = HTMLCanvasElement | OffscreenCanvas;
type Context = CanvasRenderingContext2D | OffscreenCanvasRenderingContext2D;

/**
 * A 2D canvas of `width` by `height`, off screen where the browser has them;
 * `element`: always an HTMLCanvasElement (for an engine that takes no other).
 */
export function createCanvas(width: number, height: number, element = false): { canvas: Surface; ctx: Context } {
  if (!(Number.isSafeInteger(width) && Number.isSafeInteger(height) && width >= 1 && height >= 1 && width <= MAX_PICTURE_EDGE && height <= MAX_PICTURE_EDGE && width * height <= MAX_PICTURE_PIXELS)) {
    throw new RasterError("too-large", `${width} x ${height} px`);
  }
  const canvas: Surface = !element && typeof OffscreenCanvas === "function" ? new OffscreenCanvas(width, height) : Object.assign(document.createElement("canvas"), { width, height });
  // A canvas the device cannot hold has no context.
  const ctx = canvas.getContext("2d") as Context | null;
  if (!ctx) throw new RasterError("too-large", `a canvas of ${width} x ${height} px`);
  return { canvas, ctx };
}

/** Frees a canvas's pixels now. */
export function release(canvas: Surface): void {
  canvas.width = 0;
  canvas.height = 0;
}

/** The canvas as a bitmap that owns its pixels. */
export async function bitmapOf(canvas: Surface): Promise<ImageBitmap> {
  try {
    if ("transferToImageBitmap" in canvas && typeof canvas.transferToImageBitmap === "function") return canvas.transferToImageBitmap();
    return await createImageBitmap(canvas);
  } finally {
    release(canvas);
  }
}

/** What a tile is drawn as: closed (a bitmap) or released (a canvas) once copied. */
export type TileSource = ImageBitmap | Surface;

export interface TiledOptions {
  signal?: AbortSignal;
  /** Fills the picture before the tiles are drawn (a ground, or nothing when transparent). */
  background?: string;
}

/**
 * A picture of `width` by `height` drawn as tiles of at most `tile` px
 * a side, for a renderer whose surface (a WebGL drawing buffer) is smaller
 * than the picture. `draw` makes one tile: its pixels come back at the
 * tile's own size. Tiles are copied in one at a time and freed.
 */
export async function drawTiled(width: number, height: number, tile: number, draw: (tile: Tile) => Promise<TileSource>, options: TiledOptions = {}): Promise<ImageBitmap> {
  const tiles = tilePlan(width, height, tile);
  const { canvas, ctx } = createCanvas(width, height);
  try {
    if (options.background) {
      ctx.fillStyle = options.background;
      ctx.fillRect(0, 0, width, height);
    }
    for (const t of tiles) {
      throwIfAborted(options.signal);
      const part = await draw(t);
      try {
        const w = "width" in part ? part.width : 0;
        const h = "height" in part ? part.height : 0;
        if (w !== t.width || h !== t.height) throw new RasterError("failed", `a tile of ${w} x ${h} px, not ${t.width} x ${t.height}`);
        ctx.drawImage(part, t.x, t.y);
      } finally {
        if (part instanceof ImageBitmap) part.close();
        else release(part);
      }
    }
    throwIfAborted(options.signal);
    return await bitmapOf(canvas);
  } catch (error) {
    release(canvas);
    throw asRasterError(error, options.signal);
  }
}

const TYPES: Record<RasterType, string> = { png: "image/png", jpeg: "image/jpeg", webp: "image/webp" };

export function isRasterType(v: unknown): v is RasterType {
  return typeof v === "string" && Object.hasOwn(TYPES, v);
}

/**
 * `bitmap` as an image file, in this page. JPEG has no transparency: it
 * is drawn on `background`, or white. A browser that cannot encode the type
 * (Safari has no WebP encoder) is an "unsupported" error, not a PNG under
 * another name.
 */
export async function encodeBitmap(bitmap: ImageBitmap, options: EncodeOptions & { background?: string } = {}): Promise<Blob> {
  const type = options.type ?? "png";
  if (!isRasterType(type)) throw new RasterError("invalid", `no image type ${String(type)}`);
  const quality = options.quality;
  if (quality !== undefined && !(typeof quality === "number" && quality >= 0 && quality <= 1)) throw new RasterError("invalid", "quality is between 0 and 1");
  const { canvas, ctx } = createCanvas(bitmap.width, bitmap.height);
  try {
    if (type === "jpeg") {
      ctx.fillStyle = options.background && options.background !== "transparent" ? options.background : "#ffffff";
      ctx.fillRect(0, 0, bitmap.width, bitmap.height);
    }
    ctx.drawImage(bitmap, 0, 0);
    const mime = TYPES[type];
    const blob =
      "convertToBlob" in canvas
        ? await canvas.convertToBlob({ type: mime, quality })
        : await new Promise<Blob | null>((resolve) => (canvas as HTMLCanvasElement).toBlob(resolve, mime, quality));
    if (!blob) throw new RasterError("failed", "the browser could not encode the picture");
    if (blob.type !== mime) throw new RasterError("unsupported", `this browser cannot encode ${mime}`);
    return blob;
  } catch (error) {
    // Pixels of an image shown from another origin without CORS cannot be read back.
    if (error instanceof DOMException && error.name === "SecurityError") throw new RasterError("unsupported", "the picture comes from another origin and cannot be read back", { cause: error });
    throw error;
  } finally {
    release(canvas);
  }
}

/** What a plugin gives `createPictures`. */
export interface PicturesSource {
  /** The number of pages, kept up to date. */
  count: number;
  space: RegionSpace;
  /**
   * Draws page `page` (1-based). Called only with a valid page and well-formed
   * options; throws `RasterError` (or anything: it becomes "failed", and
   * "aborted" when the signal is).
   */
  raster(page: number, options: RasterOptions): Promise<Raster>;
}

/**
 * The controller of a plugin whose pages can be drawn: its store of
 * `{ count, space }`, and `raster`, `toBlob` and `render` over the plugin's
 * own drawing. Checks the page, and gives back a `RasterError` for anything
 * that goes wrong. The store is returned too: `count` changes with a
 * replaced document.
 */
export function createPictures(source: PicturesSource) {
  const state = writable({ count: source.count, space: source.space });
  return { controller: picturesOver(state, source.raster), state };
}

/**
 * The controller over a store of `{ count, space }` and a function that draws
 * a page: the page and the signal are checked here, `toBlob` encodes in this
 * page, `render` is a `raster` that gives null where it would reject.
 */
export function picturesOver(state: Store<{ count: number; space: RegionSpace }>, draw: (page: number, options: RasterOptions) => Promise<Raster>): PicturesController {
  const checked = async (page: number, options: RasterOptions = {}): Promise<Raster> => {
    const count = state.get().count;
    if (!isPage(page, count)) throw new RasterError("invalid", `no page ${String(page)} (1 to ${count})`);
    throwIfAborted(options.signal);
    // Whatever the caller wrote: the plugin, or the frame across the port, gets the options that check.
    const clean = checkRasterOptions(options);
    if (!clean) throw new RasterError("invalid", "the options are not a size, a region, a fit, a colour...");
    try {
      const r = await draw(page, { ...clean, ...(options.signal && { signal: options.signal }) });
      if (options.signal?.aborted) {
        r.bitmap.close();
        throw new RasterError("aborted", "aborted");
      }
      return r;
    } catch (error) {
      throw asRasterError(error, options.signal);
    }
  };
  return {
    get: state.get,
    subscribe: state.subscribe,
    raster: checked,
    async toBlob(page, options = {}) {
      const { type, quality, ...rest } = options;
      // Before anything is drawn.
      if (type !== undefined && !isRasterType(type)) throw new RasterError("invalid", `no image type ${String(type)}`);
      if (quality !== undefined && !(typeof quality === "number" && quality >= 0 && quality <= 1)) throw new RasterError("invalid", "quality is between 0 and 1");
      const { bitmap, ...info } = await checked(page, rest);
      try {
        const blob = await encodeBitmap(bitmap, { type, quality, background: rest.background });
        throwIfAborted(options.signal);
        return { ...info, blob };
      } finally {
        bitmap.close();
      }
    },
    async render(page, longEdge) {
      try {
        return (await checked(page, { longEdge })).bitmap;
      } catch {
        return null;
      }
    },
  };
}

export type { RasterBlob };
