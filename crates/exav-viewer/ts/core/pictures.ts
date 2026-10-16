/** Pages drawn as pictures (`PicturesController`): sizes, limits, regions. No DOM. */
import { isColor } from "./theme.js";
import type { CameraRegion, RasterFit, RasterOptions, RasterRect, RasterRegion } from "./types.js";

/** The longest side of a picture: a drawing of a sheet at 300 dpi is 14,000 px. */
export const MAX_PICTURE_EDGE = 16_384;

/**
 * The most pixels in a picture, whatever its sides (an RGBA bitmap of this
 * size is 256 MiB). Raising the edge limit is only sound with this one.
 */
export const MAX_PICTURE_PIXELS = 64 * 1024 * 1024;

/** The most tiles one picture is drawn in. */
export const MAX_TILES = 4096;

export type RasterErrorCode =
  /** The format cannot draw this (a transparent ground, a region of a kind it has no coordinates for). */
  | "unsupported"
  /** Past `MAX_PICTURE_EDGE` or `MAX_PICTURE_PIXELS`, or more than the device can hold. */
  | "too-large"
  | "aborted"
  /** The request is not one: a size, a region, a page that does not exist. */
  | "invalid"
  | "failed";

export class RasterError extends Error {
  constructor(
    readonly code: RasterErrorCode,
    message: string = code,
    options?: { cause?: unknown },
  ) {
    super(message, options);
    this.name = "RasterError";
  }
}

export function isRasterErrorCode(v: unknown): v is RasterErrorCode {
  return v === "unsupported" || v === "too-large" || v === "aborted" || v === "invalid" || v === "failed";
}

/** The `RasterError` for whatever a drawing threw. */
export function asRasterError(error: unknown, signal?: AbortSignal): RasterError {
  if (error instanceof RasterError) return error;
  if (signal?.aborted || (error instanceof DOMException && error.name === "AbortError")) return new RasterError("aborted", "aborted");
  return new RasterError("failed", error instanceof Error ? error.message : "could not draw", { cause: error });
}

export function throwIfAborted(signal: AbortSignal | undefined): void {
  if (signal?.aborted) throw new RasterError("aborted", "aborted");
}

/** A page number a picture can be asked of: 1..count. */
export function isPage(page: unknown, count: number): page is number {
  return Number.isSafeInteger(page) && (page as number) >= 1 && (page as number) <= count;
}

const positive = (v: unknown): v is number => typeof v === "number" && Number.isFinite(v) && v > 0;

export interface SizeLimits {
  edge: number;
  pixels: number;
}

export const DEFAULT_LIMITS: SizeLimits = { edge: MAX_PICTURE_EDGE, pixels: MAX_PICTURE_PIXELS };

/**
 * The size of a picture of something whose width over height is `aspect`.
 * `longEdge` is held to the limits; a `width` and `height` beyond them are
 * refused (the caller asked for those pixels). One of `width` and `height`
 * alone takes the other from `aspect`. Whole pixels, at least one.
 */
export function rasterSize(
  options: Pick<RasterOptions, "longEdge" | "width" | "height">,
  aspect: number,
  limits: SizeLimits = DEFAULT_LIMITS,
): { width: number; height: number } {
  const { longEdge, width, height } = options;
  if (!positive(aspect)) throw new RasterError("invalid", "the region has no size");
  const given = (v: unknown, what: string) => {
    if (!positive(v)) throw new RasterError("invalid", `${what} must be a positive number`);
    return v;
  };
  if (width !== undefined || height !== undefined) {
    if (longEdge !== undefined) throw new RasterError("invalid", "longEdge, or width and height, not both");
    let w: number;
    let h: number;
    if (width !== undefined && height !== undefined) {
      w = Math.round(given(width, "width"));
      h = Math.round(given(height, "height"));
    } else if (width !== undefined) {
      w = Math.round(given(width, "width"));
      h = Math.round(w / aspect);
    } else {
      h = Math.round(given(height, "height"));
      w = Math.round(h * aspect);
    }
    w = Math.max(1, w);
    h = Math.max(1, h);
    if (w > limits.edge || h > limits.edge || w * h > limits.pixels) throw new RasterError("too-large", `${w} x ${h} px is past the limits (${limits.edge} px a side, ${limits.pixels} px in all)`);
    return { width: w, height: h };
  }
  if (longEdge === undefined) throw new RasterError("invalid", "a size is needed: longEdge, or width and/or height");
  const edge = Math.min(limits.edge, Math.max(1, Math.round(given(longEdge, "longEdge"))));
  let w = aspect >= 1 ? edge : Math.max(1, Math.round(edge * aspect));
  let h = aspect >= 1 ? Math.max(1, Math.round(edge / aspect)) : edge;
  if (w * h > limits.pixels) {
    const k = Math.sqrt(limits.pixels / (w * h));
    w = Math.max(1, Math.floor(w * k));
    h = Math.max(1, Math.floor(h * k));
  }
  return { width: w, height: h };
}

/**
 * The size of a picture of something `width` by `height` whose longest side
 * is `longEdge` px, held to the limits. Whole pixels, at least one; null for
 * a size that is not one.
 */
export function pictureSize(width: number, height: number, longEdge: number): { width: number; height: number } | null {
  if (!positive(width) || !positive(height) || !Number.isFinite(longEdge)) return null;
  try {
    return rasterSize({ longEdge }, width / height);
  } catch {
    return null;
  }
}

const SAME = 1e-9;

/**
 * `rect`, changed to the shape of a picture whose width over height is
 * `aspect`, about its centre. `unit` is how long one unit of x and of y are
 * on the paper or the screen (a page's fractions: its width and height), so
 * that the shape is the one seen. "contain" grows the region, "cover" cuts
 * it. A region already of that shape is returned as it is.
 */
export function fitRect(rect: RasterRect, aspect: number, fit: RasterFit = "contain", unit: { x: number; y: number } = { x: 1, y: 1 }): RasterRect {
  const w = rect.width * unit.x;
  const h = rect.height * unit.y;
  const have = w / h;
  if (!(w > 0 && h > 0) || Math.abs(have - aspect) <= SAME * aspect) return { ...rect };
  // Keep the height and set the width from it, or the reverse.
  const fromHeight = fit === "contain" ? aspect > have : aspect < have;
  const nw = fromHeight ? h * aspect : w;
  const nh = fromHeight ? h : w / aspect;
  const width = nw / unit.x;
  const height = nh / unit.y;
  return { x: rect.x + (rect.width - width) / 2, y: rect.y + (rect.height - height) / 2, width, height };
}

/**
 * A camera, changed to a picture of `aspect`. The vertical field of view (or
 * extent) is kept, and the horizontal one follows, unless that would cut what
 * the camera framed: "contain" then widens the vertical one, "cover" keeps
 * the camera's own horizontal one when it cuts less.
 */
export function fitCamera(camera: CameraRegion, aspect: number, fit: RasterFit = "contain"): CameraRegion {
  const have = camera.aspect;
  if (!positive(have) || Math.abs(have - aspect) <= SAME * aspect) return { ...camera, aspect };
  // The view's size along the dimension that is kept: contain keeps all of the
  // camera's view in the picture, cover fills the picture with it.
  const keepWidth = fit === "contain" ? aspect < have : aspect > have;
  if (!keepWidth) return { ...camera, aspect };
  const scale = have / aspect;
  if (camera.projection.type === "orthographic") return { ...camera, aspect, projection: { type: "orthographic", height: camera.projection.height * scale } };
  // Widths are tangents of the half angle, not angles.
  const half = Math.tan((camera.projection.fov * Math.PI) / 360) * scale;
  const fov = (2 * Math.atan(half) * 180) / Math.PI;
  return { ...camera, aspect, projection: { type: "perspective", fov } };
}

/** What a request resolves to for a format whose regions are rectangles. */
export interface RectPlan {
  width: number;
  height: number;
  /** What is drawn: the request's region, changed to the picture's shape when the size gave both sides. */
  region: RasterRect;
  /** A CSS colour, or "transparent". */
  background: string;
}

/**
 * The size, region and ground of a picture of a rectangle format.
 * `full`: the whole page, image or drawing extents, which is the region by
 * default; `unit`: the length of one unit of x and y (see `fitRect`);
 * `current`: the viewport's region, or null when there is none for this
 * page (then "current" is refused); `ground`: the default background.
 */
export function planRect(options: RasterOptions, full: RasterRect, unit: { x: number; y: number }, current: RasterRect | null, ground = "#ffffff"): RectPlan {
  let region: RasterRect;
  if (options.region === undefined) region = full;
  else if (options.region === "current") {
    if (!current) throw new RasterError("invalid", "nothing is in view to draw");
    region = current;
  } else if (isRect(options.region)) region = options.region;
  else throw new RasterError("invalid", "this format takes a rectangle for a region");
  if (options.fit !== undefined && options.fit !== "contain" && options.fit !== "cover") throw new RasterError("invalid", "fit is contain or cover");
  const aspect = (region.width * unit.x) / (region.height * unit.y);
  const size = rasterSize(options, aspect);
  const both = options.width !== undefined && options.height !== undefined;
  const shaped = both ? fitRect(region, size.width / size.height, options.fit, unit) : { ...region };
  const background = options.background ?? ground;
  if (!isColor(background)) throw new RasterError("invalid", "background is a colour or transparent");
  return { ...size, region: shaped, background };
}

export interface Tile {
  x: number;
  y: number;
  width: number;
  height: number;
}

/** `width` by `height` cut in tiles of at most `tile` px a side, row by row. */
export function tilePlan(width: number, height: number, tile: number): Tile[] {
  if (!Number.isSafeInteger(tile) || tile < 1) throw new RasterError("invalid", "a tile is at least a pixel");
  const columns = Math.ceil(width / tile);
  const rows = Math.ceil(height / tile);
  if (columns * rows > MAX_TILES) throw new RasterError("too-large", `${columns * rows} tiles`);
  const out: Tile[] = [];
  for (let y = 0; y < height; y += tile) {
    for (let x = 0; x < width; x += tile) out.push({ x, y, width: Math.min(tile, width - x), height: Math.min(tile, height - y) });
  }
  return out;
}

/**
 * The part of `region` that `tile` of a picture of `size` shows. For a
 * rectangle region the tile is cut in the same proportions; the y axis of a
 * drawing goes up, a page's down, so `up` flips it.
 */
export function tileRect(region: RasterRect, size: { width: number; height: number }, tile: Tile, up = false): RasterRect {
  const kx = region.width / size.width;
  const ky = region.height / size.height;
  const y = up ? region.y + region.height - (tile.y + tile.height) * ky : region.y + tile.y * ky;
  return { x: region.x + tile.x * kx, y, width: tile.width * kx, height: tile.height * ky };
}

// ── What a message may carry ─────────────────────────────────────────────────

/** Coordinates of a document or a drawing: finite, and nothing a sum could overflow. */
const BOUND = 1e15;
const coordinate = (v: unknown): v is number => typeof v === "number" && Number.isFinite(v) && Math.abs(v) <= BOUND;

export function isRect(v: unknown): v is RasterRect {
  if (typeof v !== "object" || v === null || Array.isArray(v)) return false;
  const r = v as Record<string, unknown>;
  return coordinate(r.x) && coordinate(r.y) && coordinate(r.width) && coordinate(r.height) && (r.width as number) > 0 && (r.height as number) > 0;
}

const vector = (v: unknown): v is [number, number, number] => Array.isArray(v) && v.length === 3 && v.every(coordinate);

export function isCamera(v: unknown): v is CameraRegion {
  if (typeof v !== "object" || v === null || Array.isArray(v)) return false;
  const c = v as Record<string, unknown>;
  if (!vector(c.position) || !vector(c.target) || (c.up !== undefined && !vector(c.up)) || !positive(c.aspect) || (c.aspect as number) > 1e6) return false;
  const p = c.projection;
  if (typeof p !== "object" || p === null) return false;
  const { type, fov, height } = p as Record<string, unknown>;
  if (type === "perspective") return positive(fov) && (fov as number) < 180;
  return type === "orthographic" && positive(height) && (height as number) <= BOUND;
}

export function isRegion(v: unknown): v is RasterRegion {
  return isRect(v) || isCamera(v);
}

const copyRegion = (r: RasterRegion): RasterRegion =>
  "projection" in r
    ? { position: [...r.position], target: [...r.target], ...(r.up && { up: [...r.up] }), projection: { ...r.projection }, aspect: r.aspect }
    : { x: r.x, y: r.y, width: r.width, height: r.height };

/** A region taken out of a message: a fresh copy, or undefined if it is none. */
export function checkRegion(v: unknown): RasterRegion | undefined {
  return isRegion(v) ? copyRegion(v) : undefined;
}

/**
 * The options of a request that crossed a message, without the `signal`:
 * known fields of the right kind, or null when one is wrong. A colour is a
 * hex value or a colour function, never a `url(...)`.
 */
export function checkRasterOptions(v: unknown): Omit<RasterOptions, "signal"> | null {
  if (typeof v !== "object" || v === null || Array.isArray(v)) return null;
  const o = v as Record<string, unknown>;
  const out: Omit<RasterOptions, "signal"> = {};
  for (const key of ["longEdge", "width", "height"] as const) {
    if (o[key] === undefined) continue;
    if (!positive(o[key]) || (o[key] as number) > 1e9) return null;
    out[key] = o[key] as number;
  }
  if (o.region !== undefined) {
    if (o.region === "current") out.region = "current";
    else {
      const region = checkRegion(o.region);
      if (!region) return null;
      out.region = region;
    }
  }
  if (o.layout !== undefined) {
    if (typeof o.layout !== "string" || o.layout.length > 1024) return null;
    out.layout = o.layout;
  }
  if (o.fit !== undefined) {
    if (o.fit !== "contain" && o.fit !== "cover") return null;
    out.fit = o.fit;
  }
  if (o.lineweight !== undefined) {
    if (o.lineweight !== "screen" && o.lineweight !== "scaled") return null;
    out.lineweight = o.lineweight;
  }
  if (o.background !== undefined) {
    if (!isColor(o.background)) return null;
    out.background = o.background;
  }
  return out;
}

/** The region type the viewport of a space has: used to check what a frame reports. */
export function regionMatches(space: string, region: unknown): boolean {
  if (space === "camera") return isCamera(region);
  if (space === "frame") return region === undefined;
  return isRect(region);
}
