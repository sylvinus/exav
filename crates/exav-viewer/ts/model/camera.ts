/**
 * The maths of a model's pictures, with no WebGL and no DOM: the model's
 * coordinates against the scene's, the camera as a region, the limits of a
 * tile, the ground. `raster.ts` draws with it.
 */
import { RasterError, type Tile } from "../core/pictures.js";
import { isColor } from "../core/theme.js";
import type { CameraRegion } from "../core/types.js";

export type Vec3 = readonly [number, number, number];

/**
 * How the viewer places a model in its scene, which is three.js's: Y up.
 * `scene = turn(point - origin) + offset`, where `turn` stands a Z-up model
 * up ((x, y, z) -> (x, z, -y)) and does nothing to a Y-up one. The model's
 * coordinates, those of `CameraRegion`, are the file's own: `origin` is the
 * engine's offset (a georeferenced IFC, whose buffers are relative to it).
 * Units are the same on both sides.
 */
export interface ModelFrame {
  zUp: boolean;
  origin: Vec3;
  /** Where the viewer moved the model to (the part is stood on the middle of its floor). */
  offset: Vec3;
}

const turn = (zUp: boolean, [x, y, z]: Vec3): Vec3 => (zUp ? [x, z, -y] : [x, y, z]);
const unturn = (zUp: boolean, [x, y, z]: Vec3): Vec3 => (zUp ? [x, -z, y] : [x, y, z]);

export function toScenePoint(f: ModelFrame, p: Vec3): Vec3 {
  const [x, y, z] = turn(f.zUp, [p[0] - f.origin[0], p[1] - f.origin[1], p[2] - f.origin[2]]);
  return [x + f.offset[0], y + f.offset[1], z + f.offset[2]];
}

export function toModelPoint(f: ModelFrame, p: Vec3): Vec3 {
  const [x, y, z] = unturn(f.zUp, [p[0] - f.offset[0], p[1] - f.offset[1], p[2] - f.offset[2]]);
  return [x + f.origin[0], y + f.origin[1], z + f.origin[2]];
}

export const toSceneVector = (f: ModelFrame, v: Vec3): Vec3 => turn(f.zUp, v);
export const toModelVector = (f: ModelFrame, v: Vec3): Vec3 => unturn(f.zUp, v);

/** The axis a model stands on, in its own coordinates: what `up` is when a region has none. */
export const modelUp = (f: Pick<ModelFrame, "zUp">): Vec3 => (f.zUp ? [0, 0, 1] : [0, 1, 0]);

/** A camera in the scene's coordinates. */
export interface SceneCamera {
  position: Vec3;
  target: Vec3;
  up: Vec3;
  projection: CameraRegion["projection"];
  aspect: number;
}

const sub = (a: Vec3, b: Vec3): Vec3 => [a[0] - b[0], a[1] - b[1], a[2] - b[2]];
const dot = (a: Vec3, b: Vec3) => a[0] * b[0] + a[1] * b[1] + a[2] * b[2];
const length = (a: Vec3) => Math.hypot(a[0], a[1], a[2]);
const cross = (a: Vec3, b: Vec3): Vec3 => [a[1] * b[2] - a[2] * b[1], a[2] * b[0] - a[0] * b[2], a[0] * b[1] - a[1] * b[0]];

/**
 * The region, as a camera in the scene. A camera that looks at nothing, or
 * along its own up axis, has no view: "invalid".
 */
export function sceneCamera(f: ModelFrame, region: CameraRegion): SceneCamera {
  const position = toScenePoint(f, region.position);
  const target = toScenePoint(f, region.target);
  const up = toSceneVector(f, region.up ?? modelUp(f));
  const look = sub(target, position);
  const span = length(look);
  if (!(span > 0)) throw new RasterError("invalid", "the camera looks at its own position");
  if (!(length(up) > 0)) throw new RasterError("invalid", "the camera has no up axis");
  if (!(length(cross(look, up)) > 1e-9 * span * length(up))) throw new RasterError("invalid", "the camera looks along its up axis");
  return { position, target, up, projection: region.projection, aspect: region.aspect };
}

/** A camera of the scene, as the region that names it in the model's coordinates; `up` is always set. */
export function cameraRegion(f: ModelFrame, c: SceneCamera): CameraRegion {
  return {
    position: toModelPoint(f, c.position),
    target: toModelPoint(f, c.target),
    up: toModelVector(f, c.up),
    projection: { ...c.projection },
    aspect: c.aspect,
  };
}

/** Whether two views are one, give or take what a damped orbit leaves: less than a ten-millionth of the distance. */
export function sameRegion(a: CameraRegion, b: CameraRegion): boolean {
  if (a.projection.type !== b.projection.type) return false;
  const reach = Math.max(length(sub(a.position, a.target)), 1e-9);
  const near = (x: number, y: number, scale = reach) => Math.abs(x - y) <= 1e-7 * scale;
  const same = (p: Vec3, q: Vec3) => p.every((v, i) => near(v, q[i]!));
  const au = a.up ?? [0, 0, 0];
  const bu = b.up ?? [0, 0, 0];
  const lens =
    a.projection.type === "perspective" && b.projection.type === "perspective"
      ? near(a.projection.fov, b.projection.fov, 1)
      : a.projection.type === "orthographic" && b.projection.type === "orthographic" && near(a.projection.height, b.projection.height, a.projection.height);
  return lens && near(a.aspect, b.aspect, a.aspect) && same(a.position, b.position) && same(a.target, b.target) && au.every((v, i) => near(v, bu[i]!, 1));
}

/**
 * The near and far planes for a camera. A perspective one keeps the viewer's
 * own (so that a view read from the viewport is drawn as the viewer draws
 * it), and goes further when the camera is far from the model; an
 * orthographic one has no viewer's to keep: it takes the model's depth.
 * `sphere` bounds the model, in the scene.
 */
export function depthRange(c: SceneCamera, sphere: { center: Vec3; radius: number }, viewer: { near: number; far: number }): { near: number; far: number } {
  const radius = Math.max(sphere.radius, 1e-9);
  const away = sub(sphere.center, c.position);
  if (c.projection.type === "orthographic") {
    const look = sub(c.target, c.position);
    const along = dot(away, look) / length(look);
    return { near: along - 2 * radius, far: along + 2 * radius };
  }
  return { near: viewer.near, far: Math.max(viewer.far, length(away) + 2 * radius) };
}

// ── Tiles ────────────────────────────────────────────────────────────────────

/** The biggest side of a tile whatever the GPU allows: a multisampled one of 4096 px is half a gigabyte. */
export const MAX_TILE = 2048;

export interface GlLimits {
  texture: number;
  renderbuffer: number;
  viewport: readonly [number, number];
}

/** Rendered pixels along a side for each pixel of the picture, where the context has no multisampling. */
export const SUPERSAMPLE = 2;

/** Samples along a side: one with a multisampled drawing buffer, else `SUPERSAMPLE`, or the forced value. */
export function supersampling(multisampled: boolean, forced?: number): number {
  if (forced !== undefined) return forced;
  return multisampled ? 1 : SUPERSAMPLE;
}

/**
 * A tile's side, in picture pixels: what the smallest limit allows once each
 * picture pixel takes `samples` along a side, never past `MAX_TILE`; `forced`
 * (a testing and tuning knob) can only make it smaller.
 */
export function tileSize(limits: GlLimits, samples: number, forced?: number): number {
  if (!Number.isSafeInteger(samples) || samples < 1 || samples > 8) throw new RasterError("invalid", "rasterSupersample is a whole number from 1 to 8");
  const edge = Math.min(limits.texture, limits.renderbuffer, limits.viewport[0], limits.viewport[1]);
  const side = Math.min(MAX_TILE, Math.floor(edge / samples));
  if (!(side >= 1)) throw new RasterError("too-large", "the GPU cannot hold a tile");
  if (forced === undefined) return side;
  if (!Number.isSafeInteger(forced) || forced < 1) throw new RasterError("invalid", "rasterTile is a whole number of pixels");
  return Math.min(side, forced);
}

/**
 * `setViewOffset`'s arguments for `tile` of a picture of `width` by `height`,
 * drawn with `samples` rendered pixels along a side for each of its own: the
 * full picture, then the tile within it, in rendered pixels.
 */
export function viewOffset(width: number, height: number, tile: Tile, samples: number) {
  return {
    fullWidth: width * samples,
    fullHeight: height * samples,
    x: tile.x * samples,
    y: tile.y * samples,
    width: tile.width * samples,
    height: tile.height * samples,
  };
}

// ── Ground ───────────────────────────────────────────────────────────────────

/** What a picture's background is when none is asked for. */
export type Ground =
  | { type: "none" }
  | { type: "solid"; color: string }
  /** A circle about `at` (fractions of the picture), reaching the farthest corner. */
  | { type: "radial"; at: readonly [number, number]; stops: readonly { offset: number; color: string }[] };

/** `text` cut at the commas that are not inside brackets. */
function split(text: string): string[] {
  const out: string[] = [];
  let depth = 0;
  let from = 0;
  for (let i = 0; i < text.length; i++) {
    if (text[i] === "(") depth++;
    else if (text[i] === ")") depth--;
    else if (text[i] === "," && depth === 0) {
      out.push(text.slice(from, i).trim());
      from = i + 1;
    }
  }
  out.push(text.slice(from).trim());
  return out;
}

const NUMBER = String.raw`(\d+(?:\.\d+)?)`;
const CIRCLE = new RegExp(`^circle(?:\\s+farthest-corner)?(?:\\s+at\\s+${NUMBER}%\\s+${NUMBER}%)?$`);
const STOP = new RegExp(`^(.+?)\\s+${NUMBER}%$`);

/**
 * The ground a stylesheet gives the model's surface, from the computed
 * `background-image` and `background-color`: a circular gradient to the
 * farthest corner (the default `--exav-viewer-model-bg`), else its middle
 * colour; a colour; else none.
 */
export function parseGround(image: string, color: string): Ground {
  const text = image.trim();
  if (text.startsWith("radial-gradient(") && text.endsWith(")")) {
    const parts = split(text.slice("radial-gradient(".length, -1));
    // The first part is a shape unless it is a colour stop; without one the shape is an ellipse, which is not read.
    const hasShape = /^(circle|ellipse|closest|farthest|at\s)/.test(parts[0] ?? "");
    const shape = hasShape ? CIRCLE.exec(parts[0] ?? "") : null;
    const stops = parts.slice(hasShape ? 1 : 0).map((p) => STOP.exec(p));
    const known = stops.every((s): s is RegExpExecArray => s !== null && isColor(s[1]));
    if (known && stops.length >= 2) {
      const list = stops.map((s) => ({ color: s![1]!, offset: Math.min(1, Number(s![2]) / 100) }));
      if (shape && list.every((s, i) => i === 0 || s.offset >= list[i - 1]!.offset)) {
        return { type: "radial", at: [shape[1] === undefined ? 0.5 : Number(shape[1]) / 100, shape[2] === undefined ? 0.5 : Number(shape[2]) / 100], stops: list };
      }
      // A shape not read: the colour in the middle stands for it.
      return { type: "solid", color: list[Math.floor(list.length / 2)]!.color };
    }
  }
  if (color && isColor(color) && !/^(transparent|rgba\(0,\s*0,\s*0,\s*0\))$/i.test(color.trim())) return { type: "solid", color };
  return { type: "none" };
}

/** The circle of a radial ground on a picture of `width` by `height`: its centre and radius, in pixels. */
export function groundCircle(at: readonly [number, number], width: number, height: number) {
  const x = at[0] * width;
  const y = at[1] * height;
  return { x, y, radius: Math.hypot(Math.max(x, width - x), Math.max(y, height - y)) };
}
