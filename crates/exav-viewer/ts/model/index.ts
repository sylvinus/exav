/**
 * `@exav/viewer/model`: an STL (ASCII or binary), Wavefront OBJ, Stanford
 * PLY (ASCII or binary) or glTF 2.0 (`.gltf`, `.glb`) mesh read by exav's own
 * engine (exav-render, compiled to WebAssembly) in a worker, drawn with
 * three.js (a peer dependency), lit by an environment, standing on a shadow
 * catcher. Orbit, pan, zoom, and the triangle count. Nothing is fetched: a
 * glTF whose buffers are other files is refused.
 *
 * Pictures (`controllers.pictures`, one page) are drawn again from the
 * geometry at any size, by a renderer off screen, and the viewport is the
 * camera in view. Both speak of a camera (`CameraRegion`) in the file's own
 * coordinates, see `ModelFrame` in `./camera.ts`: `up` defaults to Z for the
 * files shown Z up (STL by default, see `zUp`), else Y.
 */
import { MATCHERS } from "../core/formats.js";
import type { FormatPlugin } from "../core/types.js";

export interface ModelOptions {
  /** Mesh colour when the file carries none. Default 0x8c97a8. */
  surface?: number;
  /**
   * Whether the file's up axis is Z, and three.js is Y-up. Default true for
   * STL, false for OBJ, PLY and glTF.
   */
  zUp?: boolean;
  /** How long reading may take before the engine is stopped. Default 120_000 (ms). */
  timeoutMs?: number;
  /**
   * Most triangles read; past them the rest of the file is left out and the
   * `model_partial` warning shown. Default 6_000_000.
   */
  maxTriangles?: number;
  /**
   * Testing and tuning: the biggest tile (px a side) a picture
   * (`controllers.pictures`) is drawn in. Never more than the GPU allows
   * (and 2048); a picture needing more than 4096 tiles is refused.
   */
  rasterTile?: number;
  /**
   * Testing and tuning: pixels drawn along a side for each pixel of a picture,
   * 1 to 8. Default 1 where the GPU antialiases, else 2.
   */
  rasterSupersample?: number;
}

export function stl(options: ModelOptions = {}): FormatPlugin<ModelOptions> {
  return {
    id: "stl",
    match: MATCHERS.stl,
    capabilities: ["info", "pictures", "viewport"],
    options,
    load: () => import("./stl.js").then((m) => m.rendererFor("stl")),
  };
}

/** Wavefront OBJ: vertex colours and groups; materials and textures are not read. */
export function obj(options: ModelOptions = {}): FormatPlugin<ModelOptions> {
  return {
    id: "obj",
    match: MATCHERS.obj,
    capabilities: ["info", "pictures", "viewport"],
    options,
    load: () => import("./stl.js").then((m) => m.rendererFor("obj")),
  };
}

/** Stanford PLY with faces; a point cloud is refused. */
export function ply(options: ModelOptions = {}): FormatPlugin<ModelOptions> {
  return {
    id: "ply",
    match: MATCHERS.ply,
    capabilities: ["info", "pictures", "viewport"],
    options,
    load: () => import("./stl.js").then((m) => m.rendererFor("ply")),
  };
}

/** glTF 2.0, `.gltf` with its buffers embedded as `data:` URIs, and `.glb`; textures and animations are not read. */
export function gltf(options: ModelOptions = {}): FormatPlugin<ModelOptions> {
  return {
    id: "gltf",
    match: MATCHERS.gltf,
    capabilities: ["info", "pictures", "viewport"],
    options,
    load: () => import("./stl.js").then((m) => m.rendererFor("gltf")),
  };
}
