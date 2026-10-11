/**
 * `@exav/viewer/model`: an STL mesh (ASCII or binary) read by exav's own
 * engine (exav-render, compiled to WebAssembly) in a worker, drawn with
 * three.js (a peer dependency), lit by an environment, standing on a shadow
 * catcher. Orbit, pan, zoom, and the triangle count.
 */
import { MATCHERS } from "../core/formats.js";
import type { FormatPlugin } from "../core/types.js";

export interface ModelOptions {
  /** Mesh colour when the file carries none. Default 0x8c97a8. */
  surface?: number;
  /** STL is Z-up and three.js Y-up. Default true. */
  zUp?: boolean;
  /** How long reading may take before the engine is stopped. Default 120_000 (ms). */
  timeoutMs?: number;
  /**
   * Most triangles read; past them the rest of the file is left out and the
   * `model_partial` warning shown. Default 6_000_000.
   */
  maxTriangles?: number;
}

export function stl(options: ModelOptions = {}): FormatPlugin<ModelOptions> {
  return {
    id: "stl",
    match: MATCHERS.stl,
    capabilities: ["info"],
    options,
    load: () => import("./stl.js").then((m) => m.renderer),
  };
}
