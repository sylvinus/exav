/**
 * `@exav/viewer/ifc`: IFC models (IFC2X3, IFC4, IFC4X3) read and meshed by
 * exav's own engine (exav-render, Rust compiled to WebAssembly) in a
 * worker, drawn with three.js (a peer dependency). Categories can be
 * hidden, and so can building storeys (`controllers.storeys`, when the model
 * has two or more with something in them), and a tapped element says what it
 * is and where.
 *
 * Pictures (`controllers.pictures`, one page: the model) are drawn again from
 * the geometry at any size, by a renderer off screen, and the viewport is the
 * camera in view. Both speak of a camera (`CameraRegion`) in the IFC's own
 * coordinates (metres, Z up: `up` defaults to (0, 0, 1)), see `ModelFrame` in
 * `../model/camera.ts`. A picture shows what the viewer shows (hidden
 * categories stay hidden) and not its floor grid or selection.
 */
import { MATCHERS } from "../core/formats.js";
import type { FormatPlugin } from "../core/types.js";

export interface IfcOptions {
  /** Default "light". */
  ground?: "light" | "dark";
  /** Default { light: "#ffffff", dark: "#212830" }. */
  colors?: { light: string; dark: string };
  /** Selection colour. Default "#0284c7". */
  highlight?: string;
  /**
   * How long reading the model may take before the engine is stopped and
   * the file reported unreadable. Default 120_000 (ms).
   */
  timeoutMs?: number;
  /**
   * Most triangles the model may produce. Past it the remaining elements
   * are left out and the `model_truncated` warning shown. Default
   * 6_000_000: about 330 MB of vertex buffers. Lower it for
   * memory-constrained devices.
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

export function ifc(options: IfcOptions = {}): FormatPlugin<IfcOptions> {
  return {
    id: "ifc",
    match: MATCHERS.ifc,
    capabilities: ["layers", "storeys", "ground", "selection", "pictures", "viewport"],
    options,
    load: () => import("./renderer.js").then((m) => m.renderer),
  };
}
