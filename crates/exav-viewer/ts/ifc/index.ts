/**
 * `@exav/viewer/ifc`: IFC models (IFC2X3, IFC4, IFC4X3) read and meshed by
 * exav's own engine (exav-render, Rust compiled to WebAssembly) in a
 * worker, drawn with three.js (a peer dependency). Categories can be
 * hidden, and a tapped element says what it is and where.
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
}

export function ifc(options: IfcOptions = {}): FormatPlugin<IfcOptions> {
  return {
    id: "ifc",
    match: MATCHERS.ifc,
    capabilities: ["layers", "ground", "selection"],
    options,
    load: () => import("./renderer.js").then((m) => m.renderer),
  };
}
