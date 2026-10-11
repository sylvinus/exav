/**
 * The DWG and DXF plugins alone, without the engine `index.ts` re-exports:
 * what a bundle that loads the engine only on demand imports.
 */
import { MATCHERS } from "../core/formats.js";
import type { FormatPlugin } from "../core/types.js";

export interface CadOptions {
  /** Default "light". */
  ground?: "light" | "dark";
  /** Default { light: "#ffffff", dark: "#212830" }. Black is deliberately not offered. */
  colors?: { light: string; dark: string };
  /**
   * A directory serving the bundled fonts under their file names
   * (`@exav/viewer/assets/fonts/`), for hosts that publish them themselves.
   * By default they are the package's own, which the host's bundler emits.
   * Page-wide: a face is loaded once per page, from where the first drawing
   * that needed it said.
   */
  fontsUrl?: string;
  /**
   * How long parsing or drawing a layout may take before the engine is
   * stopped and the file reported unreadable. Default 120_000 (ms): a damaged
   * file can declare counts that keep the reader busy for minutes.
   */
  timeoutMs?: number;
  /**
   * Most strokes and fill vertices one layout may produce. Past it the
   * remaining entities are left out and the `scene_truncated` warning shown.
   * Default 8_000_000: about 220 MB of vertex buffers, four times the largest
   * real drawing measured. Lower it for memory-constrained devices.
   */
  maxPrimitives?: number;
  /**
   * Most bytes the compressed sections of a DWG (2004 and later) may expand
   * to while it is read; past it the file is reported unreadable. Default
   * 536_870_912 (512 MiB): a small hostile file can declare sections that
   * keep the reader expanding up to the limit.
   */
  maxDecompressedBytes?: number;
}

const CAPABILITIES = ["layers", "layouts", "ground", "zoom"] as const;

export function dwg(options: CadOptions = {}): FormatPlugin<CadOptions> {
  return {
    id: "dwg",
    match: MATCHERS.dwg,
    capabilities: CAPABILITIES,
    options,
    load: () => import("./view.js").then((m) => m.renderer),
  };
}

/** The same engine: exav-render's drawing model reads ASCII and binary DXF. */
export function dxf(options: CadOptions = {}): FormatPlugin<CadOptions> {
  return {
    id: "dxf",
    match: MATCHERS.dxf,
    capabilities: CAPABILITIES,
    options,
    load: () => import("./view.js").then((m) => m.renderer),
  };
}
