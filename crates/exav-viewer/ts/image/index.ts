/**
 * `@exav/viewer/image`: one picture on a zoomable surface, with layers a host
 * draws on (annotations, markers) and a way to redraw it sharp past its
 * resolution. With `wasmDecoders`, the formats browsers do not draw (TIFF in
 * most of them, BMP variants, ICO, PNM, QOI, DDS, farbfeld, HDR, JPEG 2000,
 * JBIG2) are decoded by exav-render's memory-safe decoders in WebAssembly.
 */
import { MATCHERS, WASM_IMAGES } from "../core/formats.js";
import type { DetailSource, FormatMatcher, FormatPlugin, ImageSurface, OverlayHost, ViewerFile } from "../core/types.js";

export interface ImageOptions<Meta = unknown> {
  /** Per file: redraws the visible region sharp past the raster's resolution. */
  detail?: (file: ViewerFile<Meta>) => DetailSource | undefined;
  /** Per file: layers drawn over the image. */
  overlay?: (file: ViewerFile<Meta>) => OverlayHost | undefined;
  /**
   * A deliberate tap: one primary pointer, moved less than `tapSlop` px, not
   * part of a pinch, inside the page. `point` in fractions of the page;
   * `context.screen` the same place in container pixels, where a host's
   * `screenLayer` markers (which never get a `click`: the surface captures
   * the pointer) are hit-tested against `surface.toScreen`.
   */
  onTap?: (
    file: ViewerFile<Meta>,
    point: { x: number; y: number },
    context: { surface: ImageSurface; event: PointerEvent; screen: { x: number; y: number } },
  ) => void;
  /** Default 8 (px). */
  tapSlop?: number;
  /** Stage scale range. Default 0.5..8. */
  minScale?: number;
  maxScale?: number;
  /** Wheel step, multiplicative. Default 0.08. */
  wheelStep?: number;
  /**
   * What a plain wheel or two-finger scroll does: "zoom" about the pointer
   * (default), or "pan" the sheet, as a document reader scrolls. With either,
   * Ctrl or ⌘ with the wheel (a trackpad pinch) zooms.
   */
  wheel?: "zoom" | "pan";
  /** Stillness before the detail is redrawn. Default 150 ms. */
  detailDelayMs?: number;
  /** Screen px drawn sharp beyond each edge. Default 64. */
  detailMargin?: number;
  /** Device pixels for the detail. Default 16_000_000. */
  detailMaxPixels?: number;
  /** Decode what the browser cannot with exav-render (WebAssembly). Default false. */
  wasmDecoders?: boolean;
  /** Most bytes of decoded RGBA the WebAssembly decoders may produce. Default 256 MiB. */
  maxDecodeBytes?: number;
  /**
   * The `<img>`'s `crossOrigin`. Default "anonymous": a URL on another
   * origin must answer with CORS headers, and its pixels can be read back (a
   * canvas export, a hit test). `null` shows it without CORS, unreadable.
   */
  crossOrigin?: "anonymous" | "use-credentials" | null;
}

function merge(a: FormatMatcher, b: FormatMatcher): FormatMatcher {
  return { types: [...(a.types ?? []), ...(b.types ?? [])], extensions: [...(a.extensions ?? []), ...(b.extensions ?? [])] };
}

export function image<Meta = unknown>(options: ImageOptions<Meta> = {}): FormatPlugin<ImageOptions<Meta>> {
  return {
    id: "image",
    match: options.wasmDecoders ? merge(MATCHERS.image, WASM_IMAGES) : MATCHERS.image,
    capabilities: ["zoom", "image-surface"],
    options,
    load: () => import("./renderer.js").then((m) => m.renderer as never),
  };
}
