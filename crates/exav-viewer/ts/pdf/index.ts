/**
 * `@exav/viewer/pdf`: PDF on pdf.js (a peer dependency, `pdfjs-dist` 5 or 6).
 *
 * Also exports the engine and the off-main-thread rasteriser for hosts that
 * draw pages themselves (thumbnails, sheets kept for offline use, a
 * `DetailSource` for an image of a page).
 */
import { MATCHERS } from "../core/formats.js";
import type { FormatPlugin } from "../core/types.js";
import { PDFJS_ASSET_DIRS, pdfjsAssetDir } from "./assets.js";

export interface PdfOptions {
  /** Zoom range, as multiples of the page fitted to the width. Default 1..6. */
  minZoom?: number;
  maxZoom?: number;
  /**
   * What a mouse drag does on a page larger than the viewer: "pan" (the
   * default) moves the page, as a hand does, "select" selects text. The user
   * can switch (the `drag` controller, and the default UI's toggle). On a
   * page that fits, a drag always selects.
   */
  drag?: "pan" | "select";
  /** Pages drawn ahead of the viewport, as a share of its height. Default "100%". */
  prerenderMargin?: string;
  /** Device pixels for one page's own bitmap. Default 8_388_608 (half iOS's canvas cap). */
  pageMaxPixels?: number;
  /** Device pixels for the sharp copy of what is on screen. Default 16_000_000. */
  detailMaxPixels?: number;
  /** Outline read at most this deep and this long. Defaults 3 and 200. */
  outlineMaxDepth?: number;
  outlineMaxEntries?: number;
}

export function pdf(options: PdfOptions = {}): FormatPlugin<PdfOptions> {
  return {
    id: "pdf",
    match: MATCHERS.pdf,
    capabilities: ["pages", "zoom", "drag", "outline"],
    options,
    load: () => import("./renderer.js").then((m) => m.renderer),
    async prefetch(assetBase) {
      // The library and its worker come with the load; the fonts, CMaps,
      // profiles and decoders are listed in the copy step's manifest.
      const [{ loadPdfjs }, { baseUrl, loadManifest }] = await Promise.all([import("./engine.js"), import("../core/assets.js")]);
      const [pdfjs, manifest] = await Promise.all([loadPdfjs(), loadManifest(assetBase)]);
      const dir = pdfjsAssetDir("", pdfjs.version).replace(/^\//, "");
      const ours = PDFJS_ASSET_DIRS.map((d) => `${dir}${d}/`);
      return manifest.all.filter((f) => ours.some((p) => f.startsWith(p))).map((f) => `${baseUrl(assetBase)}${f}`);
    },
  };
}

// What the viewer opens a document with, and where it looks for its assets,
// for a host that opens PDFs with pdf.js itself and wants the same options.
export { pdfjsAssetDir, pdfjsWasmDir } from "./assets.js";
export {
  createPdfEngine,
  documentOptions,
  renderDpr,
  type LoadedPdf,
  type PdfEngine,
  type PdfOutlineEntry,
  type PageRegion,
  type PageArea,
  type PdfLink,
  type PdfDestination,
  type PdfSource,
} from "./engine.js";
export { createPdfRasterizer, type PdfRasterizer } from "./rasterizer.js";
