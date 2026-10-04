import { PDF_DECODERS } from "../../wasm/pdf_decoders.js";

/**
 * Where pdf.js's own assets are published: `<assetBase>pdfjs/<version>/`,
 * one directory per pdf.js version so a host can serve them immutable. Copied
 * there from the host's `pdfjs-dist` by `@exav/viewer/vite` (or the
 * `exav-viewer-assets` command).
 */
export function pdfjsAssetDir(assetBase: string, version: string): string {
  const base = assetBase.endsWith("/") ? assetBase : `${assetBase}/`;
  return `${base}pdfjs/${version}/`;
}

/**
 * pdf.js's `wasmUrl`: its ICC engine (qcms, Rust) beside this package's
 * JPEG 2000, JBIG2 and CCITT decoders, which stand in for its OpenJPEG and
 * PDFium ones (`openjpeg_nowasm_fallback.js`, `jbig2_nowasm_fallback.js`).
 * Named after both versions, as either can change the files.
 */
export function pdfjsWasmDir(assetBase: string, version: string): string {
  return `${pdfjsAssetDir(assetBase, version)}wasm-${PDF_DECODERS}/`;
}

/** The directories copied from `pdfjs-dist`. */
export const PDFJS_ASSET_DIRS = ["cmaps", "standard_fonts", "iccs", "wasm"] as const;
