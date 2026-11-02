/**
 * The external converter: for the formats no converter of this package reads
 * (a drawing format, a page layout format, an Office format a native reader
 * refuses), a module the host installs, loaded where the host says. Any
 * package can be one.
 *
 * The module exports `convert`, and may export `prefetch`:
 *
 * ```ts
 * export function convert(bytes: Uint8Array, options: {
 *   hint: string;                        // what the viewer took the file for
 *   maxMemory?: number;                  // bytes the conversion may use
 *   signal?: AbortSignal;                // abort: reject with the signal's reason
 *   onProgress?: (p: ConvertProgress) => void;
 * }): Promise<{ format: "pdf" | "xlsx"; bytes: Uint8Array }>;
 * export function prefetch?(hint: string): string[] | Promise<string[]>;
 * ```
 *
 * The result is shown by the viewer's own `pdf()` or `xlsx()` plugin.
 */
import { baseUrl, loadManifest } from "../core/assets.js";
import type { Status } from "../core/types.js";

/**
 * How far a conversion is, in the order of the stages. A converter reports
 * what it has: the viewer turns each stage into a step of its status, with a
 * bar where a share is given.
 */
export type ConvertProgress =
  /** The converter's code and data arrive: bytes loaded, of `total` (0 when not known). */
  | { stage: "download"; loaded: number; total: number }
  /** The converter starts. */
  | { stage: "start" }
  /** The document is read, then the output written: steps `done` of `total`. */
  | { stage: "load" | "export"; done: number; total: number };

/** What the viewer hands `convert`. */
export interface ExternalConvertOptions {
  /**
   * What the viewer took the file for: "rtf", "doc", "odt", "ppt", "odp",
   * "keynote", "xls", "ods", "numbers", "odg", "visio", "coreldraw",
   * "publisher", "pagemaker", "freehand", "quarkxpress", "zonerdraw" or
   * "wpg". A hint: the bytes decide, and a converter may refuse a file that
   * is not what it was said to be.
   */
  hint: string;
  /** The most memory the conversion may use, in bytes; absent when the host set none. */
  maxMemory?: number;
  /** Aborted when the file is closed or the conversion takes too long: reject. */
  signal?: AbortSignal;
  onProgress?: (progress: ConvertProgress) => void;
}

/** What `convert` resolves to: a PDF, or an XLSX for the spreadsheet engine. */
export interface ExternalConvertResult {
  format: "pdf" | "xlsx";
  bytes: Uint8Array;
}

/** The module a host installs. */
export interface ExternalConverter {
  convert(bytes: Uint8Array, options: ExternalConvertOptions): Promise<ExternalConvertResult>;
  /** URLs, absolute or relative to the module, that `Viewer.prefetch` fetches for `hint`. */
  prefetch?(hint: string): string[] | Promise<string[]>;
}

/** The converter's progress as the viewer's steps. */
export function statusOf(p: ConvertProgress): Status {
  const share = (done: number, total: number) => (total > 0 ? { progress: Math.min(1, done / total) } : {});
  switch (p.stage) {
    case "download":
      return { phase: "loading", step: "engine", ...share(p.loaded, p.total) };
    case "start":
      return { phase: "converting", step: "start" };
    case "load":
      return { phase: "converting", step: "read", ...share(p.done, p.total) };
    case "export":
      return { phase: "converting", step: "convert", ...share(p.done, p.total) };
  }
}

/**
 * A file the viewer recognises and no converter of this host reads: there is
 * no `externalConverter`, or `converter: "external"` was asked for without
 * one. `format` is the viewer's name for it.
 */
export class NeedsConverterError extends Error {
  readonly kind = "needs-converter";
  constructor(readonly format: string) {
    super(`the ${format} file needs an external converter, and none is set`);
    this.name = "NeedsConverterError";
  }
}

/** The external converter failed: "timeout" when it did not answer in time, else "failed" (its error is the cause). */
export class ExternalConversionError extends Error {
  constructor(
    readonly format: string,
    readonly kind: "timeout" | "failed",
    cause?: unknown,
  ) {
    super(`the ${format} file could not be converted: ${kind}`, { cause });
    this.name = "ExternalConversionError";
  }
}

// A scheme, a rooted path or a relative path: a URL. Anything else is a package name.
const IS_URL = /^(?:[a-z][a-z0-9+.-]*:|\/|\.\.?\/)/i;

/**
 * Where the module is: a URL as it stands (relative ones against the page),
 * or the entry of a package named in the asset manifest (`converters`),
 * which the copy step of `@exav/viewer/vite` writes.
 */
export async function externalUrl(spec: string, assetBase: string): Promise<string> {
  if (IS_URL.test(spec)) return new URL(spec, document.baseURI).href;
  const entry = (await loadManifest(assetBase)).converters?.[spec];
  if (!entry) throw new Error(`${spec} is not in the asset manifest: install it beside @exav/viewer and copy the assets again with its name (externalConverter)`);
  return new URL(`${baseUrl(assetBase)}${entry}`, document.baseURI).href;
}

const modules = new Map<string, Promise<ExternalConverter>>();

/** The module at `url`, imported once; a failed import is tried again next time. */
export function loadExternal(url: string): Promise<ExternalConverter> {
  let m = modules.get(url);
  if (!m) {
    m = (import(/* @vite-ignore */ /* webpackIgnore: true */ url) as Promise<Partial<ExternalConverter>>).then((mod) => {
      if (typeof mod.convert !== "function") throw new Error(`${url} does not export convert()`);
      return mod as ExternalConverter;
    });
    modules.set(url, m);
    m.catch(() => modules.delete(url));
  }
  return m;
}
