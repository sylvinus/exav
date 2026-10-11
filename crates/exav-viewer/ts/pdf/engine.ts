/**
 * pdf.js, opened the one way this package opens it: for untrusted files, and
 * with every asset from the host's own origin.
 */
import type { PDFDocumentProxy } from "pdfjs-dist";

import type { ByteRanges } from "../core/types.js";
import { linkTarget } from "../frame/protocol.js";
import { pdfjsAssetDir, pdfjsWasmDir } from "./assets.js";

/** Part of a page, in CSS pixels of the page drawn at a given width. */
export interface PageRegion {
  x: number;
  y: number;
  width: number;
  height: number;
}

/** Part of a page, in fractions of its width and height as shown (rotation applied). */
export type PageArea = PageRegion;

/**
 * A link on a page: one area per line it covers, and either an absolute
 * http(s) address or a destination in the document (`destination()`).
 */
export type PdfLink = { areas: PageArea[]; url: string } | { areas: PageArea[]; dest: unknown };

/** Where a destination is: its page (1-based), and how far down as a fraction of the page's height, or null. */
export interface PdfDestination {
  pageNumber: number;
  offset: number | null;
}

/** Link areas kept for one page: a file can hold any number. */
export const MAX_LINK_AREAS = 1000;

/**
 * `ranges`: read by pdf.js as it needs them, the pages on screen first.
 * `onError` hears of a read that failed once the document is open: pdf.js
 * itself would wait for it forever.
 */
export type PdfSource = { url: string } | { data: Uint8Array } | { ranges: ByteRanges; onError?: (error: unknown) => void };

/** What pdf.js is given at once, and asks for at a time, from a file read by ranges. */
const RANGE_CHUNK = 65_536;

/** One entry of a document's own outline, flattened. */
export interface PdfOutlineEntry {
  title: string;
  /** 1-based. */
  pageNumber: number;
  /** 0 at the top level. */
  depth: number;
  /** Fraction of the page's height, or null for a destination with no position. */
  offset: number | null;
}

export interface LoadedPdf {
  numPages: number;
  /** In PDF points (CSS pixels at scale 1), from the object that renders. */
  pageSize(page: number): Promise<{ width: number; height: number }>;
  /** Width over height, without drawing. */
  pageAspect(page: number): Promise<number>;
  /** The page at `scale`, on white, as PNG. The canvas is freed at once. */
  renderPageToBlob(page: number, scale: number): Promise<Blob>;
  /**
   * Draws `page` into `canvas` as if it were `cssWidth` CSS pixels wide, at
   * `renderDpr()`; with `region`, only that part (CSS pixels of the page at
   * that width). Sets the bitmap size only. Drawn off screen and copied in,
   * so the canvas keeps its picture meanwhile. Renders into one canvas are
   * queued and the newest wins: an overtaken call resolves false.
   */
  renderPageTo(canvas: HTMLCanvasElement, page: number, cssWidth: number, region?: PageRegion): Promise<boolean>;
  /** Stops what is drawing into `canvas`, quietly. Call before freeing it. */
  cancelRender(canvas: HTMLCanvasElement): void;
  /** At most `maxDepth` levels and `maxEntries` entries; a broken outline is empty. */
  outline(limits?: { maxDepth?: number; maxEntries?: number }): Promise<PdfOutlineEntry[]>;
  /**
   * pdf.js's text layer for `page`, built in `container`: the page's text
   * as transparent runs placed over the drawing, to select and copy. Sized
   * by the CSS variable `--scale-factor` (CSS pixels per PDF point) of an
   * ancestor, so that a zoom needs no new layout. `done` rejects when
   * cancelled or when the text cannot be read.
   */
  textLayer(page: number, container: HTMLElement): { done: Promise<void>; cancel(): void };
  /** The links of `page`, at most `MAX_LINK_AREAS` areas; none when the page's annotations cannot be read. */
  links(page: number): Promise<PdfLink[]>;
  /** Where a link's `dest` leads, or null. */
  destination(dest: unknown): Promise<PdfDestination | null>;
  destroy(): void;
}

export interface PdfEngine {
  open(source: PdfSource, signal?: AbortSignal): Promise<LoadedPdf>;
  /** Device pixels per CSS pixel for rendering: the screen's, at most 2. */
  renderDpr(): number;
}

export function renderDpr(): number {
  return Math.min((typeof window !== "undefined" && window.devicePixelRatio) || 1, 2);
}

/**
 * The options every document is opened with, here and in the rasteriser's
 * worker.
 *
 * - `isEvalSupported: false`: pdf.js otherwise compiles PostScript functions
 *   and font programs from the file with `new Function`. Scripting is never
 *   enabled (pdf.js's API does not run a document's JavaScript).
 * - `useSystemFonts: false`: an unembedded standard font is drawn with the
 *   bundled face, not whatever the device has, so a document measures the
 *   same everywhere. It needs `standardFontDataUrl`.
 * - CMaps, ICC profiles and the image decoders from the host, so that
 *   nothing is fetched from another origin and nothing renders with the
 *   wrong glyphs for want of a table.
 * - `wasmUrl` holds pdf.js's ICC engine and, in place of its OpenJPEG and
 *   PDFium decoders, this package's (see `pdfjsWasmDir`). `useWasm` stays
 *   on: it is what loads the ICC engine and compiles PostScript functions.
 */
export function documentOptions(assetBase: string, version: string) {
  const dir = pdfjsAssetDir(assetBase, version);
  return {
    isEvalSupported: false,
    useSystemFonts: false,
    enableXfa: false,
    standardFontDataUrl: `${dir}standard_fonts/`,
    cMapUrl: `${dir}cmaps/`,
    cMapPacked: true,
    iccUrl: `${dir}iccs/`,
    wasmUrl: pdfjsWasmDir(assetBase, version),
    useWasm: true,
  };
}

const noop = () => {};

type Pdfjs = typeof import("pdfjs-dist");

let pdfjsReady: Promise<{ pdfjs: Pdfjs; worker: InstanceType<Pdfjs["PDFWorker"]> }> | null = null;

/**
 * The library, and one worker (started from this package, bundled by the
 * host) that every document is given explicitly. Documents opened through
 * `GlobalWorkerOptions.workerPort` instead share a PDFWorker that pdf.js
 * tears down with whichever of them is destroyed first: the others break,
 * and a document opened while it goes is refused.
 */
function loadPdfjsAndWorker() {
  pdfjsReady ??= (async () => {
    const pdfjs = await import("pdfjs-dist");
    const port = new Worker(new URL("./pdfjs.worker.js", import.meta.url), { type: "module" });
    // A new port: `create` makes a new PDFWorker for it.
    return { pdfjs, worker: pdfjs.PDFWorker.create({ port }) };
  })();
  pdfjsReady.catch(() => (pdfjsReady = null));
  return pdfjsReady;
}

export async function loadPdfjs(): Promise<Pdfjs> {
  return (await loadPdfjsAndWorker()).pdfjs;
}

export function createPdfEngine(config: { assetBase?: string } = {}): PdfEngine {
  const assetBase = config.assetBase ?? "/exav-viewer/";
  return {
    renderDpr,
    async open(source, signal) {
      const { pdfjs, worker } = await loadPdfjsAndWorker();
      let params: { url: string } | { data: Uint8Array } | { range: InstanceType<Pdfjs["PDFDataRangeTransport"]>; disableAutoFetch: boolean; disableStream: boolean; rangeChunkSize: number };
      let readFailed: (error: unknown) => void = () => {};
      /** The read that failed the opening, if one did. */
      const failure: { error?: unknown } = {};
      if ("ranges" in source) {
        const { ranges } = source;
        const reads = new AbortController();
        signal?.addEventListener("abort", () => reads.abort(), { once: true });
        const initial = await ranges.read(0, Math.min(ranges.size, RANGE_CHUNK), reads.signal);
        class Transport extends pdfjs.PDFDataRangeTransport {
          override requestDataRange(begin: number, end: number) {
            ranges.read(begin, end - begin, reads.signal).then(
              (chunk) => !reads.signal.aborted && this.onDataRange(begin, chunk),
              (error) => !reads.signal.aborted && readFailed(error),
            );
          }
          override abort() {
            reads.abort();
          }
        }
        // Only what is asked for: no prefetch of the rest, no progressive read.
        params = { range: new Transport(ranges.size, initial), disableAutoFetch: true, disableStream: true, rangeChunkSize: RANGE_CHUNK };
      } else {
        params = source;
      }
      const task = pdfjs.getDocument({ ...params, ...documentOptions(assetBase, pdfjs.version), worker });
      if ("ranges" in source) {
        // While the document opens, a failed read fails the opening; later, the caller hears of it.
        readFailed = (error) => {
          if (!("error" in failure)) failure.error = error;
          void task.destroy();
        };
        task.promise.then(
          () => (readFailed = (error) => source.onError?.(error)),
          () => {},
        );
      }
      const abort = () => void task.destroy();
      signal?.addEventListener("abort", abort, { once: true });
      try {
        return wrap(await task.promise, pdfjs);
      } catch (error) {
        if (signal?.aborted) throw new DOMException("aborted", "AbortError");
        if ("error" in failure) throw failure.error;
        throw error;
      } finally {
        signal?.removeEventListener("abort", abort);
      }
    },
  };
}

function wrap(doc: PDFDocumentProxy, pdfjs: Pdfjs): LoadedPdf {
  // pdf.js refuses a second render on a canvas the first is drawing into, so
  // renders for one canvas are chained, and only the newest may report.
  const generation = new Map<HTMLCanvasElement, number>();
  const chain = new Map<HTMLCanvasElement, Promise<void>>();
  const inFlight = new Map<HTMLCanvasElement, { cancel: () => void }>();

  const claim = (canvas: HTMLCanvasElement): number => {
    const mine = (generation.get(canvas) ?? 0) + 1;
    generation.set(canvas, mine);
    inFlight.get(canvas)?.cancel();
    return mine;
  };

  const pageSize = async (n: number) => {
    const { width, height } = (await doc.getPage(n)).getViewport({ scale: 1 });
    return { width, height };
  };
  const destination = destinationResolver(doc);

  return {
    numPages: doc.numPages,
    pageSize,
    async pageAspect(n) {
      const { width, height } = await pageSize(n);
      return width / height;
    },
    async renderPageToBlob(n, scale) {
      const page = await doc.getPage(n);
      const viewport = page.getViewport({ scale });
      const canvas = document.createElement("canvas");
      canvas.width = Math.max(1, Math.floor(viewport.width));
      canvas.height = Math.max(1, Math.floor(viewport.height));
      try {
        // A page is transparent where nothing is drawn: on white, as on paper.
        await page.render({ canvas, viewport, background: "#ffffff" }).promise;
        const blob = await new Promise<Blob | null>((resolve) => canvas.toBlob(resolve, "image/png"));
        if (!blob) throw new Error("could not encode the page");
        return blob;
      } finally {
        canvas.width = 0;
        canvas.height = 0;
      }
    },
    renderPageTo(canvas, n, cssWidth, region) {
      const mine = claim(canvas);
      const run = (chain.get(canvas) ?? Promise.resolve()).catch(noop).then(async () => {
        if (generation.get(canvas) !== mine) return false;
        const page = await doc.getPage(n);
        const natural = page.getViewport({ scale: 1 });
        const dpr = renderDpr();
        const scale = (cssWidth / natural.width) * dpr;
        const viewport = region
          ? page.getViewport({ scale, offsetX: -region.x * dpr, offsetY: -region.y * dpr })
          : page.getViewport({ scale });
        const width = Math.max(1, Math.floor(region ? region.width * dpr : viewport.width));
        const height = Math.max(1, Math.floor(region ? region.height * dpr : viewport.height));
        const buffer = document.createElement("canvas");
        buffer.width = width;
        buffer.height = height;
        const free = () => {
          buffer.width = 0;
          buffer.height = 0;
        };
        // Opaque: a region lies over a blurrier copy of the same page.
        const task = page.render({ canvas: buffer, viewport, background: "#ffffff" });
        inFlight.set(canvas, task);
        try {
          await task.promise;
        } catch (error) {
          free();
          if (generation.get(canvas) !== mine) return false;
          throw error;
        } finally {
          if (inFlight.get(canvas) === task) inFlight.delete(canvas);
        }
        if (generation.get(canvas) !== mine) {
          free();
          return false;
        }
        canvas.width = width;
        canvas.height = height;
        canvas.getContext("2d")?.drawImage(buffer, 0, 0);
        free();
        return true;
      });
      chain.set(canvas, run.then(noop, noop));
      return run;
    },
    cancelRender(canvas) {
      claim(canvas);
    },
    outline: (limits) => readOutline(doc, limits?.maxDepth ?? 3, limits?.maxEntries ?? 200),
    textLayer(n, container) {
      let layer: InstanceType<Pdfjs["TextLayer"]> | null = null;
      let cancelled = false;
      const done = (async () => {
        const page = await doc.getPage(n);
        if (cancelled) throw new DOMException("cancelled", "AbortError");
        const viewport = page.getViewport({ scale: 1 });
        // pdf.js sizes the layer and its text by `--total-scale-factor`,
        // which counts the page's user unit (points per unit, usually 1).
        container.style.setProperty("--total-scale-factor", `calc(var(--scale-factor) * ${viewport.userUnit ?? 1})`);
        // Normalised (ligatures split), as it should read once copied.
        layer = new pdfjs.TextLayer({ textContentSource: page.streamTextContent(), container, viewport });
        await layer.render();
      })();
      return {
        done,
        cancel() {
          cancelled = true;
          layer?.cancel();
        },
      };
    },
    async links(n) {
      try {
        const page = await doc.getPage(n);
        const viewport = page.getViewport({ scale: 1 });
        return readLinks(await page.getAnnotations({ intent: "display" }), viewport, pdfjs.AnnotationType.LINK);
      } catch {
        return [];
      }
    },
    destination,
    destroy() {
      for (const canvas of [...generation.keys()]) claim(canvas);
      generation.clear();
      chain.clear();
      inFlight.clear();
      void doc.loadingTask.destroy();
      // The text layers' measuring canvases, once no layer is being built.
      pdfjs.TextLayer.cleanup();
    },
  };
}

/** What `readLinks` reads of a pdf.js annotation. */
export interface AnnotationLike {
  annotationType?: unknown;
  rect?: unknown;
  quadPoints?: unknown;
  url?: unknown;
  dest?: unknown;
}

/** What `readLinks` needs of a pdf.js viewport at scale 1. */
export interface ViewportLike {
  width: number;
  height: number;
  convertToViewportPoint(x: number, y: number): number[];
}

/**
 * The links among a page's annotations that lead to an absolute http(s)
 * address or to a destination in the document. pdf.js gives a link one of
 * an address, a destination, or another action (named, attachment, layers,
 * which are left out). Each quadrilateral of a link spanning several lines
 * is an area of its own; without any, its rectangle is. At most
 * `MAX_LINK_AREAS` areas.
 */
export function readLinks(annotations: readonly AnnotationLike[], viewport: ViewportLike, linkType: number): PdfLink[] {
  const links: PdfLink[] = [];
  let count = 0;
  for (const a of annotations) {
    if (count >= MAX_LINK_AREAS) break;
    if (a.annotationType !== linkType) continue;
    let target: { url: string } | { dest: unknown } | null = null;
    if (a.url !== undefined && a.url !== null) {
      const url = typeof a.url === "string" ? linkTarget(a.url) : null;
      if (url) target = { url };
    } else if (typeof a.dest === "string" ? a.dest !== "" : Array.isArray(a.dest)) {
      target = { dest: a.dest };
    }
    if (!target) continue;
    const areas: PageArea[] = [];
    for (const rect of quadRects(a.quadPoints) ?? [a.rect]) {
      if (count >= MAX_LINK_AREAS) break;
      const area = toArea(rect, viewport);
      if (!area) continue;
      areas.push(area);
      count++;
    }
    if (areas.length) links.push({ ...target, areas });
  }
  return links;
}

/** Each quadrilateral's bounding rectangle, in PDF space; null when there are none. */
function quadRects(points: unknown): number[][] | null {
  if (!points || typeof (points as ArrayLike<number>).length !== "number") return null;
  const p = points as ArrayLike<number>;
  const rects: number[][] = [];
  for (let i = 0; i + 8 <= p.length; i += 8) {
    const xs = [p[i]!, p[i + 2]!, p[i + 4]!, p[i + 6]!];
    const ys = [p[i + 1]!, p[i + 3]!, p[i + 5]!, p[i + 7]!];
    rects.push([Math.min(...xs), Math.min(...ys), Math.max(...xs), Math.max(...ys)]);
  }
  return rects.length ? rects : null;
}

/** A PDF-space rectangle as fractions of the page shown, clipped to it; null when nothing is left. */
function toArea(rect: unknown, viewport: ViewportLike): PageArea | null {
  if (!Array.isArray(rect) || rect.length !== 4 || !rect.every((v) => typeof v === "number" && Number.isFinite(v))) return null;
  if (!(viewport.width > 0) || !(viewport.height > 0)) return null;
  const [x1, y1] = viewport.convertToViewportPoint(rect[0], rect[1]) as [number, number];
  const [x2, y2] = viewport.convertToViewportPoint(rect[2], rect[3]) as [number, number];
  const clip = (v: number) => Math.min(1, Math.max(0, v));
  const left = clip(Math.min(x1, x2) / viewport.width);
  const right = clip(Math.max(x1, x2) / viewport.width);
  const top = clip(Math.min(y1, y2) / viewport.height);
  const bottom = clip(Math.max(y1, y2) / viewport.height);
  if (right <= left || bottom <= top) return null;
  return { x: left, y: top, width: right - left, height: bottom - top };
}

/**
 * The outline, flattened, each entry resolved to its page and how far down
 * it. Bounded, since the file is untrusted, and a malformed outline costs the
 * outline, never the document. Entries with no title or no target are left
 * out: a heading that does not move the document reads as a broken viewer.
 */
export async function readOutline(doc: PDFDocumentProxy, maxDepth: number, maxEntries: number): Promise<PdfOutlineEntry[]> {
  const roots = await doc.getOutline().catch(() => null);
  if (!roots?.length) return [];
  const entries: PdfOutlineEntry[] = [];
  const resolve = destinationResolver(doc);

  const walk = async (nodes: unknown[], depth: number): Promise<void> => {
    if (depth >= maxDepth) return;
    for (const raw of nodes) {
      if (entries.length >= maxEntries) return;
      const node = raw as { title?: unknown; dest?: unknown; items?: unknown };
      const title = typeof node.title === "string" ? node.title.trim() : "";
      const target = title ? await resolve(node.dest) : null;
      if (title && target) entries.push({ title, depth, ...target });
      if (Array.isArray(node.items)) await walk(node.items, depth + 1);
    }
  };
  await walk(roots, 0);
  return entries;
}

/**
 * Resolves a destination (a name, or an explicit array) to its page and how
 * far down it, remembering pages and boxes already looked up. A destination
 * that cannot be resolved is null, never an error.
 */
function destinationResolver(doc: PDFDocumentProxy): (dest: unknown) => Promise<PdfDestination | null> {
  const pageOfRef = new Map<string, number>();
  const boxOfPage = new Map<number, { height: number; toViewport: (y: number) => number }>();

  return async (dest) => {
    try {
      const explicit = typeof dest === "string" ? await doc.getDestination(dest) : (dest as unknown[] | null);
      if (!Array.isArray(explicit) || !explicit[0]) return null;
      const key = JSON.stringify(explicit[0]);
      let pageNumber = pageOfRef.get(key);
      if (pageNumber === undefined) {
        pageNumber = (await doc.getPageIndex(explicit[0] as never)) + 1;
        pageOfRef.set(key, pageNumber);
      }
      const top = verticalOf(explicit);
      if (top === null) return { pageNumber, offset: null };
      let box = boxOfPage.get(pageNumber);
      if (!box) {
        const viewport = (await doc.getPage(pageNumber)).getViewport({ scale: 1 });
        // Through the viewport, which carries the page's rotation and origin.
        box = { height: viewport.height, toViewport: (y) => viewport.convertToViewportPoint(0, y)[1] as number };
        boxOfPage.set(pageNumber, box);
      }
      if (!box.height) return { pageNumber, offset: null };
      const fraction = box.toViewport(top) / box.height;
      if (!Number.isFinite(fraction)) return { pageNumber, offset: null };
      return { pageNumber, offset: Math.min(1, Math.max(0, fraction)) };
    } catch {
      return null;
    }
  };
}

/** The vertical coordinate a destination carries: XYZ, FitH, FitBH and FitR have one. */
export function verticalOf(dest: unknown[]): number | null {
  const kind = (dest[1] as { name?: string } | undefined)?.name ?? "";
  const at = (i: number) => {
    const v = dest[i];
    return typeof v === "number" && Number.isFinite(v) ? v : null;
  };
  switch (kind) {
    case "XYZ":
      return at(3);
    case "FitH":
    case "FitBH":
      return at(2);
    case "FitR":
      return at(5);
    default:
      return null;
  }
}
