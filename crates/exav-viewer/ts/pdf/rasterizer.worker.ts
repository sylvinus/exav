/**
 * Draws PDF pages off the main thread (see `rasterizer.ts`).
 *
 * Documents stay open between requests, and requests run one at a time in
 * the order they came: a host asking for a hundred sheets gets one canvas
 * alive at a time, not a hundred. Region requests carry a slot, and only the
 * newest of a slot is drawn: the others are answered `superseded`.
 */
import * as pdfjs from "pdfjs-dist";
// pdf.js parses in place when its parser is registered on
// `globalThis.pdfjsWorker`: no nested worker. Importing it also makes it post
// one message of its own, with no `id`, which the client ignores.
import * as pdfjsParser from "pdfjs-dist/build/pdf.worker.min.mjs";

import { documentOptions } from "./engine.js";
import type { RasterRequest, RasterResponse } from "./rasterizer.js";

(globalThis as { pdfjsWorker?: unknown }).pdfjsWorker = pdfjsParser;

type PdfDocument = Awaited<ReturnType<typeof pdfjs.getDocument>["promise"]>;

const scope = self as unknown as {
  postMessage(message: RasterResponse, transfer?: Transferable[]): void;
  onmessage: ((event: MessageEvent<RasterRequest>) => void) | null;
};

/** Scratch canvases for pdf.js (soft masks, patterns): there is no `document` here. */
class OffscreenCanvasFactory {
  create(width: number, height: number) {
    const canvas = new OffscreenCanvas(width, height);
    return { canvas, context: canvas.getContext("2d") };
  }
  reset(target: { canvas: OffscreenCanvas }, width: number, height: number) {
    target.canvas.width = width;
    target.canvas.height = height;
  }
  destroy(target: { canvas: OffscreenCanvas | null; context: unknown }) {
    if (target.canvas) {
      target.canvas.width = 0;
      target.canvas.height = 0;
    }
    target.canvas = null;
    target.context = null;
  }
}

/** pdf.js's SVG filters need a DOM; without one they are skipped. */
class NoFilterFactory {
  addFilter() {
    return "none";
  }
  addHCMFilter() {
    return "none";
  }
  addAlphaFilter() {
    return "none";
  }
  addLuminosityFilter() {
    return "none";
  }
  addHighlightHCMFilter() {
    return "none";
  }
  destroy() {}
}

/**
 * What pdf.js otherwise takes from `document`, which a worker has none of:
 * fonts and CMaps are fetched from here, and text drawn from glyph outlines.
 */
const WORKER_OPTIONS = {
  useWorkerFetch: true,
  disableFontFace: true,
  CanvasFactory: OffscreenCanvasFactory,
  FilterFactory: NoFilterFactory,
};

const open = new Map<string, Promise<PdfDocument>>();
const latestRegion = new Map<string, number>();

async function render(page: Awaited<ReturnType<PdfDocument["getPage"]>>, canvas: OffscreenCanvas, viewport: ReturnType<typeof page.getViewport>) {
  const ctx = canvas.getContext("2d");
  if (!ctx) throw new Error("no 2d context");
  // Transparent where nothing is drawn: on white, as on paper.
  ctx.fillStyle = "#ffffff";
  ctx.fillRect(0, 0, canvas.width, canvas.height);
  await page.render({ canvas: null, canvasContext: ctx as unknown as CanvasRenderingContext2D, viewport }).promise;
}

async function handle(r: RasterRequest): Promise<RasterResponse> {
  switch (r.kind) {
    case "open": {
      const task = pdfjs.getDocument({
        data: new Uint8Array(r.data),
        ...documentOptions(r.assetBase, pdfjs.version),
        ...WORKER_OPTIONS,
      });
      open.set(r.document, task.promise);
      try {
        await task.promise;
        return { id: r.id, ok: true };
      } catch (error) {
        open.delete(r.document);
        throw error;
      }
    }
    case "forget": {
      const doc = open.get(r.document);
      open.delete(r.document);
      void doc?.then((d) => d.loadingTask.destroy()).catch(() => undefined);
      return { id: r.id, ok: true };
    }
    case "draw": {
      const doc = await open.get(r.document);
      if (!doc) return { id: r.id, ok: false, error: "that document is not open" };
      if (r.page < 1 || r.page > doc.numPages) return { id: r.id, ok: false, error: "no such page" };
      const page = await doc.getPage(r.page);
      const natural = page.getViewport({ scale: 1 });
      const longest = Math.max(natural.width, natural.height);
      const viewport = page.getViewport({ scale: longest > 0 ? r.longEdge / longest : 1 });
      const canvas = new OffscreenCanvas(Math.max(1, Math.round(viewport.width)), Math.max(1, Math.round(viewport.height)));
      await render(page, canvas, viewport);
      page.cleanup();
      const bytes = await (await canvas.convertToBlob({ type: "image/png" })).arrayBuffer();
      canvas.width = 0;
      canvas.height = 0;
      return { id: r.id, ok: true, bytes };
    }
    case "region": {
      if (latestRegion.get(r.slot) !== r.id) return { id: r.id, ok: false, error: "superseded" };
      const doc = await open.get(r.document);
      if (!doc) return { id: r.id, ok: false, error: "that document is not open" };
      if (r.page < 1 || r.page > doc.numPages) return { id: r.id, ok: false, error: "no such page" };
      // No cleanup: the next region is usually of the same page.
      const page = await doc.getPage(r.page);
      const natural = page.getViewport({ scale: 1 });
      const scale = natural.width > 0 ? r.pageWidth / natural.width : 1;
      const full = page.getViewport({ scale });
      const canvas = new OffscreenCanvas(
        Math.max(1, Math.round(r.region.width * full.width)),
        Math.max(1, Math.round(r.region.height * full.height)),
      );
      await render(page, canvas, page.getViewport({ scale, offsetX: -r.region.x * full.width, offsetY: -r.region.y * full.height }));
      return { id: r.id, ok: true, bitmap: canvas.transferToImageBitmap() };
    }
    case "shrink": {
      const source = await createImageBitmap(new Blob([r.data], { type: "image/png" }));
      try {
        const longest = Math.max(source.width, source.height);
        // Never up.
        const scale = longest > 0 ? Math.min(1, r.longEdge / longest) : 1;
        const canvas = new OffscreenCanvas(Math.max(1, Math.round(source.width * scale)), Math.max(1, Math.round(source.height * scale)));
        const ctx = canvas.getContext("2d");
        if (!ctx) throw new Error("no 2d context");
        ctx.fillStyle = "#ffffff";
        ctx.fillRect(0, 0, canvas.width, canvas.height);
        ctx.drawImage(source, 0, 0, canvas.width, canvas.height);
        return { id: r.id, ok: true, bytes: await (await canvas.convertToBlob({ type: "image/png" })).arrayBuffer() };
      } finally {
        source.close();
      }
    }
  }
}

let queue: Promise<void> = Promise.resolve();

scope.onmessage = (event) => {
  const r = event.data;
  if (r.kind === "region") latestRegion.set(r.slot, r.id);
  queue = queue
    .then(async () => {
      let answer: RasterResponse;
      try {
        answer = await handle(r);
      } catch (error) {
        answer = { id: r.id, ok: false, error: error instanceof Error ? error.message : String(error) };
      }
      const transfer: Transferable[] = [];
      if (answer.ok && answer.bytes) transfer.push(answer.bytes);
      if (answer.ok && answer.bitmap) transfer.push(answer.bitmap);
      scope.postMessage(answer, transfer);
    })
    .catch(() => undefined);
};
