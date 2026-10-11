/**
 * PDF pages drawn off the main thread, for hosts that keep rasters of their
 * own (sheets for offline use, thumbnails, a `DetailSource`).
 *
 * Documents stay open in the worker by id, at most `maxOpen` of them (the
 * least recently used is forgotten). Where `OffscreenCanvas` is missing (iOS
 * before 16.4), the same calls run on the main thread.
 */
import { createPdfEngine, type LoadedPdf } from "./engine.js";

type Region = { x: number; y: number; width: number; height: number };

export type RasterRequest =
  | { id: number; kind: "open"; document: string; data: ArrayBuffer; assetBase: string }
  | { id: number; kind: "forget"; document: string }
  | { id: number; kind: "draw"; document: string; page: number; longEdge: number }
  | { id: number; kind: "region"; document: string; page: number; pageWidth: number; region: Region; slot: string }
  | { id: number; kind: "shrink"; data: ArrayBuffer; longEdge: number };

export type RasterResponse =
  | { id: number; ok: true; bytes?: ArrayBuffer; bitmap?: ImageBitmap }
  | { id: number; ok: false; error: string };

type Distribute<T> = T extends unknown ? Omit<T, "id"> : never;

export interface PdfRasterizer {
  /** Transfers the bytes. Resolves false when the file does not parse. */
  open(id: string, data: ArrayBuffer): Promise<boolean>;
  forget(id: string): void;
  /** A whole page, its longest side `longEdge` px, on white, as PNG. */
  draw(id: string, page: number, longEdge: number): Promise<Blob | null>;
  /** Part of a page (fractions) at `pageWidth` device px. Null when superseded. */
  region(id: string, page: number, pageWidth: number, region: Region, slot: string): Promise<ImageBitmap | null>;
  /** Downscales an already rasterised PNG, never up. */
  shrink(data: ArrayBuffer, longEdge: number): Promise<Blob | null>;
  /** Ends the worker and every open document. */
  destroy(): void;
  readonly maxOpen: number;
  readonly timeoutMs: number;
}

export function createPdfRasterizer(config: { assetBase?: string; maxOpen?: number; timeoutMs?: number } = {}): PdfRasterizer {
  const assetBase = config.assetBase ?? "/exav-viewer/";
  const maxOpen = config.maxOpen ?? 3;
  const timeoutMs = config.timeoutMs ?? 60_000;
  const recent: string[] = [];
  const touch = (id: string) => {
    const i = recent.indexOf(id);
    if (i >= 0) recent.splice(i, 1);
    recent.push(id);
  };

  if (typeof OffscreenCanvas === "undefined" || typeof Worker === "undefined") {
    return mainThread(assetBase, maxOpen, timeoutMs, recent, touch);
  }

  let worker: Worker | null = null;
  let next = 1;
  const pending = new Map<number, { resolve: (r: RasterResponse) => void; timer: ReturnType<typeof setTimeout> }>();

  const failAll = (error: string) => {
    for (const [id, p] of pending) {
      clearTimeout(p.timer);
      p.resolve({ id, ok: false, error });
    }
    pending.clear();
    recent.length = 0;
  };

  const ensure = () => {
    if (worker) return worker;
    worker = new Worker(new URL("./rasterizer.worker.js", import.meta.url), { type: "module" });
    worker.onmessage = (e: MessageEvent<RasterResponse>) => {
      const p = typeof e.data?.id === "number" ? pending.get(e.data.id) : undefined;
      if (!p) return;
      clearTimeout(p.timer);
      pending.delete(e.data.id);
      p.resolve(e.data);
    };
    // A trapped or crashed worker loses its documents: every request in
    // flight fails, and the next one starts a new worker.
    worker.onerror = () => {
      worker?.terminate();
      worker = null;
      failAll("the rasteriser stopped");
    };
    return worker;
  };

  const call = (r: Distribute<RasterRequest>, transfer: Transferable[] = []) =>
    new Promise<RasterResponse>((resolve) => {
      const id = next++;
      // The worker answers in order: one that stopped answering would hold
      // every later request too, so it is replaced, its documents with it.
      const timer = setTimeout(() => {
        worker?.terminate();
        worker = null;
        failAll("timed out");
      }, timeoutMs);
      pending.set(id, { resolve, timer });
      ensure().postMessage({ ...r, id }, transfer);
    });

  const forget = (id: string) => {
    const i = recent.indexOf(id);
    if (i >= 0) recent.splice(i, 1);
    void call({ kind: "forget", document: id });
  };

  return {
    maxOpen,
    timeoutMs,
    async open(id, data) {
      touch(id);
      while (recent.length > maxOpen) forget(recent[0]!);
      const r = await call({ kind: "open", document: id, data, assetBase }, [data]);
      return r.ok;
    },
    forget,
    async draw(id, page, longEdge) {
      touch(id);
      const r = await call({ kind: "draw", document: id, page, longEdge });
      return r.ok && r.bytes ? new Blob([r.bytes], { type: "image/png" }) : null;
    },
    async region(id, page, pageWidth, region, slot) {
      touch(id);
      const r = await call({ kind: "region", document: id, page, pageWidth, region, slot });
      return r.ok && r.bitmap ? r.bitmap : null;
    },
    async shrink(data, longEdge) {
      const r = await call({ kind: "shrink", data, longEdge }, [data]);
      return r.ok && r.bytes ? new Blob([r.bytes], { type: "image/png" }) : null;
    },
    destroy() {
      worker?.terminate();
      worker = null;
      failAll("destroyed");
    },
  };
}

/** The same contract on the main thread, for browsers without OffscreenCanvas in workers. */
function mainThread(
  assetBase: string,
  maxOpen: number,
  timeoutMs: number,
  recent: string[],
  touch: (id: string) => void,
): PdfRasterizer {
  const engine = createPdfEngine({ assetBase });
  const docs = new Map<string, Promise<LoadedPdf>>();
  const latest = new Map<string, number>();
  let n = 0;
  let queue: Promise<unknown> = Promise.resolve();
  const serial = <T>(f: () => Promise<T>) => {
    const run = queue.then(f, f);
    queue = run.catch(() => undefined);
    return run;
  };
  const forget = (id: string) => {
    const i = recent.indexOf(id);
    if (i >= 0) recent.splice(i, 1);
    void docs.get(id)?.then((d) => d.destroy()).catch(() => undefined);
    docs.delete(id);
  };
  const canvasBlob = (canvas: HTMLCanvasElement) =>
    new Promise<Blob | null>((resolve) => canvas.toBlob(resolve, "image/png")).finally(() => {
      canvas.width = 0;
      canvas.height = 0;
    });
  return {
    maxOpen,
    timeoutMs,
    async open(id, data) {
      touch(id);
      while (recent.length > maxOpen) forget(recent[0]!);
      const p = engine.open({ data: new Uint8Array(data) });
      docs.set(id, p);
      return p.then(
        () => true,
        () => (docs.delete(id), false),
      );
    },
    forget,
    draw: (id, page, longEdge) =>
      serial(async () => {
        const doc = await docs.get(id);
        if (!doc || page < 1 || page > doc.numPages) return null;
        const size = await doc.pageSize(page);
        return doc.renderPageToBlob(page, longEdge / Math.max(size.width, size.height, 1));
      }).catch(() => null),
    region(id, page, pageWidth, region, slot) {
      const mine = ++n;
      latest.set(slot, mine);
      return serial(async () => {
        if (latest.get(slot) !== mine) return null;
        const doc = await docs.get(id);
        if (!doc || page < 1 || page > doc.numPages) return null;
        const size = await doc.pageSize(page);
        // `renderPageTo` draws at renderDpr() device px per CSS px.
        const dpr = engine.renderDpr();
        const cssWidth = pageWidth / dpr;
        const cssHeight = (cssWidth * size.height) / size.width;
        const canvas = document.createElement("canvas");
        await doc.renderPageTo(canvas, page, cssWidth, {
          x: region.x * cssWidth,
          y: region.y * cssHeight,
          width: region.width * cssWidth,
          height: region.height * cssHeight,
        });
        try {
          return await createImageBitmap(canvas);
        } finally {
          canvas.width = 0;
          canvas.height = 0;
        }
      }).catch(() => null);
    },
    shrink: (data, longEdge) =>
      serial(async () => {
        const source = await createImageBitmap(new Blob([data], { type: "image/png" }));
        try {
          const longest = Math.max(source.width, source.height);
          const scale = longest > 0 ? Math.min(1, longEdge / longest) : 1;
          const canvas = document.createElement("canvas");
          canvas.width = Math.max(1, Math.round(source.width * scale));
          canvas.height = Math.max(1, Math.round(source.height * scale));
          const ctx = canvas.getContext("2d");
          if (!ctx) return null;
          ctx.fillStyle = "#ffffff";
          ctx.fillRect(0, 0, canvas.width, canvas.height);
          ctx.drawImage(source, 0, 0, canvas.width, canvas.height);
          return canvasBlob(canvas);
        } finally {
          source.close();
        }
      }).catch(() => null),
    destroy() {
      for (const id of [...docs.keys()]) forget(id);
    },
  };
}
