import type { FileSource, Renderer, SourceReader } from "../core/types.js";
import { createPdfEngine, type LoadedPdf } from "./engine.js";
import type { PdfOptions } from "./index.js";
import { createReader, READER_DEFAULTS } from "./reader.js";

export const renderer: Renderer<PdfOptions> = {
  async mount(host, ctx) {
    ctx.status({ phase: "loading" });
    const engine = createPdfEngine({ assetBase: ctx.assetBase });
    const fail = (error: unknown) => {
      console.warn("pdf: a read failed", error);
      ctx.status({ phase: "error", error: { code: "pdf", cause: error } });
    };
    const o = ctx.options;
    const limits = { maxDepth: o.outlineMaxDepth ?? 3, maxEntries: o.outlineMaxEntries ?? 200 };

    /** A document opened from `given`, with its pages' sizes, read for the reader. */
    const read = async (given: FileSource | null, reader: SourceReader, signal: AbortSignal) => {
      // A URL is streamed by pdf.js itself, with range requests where the
      // server answers them; anything else is read whole, and so is a URL with
      // `init` (headers, credentials), which pdf.js's own fetch would not send.
      // A source read by ranges is read as pdf.js asks.
      const streamed = !!given && "url" in given && !given.init;
      const source =
        given && "ranges" in given ? { ranges: given.ranges, onError: fail } : streamed ? { url: await reader.url() } : { data: await reader.bytes() };
      const doc = await engine.open(source, signal);
      if (signal.aborted) {
        doc.destroy();
        throw new DOMException("aborted", "AbortError");
      }
      try {
        const sizes = await Promise.all(Array.from({ length: doc.numPages }, (_, i) => doc.pageSize(i + 1)));
        return { doc, sizes, shown: { ...doc, outline: () => doc.outline(limits) } as LoadedPdf };
      } catch (error) {
        // A damaged page: the document must not stay open in pdf.js's worker.
        doc.destroy();
        throw error;
      }
    };

    let current = await read(ctx.file.source, ctx.source, ctx.signal);
    const reader = createReader(
      host,
      current.shown,
      current.sizes,
      {
        ...READER_DEFAULTS,
        ...(o.minZoom !== undefined && { minZoom: o.minZoom }),
        ...(o.maxZoom !== undefined && { maxZoom: o.maxZoom }),
        ...(o.drag !== undefined && { drag: o.drag }),
        ...(o.prerenderMargin !== undefined && { prerenderMargin: o.prerenderMargin }),
        ...(o.pageMaxPixels !== undefined && { pageMaxPixels: o.pageMaxPixels }),
        ...(o.detailMaxPixels !== undefined && { detailMaxPixels: o.detailMaxPixels }),
      },
      (error) => {
        console.warn("pdf: could not render a page", error);
        ctx.status({ phase: "error", error: { code: "pdf", cause: error } });
      },
    );
    ctx.status({ phase: "ready" });
    return {
      controllers: { pages: reader.pages, zoom: reader.zoom, drag: reader.drag, outline: reader.outline },
      resize: reader.resize,
      // The same document with other bytes (a report's preview after an
      // option changed): the zoom and scroll position stay.
      async replace(next) {
        const incoming = await read(next.file.source, next.source, next.signal);
        const old = current;
        current = incoming;
        reader.replace(incoming.shown, incoming.sizes);
        old.doc.destroy();
      },
      destroy() {
        reader.destroy();
        current.doc.destroy();
      },
    };
  },
};
