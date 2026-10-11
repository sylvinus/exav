import { writable } from "../core/store.js";
import type { PagesController, Renderer } from "../core/types.js";
import { readingOf } from "./delimited.js";
import type { OfficeOptions } from "./index.js";
import { textSelection } from "./selection.js";
import { trimZipTail } from "./zip-tail.js";

interface Engine {
  destroy(): void;
}

export function rendererFor(kind: "docx" | "xlsx" | "pptx" | "csv"): Renderer<OfficeOptions> {
  return {
    async mount(host, ctx) {
      ctx.status({ phase: "loading" });
      const { mode } = ctx.options;
      const common = { useGoogleFonts: ctx.options.useGoogleFonts ?? false, ...(mode && { mode }) };
      const root = document.createElement("div");
      root.className = `exv-office exv-office-${kind}`;
      host.append(root);
      const pages = writable<{ unit: "page" | "slide"; current: number; total: number } | null>(null);
      // Each engine reports what it painted in its own way; a document can lay
      // out completely and still reject (on an embedded object it cannot
      // decode, say), and then what reached the screen stays.
      let painted = false;
      let engine: Engine | null = null;
      let deck: { nextSlide(): Promise<void>; prevSlide(): Promise<void> } | null = null;
      let stopSelection: (() => void) | null = null;
      const note = (error: unknown) => console.warn(`office: ${kind}`, error);
      const canvas = (parent: HTMLElement = root) => {
        const c = document.createElement("canvas");
        c.className = "exv-office-canvas";
        parent.append(c);
        return c;
      };
      let stopResize: (() => void) | null = null;
      // Whole bytes, never a URL: the engines would read a zip's directory
      // with a range request, which neither a `blob:` URL nor many signed
      // URLs answer.
      const bytes = async () => {
        // A ZIP with bytes after its end record is refused by the engines'
        // strict check, and read by everything else (see `trimZipTail`).
        const b = kind === "csv" ? await ctx.source.bytes() : trimZipTail(await ctx.source.bytes());
        return b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength) as ArrayBuffer;
      };

      try {
        if (kind === "docx") {
          const { DocxScrollViewer } = await import("@silurus/ooxml/docx");
          const v = new DocxScrollViewer(root, {
            ...common,
            refitOnResize: true,
            // Each page's text as transparent runs over the canvas, to select
            // and copy; its hyperlinks are clicked on them.
            enableTextSelection: true,
            onVisiblePageChange: (top: number, total: number) => {
              painted = true;
              pages.set({ unit: "page", current: top + 1, total });
            },
            onError: note,
          });
          engine = v;
          stopSelection = textSelection(root);
          await v.load(await bytes());
        } else if (kind === "xlsx") {
          const { XlsxViewer } = await import("@silurus/ooxml/xlsx");
          // It brings its own sheet tabs, hence a container, not a canvas.
          const v = new XlsxViewer(root, { ...common, resizable: true, onReady: () => (painted = true), onError: note });
          engine = v;
          await v.load(await bytes());
        } else if (kind === "csv") {
          const { XlsxSheetViewer } = await import("@silurus/ooxml/xlsx");
          // The bare sheet: only it reads delimited text, and a CSV is one sheet.
          const v = new XlsxSheetViewer(canvas(), { ...common, resizable: true, onReady: () => (painted = true), onError: note });
          engine = v;
          const table = await bytes();
          await v.load(table, { format: "delimited-text", ...readingOf(table) });
        } else {
          const { PptxViewer } = await import("@silurus/ooxml/pptx");
          // The slide is fitted into the stage and centred in it, the
          // surface around it (see the stylesheet).
          const stage = document.createElement("div");
          stage.className = "exv-office-stage";
          root.append(stage);
          const v = new PptxViewer(canvas(stage), {
            ...common,
            // As for Word: the slide's text over it, its hyperlinks clicked on it.
            enableTextSelection: true,
            onSlideChange: (index: number, total: number) => {
              painted = true;
              pages.set({ unit: "slide", current: index + 1, total });
            },
            onError: note,
          });
          engine = v;
          deck = v;
          stopSelection = textSelection(root);
          await v.load(await bytes());
          await v.fitPage();
          // Fitted again when the stage changes size: the engine does not.
          // Only then: a fit draws the slide and its text again.
          let frame = 0;
          let fitted = `${stage.clientWidth}x${stage.clientHeight}`;
          const observer = new ResizeObserver(() => {
            cancelAnimationFrame(frame);
            frame = requestAnimationFrame(() => {
              const size = `${stage.clientWidth}x${stage.clientHeight}`;
              if (size === fitted) return;
              fitted = size;
              void v.fitPage();
            });
          });
          observer.observe(stage);
          stopResize = () => {
            cancelAnimationFrame(frame);
            observer.disconnect();
          };
        }
        ctx.status({ phase: "ready" });
      } catch (error) {
        if (ctx.signal.aborted || !painted) {
          stopResize?.();
          stopSelection?.();
          engine?.destroy();
          root.remove();
          throw error;
        }
        note(error);
        ctx.status({ phase: "ready", partial: true });
      }

      const pager: PagesController = {
        ...pages,
        ...(deck && {
          next: () => deck!.nextSlide(),
          prev: () => deck!.prevSlide(),
        }),
      };
      return {
        controllers: kind === "docx" || kind === "pptx" ? { pages: pager } : {},
        destroy() {
          stopResize?.();
          stopSelection?.();
          engine?.destroy();
          // The canvases are ours; `destroy` leaves them.
          root.remove();
        },
      };
    },
  };
}
