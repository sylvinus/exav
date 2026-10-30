import { RasterError } from "../core/pictures.js";
import { createPictures } from "../core/raster.js";
import { onDemand, writable } from "../core/store.js";
import type { Controllers, PagesController, RasterRect, Renderer, SheetsController, ViewportController, ZoomController } from "../core/types.js";
import { readingOf } from "./delimited.js";
import { docxExporter, pptxExporter, sheetExporter, type Current, type Exporter, type SheetExporter } from "./export.js";
import { DEFAULT_MAX_ARCHIVE_ENTRIES, type OfficeOptions } from "./index.js";
import { wantsProgressive } from "./progressive.js";
import { sheetView } from "./raster.js";
import { textSelection } from "./selection.js";
import { xlsxOfTable } from "./table.js";
import { docxView, perFrame, slideView, viewportStore, type View } from "./viewport.js";
import { trimZipTail } from "./zip-tail.js";

interface Engine {
  destroy(): void;
}

/** What the engines that zoom have in common. */
interface Zoomable {
  getScale(): number;
  setScale(scale: number): unknown;
}

/** `run` when `el` scrolls (any box inside it) or changes size; the stop. */
function watchBoxes(el: HTMLElement, run: () => void): () => void {
  el.addEventListener("scroll", run, { capture: true, passive: true });
  const observer = typeof ResizeObserver === "function" ? new ResizeObserver(run) : null;
  observer?.observe(el);
  return () => {
    el.removeEventListener("scroll", run, { capture: true });
    observer?.disconnect();
  };
}

/** Zoom range of the sheets and of Word's pages, as multiples of 100 %. */
const ZOOM = { min: 0.25, max: 4 };

/**
 * A zoom controller over `engine`, its state set by the engine's `onScaleChange`.
 * The controller's scale is 1 at the fitted view. A sheet's fit is the engine's
 * own 1; a page's is the one that fills the width (`fitBox`, the box whose
 * resizes refit it), which the engine reports as another number.
 */
function zoomOver(engine: () => Zoomable | null, fit: () => unknown, fitBox?: HTMLElement) {
  const state = writable({ scale: 1, ...ZOOM });
  // The engine's scale at the fitted view, and the last it reported.
  let base = 1;
  let last = 1;
  // The box was resized since the engine last reported: it keeps its zoom
  // relative to the fit, so the fit moved by as much as the report says.
  let resized = false;
  const publish = () => state.set({ scale: last / base, min: ZOOM.min / base, max: ZOOM.max / base });
  const observer =
    fitBox && typeof ResizeObserver === "function"
      ? new ResizeObserver(() => {
          resized = true;
          requestAnimationFrame(() => (resized = false));
        })
      : null;
  observer?.observe(fitBox!);
  const controller: ZoomController = {
    ...state,
    // The anchor is the engine's to choose: it zooms about the top left.
    setScale: (scale) => {
      const e = engine();
      if (e && Number.isFinite(scale)) void e.setScale(Math.min(ZOOM.max, Math.max(ZOOM.min, scale * base)));
    },
    fit: () =>
      void Promise.resolve(fit()).then(() => {
        if (!fitBox) return;
        base = last = engine()?.getScale() ?? last;
        publish();
      }),
  };
  return {
    controller,
    report: (scale: number) => {
      if (!Number.isFinite(scale)) return;
      if (resized && last > 0) base *= scale / last;
      last = scale;
      publish();
    },
    /** The view as it is now is the fitted one (a document as it opens). */
    fitted: () => {
      if (!fitBox) return;
      base = last;
      publish();
    },
    stop: () => observer?.disconnect(),
  };
}

export function rendererFor(kind: "docx" | "xlsx" | "pptx" | "csv"): Renderer<OfficeOptions> {
  return {
    async mount(host, ctx) {
      ctx.status({ phase: "loading" });
      const { mode } = ctx.options;
      const common = {
        useGoogleFonts: ctx.options.useGoogleFonts ?? false,
        resourceLimits: { maxArchiveEntries: ctx.options.maxArchiveEntries ?? DEFAULT_MAX_ARCHIVE_ENTRIES },
        ...(mode && { mode }),
      };
      const root = document.createElement("div");
      root.className = `exav-viewer-office exav-viewer-office-${kind}`;
      host.append(root);
      const pages = writable<{ unit: "page" | "slide"; current: number; total: number } | null>(null);
      const sheetState = writable<{ items: readonly { index: number; name: string }[]; current: number }>({ items: [], current: 0 });
      // Each engine reports what it painted in its own way; a document can lay
      // out completely and still reject (on an embedded object it cannot
      // decode, say), and then what reached the screen stays.
      let painted = false;
      let engine: Engine | null = null;
      let zoomable: Zoomable | null = null;
      let pager: Omit<PagesController, keyof typeof pages> = {};
      let sheets: SheetsController | null = null;
      let stopSelection: (() => void) | null = null;
      const note = (error: unknown) => console.warn(`office: ${kind}`, error);
      const canvas = (parent: HTMLElement = root) => {
        const c = document.createElement("canvas");
        c.className = "exav-viewer-office-canvas";
        parent.append(c);
        return c;
      };
      let stopResize: (() => void) | null = null;
      // Pictures are drawn from a second copy of the document (see
      // `export.ts`), opened by the first one. What the viewport says is read
      // off the viewer's own boxes, and only while someone follows or reads
      // the viewport store (`viewportController`).
      let exporter: Exporter | null = null;
      let currentView: () => View | null = () => null;
      const viewport = viewportStore();
      const refreshView = perFrame(() => viewport.publish(currentView()));
      let stopView: (() => void) | null = null;
      /** Listens to the viewer's scroll and size, for the viewport of a Word document. */
      let followBoxes: (() => () => void) | null = null;
      let sheetProbe: ((page: number) => { corner: { x: number; y: number }; scale: number; canvas: { width: number; height: number } } | null) | null = null;
      /** Whether the viewport store has a listener. */
      let watched = false;
      let gone = false;
      const requestView = () => watched && refreshView.run();
      const requestSheet = () => watched && sheetFrame.run();
      /** The region `region: "current"` draws: the viewport now (not the published one, which may be a frame behind). */
      const current: Current = (page, grid) => {
        if (grid) {
          const probe = sheetProbe?.(page);
          return probe ? sheetView(grid, probe.corner, probe.scale, probe.canvas) : null;
        }
        const view = currentView();
        return view && view.page === page ? view.region : null;
      };
      const stopEverything = () => {
        gone = true;
        stopResize?.();
        zoom?.stop();
        stopSelection?.();
        stopView?.();
        refreshView.cancel();
        sheetFrame.cancel();
        void exporter?.dispose();
      };
      // Whole bytes, never a URL: the source already holds them, and a ZIP
      // may need its trailing bytes cut first. Given a URL, the engines
      // fetch the whole file again.
      const bytes = async () => {
        // A ZIP with bytes after its end record is refused by the engines'
        // strict check, and read by everything else (see `trimZipTail`).
        const b = kind === "csv" ? await ctx.source.bytes() : trimZipTail(await ctx.source.bytes());
        return b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength) as ArrayBuffer;
      };
      // A large deck or document is laid out progressively: `load` resolves
      // with the first slides or pages, the rest follows. If that layout
      // then fails, what is on screen stays.
      let mounted = false;
      let layoutFailed = false;
      const laidOut = (error?: unknown) => {
        if (error === undefined) return;
        note(error);
        layoutFailed = true;
        if (mounted) ctx.status({ phase: "ready", partial: true });
      };
      const progressive = (data: ArrayBuffer) =>
        kind === "docx" || kind === "pptx" ? wantsProgressive(kind, new Uint8Array(data)) && { progressiveLayout: true, onLayoutComplete: laidOut } : {};
      const zoom =
        kind === "pptx"
          ? null
          : zoomOver(() => zoomable, () => (kind === "docx" ? (zoomable as { fitWidth(): void } | null)?.fitWidth() : zoomable?.setScale(1)), kind === "docx" ? root : undefined);
      // What a sheet's viewport is redone for, while it is watched.
      const sheetFrame = perFrame(() => measureSheetView());
      let measureSheetView = () => {};
      const range = {
        zoomMin: ZOOM.min,
        zoomMax: ZOOM.max,
        onScaleChange: (s: number) => {
          zoom?.report(s);
          requestView();
          requestSheet();
        },
      };

      try {
        if (kind === "docx") {
          const { DocxScrollViewer } = await import("@silurus/ooxml/docx");
          const data = await bytes();
          const v = new DocxScrollViewer(root, {
            ...common,
            ...range,
            ...progressive(data),
            refitOnResize: true,
            // Each page's text as transparent runs over the canvas, to select
            // and copy; its hyperlinks are clicked on them.
            enableTextSelection: true,
            onVisiblePageChange: (top: number, total: number) => {
              painted = true;
              pages.set({ unit: "page", current: top + 1, total });
              requestView();
            },
            onError: note,
          });
          engine = v;
          zoomable = v;
          pager = { goTo: (page) => void v.scrollToPage(page - 1) };
          stopSelection = textSelection(root);
          exporter = docxExporter(bytes, common);
          currentView = () => docxView(root);
          followBoxes = () => watchBoxes(root, refreshView.run);
          await v.load(data);
        } else if (kind === "xlsx" || kind === "csv") {
          const { XlsxSheetViewer } = await import("@silurus/ooxml/xlsx");
          // The bare sheet: its tabs are the `sheets` controller's, drawn by
          // the UI, and only it reads delimited text.
          const surface = canvas();
          const v = new XlsxSheetViewer(surface, {
            ...common,
            ...range,
            resizable: true,
            onReady: () => (painted = true),
            onSheetChange: (index: number) => {
              sheetState.update((s) => ({ ...s, current: index }));
              requestSheet();
            },
            onViewportChange: requestSheet,
            onError: note,
          });
          engine = v;
          zoomable = v;
          // A sheet's page is its used area, which only the document's model
          // says: the viewport is worked out (from the second copy) when
          // someone reads or follows it, and kept up to date while it is followed.
          const asWorkbook = async () => {
            const table = await bytes();
            return xlsxOfTable(table, readingOf(table)).buffer as ArrayBuffer;
          };
          const sheetPictures = sheetExporter(kind === "csv" ? asWorkbook : bytes, common);
          exporter = sheetPictures;
          sheetProbe = (page) => {
            if (page !== (kind === "csv" ? 1 : sheetState.get().current + 1)) return null;
            const corner = v.getCellViewportRect("A1");
            return corner && { corner, scale: v.getScale(), canvas: { width: surface.clientWidth, height: surface.clientHeight } };
          };
          let measuring = false;
          let again = false;
          measureSheetView = () => {
            if (gone) return;
            if (measuring) {
              again = watched;
              return;
            }
            measuring = true;
            const page = kind === "csv" ? 1 : sheetState.get().current + 1;
            sheetPictures
              .measure(page, (grid) => {
                const probe = sheetProbe?.(page);
                const region = probe && sheetView(grid, probe.corner, probe.scale, probe.canvas);
                return region ? { page, region } : null;
              })
              .then(
                (view) => viewport.publish(view),
                (error) => {
                  note(error);
                  viewport.publish(null);
                },
              )
              .finally(() => {
                measuring = false;
                if (again && watched && !gone) {
                  again = false;
                  measureSheetView();
                }
              });
          };
          if (kind === "csv") {
            const table = await bytes();
            await v.load(table, { format: "delimited-text", ...readingOf(table) });
          } else {
            await v.load(await bytes());
            sheetState.set({ items: v.sheetNames.map((name, index) => ({ index, name })), current: v.sheetIndex });
            sheets = { ...sheetState, select: (index) => v.goToSheet(index) };
          }
        } else {
          const { PptxViewer } = await import("@silurus/ooxml/pptx");
          const data = await bytes();
          // The slide is fitted into the stage and centred in it, the
          // surface around it (see the stylesheet).
          const stage = document.createElement("div");
          stage.className = "exav-viewer-office-stage";
          root.append(stage);
          const v = new PptxViewer(canvas(stage), {
            ...common,
            ...progressive(data),
            // As for Word: the slide's text over it, its hyperlinks clicked on it.
            enableTextSelection: true,
            onSlideChange: (index: number, total: number) => {
              painted = true;
              pages.set({ unit: "slide", current: index + 1, total });
              requestView();
            },
            onError: note,
          });
          engine = v;
          pager = { goTo: (slide) => void v.goToSlide(slide - 1), next: () => v.nextSlide(), prev: () => v.prevSlide() };
          stopSelection = textSelection(root);
          exporter = pptxExporter(bytes, common);
          currentView = () => {
            const slide = stage.querySelector("canvas");
            const now = pages.get();
            return slide && now ? slideView(stage, slide, now.current) : null;
          };
          await v.load(data);
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
              void v.fitPage().then(requestView);
            });
          });
          observer.observe(stage);
          stopResize = () => {
            cancelAnimationFrame(frame);
            observer.disconnect();
          };
        }
        if (zoomable) {
          zoom?.report(zoomable.getScale());
          zoom?.fitted();
        }
        ctx.status(layoutFailed ? { phase: "ready", partial: true } : { phase: "ready" });
        mounted = true;
      } catch (error) {
        if (ctx.signal.aborted || !painted) {
          stopEverything();
          engine?.destroy();
          root.remove();
          throw error;
        }
        note(error);
        ctx.status({ phase: "ready", partial: true });
      }

      // Pictures: the pages the viewer lays out, or the sheets it lists.
      const { controller: pictures, state: count } = createPictures({
        count: 0,
        space: "page",
        raster: (page, options) => {
          if (!exporter) throw new RasterError("unsupported", "nothing is drawn");
          return exporter.raster(page, options, current);
        },
      });
      const pageCount = () => (kind === "docx" || kind === "pptx" ? (pages.get()?.total ?? 0) : kind === "csv" ? 1 : sheetState.get().items.length);
      const countPages = () => count.set({ count: pageCount(), space: "page" });
      countPages();
      const stopCount = (kind === "docx" || kind === "pptx" ? pages : sheetState).subscribe(countPages);

      const isSheet = kind === "xlsx" || kind === "csv";
      // The viewport is worked out while the store has a listener, and once
      // for each read without one. A Word or PowerPoint view is read at once;
      // a sheet's is measured on the second copy, so a read has the last one
      // measured and starts the next.
      const readView = () => (isSheet ? measureSheetView() : viewport.publish(currentView()));
      const viewportController: ViewportController = onDemand(viewport.controller, {
        start() {
          if (gone) return () => {};
          watched = true;
          stopView = followBoxes?.() ?? null;
          readView();
          return () => {
            watched = false;
            stopView?.();
            stopView = null;
            refreshView.cancel();
            sheetFrame.cancel();
          };
        },
        once: () => !gone && readView(),
      });

      const controllers: Controllers = {
        ...((kind === "docx" || kind === "pptx") && { pages: { ...pages, ...pager } }),
        ...(zoom && { zoom: zoom.controller }),
        ...(sheets && { sheets }),
        ...(exporter && { pictures, viewport: viewportController }),
      };
      return {
        controllers,
        destroy() {
          gone = true;
          stopCount();
          stopEverything();
          engine?.destroy();
          // The canvases are ours; `destroy` leaves them.
          root.remove();
        },
      };
    },
  };
}
