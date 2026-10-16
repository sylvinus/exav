/**
 * What the office viewers show now, as a page and a region of it
 * (`Controllers.viewport`), read off the boxes the engines lay out.
 */
import { writable } from "../core/store.js";
import type { RasterRect, Viewport, ViewportController } from "../core/types.js";
import { pageInView, sameRegion, visibleRegion, type Box } from "./raster.js";

export type View = { page: number; region: RasterRect };

const boxOf = (el: Element): Box => {
  const r = el.getBoundingClientRect();
  return { left: r.left, top: r.top, width: r.width, height: r.height };
};

/**
 * The page of a Word scroll viewer most in view, and the part of it that
 * shows. The viewer keeps the pages near the view only, each a box holding
 * its canvas and, over it, the text layer that carries the page's index.
 */
export function docxView(root: Element): View | null {
  const boxes: { index: number; box: Box }[] = [];
  let host: Element | null = null;
  for (const layer of root.querySelectorAll('[data-overlay="text"][data-page-index]')) {
    const index = Number((layer as HTMLElement).dataset.pageIndex);
    if (!Number.isSafeInteger(index) || index < 0) continue;
    boxes.push({ index, box: boxOf(layer) });
    host ??= layer.parentElement?.parentElement ?? null;
  }
  if (!host) return null;
  // The scrolling box, less its scrollbars.
  const view = { ...boxOf(host), width: host.clientWidth, height: host.clientHeight };
  const found = pageInView(boxes, view);
  return found && { page: found.index + 1, region: found.region };
}

/** The slide in its stage: all of it, or the part the stage shows when it overflows. */
export function slideView(stage: Element, canvas: Element, page: number): View | null {
  const region = visibleRegion(boxOf(canvas), boxOf(stage));
  return region && { page, region };
}

/** A viewport store with what the engines would otherwise churn kept out: set only on a change. */
export function viewportStore(): { controller: ViewportController; publish(next: View | null): void } {
  const store = writable<Viewport | null>(null);
  return {
    controller: { get: store.get, subscribe: store.subscribe },
    publish(next) {
      const now = store.get();
      if (!next) {
        if (now) store.set(null);
        return;
      }
      if (now && now.page === next.page && sameRegion(now.region as RasterRect, next.region)) return;
      store.set({ space: "page", page: next.page, region: next.region });
    },
  };
}

/** `fn` run at most once a frame, however often asked. */
export function perFrame(fn: () => void): { run(): void; cancel(): void } {
  let handle = 0;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const fire = () => {
    handle = 0;
    timer = undefined;
    fn();
  };
  return {
    run() {
      if (handle || timer !== undefined) return;
      if (typeof requestAnimationFrame === "function") handle = requestAnimationFrame(fire);
      else timer = setTimeout(fire, 16);
    },
    cancel() {
      if (handle) cancelAnimationFrame(handle);
      clearTimeout(timer);
      handle = 0;
      timer = undefined;
    },
  };
}
