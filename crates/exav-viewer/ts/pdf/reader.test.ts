import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";

import type { LoadedPdf, PdfLink } from "./engine.js";
import { createReader, READER_DEFAULTS, type Reader, type ReaderOptions } from "./reader.js";

beforeAll(() => {
  globalThis.ResizeObserver ??= class {
    observe() {}
    unobserve() {}
    disconnect() {}
  };
  globalThis.IntersectionObserver ??= class {
    observe() {}
    unobserve() {}
    disconnect() {}
    takeRecords() {
      return [];
    }
    root = null;
    rootMargin = "";
    thresholds = [];
  } as unknown as typeof IntersectionObserver;
});

/** A document that draws nothing and says what was asked of it. */
function fakeDoc(pages: number, log: string[] = [], links: PdfLink[] = []): LoadedPdf {
  return {
    numPages: pages,
    pageSize: async () => ({ width: 600, height: 800 }),
    pageAspect: async () => 0.75,
    renderPageToBlob: async () => new Blob(),
    renderPageTo: async () => true,
    cancelRender: () => void log.push("cancel"),
    outline: async () => [],
    textLayer: () => ({ done: Promise.resolve(), cancel: () => {} }),
    links: async () => links,
    destination: async () => null,
    destroy: () => void log.push("destroy"),
  };
}

const sizes = (n: number) => Array.from({ length: n }, () => ({ width: 600, height: 800 }));

const open: Reader[] = [];
afterEach(() => open.splice(0).forEach((r) => r.destroy()));

function make(doc: LoadedPdf, over: Partial<ReaderOptions> = {}) {
  const host = document.createElement("div");
  document.body.append(host);
  const reader = createReader(host, doc, sizes(doc.numPages), { ...READER_DEFAULTS, ...over }, () => {});
  open.push(reader);
  const scroller = host.querySelector<HTMLElement>(".exv-pdf-scroller")!;
  // jsdom lays nothing out: the scroll position is a plain pair of numbers.
  let left = 0;
  let top = 0;
  // What the reader writes, since a browser empties the scroller when its content is replaced.
  const writes: { x: number[]; y: number[] } = { x: [], y: [] };
  Object.defineProperty(scroller, "clientWidth", { value: 800 });
  Object.defineProperty(scroller, "clientHeight", { value: 600 });
  Object.defineProperty(scroller, "scrollLeft", {
    get: () => left,
    set: (v: number) => {
      left = v;
      writes.x.push(v);
    },
  });
  Object.defineProperty(scroller, "scrollTop", {
    get: () => top,
    set: (v: number) => {
      top = v;
      writes.y.push(v);
    },
  });
  const root = host.querySelector<HTMLElement>(".exv-pdf")!;
  const mouse = (type: string, x: number, y: number, target: EventTarget = scroller, init: MouseEventInit = {}) =>
    target.dispatchEvent(new MouseEvent(type, { clientX: x, clientY: y, bubbles: true, cancelable: true, ...init }));
  return { reader, host, scroller, root, mouse, writes, scrollTo: (x: number, y: number) => ((left = x), (top = y)) };
}

describe("the drag controller", () => {
  it("selects while the page fits, and offers the choice only once it is larger than the viewer", () => {
    const { reader, root } = make(fakeDoc(2));
    expect(reader.drag.get()).toEqual({ mode: "select", available: false });
    expect(root.dataset.drag).toBe("select");
    reader.zoom.setScale(2);
    expect(reader.drag.get()).toEqual({ mode: "pan", available: true });
    expect(root.dataset.drag).toBe("pan");
    reader.drag.choose("select");
    expect(reader.drag.get()).toEqual({ mode: "select", available: true });
    reader.drag.choose("pan");
    reader.zoom.fit();
    expect(reader.drag.get()).toEqual({ mode: "select", available: false });
  });

  it("starts in the mode the plugin option names", () => {
    const { reader } = make(fakeDoc(1), { drag: "select" });
    reader.zoom.setScale(2);
    expect(reader.drag.get()).toEqual({ mode: "select", available: true });
  });
});

describe("dragging with the mouse", () => {
  it("pans the page when zoomed, and the press starts no text selection", () => {
    const { reader, scroller, mouse, scrollTo, host } = make(fakeDoc(2));
    reader.zoom.setScale(2);
    scrollTo(100, 200);
    const text = document.createElement("span");
    text.className = "exv-pdf-text";
    host.querySelector(".exv-pdf-page")!.append(text);
    const selecting = vi.fn();
    host.addEventListener("mousedown", selecting);
    const press = mouse("mousedown", 50, 50, text);
    // Handled before anything below it, and not left to the browser (which would select).
    expect(press).toBe(false);
    expect(selecting).not.toHaveBeenCalled();
    mouse("mousemove", 30, 20, document.body);
    expect([scroller.scrollLeft, scroller.scrollTop]).toEqual([120, 230]);
    mouse("mousemove", 80, 90, document.body);
    expect([scroller.scrollLeft, scroller.scrollTop]).toEqual([70, 160]);
    mouse("mouseup", 80, 90, document.body);
    // Released: moving no longer scrolls.
    mouse("mousemove", 0, 0, document.body);
    expect([scroller.scrollLeft, scroller.scrollTop]).toEqual([70, 160]);
  });

  it("leaves the press to the browser when the page fits, or when the user chose to select", () => {
    const fits = make(fakeDoc(1));
    expect(fits.mouse("mousedown", 5, 5)).toBe(true);
    const chosen = make(fakeDoc(1));
    chosen.reader.zoom.setScale(2);
    chosen.reader.drag.choose("select");
    expect(chosen.mouse("mousedown", 5, 5)).toBe(true);
    // Nor another button than the main one.
    const other = make(fakeDoc(1));
    other.reader.zoom.setScale(2);
    expect(other.mouse("mousedown", 5, 5, other.scroller, { button: 2 })).toBe(true);
    // Nor the scrollbars, which are at the edge of the scroller's client area (800 by 600 here).
    expect(other.mouse("mousedown", 805, 5)).toBe(true);
    expect(other.mouse("mousedown", 5, 605)).toBe(true);
    expect(other.mouse("mousedown", 5, 5)).toBe(false);
  });

  it("does not follow the link under the pointer when a drag ends on it, but follows a plain click", () => {
    const links: PdfLink[] = [{ url: "https://example.test/", areas: [{ x: 0, y: 0, width: 1, height: 1 }] }];
    const open_ = vi.spyOn(window, "open").mockImplementation(() => null);
    const { reader, scroller, mouse, host } = make(fakeDoc(1, [], links), {});
    reader.zoom.setScale(2);
    return (async () => {
      // The overlay of a near page is made when the page is: let it be.
      await new Promise((r) => setTimeout(r, 0));
      const link = host.querySelector<HTMLElement>(".exv-pdf-link");
      if (!link) throw new Error("no link overlay");
      // A drag, then the click it ends with.
      mouse("mousedown", 10, 10, link);
      mouse("mousemove", 40, 40, document.body);
      mouse("mouseup", 40, 40, document.body);
      link.dispatchEvent(new MouseEvent("click", { bubbles: true, cancelable: true }));
      expect(open_).not.toHaveBeenCalled();
      // A click with no drag before it.
      await new Promise((r) => setTimeout(r, 5));
      mouse("mousedown", 10, 10, link);
      mouse("mouseup", 10, 10, document.body);
      link.dispatchEvent(new MouseEvent("click", { bubbles: true, cancelable: true }));
      expect(open_).toHaveBeenCalledTimes(1);
      expect(scroller).toBeTruthy();
    })();
  });
});

describe("replacing the document", () => {
  it("shows the new pages at the same zoom and scroll position, frees the old document's renders, and follows the new page count", () => {
    const log: string[] = [];
    const { reader, host, scrollTo, scroller, writes } = make(fakeDoc(3, log));
    reader.zoom.setScale(2);
    scrollTo(40, 500);
    const before = host.querySelectorAll(".exv-pdf-page").length;
    expect(before).toBe(3);
    writes.x.length = writes.y.length = 0;
    reader.replace(fakeDoc(5), sizes(5));
    expect(host.querySelectorAll(".exv-pdf-page")).toHaveLength(5);
    expect(reader.zoom.get().scale).toBe(2);
    // Put back where it was, after the new pages are laid out.
    expect([scroller.scrollLeft, scroller.scrollTop]).toEqual([40, 500]);
    expect([writes.x.at(-1), writes.y.at(-1)]).toEqual([40, 500]);
    expect(reader.pages.get()?.total).toBe(5);
    // The old document's bitmaps were released through it, before the swap.
    expect(log).toContain("cancel");
    // The mode stays too.
    expect(reader.drag.get()).toEqual({ mode: "pan", available: true });
  });

  it("reads the new document's outline, and the new pages' links", async () => {
    const { reader, host } = make(fakeDoc(1));
    const next = fakeDoc(1, [], [{ url: "https://example.test/new", areas: [{ x: 0, y: 0, width: 0.5, height: 0.1 }] }]);
    next.outline = async () => [{ title: "Intro", pageNumber: 1, depth: 0, offset: null }];
    reader.replace(next, sizes(1));
    await new Promise((r) => setTimeout(r, 0));
    expect(reader.outline.get()).toEqual([{ title: "Intro", page: 1, depth: 0, offset: null }]);
    expect(host.querySelector<HTMLAnchorElement>(".exv-pdf-link")?.href).toBe("https://example.test/new");
  });
});
