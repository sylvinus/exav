import { afterEach, describe, expect, it, vi } from "vitest";

import { docxView, perFrame, slideView, viewportStore } from "./viewport.js";

type Rect = [left: number, top: number, width: number, height: number];

/** An element that reports the box it is given. */
function box(rect: Rect, attributes: Record<string, string> = {}, client?: [number, number]): HTMLElement {
  const el = document.createElement("div");
  for (const [k, v] of Object.entries(attributes)) el.setAttribute(k, v);
  el.getBoundingClientRect = () => ({ left: rect[0], top: rect[1], width: rect[2], height: rect[3], right: rect[0] + rect[2], bottom: rect[1] + rect[3], x: rect[0], y: rect[1] }) as DOMRect;
  if (client) {
    Object.defineProperty(el, "clientWidth", { value: client[0] });
    Object.defineProperty(el, "clientHeight", { value: client[1] });
  }
  return el;
}

/** The scroll viewer's DOM: a scrolling box holding a box for each page near the view, with its canvas and its text layer. */
function viewer(host: Rect, pages: [index: number, rect: Rect][], client: [number, number] = [host[2], host[3]]) {
  const root = document.createElement("div");
  const scroller = box(host, {}, client);
  root.append(scroller);
  for (const [index, rect] of pages) {
    const slot = box(rect);
    slot.append(box(rect), box(rect, { "data-overlay": "text", "data-page-index": String(index) }));
    scroller.append(slot);
  }
  return root;
}

describe("the Word page in view", () => {
  it("is the page with most of it showing, and the part of it that does", () => {
    // A 600 x 400 scroller: page 0 (782 high) scrolled up by 700, page 1 starting at 82 and 782 high.
    const root = viewer([0, 0, 600, 400], [
      [0, [20, -700, 553, 782]],
      [1, [20, 82, 553, 782]],
    ]);
    const v = docxView(root)!;
    expect(v.page).toBe(2);
    expect(v.region.x).toBeCloseTo(0);
    expect(v.region.width).toBeCloseTo(1);
    expect(v.region.y).toBeCloseTo(0);
    expect(v.region.height).toBeCloseTo(318 / 782);
  });

  it("leaves out the scrollbars", () => {
    const root = viewer([0, 0, 600, 400], [[0, [0, 0, 600, 1000]]], [585, 385]);
    const v = docxView(root)!;
    expect(v.region.width).toBeCloseTo(585 / 600);
    expect(v.region.height).toBeCloseTo(385 / 1000);
  });

  it("counts pages from 1, however many are mounted before it", () => {
    const root = viewer([0, 0, 600, 400], [[41, [0, 0, 500, 700]]]);
    expect(docxView(root)!.page).toBe(42);
  });

  it("is null with no page laid out or none in view", () => {
    expect(docxView(document.createElement("div"))).toBeNull();
    expect(docxView(viewer([0, 0, 600, 400], [[0, [0, 900, 500, 700]]]))).toBeNull();
  });
});

describe("the slide in its stage", () => {
  it("is all of it when it fits, and the part showing when it overflows", () => {
    const stage = box([0, 0, 800, 600]);
    expect(slideView(stage, box([100, 50, 600, 400]), 3)).toEqual({ page: 3, region: { x: 0, y: 0, width: 1, height: 1 } });
    expect(slideView(stage, box([-200, 0, 1000, 600]), 1)!.region).toEqual({ x: 0.2, y: 0, width: 0.8, height: 1 });
    expect(slideView(stage, box([900, 0, 100, 100]), 1)).toBeNull();
  });
});

describe("the viewport store", () => {
  it("is set only on a change, to a ten-thousandth of the page", () => {
    const { controller, publish } = viewportStore();
    const seen = vi.fn();
    controller.subscribe(seen);
    expect(controller.get()).toBeNull();
    publish({ page: 1, region: { x: 0, y: 0, width: 1, height: 0.5 } });
    publish({ page: 1, region: { x: 0, y: 0, width: 1, height: 0.50001 } });
    expect(seen).toHaveBeenCalledTimes(1);
    expect(controller.get()).toEqual({ space: "page", page: 1, region: { x: 0, y: 0, width: 1, height: 0.5 } });
    publish({ page: 2, region: { x: 0, y: 0, width: 1, height: 0.5 } });
    publish({ page: 2, region: { x: 0, y: 0.1, width: 1, height: 0.5 } });
    expect(seen).toHaveBeenCalledTimes(3);
    publish(null);
    publish(null);
    expect(seen).toHaveBeenCalledTimes(4);
    expect(controller.get()).toBeNull();
  });

  it("is read only to its reader", () => {
    expect(Object.keys(viewportStore().controller).sort()).toEqual(["get", "subscribe"]);
  });
});

describe("work done at most once a frame", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("runs once however often asked, and not after it is cancelled", () => {
    const frames: (() => void)[] = [];
    vi.stubGlobal("requestAnimationFrame", (f: () => void) => frames.push(f));
    vi.stubGlobal("cancelAnimationFrame", (n: number) => delete frames[n - 1]);
    const fn = vi.fn();
    const p = perFrame(fn);
    p.run();
    p.run();
    p.run();
    expect(frames).toHaveLength(1);
    frames[0]!();
    expect(fn).toHaveBeenCalledTimes(1);
    p.run();
    expect(frames).toHaveLength(2);
    p.cancel();
    frames[1]?.();
    expect(fn).toHaveBeenCalledTimes(1);
  });
});
