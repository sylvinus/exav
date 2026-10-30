import { describe, expect, it } from "vitest";

import { RasterError, tilePlan, tileRect } from "../core/pictures.js";
import type { Viewport } from "../core/types.js";
import {
  abortable,
  checkScale,
  currentFor,
  DEFAULT_TILE,
  defaultRegion,
  exportView,
  glTile,
  layoutFor,
  lineweightFactors,
  linked,
  MAX_TILE,
  minScaleFor,
  planExport,
  referenceCanvas,
  serial,
  tileCamera,
  tileEdge,
  viewportRegion,
} from "./raster.js";
import { FIT_MARGIN } from "./renderer/camera.js";

const code = (f: () => unknown) => {
  try {
    f();
  } catch (e) {
    return e instanceof RasterError ? e.code : `not a RasterError: ${String(e)}`;
  }
  return "none";
};
const codeOf = async (p: Promise<unknown>) => {
  try {
    await p;
  } catch (e) {
    return e instanceof RasterError ? e.code : `not a RasterError: ${String(e)}`;
  }
  return "none";
};

const layouts = [
  { id: "", name: "Model", isModel: true },
  { id: "Sheet A", name: "Sheet A", isModel: false },
  { id: "Sheet B", name: "Sheet B", isModel: false },
];

describe("the layout a page is", () => {
  it("is the layout of that place in the layouts controller, model space first", () => {
    expect(layoutFor(layouts, 1, {})).toEqual({ id: "", page: 1 });
    expect(layoutFor(layouts, 3, {})).toEqual({ id: "Sheet B", page: 3 });
  });

  it("is the layout asked for by its id, which wins over the page", () => {
    expect(layoutFor(layouts, 1, { layout: "Sheet A" })).toEqual({ id: "Sheet A", page: 2 });
    expect(layoutFor(layouts, 3, { layout: "" })).toEqual({ id: "", page: 1 });
  });

  it("is refused for an id that no layout has, or a page past the list", () => {
    expect(code(() => layoutFor(layouts, 1, { layout: "Model" }))).toBe("invalid");
    expect(code(() => layoutFor(layouts, 1, { layout: 3 as never }))).toBe("invalid");
    expect(code(() => layoutFor(layouts, 4, {}))).toBe("invalid");
  });
});

describe("the viewport as a region", () => {
  const camera = { cx: 10, cy: -20, scale: 0.5, width: 800, height: 600 };

  it("is what the camera shows, in drawing units: the origin added back to the local view", () => {
    expect(viewportRegion(camera, [1000, 2000])).toEqual({ x: 1000 + 10 - 200, y: 2000 - 20 - 150, width: 400, height: 300 });
    expect(viewportRegion(camera, [0, 0])).toEqual({ x: -190, y: -170, width: 400, height: 300 });
  });

  it("is the region of its layout alone", () => {
    const viewport: Viewport = { space: "drawing", page: 2, layout: "Sheet A", region: { x: 1, y: 2, width: 3, height: 4 } };
    expect(currentFor(viewport, "Sheet A")).toEqual({ x: 1, y: 2, width: 3, height: 4 });
    expect(currentFor(viewport, "")).toBeNull();
    expect(currentFor(null, "")).toBeNull();
    expect(currentFor({ ...viewport, space: "pixels" }, "Sheet A")).toBeNull();
  });

  it("drawn at the canvas's own size is the same view, to the pixel", () => {
    const region = viewportRegion(camera, [1000, 2000]);
    const view = exportView({ width: 800, height: 600, region });
    expect(view.scale).toBeCloseTo(0.5, 12);
    expect(view.cx - 1000).toBeCloseTo(10, 9);
    expect(view.cy - 2000).toBeCloseTo(-20, 9);
    expect(view.region.x).toBeCloseTo(region.x, 9);
    expect(view.region.height).toBeCloseTo(300, 9);
  });
});

describe("what is drawn when no region is asked", () => {
  it("is the extents with the margin the viewer's fit leaves, about their centre", () => {
    const r = defaultRegion([-50, -25, 50, 25], [1000, 500]);
    expect(r.width).toBeCloseTo(100 * (1 + 2 * FIT_MARGIN), 9);
    expect(r.height).toBeCloseTo(50 * (1 + 2 * FIT_MARGIN), 9);
    expect(r.x + r.width / 2).toBeCloseTo(1000, 9);
    expect(r.y + r.height / 2).toBeCloseTo(500, 9);
  });

  it("gives a line some height and an empty layout a unit", () => {
    const line = defaultRegion([0, 0, 100, 0], [0, 0]);
    expect(line.height).toBeCloseTo(1 * (1 + 2 * FIT_MARGIN), 9);
    expect(line.width).toBeCloseTo(100 * (1 + 2 * FIT_MARGIN), 9);
    const empty = defaultRegion([0, 0, 0, 0], [5, 6]);
    expect(empty.width).toBeCloseTo(1 + 2 * FIT_MARGIN, 9);
    expect(empty.x + empty.width / 2).toBeCloseTo(5, 9);
    expect(defaultRegion([NaN, 0, NaN, 0], [0, 0]).width).toBeGreaterThan(0);
  });
});

describe("planning a picture of a drawing", () => {
  const full = { x: 0, y: 0, width: 200, height: 100 };

  it("waits for the extents when no region is asked, and does not otherwise", () => {
    expect(planExport({ longEdge: 100 }, null, null, "#ffffff")).toBeNull();
    expect(planExport({ longEdge: 100, region: { x: 1, y: 2, width: 3, height: 4 } }, null, null, "#ffffff")).toMatchObject({ width: 75, height: 100 });
    expect(planExport({ longEdge: 100, region: "current" }, null, { x: 0, y: 0, width: 4, height: 2 }, "#ffffff")).toMatchObject({ width: 100, height: 50 });
  });

  it("draws the extents on the ground by default, the picture taking their shape", () => {
    expect(planExport({ longEdge: 400 }, full, null, "#212830")).toEqual({ width: 400, height: 200, region: full, background: "#212830" });
  });

  it("widens the region to a picture of another shape (contain) or narrows it (cover), about its centre", () => {
    expect(planExport({ width: 100, height: 100 }, full, null, "#fff")!.region).toEqual({ x: 0, y: -50, width: 200, height: 200 });
    expect(planExport({ width: 100, height: 100, fit: "cover" }, full, null, "#fff")!.region).toEqual({ x: 50, y: 0, width: 100, height: 100 });
  });

  it("refuses 'current' where no region is in view, a camera region, a bad lineweight, background or size", () => {
    expect(code(() => planExport({ longEdge: 10, region: "current" }, full, null, "#fff"))).toBe("invalid");
    const camera = { position: [0, 0, 1], target: [0, 0, 0], projection: { type: "perspective", fov: 50 }, aspect: 1 } as const;
    expect(code(() => planExport({ longEdge: 10, region: camera }, full, null, "#fff"))).toBe("invalid");
    expect(code(() => planExport({ longEdge: 10, lineweight: "heavy" as never }, null, null, "#fff"))).toBe("invalid");
    expect(code(() => planExport({ longEdge: 10, background: "url(x)" }, full, null, "#fff"))).toBe("invalid");
    expect(code(() => planExport({ longEdge: 0 }, full, null, "#fff"))).toBe("invalid");
    expect(code(() => planExport({ width: 20000, height: 2 }, full, null, "#fff"))).toBe("too-large");
  });
});

describe("the view of a picture", () => {
  it("is the region as the picture's pixels make it: the same scale along both axes, about the region's centre", () => {
    // 100 x 50 units in 1000 x 501 px: a hair taller than the region's shape.
    const view = exportView({ width: 1000, height: 501, region: { x: 10, y: 20, width: 100, height: 50 } });
    expect(view.scale).toBeCloseTo(0.1, 12);
    expect(view.region.width / 1000).toBeCloseTo(view.region.height / 501, 12);
    expect(view.region.height).toBeCloseTo(50.1, 9);
    expect(view.cx).toBe(60);
    expect(view.cy).toBe(45);
    expect(view.region.x + view.region.width / 2).toBeCloseTo(60, 9);
    expect(view.region.y + view.region.height / 2).toBeCloseTo(45, 9);
    // The region asked is inside the one drawn.
    expect(view.region.height).toBeGreaterThanOrEqual(50);
  });

  it("refuses a region with no size", () => {
    expect(code(() => exportView({ width: 10, height: 10, region: { x: 0, y: 0, width: 0, height: 0 } }))).toBe("invalid");
    expect(code(() => exportView({ width: 10, height: 10, region: { x: 0, y: 0, width: Infinity, height: 5 } }))).toBe("invalid");
    expect(code(() => planExport({ longEdge: 10, region: { x: 0, y: 0, width: 0, height: 5 } }, null, null, "#fff"))).toBe("invalid");
  });

  it("is refused closer than the f32 coordinates can place, as the viewer's zoom is", () => {
    const extents = [-500, -500, 500, 500] as const;
    const min = minScaleFor(extents);
    expect(min).toBeCloseTo(1000 * 2 ** -21, 12);
    expect(code(() => checkScale(min * 0.9, extents))).toBe("invalid");
    expect(code(() => checkScale(min * 1.1, extents))).toBe("none");
    // A drawing far from its origin has less precision to give.
    expect(minScaleFor([1e6, 1e6, 1e6 + 10, 1e6 + 10])).toBeGreaterThan(minScaleFor([0, 0, 10, 10]));
  });
});

describe("tiles of a picture", () => {
  it("are at most the plugin's, the default's or the GPU's, whichever is least, and never past 4096", () => {
    const gpu = { texture: 16384, renderbuffer: 16384, viewport: [16384, 16384] as const };
    expect(tileEdge(gpu)).toBe(DEFAULT_TILE);
    expect(tileEdge(gpu, 64)).toBe(64);
    expect(tileEdge(gpu, 100000)).toBe(MAX_TILE);
    expect(tileEdge({ texture: 8192, renderbuffer: 1024, viewport: [8192, 8192] }, 4096)).toBe(1024);
    expect(tileEdge({ texture: 8192, renderbuffer: 8192, viewport: [8192, 512] })).toBe(512);
    for (const bad of [0, -3, 1.5, NaN, Infinity]) expect(tileEdge(gpu, bad), String(bad)).toBe(DEFAULT_TILE);
  });

  it("have each the camera that shows its part of the picture: the same scale, centred where the tile is", () => {
    const whole = { cx: 100, cy: 50, scale: 0.25, width: 400, height: 200 };
    // The picture's own tile.
    expect(tileCamera(whole, { x: 0, y: 0, width: 400, height: 200 })).toEqual(whole);
    // The bottom left 100 x 100 px: 150 px left of the centre horizontally, 50 below it.
    expect(tileCamera(whole, { x: 0, y: 0, width: 100, height: 100 })).toEqual({ cx: 100 - 150 * 0.25, cy: 50 - 50 * 0.25, scale: 0.25, width: 100, height: 100 });
  });

  it("turn the picture's rows (first at the top) into GL's (first at the bottom)", () => {
    expect(glTile({ height: 200 }, { x: 0, y: 0, width: 100, height: 100 })).toEqual({ x: 0, y: 100, width: 100, height: 100 });
    expect(glTile({ height: 120 }, { x: 100, y: 100, width: 50, height: 20 })).toEqual({ x: 100, y: 0, width: 50, height: 20 });
  });

  it("show together the picture's view, each pixel at the same place in the drawing whichever tile has it", () => {
    const size = { width: 250, height: 130 };
    const view = exportView({ ...size, region: { x: 1000, y: -400, width: 25, height: 13 } });
    const whole = { cx: view.cx, cy: view.cy, scale: view.scale, ...size };
    const world = (cam: { cx: number; scale: number; width: number }, px: number) => cam.cx + (px - cam.width / 2) * cam.scale;
    const worldY = (cam: { cy: number; scale: number; height: number }, py: number) => cam.cy + (py - cam.height / 2) * cam.scale;
    const tiles = tilePlan(size.width, size.height, 64);
    expect(tiles.length).toBe(4 * 3);
    for (const tile of tiles) {
      const gl = glTile(size, tile);
      const cam = tileCamera(whole, gl);
      // The tile's left and bottom edges in the drawing: the same as the whole picture's pixel there.
      expect(world(cam, 0)).toBeCloseTo(world(whole, gl.x), 9);
      expect(worldY(cam, 0)).toBeCloseTo(worldY(whole, gl.y), 9);
      // And the same as `tileRect`, which the core tests: the tile's rectangle of the region.
      const r = tileRect(view.region, size, tile, true);
      expect(world(cam, 0)).toBeCloseTo(r.x, 9);
      expect(worldY(cam, 0)).toBeCloseTo(r.y, 9);
      expect(cam.width * cam.scale).toBeCloseTo(r.width, 9);
      expect(cam.height * cam.scale).toBeCloseTo(r.height, 9);
    }
    // The first row of the picture is the top of the region.
    const top = glTile(size, tiles[0]!);
    expect(worldY(tileCamera(whole, top), top.height)).toBeCloseTo(view.region.y + view.region.height, 9);
  });
});

describe("line weights in a picture", () => {
  const canvas = { width: 800, height: 600 };
  const region = { x: 0, y: 0, width: 400, height: 300 };

  it("are the viewer's own by default: the pixel widths as they are, a sheet's at the viewer's zoom on the region", () => {
    // The viewer fits 400 units in 800 px: 0.5 units per pixel. A picture of 1600 px: 0.25.
    expect(lineweightFactors(undefined, region, 0.25, canvas)).toEqual({ pixel: 1, paper: 0.5 });
    expect(lineweightFactors("screen", region, 0.5, canvas)).toEqual({ pixel: 1, paper: 1 });
    expect(lineweightFactors("screen", region, 1, canvas)).toEqual({ pixel: 1, paper: 2 });
  });

  it("scaled grow with the picture: as the viewer's zoom raised until the region fills it", () => {
    // Twice the pixels along a side: twice the width in pixels, and a sheet's lineweight at its real width.
    expect(lineweightFactors("scaled", region, 0.25, canvas)).toEqual({ pixel: 2, paper: 1 });
    expect(lineweightFactors("scaled", region, 0.5, canvas)).toEqual({ pixel: 1, paper: 1 });
    expect(lineweightFactors("scaled", region, 2, canvas)).toEqual({ pixel: 0.25, paper: 1 });
  });

  it("are the same either way for what the viewer shows, at its own size", () => {
    const viewer = viewportRegion({ cx: 3, cy: 4, scale: 0.7, ...canvas }, [0, 0]);
    const view = exportView({ ...canvas, region: viewer });
    const screen = lineweightFactors("screen", view.region, view.scale, canvas);
    const scaled = lineweightFactors("scaled", view.region, view.scale, canvas);
    expect(screen.pixel).toBeCloseTo(1, 12);
    expect(screen.paper).toBeCloseTo(1, 12);
    expect(scaled.pixel).toBeCloseTo(1, 12);
    expect(scaled.paper).toBeCloseTo(1, 12);
  });

  it("measure the region against the viewer's canvas by the longer side it needs, so that it fits", () => {
    // A tall region in a wide canvas: the height decides.
    const tall = { x: 0, y: 0, width: 100, height: 600 };
    expect(lineweightFactors("scaled", tall, 0.5, canvas).pixel).toBeCloseTo(2, 12);
  });

  it("take an ordinary screen for a canvas not laid out", () => {
    expect(referenceCanvas({ width: 1, height: 1 })).toEqual({ width: 1024, height: 768 });
    expect(referenceCanvas({ width: 63, height: 500 })).toEqual({ width: 1024, height: 768 });
    expect(referenceCanvas({ width: 64, height: 64 })).toEqual({ width: 64, height: 64 });
    const hidden = lineweightFactors("scaled", { x: 0, y: 0, width: 1024, height: 768 }, 1, { width: 1, height: 1 });
    expect(hidden.pixel).toBe(1);
  });
});

describe("one picture at a time", () => {
  const defer = <T = void>() => {
    let resolve!: (v: T) => void;
    let reject!: (e: unknown) => void;
    const promise = new Promise<T>((res, rej) => ((resolve = res), (reject = rej)));
    return { promise, resolve, reject };
  };
  const tick = () => new Promise((r) => setTimeout(r, 0));

  it("runs jobs in order, the next after the last has let go", async () => {
    const run = serial();
    const log: string[] = [];
    const first = defer();
    const a = run(undefined, async () => (log.push("a start"), await first.promise, log.push("a end"), "a"));
    const b = run(undefined, async () => (log.push("b"), "b"));
    await tick();
    expect(log).toEqual(["a start"]);
    first.resolve();
    expect(await Promise.all([a, b])).toEqual(["a", "b"]);
    expect(log).toEqual(["a start", "a end", "b"]);
  });

  it("goes on after a job that failed", async () => {
    const run = serial();
    const a = run(undefined, () => Promise.reject(new Error("no")));
    await expect(a).rejects.toThrow("no");
    expect(await run(undefined, async () => 2)).toBe(2);
  });

  it("rejects a job aborted while it waits, at once, and never runs it", async () => {
    const run = serial();
    const first = defer();
    const a = run(undefined, () => first.promise);
    const abort = new AbortController();
    let ran = false;
    const b = run(abort.signal, async () => ((ran = true), 1));
    abort.abort();
    expect(await codeOf(b)).toBe("aborted");
    first.resolve();
    await a;
    await tick();
    expect(ran).toBe(false);
  });

  it("rejects a job aborted while it runs at once, and lets the next start only when it has let go", async () => {
    const run = serial();
    const abort = new AbortController();
    const working = defer();
    const log: string[] = [];
    const a = run(abort.signal, async () => (await working.promise, log.push("a freed")));
    const b = run(undefined, async () => (log.push("b"), "b"));
    await tick();
    abort.abort();
    expect(await codeOf(a)).toBe("aborted");
    await tick();
    expect(log).toEqual([]);
    working.resolve();
    expect(await b).toBe("b");
    expect(log).toEqual(["a freed", "b"]);
  });

  it("does not run a job whose signal was aborted before it was asked", async () => {
    const run = serial();
    const abort = new AbortController();
    abort.abort();
    let ran = false;
    expect(await codeOf(run(abort.signal, async () => ((ran = true), 1)))).toBe("aborted");
    expect(ran).toBe(false);
  });

  it("drops the answer of work that went on after its abort, without an unhandled rejection", async () => {
    const abort = new AbortController();
    const work = defer<number>();
    const p = abortable(work.promise, abort.signal);
    abort.abort();
    expect(await codeOf(p)).toBe("aborted");
    work.reject(new Error("late"));
    await tick();
  });

  it("links signals, and lets go of them", () => {
    const one = new AbortController();
    const two = new AbortController();
    const both = linked([one.signal, undefined, two.signal]);
    expect(both.signal.aborted).toBe(false);
    two.abort();
    expect(both.signal.aborted).toBe(true);
    const three = new AbortController();
    const detached = linked([three.signal]);
    detached.dispose();
    three.abort();
    expect(detached.signal.aborted).toBe(false);
    const done = new AbortController();
    done.abort();
    expect(linked([done.signal]).signal.aborted).toBe(true);
  });
});
