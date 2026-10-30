import { describe, expect, it } from "vitest";

import {
  checkRasterOptions,
  fitCamera,
  fitRect,
  isPage,
  MAX_PICTURE_EDGE,
  MAX_PICTURE_PIXELS,
  pictureSize,
  planRect,
  RasterError,
  rasterSize,
  tilePlan,
  tileRect,
} from "./pictures.js";

it("sizes a picture by its longest side, held to the largest picture", () => {
  expect(pictureSize(600, 800, 200)).toEqual({ width: 150, height: 200 });
  expect(pictureSize(800, 600, 200)).toEqual({ width: 200, height: 150 });
  // Past the edge limit and the pixel budget of a tall page: the budget decides.
  const tall = pictureSize(600, 800, 1e9)!;
  expect(tall.height).toBeLessThan(MAX_PICTURE_EDGE);
  expect(tall.width * tall.height).toBeLessThanOrEqual(MAX_PICTURE_PIXELS);
  expect(tall.width * tall.height).toBeGreaterThan(MAX_PICTURE_PIXELS * 0.99);
  expect(tall.height / tall.width).toBeCloseTo(800 / 600, 2);
  // A thin page reaches the edge limit before the budget.
  expect(pictureSize(100, 400, 1e9)).toEqual({ width: 4096, height: MAX_PICTURE_EDGE });
  // A sliver keeps a pixel.
  expect(pictureSize(10_000, 1, 100)).toEqual({ width: 100, height: 1 });
  expect(pictureSize(0, 800, 200)).toBeNull();
  expect(pictureSize(600, NaN, 200)).toBeNull();
  expect(pictureSize(600, 800, Infinity)).toBeNull();
});

it("knows a page by its number", () => {
  expect(isPage(1, 3)).toBe(true);
  expect(isPage(3, 3)).toBe(true);
  for (const p of [0, 4, 1.5, "1", NaN]) expect(isPage(p, 3), String(p)).toBe(false);
});

const code = (f: () => unknown) => {
  try {
    f();
  } catch (e) {
    return e instanceof RasterError ? e.code : `not a RasterError: ${String(e)}`;
  }
  return "none";
};

describe("the size of a raster", () => {
  it("takes the other side from the region's shape when only one is given", () => {
    expect(rasterSize({ width: 300 }, 1.5)).toEqual({ width: 300, height: 200 });
    expect(rasterSize({ height: 200 }, 1.5)).toEqual({ width: 300, height: 200 });
    expect(rasterSize({ width: 100, height: 70 }, 1.5)).toEqual({ width: 100, height: 70 });
    expect(rasterSize({ longEdge: 300 }, 1.5)).toEqual({ width: 300, height: 200 });
    expect(rasterSize({ longEdge: 300 }, 0.5)).toEqual({ width: 150, height: 300 });
    // Whole pixels, at least one.
    expect(rasterSize({ width: 10.4 }, 1000)).toEqual({ width: 10, height: 1 });
    expect(rasterSize({ longEdge: 0.2 }, 1)).toEqual({ width: 1, height: 1 });
  });

  it("holds a longEdge to the limits, and refuses a width and height past them", () => {
    expect(rasterSize({ longEdge: 1e9 }, 1000)).toEqual({ width: MAX_PICTURE_EDGE, height: 16 });
    const wide = rasterSize({ longEdge: 1e9 }, 1);
    expect(wide.width * wide.height).toBeLessThanOrEqual(MAX_PICTURE_PIXELS);
    expect(wide.width).toBe(wide.height);
    expect(code(() => rasterSize({ width: MAX_PICTURE_EDGE + 1, height: 1 }, 1))).toBe("too-large");
    expect(code(() => rasterSize({ width: MAX_PICTURE_EDGE, height: MAX_PICTURE_EDGE }, 1))).toBe("too-large");
    expect(code(() => rasterSize({ width: MAX_PICTURE_EDGE }, 0.001))).toBe("too-large");
    // Exactly the budget is allowed.
    expect(rasterSize({ width: 8192, height: 8192 }, 1)).toEqual({ width: 8192, height: 8192 });
  });

  it("refuses what is no size", () => {
    for (const o of [{}, { longEdge: 0 }, { longEdge: -1 }, { longEdge: NaN }, { longEdge: Infinity }, { width: 0 }, { height: NaN }, { width: 10, height: -3 }, { longEdge: 10, width: 10 }]) {
      expect(code(() => rasterSize(o, 1)), JSON.stringify(o)).toBe("invalid");
    }
    for (const aspect of [0, -1, NaN, Infinity]) expect(code(() => rasterSize({ longEdge: 10 }, aspect)), String(aspect)).toBe("invalid");
  });
});

describe("fitting a region to a picture's shape", () => {
  const square = { x: 10, y: 20, width: 100, height: 100 };

  it("widens the region to a wider picture (contain) and heightens it for a taller one, about its centre", () => {
    expect(fitRect(square, 2, "contain")).toEqual({ x: -40, y: 20, width: 200, height: 100 });
    expect(fitRect(square, 0.5, "contain")).toEqual({ x: 10, y: -30, width: 100, height: 200 });
    expect(fitRect(square, 1, "contain")).toEqual(square);
    // The default is contain.
    expect(fitRect(square, 2)).toEqual(fitRect(square, 2, "contain"));
  });

  it("narrows it for cover, so that the picture is filled", () => {
    expect(fitRect(square, 2, "cover")).toEqual({ x: 10, y: 45, width: 100, height: 50 });
    expect(fitRect(square, 0.5, "cover")).toEqual({ x: 35, y: 20, width: 50, height: 100 });
  });

  it("sees the shape on the paper, not in the coordinates: a page's fractions are as long as the page is", () => {
    // A landscape page, 400 x 200 pt: the whole page is 2:1 and fits a 2:1 picture as it is.
    const page = { x: 0, y: 0, width: 1, height: 1 };
    expect(fitRect(page, 2, "contain", { x: 400, y: 200 })).toEqual(page);
    // A square picture: contain adds height, in fractions of the page's height.
    expect(fitRect(page, 1, "contain", { x: 400, y: 200 })).toEqual({ x: 0, y: -0.5, width: 1, height: 2 });
    expect(fitRect(page, 1, "cover", { x: 400, y: 200 })).toEqual({ x: 0.25, y: 0, width: 0.5, height: 1 });
  });

  it("does not move the region it is given", () => {
    const copy = { ...square };
    fitRect(square, 3, "cover");
    expect(square).toEqual(copy);
  });

  it("fits a camera: contain keeps all of what it framed, cover fills the picture with it", () => {
    const ortho = { position: [0, 0, 10], target: [0, 0, 0], projection: { type: "orthographic", height: 10 }, aspect: 2 } as const;
    // Wider picture: contain keeps the vertical extent (the width grows with the aspect).
    expect(fitCamera(ortho, 4, "contain")).toMatchObject({ aspect: 4, projection: { type: "orthographic", height: 10 } });
    // Narrower picture: contain keeps the horizontal extent (20 wide), so the height grows.
    expect(fitCamera(ortho, 1, "contain")).toMatchObject({ aspect: 1, projection: { type: "orthographic", height: 20 } });
    // Cover is the other way about.
    expect(fitCamera(ortho, 1, "cover")).toMatchObject({ projection: { height: 10 } });
    expect(fitCamera(ortho, 4, "cover")).toMatchObject({ projection: { height: 5 } });
    expect(fitCamera(ortho, 2, "cover")).toMatchObject({ aspect: 2, projection: { height: 10 } });
    // A perspective camera widens by the tangent of the half angle, not the angle.
    const persp = { ...ortho, projection: { type: "perspective", fov: 60 } } as const;
    const narrow = fitCamera(persp, 1, "contain").projection as { fov: number };
    expect(Math.tan((narrow.fov * Math.PI) / 360)).toBeCloseTo(Math.tan(Math.PI / 6) * 2, 9);
    expect((fitCamera(persp, 4, "contain").projection as { fov: number }).fov).toBeCloseTo(60, 9);
  });
});

describe("tiles", () => {
  it("cover the picture once, row by row, the last ones cut", () => {
    const tiles = tilePlan(250, 120, 100);
    expect(tiles).toHaveLength(6);
    expect(tiles[0]).toEqual({ x: 0, y: 0, width: 100, height: 100 });
    expect(tiles[2]).toEqual({ x: 200, y: 0, width: 50, height: 100 });
    expect(tiles[5]).toEqual({ x: 200, y: 100, width: 50, height: 20 });
    // Every pixel exactly once.
    expect(tiles.reduce((n, t) => n + t.width * t.height, 0)).toBe(250 * 120);
    expect(tilePlan(100, 100, 100)).toHaveLength(1);
    expect(tilePlan(1, 1, 4096)).toEqual([{ x: 0, y: 0, width: 1, height: 1 }]);
  });

  it("are at most MAX_TILES, and at least a pixel", () => {
    expect(code(() => tilePlan(MAX_PICTURE_EDGE, MAX_PICTURE_EDGE, 128))).toBe("too-large");
    expect(tilePlan(MAX_PICTURE_EDGE, 4096, 256)).toHaveLength(64 * 16);
    for (const t of [0, -1, 1.5, NaN]) expect(code(() => tilePlan(10, 10, t)), String(t)).toBe("invalid");
  });

  it("show the part of the region they cover, the y axis of a drawing going up", () => {
    const region = { x: 0, y: 0, width: 200, height: 100 };
    const size = { width: 400, height: 200 };
    const tile = { x: 100, y: 50, width: 100, height: 100 };
    expect(tileRect(region, size, tile)).toEqual({ x: 50, y: 25, width: 50, height: 50 });
    // Up: the picture's top row is the region's top (largest y).
    expect(tileRect(region, size, tile, true)).toEqual({ x: 50, y: 25, width: 50, height: 50 });
    expect(tileRect(region, size, { x: 0, y: 0, width: 100, height: 50 }, true)).toEqual({ x: 0, y: 75, width: 50, height: 25 });
    expect(tileRect(region, size, { x: 0, y: 0, width: 100, height: 50 })).toEqual({ x: 0, y: 0, width: 50, height: 25 });
  });
});

describe("planning a raster of a rectangle format", () => {
  const full = { x: 0, y: 0, width: 1, height: 1 };
  const page = { x: 400, y: 200 };

  it("draws the whole page by default, on white, at the size of its shape", () => {
    expect(planRect({ longEdge: 800 }, full, page, null)).toEqual({ width: 800, height: 400, region: full, background: "#ffffff" });
  });

  it("takes the viewport for 'current', and refuses it where there is none", () => {
    const here = { x: 0.5, y: 0, width: 0.5, height: 1 };
    expect(planRect({ longEdge: 100, region: "current" }, full, page, here).region).toEqual(here);
    expect(code(() => planRect({ longEdge: 100, region: "current" }, full, page, null))).toBe("invalid");
  });

  it("changes the region to the picture's shape only when both sides are given", () => {
    const region = { x: 0, y: 0, width: 0.5, height: 1 };
    // 200 x 200 pt region.
    expect(planRect({ longEdge: 100, region }, full, page, null).region).toEqual(region);
    expect(planRect({ width: 100, region }, full, page, null)).toMatchObject({ width: 100, height: 100, region });
    // Both sides, a 2:1 picture of a square region (200 x 200 pt): contain widens it past the page's left edge, cover cuts its height.
    expect(planRect({ width: 200, height: 100, region }, full, page, null).region).toEqual({ x: -0.25, y: 0, width: 1, height: 1 });
    expect(planRect({ width: 200, height: 100, region, fit: "cover" }, full, page, null).region).toEqual({ x: 0, y: 0.25, width: 0.5, height: 0.5 });
  });

  it("refuses a region of another kind, a bad background, a bad fit", () => {
    const camera = { position: [0, 0, 1], target: [0, 0, 0], projection: { type: "perspective", fov: 50 }, aspect: 1 } as const;
    expect(code(() => planRect({ longEdge: 10, region: camera }, full, page, null))).toBe("invalid");
    expect(code(() => planRect({ longEdge: 10, region: { x: 0, y: 0, width: 0, height: 1 } }, full, page, null))).toBe("invalid");
    expect(code(() => planRect({ longEdge: 10, background: "url(x)" }, full, page, null))).toBe("invalid");
    expect(code(() => planRect({ longEdge: 10, fit: "stretch" as never }, full, page, null))).toBe("invalid");
    expect(planRect({ longEdge: 10, background: "transparent" }, full, page, null).background).toBe("transparent");
    expect(planRect({ longEdge: 10 }, full, page, null, "transparent").background).toBe("transparent");
  });
});

describe("options that cross a message", () => {
  it("keep the known fields and drop the rest", () => {
    expect(checkRasterOptions({ longEdge: 5, extra: 1, signal: {} })).toEqual({ longEdge: 5 });
    expect(checkRasterOptions({})).toEqual({});
    expect(checkRasterOptions({ region: { x: 1, y: 2, width: 3, height: 4, z: 5 } })).toEqual({ region: { x: 1, y: 2, width: 3, height: 4 } });
  });

  it("are null when any field is wrong", () => {
    for (const bad of [null, [], "x", { longEdge: "5" }, { width: 1e10 }, { region: { x: 1e16, y: 0, width: 1, height: 1 } }, { layout: 3 }, { fit: "fill" }, { background: "expression(1)" }]) {
      expect(checkRasterOptions(bad), JSON.stringify(bad)).toBeNull();
    }
  });
});
