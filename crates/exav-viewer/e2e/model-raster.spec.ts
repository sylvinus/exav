// The pictures and the viewport of 3D models (IFC, STL, OBJ): drawn again from
// the geometry by an off-screen renderer at any size, in tiles when needed,
// from a camera in the file's own coordinates.
import { expect, test, type Page } from "@playwright/test";

import { failOnViolations } from "./csp.js";
import { decodePng, difference, find, type Pixels } from "./pixels.js";
import { openSample, pick } from "./samples.js";

failOnViolations();

type Which = "exavDemo" | "headless";
type Camera = {
  position: number[];
  target: number[];
  up?: number[];
  projection: { type: "perspective"; fov: number } | { type: "orthographic"; height: number };
  aspect: number;
};
type Info = { width: number; height: number; page: number; space: string; region: Camera };
type Options = Record<string, unknown>;

declare global {
  interface Window {
    glContexts: { ctx: WebGLRenderingContext | WebGL2RenderingContext; offscreen: boolean }[];
    viewports: string[];
  }
}

test.beforeEach(async ({ page }) => {
  // Each picture builds its own context, lights and shaders: seconds on a software GPU.
  test.setTimeout(600_000);
  await page.addInitScript(() => {
    // Every WebGL context made, and the size of every viewport set: to see what is freed and how a picture is cut.
    window.glContexts = [];
    window.viewports = [];
    const watch = (proto: { getContext: (...a: never[]) => unknown }, offscreen: boolean) => {
      const real = proto.getContext;
      proto.getContext = function (this: unknown, ...a: never[]) {
        const ctx = real.apply(this, a) as WebGLRenderingContext | null;
        if (ctx && typeof (ctx as WebGLRenderingContext).viewport === "function" && !window.glContexts.some((g) => g.ctx === ctx)) window.glContexts.push({ ctx, offscreen });
        return ctx;
      } as never;
    };
    watch(HTMLCanvasElement.prototype as never, false);
    if (typeof OffscreenCanvas === "function") watch(OffscreenCanvas.prototype as never, true);
    for (const C of [WebGLRenderingContext, typeof WebGL2RenderingContext === "function" ? WebGL2RenderingContext : null]) {
      if (!C) continue;
      const real = C.prototype.viewport;
      C.prototype.viewport = function (this: WebGLRenderingContext, x: number, y: number, w: number, h: number) {
        window.viewports.push(`${w}x${h}`);
        return real.call(this, x, y, w, h);
      };
    }
  });
});

const phase = (page: Page) => page.locator(".demo-frame .exav-viewer-body");

async function open(page: Page, name: string, params: Record<string, string> = { mode: "page" }) {
  await openSample(page, name, params);
  await expect(phase(page)).toHaveAttribute("data-phase", "ready");
}

const canvas = (page: Page) => page.locator(".demo-frame .exav-viewer-model-canvas");

async function shot(page: Page): Promise<Pixels> {
  const set = (value: string) => page.locator(".exav-viewer-tools").evaluateAll((els, v) => els.forEach((e) => ((e as HTMLElement).style.visibility = v)), value);
  await set("hidden");
  try {
    return decodePng(await canvas(page).screenshot({ animations: "disabled" }));
  } finally {
    await set("");
  }
}

async function settled(page: Page): Promise<Pixels> {
  let last = await shot(page);
  for (let i = 0; i < 30; i++) {
    await page.waitForTimeout(150);
    const next = await shot(page);
    if (difference(last, next) === 0) return next;
    last = next;
  }
  return last;
}

/** The picture as the session's `toBlob` gives it (PNG), read here. */
async function exportPng(page: Page, options: Options, which: Which = "exavDemo"): Promise<{ px: Pixels; info: Info }> {
  const started = Date.now();
  const out = await page.evaluate(
    async ([which, options]) => {
      const session = (window as unknown as Record<string, { session(): { controllers: { get(): { pictures: { toBlob(p: number, o: unknown): Promise<{ blob: Blob } & Record<string, unknown>> } } } } }>)[which as string]!.session();
      const { blob, ...info } = await session.controllers.get().pictures.toBlob(1, { ...(options as object), type: "png" });
      const bytes = new Uint8Array(await blob.arrayBuffer());
      let s = "";
      for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
      return { b64: btoa(s), info };
    },
    [which, options] as const,
  );
  console.log(`picture ${out.info.width}x${out.info.height}: ${Date.now() - started} ms`);
  return { px: decodePng(Buffer.from(out.b64, "base64")), info: out.info as unknown as Info };
}

/** The error code a picture is refused with, or "none". */
const failure = (page: Page, options: Options, which: Which = "exavDemo") =>
  page.evaluate(
    async ([which, options]) => {
      const session = (window as unknown as Record<string, { session(): { controllers: { get(): { pictures: { raster(p: number, o: unknown): Promise<{ bitmap: ImageBitmap }> } } } } }>)[which as string]!.session();
      try {
        (await session.controllers.get().pictures.raster(1, options)).bitmap.close();
        return "none";
      } catch (e) {
        return (e as { code?: string }).code ?? String(e);
      }
    },
    [which, options] as const,
  );

const viewport = (page: Page, which: Which = "exavDemo") =>
  page.evaluate((which) => {
    const s = (window as unknown as Record<string, { session(): { controllers: { get(): { viewport: { get(): unknown } } } } }>)[which]!.session();
    return s.controllers.get().viewport.get() as { space: string; page: number; region: Camera } | null;
  }, which);

const at = (p: Pixels, x: number, y: number) => {
  const i = (Math.floor(y) * p.width + Math.floor(x)) * 4;
  return [p.data[i]!, p.data[i + 1]!, p.data[i + 2]!, p.data[i + 3]!];
};

const RED = [255, 0, 0, 255];
const isRed = (c: number[]) => c[0]! > 250 && c[1]! < 5 && c[2]! < 5 && c[3] === 255;

/** The mask of what is not the picture's corner colour. */
const body = (p: Pixels) => find(p, (r, g, b) => Math.max(Math.abs(r - p.data[0]!), Math.abs(g - p.data[1]!), Math.abs(b - p.data[2]!)) > 40);

/** Top view of the STL house (x 0..60, y 0..30, Z up), 10 px a unit at 600 x 400, the ground red. */
const STL_TOP: Camera = { position: [30, 15, 100], target: [30, 15, 0], up: [0, 1, 0], projection: { type: "orthographic", height: 40 }, aspect: 1.5 };
/** The IFC house (x 0..12, y 0..8, walls 3 m high on a slab). */
const IFC_TOP: Camera = { position: [6, 4, 50], target: [6, 4, 0], up: [0, 1, 0], projection: { type: "orthographic", height: 12 }, aspect: 1.5 };

test.describe("the picture is the viewer's view", () => {
  for (const name of ["house.stl", "house.ifc"]) {
    test(`${name}: region "current" equals a screenshot of the canvas, also after the user orbits`, async ({ page }) => {
      await open(page, name);
      const reference = await settled(page);
      const view = (await viewport(page))!;
      expect(view.space).toBe("camera");
      expect(view.page).toBe(1);
      expect(view.region.aspect).toBeCloseTo(reference.width / reference.height, 2);
      expect(view.region.up).toBeDefined();
      const { px, info } = await exportPng(page, { width: reference.width, height: reference.height, region: "current" });
      expect([px.width, px.height]).toEqual([reference.width, reference.height]);
      expect(info).toMatchObject({ width: reference.width, height: reference.height, page: 1, space: "camera" });
      // The camera used is the one in view.
      info.region.position.forEach((v, i) => expect(v).toBeCloseTo(view.region.position[i]!, 6));
      info.region.target.forEach((v, i) => expect(v).toBeCloseTo(view.region.target[i]!, 6));
      expect(info.region.projection.type).toBe("perspective");
      // The picture's pixels round the canvas's shape, which moves the field of view by a fraction of a degree.
      expect((info.region.projection as { fov: number }).fov).toBeCloseTo((view.region.projection as { fov: number }).fov, 0);
      const diff = difference(reference, px);
      console.log(name, "mean difference", diff);
      expect(diff).toBeLessThan(3);
      // Only silhouette pixels (and the IFC's floor grid, which the picture leaves out) may differ much.
      let far = 0;
      for (let i = 0; i < reference.data.length; i += 4) if (Math.max(Math.abs(reference.data[i]! - px.data[i]!), Math.abs(reference.data[i + 1]! - px.data[i + 1]!), Math.abs(reference.data[i + 2]! - px.data[i + 2]!)) > 40) far++;
      console.log(name, "pixels differing by more than 40:", far, "of", reference.width * reference.height);
      // (The IFC's grid lines are about 1% of its pixels.)
      expect(far).toBeLessThan(reference.width * reference.height * (name === "house.ifc" ? 0.012 : 0.002));

      // The user orbits: the viewport follows, and the picture follows it.
      const box = (await canvas(page).boundingBox())!;
      await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2);
      await page.mouse.down();
      await page.mouse.move(box.x + box.width / 2 + 120, box.y + box.height / 2 - 40, { steps: 8 });
      await page.mouse.up();
      await expect.poll(async () => (await viewport(page))!.region.position[0]).not.toBeCloseTo(view.region.position[0]!, 3);
      // Damping has settled: the screenshot stops changing, and the viewport is at the final camera.
      const moved = await settled(page);
      await page.waitForTimeout(300);
      const again = await exportPng(page, { width: moved.width, height: moved.height, region: "current" });
      const diff2 = difference(moved, again.px);
      console.log(name, "mean difference after orbit", diff2);
      expect(diff2).toBeLessThan(3);
      expect(difference(reference, moved)).toBeGreaterThan(difference(moved, again.px));
    });
  }

  test("a viewport read back is the same view as 'current'", async ({ page }) => {
    await open(page, "house.stl");
    await settled(page);
    const view = (await viewport(page))!;
    const a = await exportPng(page, { width: 300, height: 200, region: "current" });
    const b = await exportPng(page, { width: 300, height: 200, region: view.region });
    expect(difference(a.px, b.px)).toBeLessThan(0.5);
  });

  test("with no region the picture is the model framed as the viewer opens it, in the canvas's shape", async ({ page }) => {
    await open(page, "house.stl");
    const reference = await settled(page);
    const { px, info } = await exportPng(page, { longEdge: 500 });
    expect(px.width).toBe(500);
    expect(px.height / px.width).toBeCloseTo(reference.height / reference.width, 1);
    expect(info.region.aspect).toBeCloseTo(reference.width / reference.height, 2);
    // Whole in the picture, not cut by an edge.
    const box = body(px).box!;
    expect(box.minX).toBeGreaterThan(2);
    expect(box.minY).toBeGreaterThan(2);
    expect(box.maxX).toBeLessThan(px.width - 3);
    expect(box.maxY).toBeLessThan(px.height - 3);
  });
});

test.describe("a known camera", () => {
  test("STL from above: the colours are where the camera says, in both fits", async ({ page }) => {
    await open(page, "house.stl");
    const { px, info } = await exportPng(page, { width: 600, height: 400, region: STL_TOP, background: "#ff0000" });
    expect(info.region.projection).toEqual({ type: "orthographic", height: 40 });
    expect(info.region.aspect).toBeCloseTo(1.5, 9);
    // Beyond the house, south of it where no shadow falls: the ground asked for, to the pixel.
    expect(at(px, 5, 395)).toEqual(RED);
    expect(at(px, 200, 360)).toEqual(RED);
    expect(at(px, 500, 330)).toEqual(RED);
    expect(at(px, 595, 395)).toEqual(RED);
    expect(at(px, 590, 5)).toEqual(RED);
    // The roof and the annex.
    for (const [x, y] of [
      [200, 200],
      [100, 150],
      [300, 320],
      [500, 200],
      [450, 120],
    ] as const) {
      const c = at(px, x, y);
      expect(isRed(c), `${x},${y}`).toBe(false);
      expect(c[3]).toBe(255);
      // The grey-blue of the surface: blue over red.
      expect(c[2]! - c[0]!, `${x},${y}`).toBeGreaterThan(5);
    }
    // The silhouette: the house is 40 x 30 units, the annex 20 x 20, at 10 px a unit.
    const box = find(px, (r, _g, b) => b - r > 5).box!;
    expect(box.minX).toBeLessThanOrEqual(1);
    expect(box.maxX).toBeGreaterThanOrEqual(598);
    expect(Math.abs(box.minY - 50)).toBeLessThanOrEqual(1);
    expect(Math.abs(box.maxY - 349)).toBeLessThanOrEqual(1);

    // A square picture of a 3:2 camera: "contain" keeps its width (a taller view), "cover" its height.
    const contain = await exportPng(page, { width: 600, height: 600, region: STL_TOP, background: "#ff0000", fit: "contain" });
    const cover = await exportPng(page, { width: 600, height: 600, region: STL_TOP, background: "#ff0000", fit: "cover" });
    expect(contain.info.region.projection).toEqual({ type: "orthographic", height: 60 });
    expect(cover.info.region.projection).toEqual({ type: "orthographic", height: 40 });
    expect([contain.info.region.aspect, cover.info.region.aspect]).toEqual([1, 1]);
    // x 0..60 over 600 px, y -15..45 (row = 45 - y, times 10): the house spans rows 150..450, the annex ends at x 60.
    expect(isRed(at(contain.px, 200, 500))).toBe(true);
    expect(isRed(at(contain.px, 200, 440))).toBe(false);
    expect(isRed(at(contain.px, 590, 500))).toBe(true);
    expect(isRed(at(contain.px, 590, 300))).toBe(false);
    // x 10..50 over 600 px (15 px a unit), y -5..35 (row = 35 - y, times 15): the annex, y 5..25, is rows 150..450 and reaches the right edge.
    expect(isRed(at(cover.px, 590, 180))).toBe(false);
    expect(isRed(at(cover.px, 590, 570))).toBe(true);
    // The house is 40 units wide: from x 10 it fills the left, 450 px of the 600.
    expect(isRed(at(cover.px, 400, 300))).toBe(false);
    expect(isRed(at(cover.px, 455, 560))).toBe(true);
    // The picture's own shape, when one side is given.
    const wide = await exportPng(page, { height: 200, region: STL_TOP, background: "#ff0000" });
    expect([wide.px.width, wide.px.height]).toEqual([300, 200]);
  });

  test("IFC from above, in the model's metres", async ({ page }) => {
    await open(page, "house.ifc");
    const { px, info } = await exportPng(page, { width: 600, height: 400, region: IFC_TOP, background: "#ff0000" });
    expect(info.region.position).toEqual(IFC_TOP.position);
    // x -3..15 over 600 px (33.3 px a unit), y -2..10: the slab is x 0..12, y 0..8.
    expect(at(px, 20, 20)).toEqual(RED);
    expect(at(px, 580, 380)).toEqual(RED);
    expect(at(px, 300, 200)[3]).toBe(255);
    expect(isRed(at(px, 300, 200))).toBe(false);
    const box = find(px, (r, g, b) => !(r > 250 && g < 5 && b < 5)).box!;
    expect(Math.abs(box.minX - 100)).toBeLessThanOrEqual(2);
    expect(Math.abs(box.maxX - 500)).toBeLessThanOrEqual(2);
    expect(Math.abs(box.minY - 67)).toBeLessThanOrEqual(2);
    expect(Math.abs(box.maxY - 333)).toBeLessThanOrEqual(2);
  });

  test("a perspective camera looks at its target, and the model's up is Z for the STL", async ({ page }) => {
    await open(page, "house.stl");
    const region: Camera = { position: [30, -90, 20], target: [30, 15, 20], projection: { type: "perspective", fov: 30 }, aspect: 1.5 };
    const withDefault = await exportPng(page, { width: 300, height: 200, region });
    const withUp = await exportPng(page, { width: 300, height: 200, region: { ...region, up: [0, 0, 1] } });
    expect(difference(withDefault.px, withUp.px)).toBe(0);
    expect(withDefault.info.region.up).toEqual([0, 0, 1]);
    // The house is close to the ground's colour, so what is looked at is where the pixels step by more than the ground's gradient does.
    const edges = (p: Pixels) => {
      const step = (i: number, j: number) => Math.max(Math.abs(p.data[i]! - p.data[j]!), Math.abs(p.data[i + 1]! - p.data[j + 1]!), Math.abs(p.data[i + 2]! - p.data[j + 2]!));
      let n = 0;
      let rows = 0;
      for (let y = 0; y < p.height - 1; y++)
        for (let x = 0; x < p.width - 1; x++) {
          const i = (y * p.width + x) * 4;
          if (step(i, i + 4) > 8 || step(i, i + p.width * 4) > 8) {
            n++;
            rows += y;
          }
        }
      return { n, meanY: rows / n };
    };
    // Upright: the roof ridge (z 40) is above the eaves (z 25) in the picture, and the ground below the house: the lines are mostly in the lower half.
    const upright = edges(withDefault.px);
    expect(upright.n).toBeGreaterThan(300);
    expect(upright.meanY).toBeGreaterThan(110);
    // With the opposite up the picture is upside down: the same lines, turned about the picture's centre.
    const flipped = await exportPng(page, { width: 300, height: 200, region: { ...region, up: [0, 0, -1] } });
    // (The lighting and the ground's gradient do not turn with it, hence the margin; the picture not turned is 40 rows away.)
    expect(Math.abs(edges(flipped.px).meanY - (199 - upright.meanY))).toBeLessThanOrEqual(10);
  });

  test("the same view in the OBJ's own Y-up coordinates is the STL's picture", async ({ page }) => {
    await open(page, "house.stl");
    const stl = await exportPng(page, { width: 600, height: 400, region: STL_TOP, background: "#ff0000" });
    // (x, y, z) of the STL is (x, z, -y) in the OBJ.
    await pick(page, "house.obj");
    await expect(phase(page)).toHaveAttribute("data-phase", "ready");
    const OBJ_TOP: Camera = { position: [30, 100, -15], target: [30, 0, -15], up: [0, 0, -1], projection: { type: "orthographic", height: 40 }, aspect: 1.5 };
    const obj = await exportPng(page, { width: 600, height: 400, region: OBJ_TOP, background: "#ff0000" });
    const mask = (p: Pixels) => find(p, (r, g, b) => !(r > 250 && g < 5 && b < 5));
    const a = mask(stl.px);
    const b = mask(obj.px);
    expect(Math.abs(a.count - b.count) / a.count).toBeLessThan(0.01);
    for (const k of ["minX", "minY", "maxX", "maxY"] as const) expect(Math.abs(a.box![k] - b.box![k]), k).toBeLessThanOrEqual(1);
    // No up given: a Y-up file takes Y, and the picture is the same as with it said.
    const side: Camera = { position: [30, 15, 100], target: [30, 15, 0], projection: { type: "perspective", fov: 40 }, aspect: 1.5 };
    const implicit = await exportPng(page, { width: 150, height: 100, region: side });
    const explicit = await exportPng(page, { width: 150, height: 100, region: { ...side, up: [0, 1, 0] } });
    expect(difference(implicit.px, explicit.px)).toBe(0);
    expect(implicit.info.region.up).toEqual([0, 1, 0]);
  });
});

test.describe("sharp at any size", () => {
  test("a picture bigger than a tile has a one pixel silhouette, and agrees with a small one", async ({ page }) => {
    await open(page, "house.stl");
    const small = await exportPng(page, { width: 300, height: 200, region: STL_TOP, background: "#ff0000" });
    await page.evaluate(() => (window.viewports.length = 0));
    const big = await exportPng(page, { width: 3000, height: 2000, region: STL_TOP, background: "#ff0000" });
    expect([big.px.width, big.px.height]).toEqual([3000, 2000]);
    // More than one tile: no viewport as large as the picture.
    const sizes = await page.evaluate(() => [...new Set(window.viewports)]);
    expect(sizes).not.toContain("3000x2000");
    expect(sizes.some((s) => s.startsWith("2048x"))).toBe(true);
    // The house's south edge (y 0) is at row 1750 of 2000, where no shadow falls: red to model within two pixels, down a column.
    const column = (x: number) => Array.from({ length: 12 }, (_, i) => at(big.px, x, 1744 + i));
    const inBetween = column(600).filter((c) => !isRed(c) && !(c[2]! - c[0]! > 5 && c[3] === 255)).length;
    expect(inBetween).toBeLessThanOrEqual(2);
    // The seam of the two tiles (column 2048): not a line.
    const row = Array.from({ length: 8 }, (_, i) => at(big.px, 2044 + i, 1000));
    const first = row[0]!;
    for (const c of row) for (let k = 0; k < 3; k++) expect(Math.abs(c[k]! - first[k]!)).toBeLessThanOrEqual(6);
    // Averaged down to the small picture's size, they agree.
    const down: Pixels = { width: 300, height: 200, data: new Uint8Array(300 * 200 * 4) };
    for (let y = 0; y < 200; y++)
      for (let x = 0; x < 300; x++)
        for (let k = 0; k < 4; k++) {
          let sum = 0;
          for (let j = 0; j < 10; j++) for (let i = 0; i < 10; i++) sum += big.px.data[((y * 10 + j) * 3000 + x * 10 + i) * 4 + k]!;
          down.data[(y * 300 + x) * 4 + k] = Math.round(sum / 100);
        }
    const diff = difference(small.px, down);
    console.log("big against small", diff);
    expect(diff).toBeLessThan(4);
  });
});

test.describe("tiles", () => {
  const region: Camera = { position: [90, -80, 70], target: [30, 15, 12], projection: { type: "perspective", fov: 35 }, aspect: 4 / 3 };
  for (const [name, camera] of [
    ["house.stl", region],
    ["house.ifc", { position: [20, -16, 14], target: [6, 4, 1], projection: { type: "perspective" as const, fov: 40 }, aspect: 4 / 3 }],
  ] as const) {
    test(`${name}: a picture in tiles of 64 px is the picture in one pass, with no seams`, async ({ page }) => {
      await open(page, name);
      const single = await exportPng(page, { width: 400, height: 300, region: camera });
      const sizes = await page.evaluate(() => [...new Set(window.viewports)]);
      expect(sizes).toContain("400x300");

      await open(page, name, { mode: "page", rasterTile: "64" });
      await page.evaluate(() => (window.viewports.length = 0));
      const tiled = await exportPng(page, { width: 400, height: 300, region: camera });
      const tileSizes = await page.evaluate(() => [...new Set(window.viewports)]);
      expect(tileSizes).toContain("64x64");
      expect(tileSizes).not.toContain("400x300");
      // The same picture: a pixel may differ where an edge falls on a tile's border.
      expect(difference(single.px, tiled.px)).toBeLessThan(0.3);
      let far = 0;
      let worst = 0;
      for (let i = 0; i < single.px.data.length; i += 4) {
        const d = Math.max(Math.abs(single.px.data[i]! - tiled.px.data[i]!), Math.abs(single.px.data[i + 1]! - tiled.px.data[i + 1]!), Math.abs(single.px.data[i + 2]! - tiled.px.data[i + 2]!));
        worst = Math.max(worst, d);
        if (d > 40) far++;
      }
      console.log(name, "tiles: mean", difference(single.px, tiled.px), "worst", worst, "far", far);
      expect(far).toBeLessThanOrEqual(20);
      // Along the tile borders (columns 63/64, 127/128, ... and rows alike) nothing is a line.
      let seam = 0;
      for (let x = 64; x < 400; x += 64)
        for (let y = 0; y < 300; y++) {
          const a = at(tiled.px, x - 1, y);
          const b = at(tiled.px, x, y);
          const s = at(single.px, x - 1, y);
          const t = at(single.px, x, y);
          for (let k = 0; k < 3; k++) if (Math.abs(a[k]! - b[k]!) - Math.abs(s[k]! - t[k]!) > 30) seam++;
        }
      expect(seam).toBeLessThanOrEqual(6);
    });
  }

  test("a picture needing more tiles than the limit is refused before anything is drawn", async ({ page }) => {
    await open(page, "house.stl", { mode: "page", rasterTile: "2" });
    const before = await page.evaluate(() => window.glContexts.length);
    expect(await failure(page, { width: 400, height: 300 })).toBe("too-large");
    // The context was made and freed.
    expect(await page.evaluate((from) => window.glContexts.slice(from).every((g) => g.ctx.isContextLost()), before)).toBe(true);
  });

  test("without multisampling a picture is drawn at twice the size and averaged down", async ({ page }) => {
    await open(page, "house.stl");
    const single = await exportPng(page, { width: 300, height: 200, region: STL_TOP, background: "#ff0000" });
    await open(page, "house.stl", { mode: "page", rasterSupersample: "2" });
    await page.evaluate(() => (window.viewports.length = 0));
    const super2 = await exportPng(page, { width: 300, height: 200, region: STL_TOP, background: "#ff0000" });
    const sizes = await page.evaluate(() => [...new Set(window.viewports)]);
    expect(sizes).toContain("600x400");
    expect(difference(single.px, super2.px)).toBeLessThan(2);
    expect(isRed(at(super2.px, 5, 195))).toBe(true);
  });
});

test.describe("the ground and transparency", () => {
  test("transparent has no alpha outside the model, and an edge is the model's colour at a fraction of its alpha", async ({ page }) => {
    await open(page, "house.stl");
    // Off the pixel grid: the house's south edge (y 0) falls in the middle of a row.
    const shifted: Camera = { ...STL_TOP, position: [30, 15.03, 100], target: [30, 15.03, 0] };
    const { px } = await exportPng(page, { width: 600, height: 400, region: shifted, background: "transparent" });
    // South of the house and east of the annex: no model, no shadow.
    expect(at(px, 5, 395)[3]).toBe(0);
    expect(at(px, 590, 10)[3]).toBe(0);
    expect(at(px, 590, 390)[3]).toBe(0);
    expect(at(px, 200, 200)[3]).toBe(255);
    // The edges are partly covered pixels (the sky of the silhouette).
    let partial = 0;
    for (let i = 3; i < px.data.length; i += 4) if (px.data[i]! > 20 && px.data[i]! < 235) partial++;
    expect(partial).toBeGreaterThan(100);
    // The picture on transparency, composed over red, is the picture on red: no clear colour bleeds into the edges.
    const red = await exportPng(page, { width: 600, height: 400, region: shifted, background: "#ff0000" });
    let worst = 0;
    let off = 0;
    for (let i = 0; i < px.data.length; i += 4) {
      const a = px.data[i + 3]! / 255;
      const over = [px.data[i]! * a + 255 * (1 - a), px.data[i + 1]! * a, px.data[i + 2]! * a];
      const d = Math.max(Math.abs(over[0]! - red.px.data[i]!), Math.abs(over[1]! - red.px.data[i + 1]!), Math.abs(over[2]! - red.px.data[i + 2]!));
      worst = Math.max(worst, d);
      if (d > 12) off++;
    }
    console.log("transparent over red against red: worst", worst, "pixels off", off, "partial", partial);
    expect(off).toBeLessThanOrEqual(10);
  });

  test("a colour with alpha is composed over the picture, and the viewer's ground is the default", async ({ page }) => {
    await open(page, "house.stl");
    const half = await exportPng(page, { width: 300, height: 200, region: STL_TOP, background: "rgba(255, 0, 0, 0.5)" });
    const c = at(half.px, 295, 195);
    expect(c[0]).toBeGreaterThan(250);
    expect(c[3]).toBeGreaterThan(120);
    expect(c[3]).toBeLessThan(135);
    // The default is the surface the canvas is drawn on (`--exav-viewer-model-bg`: a circle about 50% 30% from
    // white to #cbd5e1 at the farthest corner), not transparent. The model is small in this view.
    const far: Camera = { ...STL_TOP, projection: { type: "orthographic", height: 400 } };
    const ground = await exportPng(page, { width: 300, height: 200, region: far });
    const middle = at(ground.px, 150, 60);
    const corner = at(ground.px, 299, 199);
    expect(middle[3]).toBe(255);
    for (let k = 0; k < 3; k++) expect(middle[k]).toBeGreaterThan(252);
    for (let k = 0; k < 3; k++) expect(Math.abs(corner[k]! - [203, 213, 225][k]!)).toBeLessThanOrEqual(4);
    expect(await failure(page, { longEdge: 100, background: "url(http://example.org/a.png)" })).toBe("invalid");
  });

  test("the IFC's default ground is its light or dark colour", async ({ page }) => {
    await open(page, "house.ifc");
    const light = await exportPng(page, { width: 300, height: 200, region: IFC_TOP });
    expect(at(light.px, 3, 3)).toEqual([255, 255, 255, 255]);
    await page.evaluate(() => {
      const s = (window as unknown as { exavDemo: { session(): { controllers: { get(): { ground: { set(g: string): void } } } } } }).exavDemo.session();
      s.controllers.get().ground.set("dark");
    });
    const dark = await exportPng(page, { width: 300, height: 200, region: IFC_TOP });
    expect(at(dark.px, 3, 3)).toEqual([0x21, 0x28, 0x30, 255]);
  });
});

test.describe("what the viewer shows", () => {
  test("a hidden category stays hidden, and the selection and the floor grid are not drawn", async ({ page }) => {
    await open(page, "house.ifc");
    const all = await exportPng(page, { width: 600, height: 400, region: IFC_TOP, background: "#ff0000" });
    // The north wall's top (y 7.8..8, x 0..12) is at rows 67..73.
    const wall = at(all.px, 300, 69);
    const slab = at(all.px, 300, 200);
    expect(wall.slice(0, 3)).not.toEqual(slab.slice(0, 3));
    await page.evaluate(() => {
      const s = (window as unknown as { exavDemo: { session(): { controllers: { get(): { layers: { setVisible(id: string, v: boolean): void } } } } } }).exavDemo.session();
      s.controllers.get().layers.setVisible("IFCWALL", false);
    });
    const hidden = await exportPng(page, { width: 600, height: 400, region: IFC_TOP, background: "#ff0000" });
    expect(at(hidden.px, 300, 69).slice(0, 3)).toEqual(at(hidden.px, 300, 200).slice(0, 3));
    expect(isRed(at(hidden.px, 300, 40))).toBe(true);

    // A tap picks an element: the viewer highlights it, the picture does not.
    await page.evaluate(() => {
      const s = (window as unknown as { exavDemo: { session(): { controllers: { get(): { layers: { setAll(v: boolean): void } } } } } }).exavDemo.session();
      s.controllers.get().layers.setAll(true);
    });
    const before = await exportPng(page, { width: 300, height: 200 });
    const box = (await canvas(page).boundingBox())!;
    await page.mouse.click(box.x + box.width / 2, box.y + box.height / 2);
    await expect
      .poll(() => page.evaluate(() => (window as unknown as { exavDemo: { session(): { controllers: { get(): { selection: { get(): unknown } } } } } }).exavDemo.session().controllers.get().selection.get()))
      .not.toBeNull();
    const after = await exportPng(page, { width: 300, height: 200 });
    expect(difference(before.px, after.px)).toBe(0);
  });
});

test.describe("freeing the GPU", () => {
  test("every picture's context is lost when it is done, failed or stopped", async ({ page }) => {
    await open(page, "house.stl", { mode: "page", rasterTile: "16" });
    const live = () => page.evaluate(() => window.glContexts.filter((g) => !g.ctx.isContextLost()).length);
    const made = () => page.evaluate(() => window.glContexts.length);
    const baseline = await live();
    const first = await made();

    // Stopped while it draws: 600 x 600 in tiles of 16.
    const code = await page.evaluate(async () => {
      const s = (window as unknown as { exavDemo: { session(): { controllers: { get(): { pictures: { raster(p: number, o: unknown): Promise<unknown> } } } } } }).exavDemo.session();
      const stop = new AbortController();
      setTimeout(() => stop.abort(), 200);
      try {
        await s.controllers.get().pictures.raster(1, { width: 600, height: 600, signal: stop.signal });
        return "none";
      } catch (e) {
        return (e as { code?: string }).code ?? String(e);
      }
    });
    expect(code).toBe("aborted");
    expect(await made()).toBe(first + 1);
    // The promise rejects at once; the drawing stops and frees its context at the next tile.
    await expect.poll(live).toBe(baseline);

    // Done, refused after the context was made (too many tiles), and refused before.
    await exportPng(page, { width: 40, height: 30 });
    expect(await failure(page, { width: 4000, height: 4000 })).toBe("too-large");
    expect(await failure(page, { width: 40, height: 30, fit: "stretch" })).toBe("invalid");
    expect(await made()).toBe(first + 3);
    expect(await live()).toBe(baseline);
    // Made off screen where the browser has it, and never attached to the page.
    expect(await page.evaluate((from) => window.glContexts.slice(from).every((g) => g.offscreen), first)).toBe(true);
    expect(await page.evaluate(() => document.querySelectorAll("canvas").length)).toBe(1);
  });

  test("pictures asked together are drawn one after another", async ({ page }) => {
    await open(page, "house.stl");
    const baseline = await page.evaluate(() => window.glContexts.filter((g) => !g.ctx.isContextLost()).length);
    const most = await page.evaluate(async () => {
      const s = (window as unknown as { exavDemo: { session(): { controllers: { get(): { pictures: { raster(p: number, o: unknown): Promise<{ bitmap: ImageBitmap }> } } } } } }).exavDemo.session();
      let most = 0;
      const timer = setInterval(() => (most = Math.max(most, window.glContexts.filter((g) => !g.ctx.isContextLost()).length)), 1);
      const all = await Promise.all([1, 2, 3, 4].map(() => s.controllers.get().pictures.raster(1, { longEdge: 400 })));
      clearInterval(timer);
      all.forEach((r) => r.bitmap.close());
      return most;
    });
    expect(most).toBeLessThanOrEqual(baseline + 1);
  });

  test("the visible canvas keeps no drawing buffer", async ({ page }) => {
    await open(page, "house.stl");
    const kept = await page.evaluate(() => {
      const c = document.querySelector<HTMLCanvasElement>(".exav-viewer-model-canvas")!;
      const gl = (c.getContext("webgl2") ?? c.getContext("webgl")) as WebGLRenderingContext;
      return gl.getContextAttributes()!.preserveDrawingBuffer;
    });
    expect(kept).toBe(false);
  });
});

test.describe("through the sandboxed frame", () => {
  for (const name of ["house.stl", "house.ifc"]) {
    test(`${name}: the same size and camera, and the viewport crosses the frame`, async ({ page }) => {
      // The page's own session, for the camera the model opens on.
      await open(page, name);
      const own = await exportPng(page, { width: 300, height: 200 });

      await page.goto("./headless.html?lang=en");
      await page.getByTestId("file-input").setInputFiles({ name, mimeType: "", buffer: (await import("./samples.js")).sample(name) });
      await expect
        .poll(() => page.evaluate(() => (window as unknown as { headless: { session(): { status: { get(): { phase: string } } } | null } }).headless.session()?.status.get().phase), { timeout: 30_000 })
        .toBe("ready");
      await expect.poll(() => viewport(page, "headless")).not.toBeNull();
      const view = (await viewport(page, "headless"))!;
      expect(view.space).toBe("camera");
      expect(view.region.up).toBeDefined();
      const framed = await exportPng(page, { width: 300, height: 200 }, "headless");
      expect([framed.px.width, framed.px.height]).toEqual([300, 200]);
      expect(framed.info).toMatchObject({ width: 300, height: 200, page: 1, space: "camera" });
      // The camera the model opens on, wherever it is shown.
      framed.info.region.position.forEach((v, i) => expect(v).toBeCloseTo(own.info.region.position[i]!, 5));
      framed.info.region.target.forEach((v, i) => expect(v).toBeCloseTo(own.info.region.target[i]!, 5));
      expect(framed.info.region.aspect).toBeCloseTo(1.5, 9);
      expect(body(framed.px).count).toBeGreaterThan(500);

      // "current" resolves in the frame to the viewport it reports.
      const current = await exportPng(page, { width: 300, height: 200, region: "current" }, "headless");
      current.info.region.position.forEach((v, i) => expect(v).toBeCloseTo(view.region.position[i]!, 5));
      const viaViewport = await exportPng(page, { width: 300, height: 200, region: view.region }, "headless");
      expect(difference(current.px, viaViewport.px)).toBeLessThan(0.5);
    });
  }

  test("the user orbits in the frame and the viewport follows", async ({ page }) => {
    await page.goto("./headless.html?lang=en");
    await page.getByTestId("file-input").setInputFiles({ name: "house.stl", mimeType: "", buffer: (await import("./samples.js")).sample("house.stl") });
    await expect
      .poll(() => page.evaluate(() => (window as unknown as { headless: { session(): { status: { get(): { phase: string } } } | null } }).headless.session()?.status.get().phase), { timeout: 30_000 })
      .toBe("ready");
    await expect.poll(() => viewport(page, "headless")).not.toBeNull();
    const before = (await viewport(page, "headless"))!;
    const box = (await page.locator("#stage iframe").boundingBox())!;
    await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2);
    await page.mouse.down();
    await page.mouse.move(box.x + box.width / 2 + 100, box.y + box.height / 2, { steps: 6 });
    await page.mouse.up();
    await expect.poll(async () => (await viewport(page, "headless"))!.region.position[0]).not.toBeCloseTo(before.region.position[0]!, 3);
  });
});
