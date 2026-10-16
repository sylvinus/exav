// Pictures of DWG and DXF drawings (`controllers.pictures`) and the viewport
// store: drawn again from the vectors in a context of their own, at the asked
// size and region, whatever the viewer shows. In the page (`mode=page`), where
// `rasterTile=64` forces tiles; the sandboxed frame is the last test.
import { expect, test, type Locator, type Page } from "@playwright/test";

import { failOnViolations } from "./csp.js";
import { decodePng, difference, find, type Pixels } from "./pixels.js";
import { openSample, sample } from "./samples.js";

failOnViolations();

interface Info {
  width: number;
  height: number;
  page: number;
  layout?: string;
  space: string;
  region: { x: number; y: number; width: number; height: number };
}
interface Picture extends Pixels {
  info: Info;
}

type Options = Record<string, unknown>;

/** `pictures.raster(page, options)` in the page, its bitmap read back as pixels. */
async function raster(page: Page, n: number, options: Options): Promise<Picture> {
  const out = await page.evaluate(
    async ([n, options]) => {
      const session = (window as unknown as { exavDemo: { session(): { controllers: { get(): { pictures: { raster(n: number, o: object): Promise<{ bitmap: ImageBitmap } & Record<string, unknown>> } } } } } }).exavDemo.session();
      const r = await session.controllers.get().pictures.raster(n, options as object);
      const canvas = new OffscreenCanvas(r.bitmap.width, r.bitmap.height);
      canvas.getContext("2d")!.drawImage(r.bitmap, 0, 0);
      r.bitmap.close();
      const bytes = new Uint8Array(await (await canvas.convertToBlob({ type: "image/png" })).arrayBuffer());
      let binary = "";
      for (let i = 0; i < bytes.length; i += 0x8000) binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
      const { bitmap: _bitmap, ...info } = r;
      return { png: btoa(binary), info };
    },
    [n, options] as const,
  );
  return { ...decodePng(Buffer.from(out.png, "base64")), info: out.info as unknown as Info };
}

/** The code of the RasterError a raster is refused with. */
async function refused(page: Page, n: number, options: Options): Promise<string> {
  return page.evaluate(
    async ([n, options]) => {
      const session = (window as unknown as { exavDemo: { session(): { controllers: { get(): { pictures: { raster(n: number, o: object): Promise<unknown> } } } } } }).exavDemo.session();
      try {
        await session.controllers.get().pictures.raster(n, options as object);
        return "none";
      } catch (e) {
        return (e as { code?: string }).code ?? String(e);
      }
    },
    [n, options] as const,
  );
}

interface View {
  space: string;
  page: number;
  layout?: string;
  region: { x: number; y: number; width: number; height: number };
}
const viewport = (page: Page) =>
  page.evaluate(() => {
    const s = (window as unknown as { exavDemo: { session(): { controllers: { get(): { viewport: { get(): unknown } } } } } }).exavDemo.session();
    return s.controllers.get().viewport.get() as View | null;
  });

async function shot(target: Locator): Promise<Pixels> {
  const tools = target.page().locator(".exav-viewer-tools");
  await tools.evaluateAll((els) => els.forEach((e) => ((e as HTMLElement).style.visibility = "hidden")));
  try {
    return decodePng(await target.screenshot({ animations: "disabled" }));
  } finally {
    await tools.evaluateAll((els) => els.forEach((e) => ((e as HTMLElement).style.visibility = "")));
  }
}

/** Two screenshots in a row that agree: the canvas has settled. */
async function settled(target: Locator): Promise<Pixels> {
  // A zoom scales the canvas as drawn until it pauses: its box is not its own.
  await expect.poll(() => target.evaluate((e) => (e as HTMLElement).style.transform)).toBe("");
  let last = await shot(target);
  for (let i = 0; i < 20; i++) {
    await target.page().waitForTimeout(150);
    const next = await shot(target);
    if (difference(last, next) === 0) return next;
    last = next;
  }
  return last;
}

async function open(page: Page, name: string, params: Record<string, string> = {}): Promise<Locator> {
  await openSample(page, name, { mode: "page", ...params });
  await expect(page.locator(".demo-frame .exav-viewer-body")).toHaveAttribute("data-phase", "ready");
  await expect.poll(() => viewport(page)).not.toBeNull();
  const canvas = page.locator(".demo-frame .exav-viewer-cad-canvas");
  // A whole number of pixels, so that a screenshot of the canvas is its own pixels.
  await page.locator(".demo-frame .exav-viewer-cad").evaluate((e) => Object.assign(e.style, { position: "fixed", left: "0px", top: "0px", zIndex: "10", flex: "none", width: "700px", height: "500px" }));
  await expect.poll(() => canvas.evaluate((c: HTMLCanvasElement) => [c.width, c.height])).toEqual([700, 500]);
  return canvas;
}

/** The page a layout is: its place in the layouts controller, model space first. */
const pageOf = (page: Page, id: string) =>
  page.evaluate((id) => {
    const s = (window as unknown as { exavDemo: { session(): { controllers: { get(): { layouts: { get(): { items: { id: string }[] } } } } } } }).exavDemo.session();
    return s.controllers.get().layouts.get().items.findIndex((l) => l.id === id) + 1;
  }, id);

async function layout(page: Page, name: string): Promise<void> {
  // By the DOM: the canvas is fixed over the corner of the page (see `open`).
  await page.locator(".exav-viewer-layouts").getByRole("button", { name }).evaluate((b) => (b as HTMLElement).click());
  await expect(page.locator(".demo-frame .exav-viewer-body")).toHaveAttribute("data-phase", "ready");
  await expect.poll(async () => (await viewport(page))?.layout).toBe(name);
}

const at = (p: Pixels, x: number, y: number): [number, number, number, number] => {
  const i = (y * p.width + x) * 4;
  return [p.data[i]!, p.data[i + 1]!, p.data[i + 2]!, p.data[i + 3]!];
};
const near = (a: readonly number[], b: readonly number[], tolerance = 24) => a.every((v, i) => Math.abs(v - b[i]!) <= tolerance);
const ink = (r: number, g: number, b: number) => r < 160 && g < 160 && b < 160;
/** The largest difference of any channel of any pixel. */
function worst(a: Pixels, b: Pixels): number {
  expect([a.width, a.height]).toEqual([b.width, b.height]);
  let m = 0;
  for (let i = 0; i < a.data.length; i++) m = Math.max(m, Math.abs(a.data[i]! - b.data[i]!));
  return m;
}
/** Rows from `from` to `to` (inclusive) of column `x` that `test` accepts. */
function column(p: Pixels, x: number, test: (r: number, g: number, b: number) => boolean): number[] {
  const rows: number[] = [];
  for (let y = 0; y < p.height; y++) {
    const [r, g, b] = at(p, x, y);
    if (test(r, g, b)) rows.push(y);
  }
  return rows;
}
function row(p: Pixels, y: number, test: (r: number, g: number, b: number) => boolean): number[] {
  const cols: number[] = [];
  for (let x = 0; x < p.width; x++) {
    const [r, g, b] = at(p, x, y);
    if (test(r, g, b)) cols.push(x);
  }
  return cols;
}

const red = (r: number, g: number, b: number) => r > 200 && g < 80 && b < 80;
const cyan = (r: number, g: number, b: number) => r < 80 && g > 200 && b > 200;
const notWhite = (r: number, g: number, b: number) => r < 250 || g < 250 || b < 250;

test.describe("a region of the drawing", () => {
  // colours.dxf: a yellow line (y 0), a red one (y 20), both 100 long and 2.11 mm
  // wide, and a cyan band from y 40 to 60, all from x 0 to 100.
  test("is drawn where its drawing units are: x to the right, y up", async ({ page }) => {
    await open(page, "cad-colours.dxf");
    // 200 x 50 units in 800 x 200 px: 4 px a unit, x from -50, y from 15 to 65.
    const p = await raster(page, 1, { region: { x: -50, y: 15, width: 200, height: 50 }, width: 800, height: 200 });
    expect(p.info).toMatchObject({ width: 800, height: 200, page: 1, layout: "", space: "drawing" });
    expect(p.info.region).toMatchObject({ x: -50, y: 15, width: 200, height: 50 });
    // The band, from y 60 (row 20) to 40 (row 100), across x 0..100 (columns 200..600).
    const band = find(p, cyan).box!;
    expect(band.minX).toBeGreaterThanOrEqual(198);
    expect(band.maxX).toBeLessThanOrEqual(602);
    expect(Math.abs(band.minY - 20)).toBeLessThanOrEqual(2);
    expect(Math.abs(band.maxY - 100)).toBeLessThanOrEqual(2);
    // The red line at y 20: row 180, below the band. Round caps reach 4 px past its ends.
    const line = find(p, red).box!;
    expect(Math.abs((line.minY + line.maxY) / 2 - 180)).toBeLessThanOrEqual(2);
    expect(Math.abs(line.minX - 196)).toBeLessThanOrEqual(3);
    expect(Math.abs(line.maxX - 604)).toBeLessThanOrEqual(3);
    // The paper outside is the ground.
    expect(near(at(p, 20, 100), [255, 255, 255, 255], 2)).toBe(true);
    expect(near(at(p, 700, 20), [255, 255, 255, 255], 2)).toBe(true);
  });

  test("is widened to the picture's shape (contain) or narrowed to it (cover), and reported as drawn", async ({ page }) => {
    await open(page, "cad-colours.dxf");
    const region = { x: 0, y: 40, width: 100, height: 20 };
    const wide = await raster(page, 1, { region, width: 400, height: 400 });
    expect(wide.info.region.width).toBeCloseTo(100, 6);
    expect(wide.info.region.height).toBeCloseTo(100, 6);
    expect(wide.info.region.x).toBeCloseTo(0, 6);
    expect(wide.info.region.y).toBeCloseTo(0, 6);
    // The band is in the middle of the picture, a fifth of its height.
    const band = find(wide, cyan).box!;
    expect(Math.abs(band.minY - 160)).toBeLessThanOrEqual(2);
    expect(Math.abs(band.maxY - 240)).toBeLessThanOrEqual(2);
    const cover = await raster(page, 1, { region, width: 400, height: 400, fit: "cover" });
    expect(cover.info.region.width).toBeCloseTo(20, 6);
    expect(cover.info.region.height).toBeCloseTo(20, 6);
    expect(cover.info.region.x).toBeCloseTo(40, 6);
    // Cover: the band fills the picture.
    expect(find(cover, cyan).count).toBe(400 * 400);
  });

  test("takes its shape from a longEdge alone, and refuses what is no size or region", async ({ page }) => {
    await open(page, "cad-colours.dxf");
    const p = await raster(page, 1, { region: { x: 0, y: 0, width: 100, height: 25 }, longEdge: 200 });
    expect([p.width, p.height]).toEqual([200, 50]);
    expect(p.info.region.width / p.info.region.height).toBeCloseTo(4, 2);
    expect(await refused(page, 1, { longEdge: 0 })).toBe("invalid");
    expect(await refused(page, 1, { longEdge: 100, region: { x: 0, y: 0, width: 0, height: 5 } })).toBe("invalid");
    expect(await refused(page, 1, { longEdge: 100, lineweight: "heavy" })).toBe("invalid");
    expect(await refused(page, 1, { longEdge: 100, background: "url(x)" })).toBe("invalid");
    expect(await refused(page, 1, { width: 20000, height: 20000 })).toBe("too-large");
    expect(await refused(page, 99, { longEdge: 100 })).toBe("invalid");
    expect(await refused(page, 1, { longEdge: 100, layout: "Nope" })).toBe("invalid");
    // So close that the f32 coordinates cannot place it.
    expect(await refused(page, 1, { longEdge: 100, region: { x: 0, y: 0, width: 1e-9, height: 1e-9 } })).toBe("invalid");
  });

  test("the whole layout by default, on the viewer's ground", async ({ page }) => {
    await open(page, "cad-colours.dxf");
    const p = await raster(page, 1, { longEdge: 600 });
    expect(p.info.region.width / p.info.region.height).toBeGreaterThan(1.5);
    // The extents with the viewer's margin around them: the drawing is inside, the edge is ground.
    const box = find(p, notWhite).box!;
    expect(box.minX).toBeGreaterThan(5);
    expect(box.maxX).toBeLessThan(p.width - 5);
    expect(near(at(p, 0, 0), [255, 255, 255, 255], 2)).toBe(true);
  });
});

test.describe("the viewport", () => {
  test("follows the camera, in drawing units, and 'current' draws it as the viewer shows it", async ({ page }) => {
    const canvas = await open(page, "cad-colours.dxf");
    const box = (await canvas.boundingBox())!;
    const fitted = (await viewport(page))!;
    expect(fitted).toMatchObject({ space: "drawing", page: 1, layout: "" });
    // The drawing's extents (x 0..100, y 0..60 less the band's edge) are inside it.
    expect(fitted.region.x).toBeLessThan(0);
    expect(fitted.region.x + fitted.region.width).toBeGreaterThan(100);
    await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2);
    await page.mouse.wheel(0, -500);
    await expect.poll(async () => (await viewport(page))!.region.width).toBeLessThan(fitted.region.width * 0.6);
    const screen = await settled(canvas);
    const view = (await viewport(page))!;
    const [cw, ch] = await canvas.evaluate((c: HTMLCanvasElement) => [c.width, c.height]);
    expect([screen.width, screen.height]).toEqual([cw, ch]);
    const p = await raster(page, 1, { region: "current", width: cw, height: ch });
    expect(p.info.region.x).toBeCloseTo(view.region.x, 6);
    expect(p.info.region.y).toBeCloseTo(view.region.y, 6);
    expect(p.info.region.width).toBeCloseTo(view.region.width, 6);
    expect(p.info.region.height).toBeCloseTo(view.region.height, 6);
    expect(difference(screen, p)).toBeLessThan(0.5);
    expect(worst(screen, p)).toBeLessThan(80);
  });

  test("a drawing with text: 'current' at the canvas's size is the picture on screen", async ({ page }) => {
    const canvas = await open(page, "plan.dxf");
    const box = (await canvas.boundingBox())!;
    await page.mouse.move(box.x + box.width * 0.25, box.y + box.height * 0.5);
    await page.mouse.wheel(0, -600);
    await page.waitForTimeout(600);
    const screen = await settled(canvas);
    const [cw, ch] = await canvas.evaluate((c: HTMLCanvasElement) => [c.width, c.height]);
    const p = await raster(page, 1, { region: "current", width: cw, height: ch });
    // Another glyph atlas, at the size the picture wants: a hair apart.
    expect(difference(screen, p)).toBeLessThan(1.5);
    expect(find(p, notWhite).count).toBeGreaterThan(200);
  });

  test("is a pan, a zoom and a resize away from where it was, and dedupes", async ({ page }) => {
    const canvas = await open(page, "cad-colours.dxf");
    const seen = await page.evaluate(() => {
      const s = (window as unknown as { exavDemo: { session(): { controllers: { get(): { viewport: { subscribe(f: (v: unknown) => void): () => void } } } } } }).exavDemo.session();
      const log: unknown[] = [];
      (window as unknown as { log: unknown[] }).log = log;
      s.controllers.get().viewport.subscribe((v) => log.push(v));
      return log.length;
    });
    expect(seen).toBe(0);
    const before = (await viewport(page))!;
    const box = (await canvas.boundingBox())!;
    await page.mouse.move(box.x + 100, box.y + 100);
    await page.mouse.down();
    await page.mouse.move(box.x + 160, box.y + 100, { steps: 4 });
    await page.mouse.up();
    const after = (await viewport(page))!;
    expect(after.region.width).toBeCloseTo(before.region.width, 6);
    // Dragged to the right by 60 px: the view moves left.
    expect(after.region.x).toBeLessThan(before.region.x);
    const notified = await page.evaluate(() => (window as unknown as { log: unknown[] }).log.length);
    expect(notified).toBeGreaterThan(0);
    // A store set again with what it had does not notify.
    await page.evaluate(() => window.dispatchEvent(new Event("resize")));
    await page.waitForTimeout(300);
    expect(await page.evaluate(() => (window as unknown as { log: unknown[] }).log.length)).toBe(notified);
  });

  test("is the sheet's, in paper units, once a layout is shown; 'current' is refused for the layout not shown", async ({ page }) => {
    await open(page, "cad-sheets.dxf");
    const metric = await pageOf(page, "Metric");
    const imperial = await pageOf(page, "Imperial");
    expect(await refused(page, metric, { longEdge: 100, region: "current" })).toBe("invalid");
    await layout(page, "Metric");
    const view = (await viewport(page))!;
    expect(view).toMatchObject({ space: "drawing", page: metric, layout: "Metric" });
    // A sheet of 297 by 210 mm is inside the view.
    expect(view.region.width).toBeGreaterThan(297);
    const p = await raster(page, metric, { region: "current", longEdge: 300 });
    expect(p.info.layout).toBe("Metric");
    // The sheet's view, to the hair a picture of whole pixels widens it by.
    expect(Math.abs(p.info.region.width / view.region.width - 1)).toBeLessThan(0.01);
    expect(await refused(page, 1, { longEdge: 100, region: "current" })).toBe("invalid");
    expect(await refused(page, imperial, { longEdge: 100, region: "current" })).toBe("invalid");
  });
});

test.describe("layouts", () => {
  // sheets.dxf: model space holds a line; "Metric" and "Imperial" are sheets
  // (A4 in mm, letter in inches) with a square of an inch and, below it, a line
  // 2.11 mm wide: the square is 25.4 units on the first, 1 on the other.
  test("a paper layout is drawn as its sheet: the paper on a surround, in paper units", async ({ page }) => {
    const canvas = await open(page, "cad-sheets.dxf");
    const before = await settled(canvas);
    const p = await raster(page, await pageOf(page, "Metric"), { longEdge: 900 });
    expect(p.info).toMatchObject({ page: await pageOf(page, "Metric"), layout: "Metric" });
    const surround = (r: number, g: number, b: number) => Math.abs(r - 224) < 8 && Math.abs(g - 224) < 8 && Math.abs(b - 224) < 8;
    const white = (r: number, g: number, b: number) => r > 250 && g > 250 && b > 250;
    expect(find(p, surround).count).toBeGreaterThan(1000);
    const sheet = find(p, white).box!;
    expect(sheet.width / sheet.height).toBeGreaterThan(1.37);
    expect(sheet.width / sheet.height).toBeLessThan(1.46);
    // Paper units: the sheet is 297 wide, so it is that many units of the region.
    const unit = p.width / p.info.region.width;
    expect(sheet.width / unit).toBeGreaterThan(290);
    expect(sheet.width / unit).toBeLessThan(300);
    // What the viewer shows was not touched.
    expect(await refused(page, 1, { longEdge: 50 })).toBe("none");
    expect(difference(before, await settled(canvas))).toBe(0);
    expect((await viewport(page))!.layout).toBe("");
  });

  test("the layout option selects by id and wins over the page", async ({ page }) => {
    await open(page, "cad-sheets.dxf");
    const p = await raster(page, 1, { layout: "Imperial", longEdge: 200 });
    expect(p.info).toMatchObject({ page: await pageOf(page, "Imperial"), layout: "Imperial" });
    const q = await raster(page, 2, { layout: "", longEdge: 200 });
    expect(q.info).toMatchObject({ page: 1, layout: "" });
  });

  test("a lineweight on a sheet is millimetres on the page; screen follows the viewer, scaled the picture", async ({ page }) => {
    const canvas = await open(page, "cad-sheets.dxf");
    // Metric: 10 px a unit; the line, 2.11 mm wide, at y -25.4: row 554.
    const region = { x: -10, y: -30, width: 60, height: 60 };
    const size = { width: 600, height: 600 };
    const thickness = (p: Pixels) => column(p, 250, ink).length;
    const scaled = await raster(page, 1, { layout: "Metric", region, ...size, lineweight: "scaled" });
    const lines = column(scaled, 250, ink);
    // The line is the lowest ink in the column.
    const bottom = lines.filter((y) => y > 450);
    expect(bottom.length).toBeGreaterThan(18);
    expect(bottom.length).toBeLessThan(24);
    expect(Math.abs((bottom[0]! + bottom.at(-1)!) / 2 - 554)).toBeLessThanOrEqual(3);
    // On screen: the width the viewer would have when its canvas shows the region.
    const screen = await raster(page, 1, { layout: "Metric", region, ...size });
    const cw = (await canvas.evaluate((c: HTMLCanvasElement) => [c.width, c.height])) as [number, number];
    const k = Math.max(60 / cw[0], 60 / cw[1]) / 0.1;
    const wanted = 21.1 / k;
    const got = column(screen, 250, ink).filter((y) => y > 450).length;
    expect(Math.abs(got - Math.max(wanted, 1))).toBeLessThanOrEqual(3);
    expect(thickness(scaled)).toBeGreaterThan(got);
  });

  test("a viewport's content is clipped to its window, as the viewer shows it", async ({ page }) => {
    // A text 60 long and a viewport onto x -10 to 30 of it, 40 by 20 on the sheet.
    await open(page, "cad-viewport_text.dxf");
    const p = await raster(page, 1, { layout: "Sheet", longEdge: 1200 });
    expect(p.info.layout).toBe("Sheet");
    const box = find(p, ink).box!;
    expect(box.width / box.height).toBeGreaterThan(4.5);
    expect(box.width / box.height).toBeLessThan(7);
    // The model itself has all the text, and the other one far to the right.
    const model = await raster(page, 1, { longEdge: 1200 });
    expect(find(model, ink).box!.width / find(model, ink).box!.height).toBeGreaterThan(10);
  });
});

test.describe("tiles", () => {
  /** The same picture in one pass, and in tiles of 64 px (the page's `rasterTile`). */
  async function both(browserPage: Page, name: string, n: number, options: Options) {
    // The tiles drawn: one GL canvas read back each.
    await browserPage.addInitScript(() => {
      if ((window as unknown as { tiles?: number }).tiles !== undefined) return;
      (window as unknown as { tiles: number }).tiles = 0;
      const original = OffscreenCanvas.prototype.transferToImageBitmap;
      OffscreenCanvas.prototype.transferToImageBitmap = function (this: OffscreenCanvas) {
        (window as unknown as { tiles: number }).tiles++;
        return original.call(this);
      };
    });
    const drawn = () => browserPage.evaluate(() => (window as unknown as { tiles: number }).tiles);
    await open(browserPage, name);
    const whole = await raster(browserPage, n, options);
    const single = await drawn();
    await open(browserPage, name, { rasterTile: "64" });
    const tiled = await raster(browserPage, n, options);
    // Tiles of 64 px, so many of them: the tiled picture is not the single pass. (One more read, of the composed picture.)
    expect([single - 1, (await drawn()) - 1]).toEqual([1, Math.ceil(tiled.width / 64) * Math.ceil(tiled.height / 64)]);
    return { whole, tiled };
  }

  test("a picture drawn in small tiles is the picture drawn in one pass, no gap and no line twice at the seams", async ({ page }) => {
    const { whole, tiled } = await both(page, "cad-halo.dxf", 1, { longEdge: 500 });
    expect([tiled.width, tiled.height]).toEqual([whole.width, whole.height]);
    expect(tiled.info.region).toEqual(whole.info.region);
    // A red band 8 px wide and a thin line cross the seams every 64 px.
    expect(find(whole, red).count).toBeGreaterThan(500);
    expect(worst(whole, tiled)).toBeLessThanOrEqual(2);
    expect(difference(whole, tiled)).toBeLessThan(0.01);
  });

  test("with text, fills and the sheet's paper", async ({ page }) => {
    const text = await both(page, "plan.dxf", 1, { longEdge: 600 });
    expect(find(text.whole, ink).count).toBeGreaterThan(300);
    expect(worst(text.whole, text.tiled)).toBeLessThanOrEqual(6);
    expect(difference(text.whole, text.tiled)).toBeLessThan(0.05);
    const sheet = await both(page, "cad-sheets.dxf", 1, { layout: "Metric", longEdge: 700 });
    expect(worst(sheet.whole, sheet.tiled)).toBeLessThanOrEqual(2);
    expect(difference(sheet.whole, sheet.tiled)).toBeLessThan(0.01);
    const fills = await both(page, "cad-colours.dxf", 1, { region: { x: 10, y: 30, width: 50, height: 40 }, width: 330, height: 270 });
    expect(find(fills.whole, cyan).count).toBeGreaterThan(1000);
    expect(worst(fills.whole, fills.tiled)).toBeLessThanOrEqual(2);
  });

  test("a picture past the default tile, over two sides, is composed", async ({ page }) => {
    await open(page, "cad-colours.dxf");
    // 2600 px wide: two tiles of 2048 across.
    const p = await raster(page, 1, { region: { x: 0, y: 0, width: 100, height: 60 }, width: 2600, height: 1560 });
    expect([p.width, p.height]).toEqual([2600, 1560]);
    const band = find(p, cyan).box!;
    // x 0..100 is the whole width; y 40..60 is the top third of the region.
    expect(band.minX).toBeLessThanOrEqual(1);
    expect(band.maxX).toBeGreaterThanOrEqual(2598);
    expect(Math.abs(band.minY - 0)).toBeLessThanOrEqual(2);
    expect(Math.abs(band.maxY - 520)).toBeLessThanOrEqual(2);
    // Across the tile seam at column 2048, nothing is missing.
    expect(column(p, 2047, cyan).length).toBe(column(p, 2048, cyan).length);
    expect(column(p, 2047, cyan).length).toBeGreaterThan(500);
  });
});

test.describe("sharpness", () => {
  test("a hairline stays a pixel wide at four times the zoom on screen", async ({ page }) => {
    const canvas = await open(page, "cad-halo.dxf");
    const screen = await settled(canvas);
    const view = (await viewport(page))!;
    // halo.dxf: a thin vertical line at x 50 below a wide red one.
    const w = screen.width * 4;
    const h = screen.height * 4;
    const p = await raster(page, 1, { region: "current", width: w, height: h });
    const y = Math.round(h * 0.85);
    const touched = (r: number, g: number, b: number) => r < 235 || g < 235 || b < 235;
    // How much ink a row has, in pixels of the line's colour (a grey of 51: 204 under white).
    const inkOf = (q: Pixels) => row(q, y, touched).reduce((n, x) => n + (255 - at(q, x, y)[0]) / 204, 0);
    const dark = row(p, y, touched);
    expect(dark.length).toBeGreaterThan(0);
    expect(dark.length).toBeLessThanOrEqual(3);
    // One pixel of ink, not an upscaled one's four.
    expect(inkOf(p)).toBeGreaterThan(0.75);
    expect(inkOf(p)).toBeLessThan(1.35);
    // In the picture where the line is: the middle of the region.
    const centre = Math.round(((50 - view.region.x) / view.region.width) * w);
    expect(Math.abs(dark[0]! - centre)).toBeLessThanOrEqual(3);
    // Scaled with the picture it is four times as wide.
    const scaled = await raster(page, 1, { region: "current", width: w, height: h, lineweight: "scaled" });
    expect(inkOf(scaled)).toBeGreaterThan(3.4);
    expect(inkOf(scaled)).toBeLessThan(4.7);
  });

  test("text is drawn at the picture's scale, not magnified: edges a pixel or two wide", async ({ page }) => {
    await open(page, "cad-text_many.dxf");
    const view = (await viewport(page))!;
    // The middle of the drawing, zoomed thirty times.
    const cx = view.region.x + view.region.width / 2;
    const cy = view.region.y + view.region.height / 2;
    const w = view.region.width / 30;
    const p = await raster(page, 1, { region: { x: cx - w / 2, y: cy - w / 4, width: w, height: w / 2 }, width: 1200, height: 600 });
    const lum = (r: number, g: number, b: number) => (r + g + b) / 3;
    const dark = find(p, (r, g, b) => lum(r, g, b) < 80).count;
    const edge = find(p, (r, g, b) => lum(r, g, b) >= 80 && lum(r, g, b) < 200).count;
    expect(dark).toBeGreaterThan(2000);
    expect(edge / dark).toBeLessThan(0.15);
  });
});

test.describe("the ground", () => {
  test("is any CSS colour, the viewer's ground by default", async ({ page }) => {
    await open(page, "cad-colours.dxf");
    const p = await raster(page, 1, { region: { x: 200, y: 200, width: 10, height: 10 }, width: 20, height: 20, background: "rgb(10 200 30)" });
    expect(near(at(p, 10, 10), [10, 200, 30, 255], 1)).toBe(true);
    const q = await raster(page, 1, { region: { x: 200, y: 200, width: 10, height: 10 }, width: 20, height: 20, background: "#ff000080" });
    expect(near(at(q, 10, 10), [255, 0, 0, 128], 2)).toBe(true);
    // The dark ground of the session: a drawing resolved against it.
    const dark = await raster(page, 1, { region: { x: 200, y: 200, width: 10, height: 10 }, width: 20, height: 20, background: "#212830" });
    expect(near(at(dark, 3, 3), [0x21, 0x28, 0x30, 255], 1)).toBe(true);
  });

  test("transparent has no ground, and its edges and text are premultiplied right", async ({ page }) => {
    await open(page, "plan.dxf");
    const options = { longEdge: 700 };
    const opaque = await raster(page, 1, { ...options, background: "#ffffff" });
    const clear = await raster(page, 1, { ...options, background: "transparent" });
    expect(at(clear, 0, 0)[3]).toBe(0);
    let partial = 0;
    let solid = 0;
    for (let i = 0; i < clear.data.length; i += 4) {
      const a = clear.data[i + 3]!;
      if (a === 255) solid++;
      else if (a > 0) partial++;
    }
    expect(solid).toBeGreaterThan(300);
    expect(partial).toBeGreaterThan(300);
    // The picture on white is the picture with a white ground: a premultiplied edge
    // read as straight, or a glyph's twice over, would darken or lighten it.
    const over = new Uint8Array(clear.data.length);
    for (let i = 0; i < over.length; i += 4) {
      const a = clear.data[i + 3]! / 255;
      for (let c = 0; c < 3; c++) over[i + c] = Math.round(clear.data[i + c]! * a + 255 * (1 - a));
      over[i + 3] = 255;
    }
    const composed = { width: clear.width, height: clear.height, data: over };
    expect(difference(composed, opaque)).toBeLessThan(0.1);
    expect(worst(composed, opaque)).toBeLessThanOrEqual(24);
    // A pixel that is part ink keeps the ink's own colour (the circle's cyan, 0 194 194 on a light ground), not a darker one.
    let tinted = 0;
    for (let i = 0; i < clear.data.length; i += 4) {
      const a = clear.data[i + 3]!;
      if (a > 60 && a < 200 && clear.data[i]! < 20 && Math.abs(clear.data[i + 1]! - 194) < 8 && Math.abs(clear.data[i + 2]! - 194) < 8) tinted++;
    }
    expect(tinted).toBeGreaterThan(20);
  });

  test("a sheet on transparency is its content alone, without paper or surround", async ({ page }) => {
    await open(page, "cad-sheets.dxf");
    const p = await raster(page, 1, { layout: "Metric", longEdge: 400, background: "transparent" });
    expect(at(p, 2, 2)[3]).toBe(0);
    expect(at(p, p.width / 2, p.height / 2)[3]).toBe(0);
  });
});

test.describe("resources", () => {
  /** Records the WebGL2 contexts of off screen canvases (the exports'), and how many were live when each was made. */
  async function track(page: Page) {
    await page.addInitScript(() => {
      const log: { gl: WebGL2RenderingContext; before: number }[] = [];
      (window as unknown as { exports: typeof log }).exports = log;
      const original = OffscreenCanvas.prototype.getContext;
      OffscreenCanvas.prototype.getContext = function (this: OffscreenCanvas, kind: string, ...rest: unknown[]) {
        const gl = (original as (...a: unknown[]) => unknown).call(this, kind, ...rest);
        if (kind === "webgl2" && gl) log.push({ gl: gl as WebGL2RenderingContext, before: log.filter((e) => !e.gl.isContextLost()).length });
        return gl;
      } as typeof original;
    });
  }
  const contexts = (page: Page) =>
    page.evaluate(() => {
      const log = (window as unknown as { exports: { gl: WebGL2RenderingContext; before: number }[] }).exports;
      return { made: log.length, live: log.filter((e) => !e.gl.isContextLost()).length, before: log.map((e) => e.before) };
    });

  test("a context is made for a picture and given back, on success and on error", async ({ page }) => {
    await track(page);
    await open(page, "cad-colours.dxf");
    await raster(page, 1, { longEdge: 300 });
    expect(await contexts(page)).toMatchObject({ made: 1, live: 0 });
    expect(await refused(page, 1, { longEdge: 300, region: { x: 0, y: 0, width: 1e-9, height: 1e-9 } })).toBe("invalid");
    expect(await contexts(page)).toMatchObject({ live: 0 });
  });

  test("pictures are drawn one at a time", async ({ page }) => {
    await track(page);
    await open(page, "cad-colours.dxf", { rasterTile: "64" });
    const sizes = await page.evaluate(async () => {
      const s = (window as unknown as { exavDemo: { session(): { controllers: { get(): { pictures: { raster(n: number, o: object): Promise<{ bitmap: ImageBitmap; width: number }> } } } } } }).exavDemo.session();
      const p = s.controllers.get().pictures;
      const all = await Promise.all([p.raster(1, { longEdge: 300 }), p.raster(1, { longEdge: 200 }), p.raster(1, { longEdge: 100 })]);
      all.forEach((r) => r.bitmap.close());
      return all.map((r) => r.width);
    });
    expect(sizes).toEqual([300, 200, 100]);
    const { made, before, live } = await contexts(page);
    expect(made).toBe(3);
    expect(before).toEqual([0, 0, 0]);
    expect(live).toBe(0);
  });

  test("an abort in the middle of tiles stops the drawing and frees the context", async ({ page }) => {
    await track(page);
    await open(page, "plan.dxf", { rasterTile: "32" });
    const result = await page.evaluate(async () => {
      const s = (window as unknown as { exavDemo: { session(): { controllers: { get(): { pictures: { raster(n: number, o: object): Promise<unknown> } } } } } }).exavDemo.session();
      const abort = new AbortController();
      const started = performance.now();
      const done = s.controllers.get().pictures.raster(1, { width: 1500, height: 1000, signal: abort.signal }).then(
        () => "drawn",
        (e: { code?: string }) => e.code ?? String(e),
      );
      // Once the first context has been made, the tiles are being drawn.
      const log = (window as unknown as { exports: unknown[] }).exports;
      while (log.length === 0 && performance.now() - started < 20000) await new Promise((r) => setTimeout(r, 5));
      await new Promise((r) => setTimeout(r, 150));
      abort.abort();
      return { code: await done, ms: performance.now() - started };
    });
    expect(result.code).toBe("aborted");
    await page.waitForTimeout(200);
    expect(await contexts(page)).toMatchObject({ made: 1, live: 0 });
    // The session goes on, and a picture can be asked again.
    const p = await raster(page, 1, { longEdge: 100 });
    expect(p.width).toBe(100);
  });

  test("an abort while the worker draws the layout is at once, before any context", async ({ page }) => {
    await track(page);
    await open(page, "cad-sheets.dxf");
    const code = await page.evaluate(async () => {
      const s = (window as unknown as { exavDemo: { session(): { controllers: { get(): { pictures: { raster(n: number, o: object): Promise<unknown> } } } } } }).exavDemo.session();
      const abort = new AbortController();
      const done = s.controllers.get().pictures.raster(2, { longEdge: 300, signal: abort.signal }).then(
        () => "drawn",
        (e: { code?: string }) => e.code ?? String(e),
      );
      abort.abort();
      return done;
    });
    expect(code).toBe("aborted");
    const p = await raster(page, 1, { layout: "Metric", longEdge: 100 });
    expect(p.width).toBeGreaterThan(0);
    expect((await contexts(page)).live).toBe(0);
  });

  test("the visible canvas keeps no drawing buffer", async ({ page }) => {
    const canvas = await open(page, "cad-colours.dxf");
    expect(await canvas.evaluate((c: HTMLCanvasElement) => c.getContext("webgl2")!.getContextAttributes()!.preserveDrawingBuffer)).toBe(false);
    await raster(page, 1, { longEdge: 200 });
    expect(await canvas.evaluate((c: HTMLCanvasElement) => c.getContext("webgl2")!.getContextAttributes()!.preserveDrawingBuffer)).toBe(false);
  });
});

test.describe("in the sandboxed frame", () => {
  test("a picture has the size, region and pixels it has in the page", async ({ page }) => {
    await open(page, "cad-colours.dxf");
    const options = { region: { x: -50, y: 15, width: 200, height: 50 }, width: 800, height: 200 };
    const inPage = await raster(page, 1, options);

    await page.goto("./headless.html?lang=en");
    await page.getByTestId("file-input").setInputFiles({ name: "cad-colours.dxf", mimeType: "", buffer: sample("cad-colours.dxf") });
    await expect
      .poll(() => page.evaluate(() => (window as unknown as { headless: { session(): { status: { get(): { phase: string } } } | null } }).headless.session()?.status.get().phase))
      .toBe("ready");
    const out = await page.evaluate(async (options) => {
      const s = (window as unknown as { headless: { session(): { controllers: { get(): { pictures: { raster(n: number, o: object): Promise<{ bitmap: ImageBitmap } & Record<string, unknown>> }; viewport: { get(): unknown } } } } } }).headless.session();
      let c = s.controllers.get();
      for (let i = 0; i < 100 && !(c.pictures && c.viewport.get()); i++) {
        await new Promise((r) => setTimeout(r, 100));
        c = s.controllers.get();
      }
      const r = await c.pictures.raster(1, options);
      const canvas = new OffscreenCanvas(r.bitmap.width, r.bitmap.height);
      canvas.getContext("2d")!.drawImage(r.bitmap, 0, 0);
      r.bitmap.close();
      const bytes = new Uint8Array(await (await canvas.convertToBlob({ type: "image/png" })).arrayBuffer());
      let binary = "";
      for (let i = 0; i < bytes.length; i += 0x8000) binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
      const { bitmap: _bitmap, ...info } = r;
      return { png: btoa(binary), info, view: c.viewport.get() };
    }, options);
    const inFrame = decodePng(Buffer.from(out.png, "base64"));
    expect([inFrame.width, inFrame.height]).toEqual([inPage.width, inPage.height]);
    expect(out.info).toMatchObject({ width: 800, height: 200, page: 1, layout: "", space: "drawing", region: options.region });
    expect(out.view).toMatchObject({ space: "drawing", page: 1, layout: "" });
    expect(difference(inPage, inFrame)).toBeLessThan(0.05);
  });
});
