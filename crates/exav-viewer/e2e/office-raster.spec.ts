// Pictures of Word, PowerPoint, Excel, CSV and video (`controllers.pictures`)
// and the viewport store: drawn again from the document's data by a second
// copy of it, at the size and region asked, whatever the viewer shows. In the
// page (`mode=page`), the converted formats too, and the sandboxed frame.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { expect, test, type Page } from "@playwright/test";

import { failOnViolations } from "./csp.js";
import { decodePng, difference, find, type Pixels } from "./pixels.js";
import { openSample, sample } from "./samples.js";

failOnViolations();

const FIXTURES = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "exav-render", "tests", "fixtures", "office");
const OUT = path.join(path.dirname(fileURLToPath(import.meta.url)), ".out");

interface Region {
  x: number;
  y: number;
  width: number;
  height: number;
}
interface Info {
  width: number;
  height: number;
  page: number;
  space: string;
  region?: Region;
}
interface Picture extends Pixels {
  info: Info;
}
type Options = Record<string, unknown>;
interface Controllers {
  pictures: { get(): { count: number; space: string }; raster(n: number, o: object): Promise<{ bitmap: ImageBitmap } & Record<string, unknown>> };
  viewport: { get(): unknown; subscribe(f: (v: unknown) => void): () => void };
  zoom?: { setScale(n: number): void };
}
type Where = "exavDemo" | "headless";

/** The session's controllers, in the page of the demo or of the headless host (the frame). */
const session = (w: Where) => `(window).${w}.session()`;

/** `pictures.raster(page, options)`, its bitmap read back as pixels. */
async function raster(page: Page, n: number, options: Options, where: Where = "exavDemo"): Promise<Picture> {
  const out = await page.evaluate(
    async ([n, options, where]) => {
      const s = (window as unknown as Record<string, { session(): { controllers: { get(): Controllers } } }>)[where]!.session();
      const r = await s.controllers.get().pictures.raster(n, options as object);
      const canvas = new OffscreenCanvas(r.bitmap.width, r.bitmap.height);
      canvas.getContext("2d")!.drawImage(r.bitmap, 0, 0);
      r.bitmap.close();
      const bytes = new Uint8Array(await (await canvas.convertToBlob({ type: "image/png" })).arrayBuffer());
      let binary = "";
      for (let i = 0; i < bytes.length; i += 0x8000) binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
      const { bitmap: _bitmap, ...info } = r;
      return { png: btoa(binary), info };
    },
    [n, options, where] as const,
  );
  const png = Buffer.from(out.png, "base64");
  return { ...decodePng(png), info: out.info as unknown as Info };
}

/** The code of the RasterError a raster is refused with. */
async function refused(page: Page, n: number, options: Options, where: Where = "exavDemo"): Promise<string> {
  return page.evaluate(
    async ([n, options, where]) => {
      const s = (window as unknown as Record<string, { session(): { controllers: { get(): Controllers } } }>)[where]!.session();
      try {
        const r = await s.controllers.get().pictures.raster(n, options as object);
        r.bitmap.close();
        return "none";
      } catch (e) {
        return (e as { code?: string }).code ?? String(e);
      }
    },
    [n, options, where] as const,
  );
}

const controllers = <T>(page: Page, fn: string, where: Where = "exavDemo") =>
  page.evaluate(`(async () => { const c = ${session(where)}.controllers.get(); return (${fn})(c); })()`) as Promise<T>;

/** Waits for the viewport to be a page and a region (a sheet's is worked out once asked for: subscribing asks). */
async function viewport(page: Page, where: Where = "exavDemo"): Promise<{ page: number; space: string; region: Region } | null> {
  return controllers(page, `(c) => { c.viewport.subscribe(() => {}); return c.viewport.get(); }`, where);
}

const inkAt = (r: number, g: number, b: number) => r < 160 && g < 160 && b < 160;

/** Dark pixels in the rectangle `[x0, x1) x [y0, y1)` of `p`. */
function ink(p: Pixels, x0 = 0, y0 = 0, x1 = p.width, y1 = p.height): number {
  let n = 0;
  for (let y = Math.max(0, y0); y < Math.min(p.height, y1); y++)
    for (let x = Math.max(0, x0); x < Math.min(p.width, x1); x++) {
      const i = (y * p.width + x) * 4;
      if (p.data[i + 3]! > 128 && inkAt(p.data[i]!, p.data[i + 1]!, p.data[i + 2]!)) n++;
    }
  return n;
}

function crop(p: Pixels, x: number, y: number, width: number, height: number): Pixels {
  const data = new Uint8Array(width * height * 4);
  for (let r = 0; r < height; r++) data.set(p.data.subarray(((y + r) * p.width + x) * 4, ((y + r) * p.width + x + width) * 4), r * width * 4);
  return { width, height, data };
}

/** The mean difference of two pictures cut to the size they share (one of them may be a pixel larger). */
function close(a: Pixels, b: Pixels): number {
  const w = Math.min(a.width, b.width);
  const h = Math.min(a.height, b.height);
  expect(Math.abs(a.width - b.width) + Math.abs(a.height - b.height)).toBeLessThanOrEqual(2);
  return difference(crop(a, 0, 0, w, h), crop(b, 0, 0, w, h));
}

/** A screenshot of a rectangle of the page, in CSS px. */
async function shot(page: Page, clip: Region): Promise<Pixels> {
  // The viewer's tools lie over the surface.
  const tools = page.locator(".exav-viewer-tools");
  await tools.evaluateAll((els) => els.forEach((e) => ((e as HTMLElement).style.visibility = "hidden")));
  try {
    // A box on a fraction of a pixel is cut at the pixel the engines draw it on: Chromium rounds it, Firefox and WebKit floor it.
    const png = await page.screenshot({ clip: { ...clip, x: Math.round(clip.x), y: Math.round(clip.y) }, animations: "disabled" });
    return decodePng(png);
  } finally {
    await tools.evaluateAll((els) => els.forEach((e) => ((e as HTMLElement).style.visibility = "")));
  }
}

async function open(page: Page, name: string, params: Record<string, string> = {}): Promise<void> {
  await openSample(page, name, { mode: "page", ...params });
  await expect(page.locator(".demo-frame .exav-viewer-body")).toHaveAttribute("data-phase", "ready", { timeout: 60_000 });
}

async function openFixture(page: Page, dir: string, name: string): Promise<void> {
  await page.goto(`./?${new URLSearchParams({ lang: "en", converter: "exav", mode: "page" })}`);
  await page.getByTestId("file-input").setInputFiles({ name, mimeType: "", buffer: fs.readFileSync(path.join(FIXTURES, dir, name)) });
  await expect(page.locator(".demo-frame .exav-viewer-body")).toHaveAttribute("data-phase", "ready", { timeout: 60_000 });
}

/** The pictures controller exists and has its pages (the count follows the viewer's). */
const pages = (page: Page, where: Where = "exavDemo") => expect.poll(() => controllers<number>(page, `(c) => c.pictures.get().count`, where), { timeout: 30_000 });

/** The box of the first page's canvas on screen, once it is drawn. */
const docCanvas = (page: Page) => page.locator(".demo-frame .exav-viewer-office-docx canvas").first();
const sheetCanvas = (page: Page) => page.locator(".demo-frame .exav-viewer-office-canvas").first();

test.describe("a Word document", () => {
  test("is drawn whole at the width asked, on white, with its heading at the top left", async ({ page }) => {
    await open(page, "notes.docx");
    await pages(page).toBe(2);
    const p = await raster(page, 1, { width: 800 });
    expect([p.width, p.height, p.info.space, p.info.page]).toEqual([800, 1131, "page", 1]);
    expect(p.info.region).toEqual({ x: 0, y: 0, width: 1, height: 1 });
    expect(ink(p, 0, 0, 400, 283)).toBeGreaterThan(500);
    expect(ink(p, 400, 0, 800, 1131)).toBe(0);
    expect(ink(p, 0, 283, 800, 1131)).toBe(0);
    // Opaque white.
    expect([...p.data.subarray(0, 4)]).toEqual([255, 255, 255, 255]);
    // Page 2 is another page.
    const second = await raster(page, 2, { width: 400 });
    expect(second.info.page).toBe(2);
    expect(difference(second, await raster(page, 1, { width: 400 }))).toBeGreaterThan(0.2);
  });

  test("a region is the same pixels as that part of the whole page at the same scale", async ({ page }) => {
    await open(page, "notes.docx");
    await pages(page).toBe(2);
    const whole = await raster(page, 1, { width: 800 });
    // The top left quarter, 400 px wide: the page at 800.
    const quarter = await raster(page, 1, { width: 400, region: { x: 0, y: 0, width: 0.5, height: 0.25 } });
    expect([quarter.width, quarter.height]).toEqual([400, 283]);
    expect(quarter.info.region).toMatchObject({ x: 0, y: 0, width: 0.5 });
    expect(difference(quarter, crop(whole, 0, 0, 400, 283))).toBe(0);
    expect(ink(quarter)).toBeGreaterThan(500);
    // The bottom right has no ink.
    const empty = await raster(page, 1, { width: 400, region: { x: 0.5, y: 0.5, width: 0.5, height: 0.5 } });
    expect(ink(empty)).toBe(0);
    // A region off the page shows the background there.
    const beyond = await raster(page, 1, { width: 200, height: 200, background: "#ff0000", region: { x: 0, y: 0, width: 1, height: 1 } });
    // The page is taller than wide: contain widens the region at the sides.
    expect(beyond.info.region!.x).toBeLessThan(0);
    expect([...beyond.data.subarray(0, 3)]).toEqual([255, 0, 0]);
    expect([...beyond.data.subarray((100 * 200 + 100) * 4, (100 * 200 + 100) * 4 + 4)]).toEqual([255, 255, 255, 255]);
  });

  test("the whole page at the on-screen width is what the viewer shows", async ({ page }) => {
    await open(page, "notes.docx");
    await pages(page).toBe(2);
    const canvas = docCanvas(page);
    await expect.poll(() => canvas.evaluate((c: HTMLCanvasElement) => c.width)).toBeGreaterThan(300);
    await canvas.scrollIntoViewIfNeeded();
    const box = (await canvas.boundingBox())!;
    const p = await raster(page, 1, { width: Math.round(box.width) });
    // The visible canvas is drawn at the display's pixel density; the screenshot is that bitmap scaled to the box.
    const part = { x: box.x, y: box.y, width: box.width, height: Math.min(box.height, 700) };
    const screen = await shot(page, { ...part, width: Math.round(part.width), height: Math.round(part.height) });
    expect(close(screen, crop(p, 0, 0, screen.width, Math.min(screen.height, p.height)))).toBeLessThan(6);
  });

  test("region current is what is in view: the page most in view and the part showing", async ({ page }) => {
    await open(page, "notes.docx");
    await pages(page).toBe(2);
    await expect.poll(() => viewport(page)).not.toBeNull();
    expect((await viewport(page))!.page).toBe(1);
    // Scroll down so the second page takes over.
    await page.locator(".demo-frame .exav-viewer-office-docx > div > div").first().evaluate((el) => {
      el.scrollTop = el.scrollHeight - el.clientHeight;
    });
    await expect.poll(async () => (await viewport(page))?.page).toBe(2);
    const v = (await viewport(page))!;
    expect(v.space).toBe("page");
    expect(v.region.y).toBeLessThan(0.5);
    const current = await raster(page, 2, { width: 300, region: "current" });
    expect(current.info.region!.y).toBeCloseTo(v.region.y, 1);
    expect(current.info.page).toBe(2);
    // Another page than the one in view has none.
    expect(await refused(page, 1, { width: 300, region: "current" })).toBe("invalid");
  });

  test("a transparent background is not drawn, and a too small region is refused before drawing", async ({ page }) => {
    await open(page, "notes.docx");
    await pages(page).toBe(2);
    expect(await refused(page, 1, { width: 100, background: "transparent" })).toBe("unsupported");
    expect(await refused(page, 1, { width: 400, region: { x: 0, y: 0, width: 0.01, height: 0.01 } })).toBe("too-large");
    expect(await refused(page, 1, { width: 20000 })).toBe("too-large");
    expect(await refused(page, 3, { width: 100 })).toBe("invalid");
    expect(await refused(page, 1, { width: 100, background: "url(x)" })).toBe("invalid");
  });

  test("a drawing is stopped by its signal, and the next is not harmed", async ({ page }) => {
    await open(page, "notes.docx");
    await pages(page).toBe(2);
    const out = await page.evaluate(async () => {
      const c = (window as unknown as { exavDemo: { session(): { controllers: { get(): Controllers } } } }).exavDemo.session().controllers.get();
      const abort = new AbortController();
      const first = c.pictures.raster(1, { width: 2000, signal: abort.signal }).then(
        () => "none",
        (e: { code: string }) => e.code,
      );
      abort.abort();
      const already = new AbortController();
      already.abort();
      const second = await c.pictures.raster(1, { width: 2000, signal: already.signal }).then(
        () => "none",
        (e: { code: string }) => e.code,
      );
      // Three at once are drawn one after the other, each whole.
      const three = await Promise.all([300, 200, 100].map((width) => c.pictures.raster(1, { width }).then((r) => [r.width, (r.bitmap.close(), "ok")])));
      return { first: await first, second, three };
    });
    expect(out).toEqual({ first: "aborted", second: "aborted", three: [[300, "ok"], [200, "ok"], [100, "ok"]] });
    expect(ink(await raster(page, 1, { width: 400 }))).toBeGreaterThan(300);
  });
});

test.describe("a PowerPoint deck", () => {
  test("is drawn slide by slide, the heading at the top left", async ({ page }) => {
    await open(page, "visit.pptx");
    await pages(page).toBe(2);
    const one = await raster(page, 1, { width: 960 });
    expect([one.width, one.height]).toEqual([960, 540]);
    expect(ink(one, 0, 0, 480, 135)).toBeGreaterThan(100);
    expect(ink(one, 480, 0, 960, 540)).toBe(0);
    const quarter = await raster(page, 1, { width: 480, region: { x: 0, y: 0, width: 0.5, height: 0.5 } });
    expect(difference(quarter, crop(one, 0, 0, 480, 270))).toBe(0);
    const two = await raster(page, 2, { width: 480 });
    expect(two.info.page).toBe(2);
    expect(difference(two, await raster(page, 1, { width: 480 }))).toBeGreaterThan(0.1);
    expect(await refused(page, 1, { width: 100, background: "transparent" })).toBe("unsupported");
  });

  test("the whole slide at the on-screen size is what the viewer shows, and the viewport is the slide", async ({ page }) => {
    await open(page, "visit.pptx");
    await pages(page).toBe(2);
    const canvas = page.locator(".demo-frame .exav-viewer-office-stage canvas");
    await expect.poll(() => canvas.evaluate((c: HTMLCanvasElement) => c.width)).toBeGreaterThan(300);
    await page.waitForTimeout(500);
    const box = (await canvas.boundingBox())!;
    const p = await raster(page, 1, { width: Math.round(box.width) });
    const screen = await shot(page, { x: box.x, y: box.y, width: Math.round(box.width), height: Math.round(box.height) });
    expect(close(screen, p)).toBeLessThan(6);
    expect(await viewport(page)).toEqual({ space: "page", page: 1, region: { x: 0, y: 0, width: 1, height: 1 } });
    await page.getByRole("button", { name: /next/i }).first().click();
    await expect.poll(async () => (await viewport(page))?.page).toBe(2);
    const current = await raster(page, 2, { width: 200, region: "current" });
    expect(current.info.region).toEqual({ x: 0, y: 0, width: 1, height: 1 });
  });
});

test.describe("a spreadsheet", () => {
  test("is its used area without the headers, one picture for each sheet", async ({ page }) => {
    await open(page, "book.xlsx");
    await pages(page).toBe(2);
    // Sheet 1: A1:D4, 464 x 80 at 100 %; its first row is Item, Quantity, Unit price, Total.
    const whole = await raster(page, 1, { width: 464 });
    expect([whole.width, whole.height]).toEqual([464, 80]);
    expect(whole.info.region).toEqual({ x: 0, y: 0, width: 1, height: 1 });
    expect(ink(whole, 0, 0, 464, 20)).toBeGreaterThan(80);
    // No header band: inside the first cell, white.
    expect([...whole.data.subarray((5 * 464 + 100) * 4, (5 * 464 + 100) * 4 + 3)]).toEqual([255, 255, 255]);
    const bigger = await raster(page, 1, { width: 928 });
    expect(bigger.height).toBe(160);
    // Sheet 2 is another sheet: its own size, and "Note" in its first row.
    const note = await raster(page, 2, { width: 600 });
    expect([note.info.page, note.width, note.height]).toEqual([2, 600, 136]);
    expect(ink(note, 0, 0, 300, 68)).toBeGreaterThan(300);
  });

  test("a region is drawn from the cells it covers, the same pixels as that part of the whole", async ({ page }) => {
    await open(page, "book.xlsx");
    await pages(page).toBe(2);
    const whole = await raster(page, 1, { width: 928 });
    // Columns A and B (176 + 96 of 464) and the first two rows, at 2x.
    const part = await raster(page, 1, { width: 544, region: { x: 0, y: 0, width: 272 / 464, height: 0.5 } });
    expect([part.width, part.height]).toEqual([544, 80]);
    expect(close(part, crop(whole, 0, 0, 544, 80))).toBeLessThan(3);
    // Only the right-hand column D: the numbers are right-aligned, the left is blank.
    const total = await raster(page, 1, { width: 192, region: { x: 368 / 464, y: 0, width: 96 / 464, height: 1 } });
    expect(ink(total, 0, 0, 96, 160)).toBeLessThan(ink(total, 96, 0, 192, 160));
    // Beyond the used area is the background.
    const beyond = await raster(page, 1, { width: 464, region: { x: 0.5, y: 0, width: 1, height: 1 }, background: "#00ff00" });
    expect([...beyond.data.subarray(((40 * beyond.width) + beyond.width - 5) * 4, ((40 * beyond.width) + beyond.width - 5) * 4 + 3)]).toEqual([0, 255, 0]);
  });

  test("a small picture of a sheet is the sheet scaled down, and a refused one says why", async ({ page }) => {
    await open(page, "book.xlsx");
    await pages(page).toBe(2);
    const small = await raster(page, 1, { width: 116 });
    expect([small.width, small.height]).toEqual([116, 20]);
    expect(ink(small)).toBeGreaterThan(10);
    expect(await refused(page, 1, { width: 100, background: "transparent" })).toBe("unsupported");
    expect(await refused(page, 1, { width: 464, region: { x: 0, y: 0, width: 1e-6, height: 1e-6 } })).toBe("too-large");
    expect(await refused(page, 3, { width: 100 })).toBe("invalid");
  });

  test("the cells at the on-screen scale are what the viewer shows", async ({ page }) => {
    await open(page, "quote.xlsx");
    await pages(page).toBe(1);
    const canvas = sheetCanvas(page);
    await page.waitForTimeout(800);
    const box = (await canvas.boundingBox())!;
    // A1:D4 starts under the 50 x 22 headers.
    const screen = await shot(page, { x: box.x + 50, y: box.y + 22, width: 464, height: 80 });
    const p = await raster(page, 1, { width: 464 });
    expect(close(screen, p)).toBeLessThan(6);
  });

  test("the viewport is the part of the used area in view, and region current draws it", async ({ page }) => {
    await open(page, "quote.xlsx");
    await pages(page).toBe(1);
    await page.waitForTimeout(800);
    // Everything is in view at 100 %.
    await expect.poll(() => viewport(page)).toEqual({ space: "page", page: 1, region: { x: 0, y: 0, width: 1, height: 1 } });
    // Zoomed to 4x the 464 px of cells are 1856: part of them show.
    await controllers(page, `(c) => c.zoom.setScale(4)`);
    await expect.poll(async () => (await viewport(page))?.region.width ?? 1).toBeLessThan(0.9);
    await page.waitForTimeout(800);
    const v = (await viewport(page))!;
    const canvas = sheetCanvas(page);
    const box = (await canvas.boundingBox())!;
    // Cells show from under the headers (200 x 88 at 4x) to the canvas edge.
    const clip = { x: box.x + 200, y: box.y + 88, width: Math.round(box.width - 200), height: Math.round(Math.min(box.height - 88, 80 * 4)) };
    const screen = await shot(page, clip);
    const current = await raster(page, 1, { width: clip.width, height: clip.height, region: "current" });
    expect(current.info.region!.x).toBeCloseTo(v.region.x, 2);
    expect(current.info.region!.width).toBeCloseTo(v.region.width, 1);
    expect(close(screen, current)).toBeLessThan(8);
  });
});

test.describe("a CSV", () => {
  test("is one sheet drawn as the viewer shows it, from its own cells", async ({ page }) => {
    await open(page, "quote.csv");
    await pages(page).toBe(1);
    await page.waitForTimeout(800);
    const box = (await sheetCanvas(page).boundingBox())!;
    // Four rows of 20 under the 50 x 22 headers, and four columns as wide as
    // the machine's font makes them (59 in one, 67 in another).
    const shape = await raster(page, 1, { width: 1000 });
    const width = Math.round((shape.width / shape.height) * 80);
    const screen = await shot(page, { x: box.x + 50, y: box.y + 22, width, height: 80 });
    const p = await raster(page, 1, { width });
    expect([p.width, p.height]).toEqual([width, 80]);
    expect(close(screen, p)).toBeLessThan(6);
    const left = await raster(page, 1, { width: 118, region: { x: 0, y: 0, width: 0.5, height: 1 } });
    expect(ink(left)).toBeGreaterThan(50);
    expect(await refused(page, 2, { width: 100 })).toBe("invalid");
    await expect.poll(async () => (await viewport(page))?.page).toBe(1);
  });
});

test.describe("the converted formats", () => {
  test("a spreadsheet, a deck and a text document are drawn by the engines that show them", async ({ page }) => {
    await openFixture(page, "sheets", "sample.xls");
    await pages(page).toBe(2);
    expect(ink(await raster(page, 1, { width: 400 }))).toBeGreaterThan(50);
    expect(ink(await raster(page, 2, { width: 400 }))).toBeGreaterThan(50);
    await expect.poll(() => viewport(page)).not.toBeNull();
    await openFixture(page, "slides", "sample.ppt");
    await pages(page).toBeGreaterThanOrEqual(1);
    const slide = await raster(page, 1, { width: 480 });
    expect(slide.height).toBeGreaterThan(200);
    expect(ink(slide)).toBeGreaterThan(50);
    expect((await viewport(page))!.page).toBe(1);
    await openFixture(page, "docs", "sample.doc");
    await pages(page).toBeGreaterThanOrEqual(1);
    const doc = await raster(page, 1, { width: 500 });
    expect(ink(doc)).toBeGreaterThan(300);
    expect(await refused(page, 1, { width: 100, background: "transparent" })).toBe("unsupported");
  });
});

test.describe("in the sandboxed frame", () => {
  async function headless(page: Page, name: string, bytes: Buffer): Promise<void> {
    await page.goto("./headless.html?lang=en");
    await page.getByTestId("file-input").setInputFiles({ name, mimeType: "", buffer: bytes });
    await expect
      .poll(() => page.evaluate(() => (window as unknown as { headless: { session(): { status: { get(): { phase: string } } } | null } }).headless.session()?.status.get().phase), { timeout: 60_000 })
      .toBe("ready");
    await expect.poll(() => controllers<boolean>(page, `(c) => !!c.pictures && c.pictures.get().count > 0`, "headless"), { timeout: 30_000 }).toBe(true);
  }

  for (const [name, width] of [
    ["notes.docx", 400],
    ["visit.pptx", 480],
    ["book.xlsx", 464],
    ["quote.csv", 236],
  ] as const) {
    test(`${name}: a picture has the size and the pixels it has in the page, and the viewport comes through`, async ({ page }) => {
      await open(page, name);
      await pages(page).toBeGreaterThanOrEqual(1);
      const inPage = await raster(page, 1, { width });
      await headless(page, name, sample(name));
      const inFrame = await raster(page, 1, { width }, "headless");
      expect([inFrame.width, inFrame.height]).toEqual([inPage.width, inPage.height]);
      expect(close(inFrame, inPage)).toBeLessThan(1);
      expect(inFrame.info.region).toEqual(inPage.info.region);
      await expect.poll(() => viewport(page, "headless")).not.toBeNull();
      expect(await refused(page, 1, { width: 50, background: "transparent" }, "headless")).toBe("unsupported");
    });
  }
});

test.describe("video", () => {
  const playable = (page: Page) => page.evaluate(() => document.createElement("video").canPlayType('video/webm; codecs="vp8"') !== "");
  const clip = () => fs.readFileSync(path.join(OUT, "clip.webm"));

  async function drawnFrame(page: Page, where: Where, selector: string) {
    return controllers<{ equal: number; width: number; height: number; transparent: number }>(
      page,
      `async (c) => {
        const v = document.querySelector(${JSON.stringify(selector)});
        v.pause();
        v.currentTime = 1;
        await new Promise((r) => (v.seeking ? v.addEventListener("seeked", r, { once: true }) : r()));
        // The new frame is presented a moment after the seek ends.
        await new Promise((r) => setTimeout(r, 300));
        const r = await c.pictures.raster(1, { width: 160 });
        const canvas = new OffscreenCanvas(r.width, r.height);
        const ctx = canvas.getContext("2d");
        // The clip is noise: only the same resampling gives the same pixels.
        ctx.imageSmoothingQuality = "high";
        ctx.drawImage(v, 0, 0, r.width, r.height);
        const want = ctx.getImageData(0, 0, r.width, r.height).data;
        const got = new OffscreenCanvas(r.width, r.height);
        const g = got.getContext("2d");
        g.drawImage(r.bitmap, 0, 0);
        r.bitmap.close();
        const have = g.getImageData(0, 0, r.width, r.height).data;
        let diff = 0, transparent = 0;
        for (let i = 0; i < have.length; i += 4) { diff += Math.abs(have[i] - want[i]) + Math.abs(have[i + 1] - want[i + 1]) + Math.abs(have[i + 2] - want[i + 2]); if (have[i + 3] < 255) transparent++; }
        return { equal: diff / (have.length / 4 * 3), width: r.width, height: r.height, transparent, space: r.space };
      }`,
      where,
    );
  }

  test("the frame being shown is a picture, drawn at the size asked", async ({ page }) => {
    await page.goto("./?lang=en&mode=page");
    test.skip(!(await playable(page)), "this browser cannot play VP8 WebM");
    await page.getByTestId("file-input").setInputFiles({ name: "clip.webm", mimeType: "video/webm", buffer: clip() });
    await expect(page.locator(".demo-frame .exav-viewer-body")).toHaveAttribute("data-phase", "ready");
    const video = page.locator(".demo-frame .exav-viewer-media video");
    await expect.poll(() => video.evaluate((v: HTMLVideoElement) => v.readyState)).toBeGreaterThanOrEqual(2);
    expect(await controllers(page, `(c) => c.pictures.get()`)).toEqual({ count: 1, space: "frame" });
    const frame = await drawnFrame(page, "exavDemo", ".demo-frame .exav-viewer-media video");
    expect(frame.transparent).toBe(0);
    expect(frame.equal).toBeLessThan(2);
    const p = await raster(page, 1, { longEdge: 64 });
    expect(Math.max(p.width, p.height)).toBe(64);
    expect(p.info.space).toBe("frame");
    expect(p.info.region).toBeUndefined();
    // A frame has no region, and a size is needed.
    expect(await refused(page, 1, { width: 10, region: { x: 0, y: 0, width: 1, height: 1 } })).toBe("invalid");
    expect(await refused(page, 1, { width: 10, region: "current" })).toBe("invalid");
    expect(await refused(page, 1, {})).toBe("invalid");
    expect(await refused(page, 2, { width: 10 })).toBe("invalid");
    // Shaped by a width and a height, never stretched, the bars transparent.
    const boxed = await raster(page, 1, { width: 100, height: 100 });
    expect([boxed.width, boxed.height]).toEqual([100, 100]);
    expect(boxed.data[3]).toBe(0);
    expect(await controllers(page, `(c) => !!c.viewport`)).toBe(false);
  });

  test("in the frame, a video delivered as a blob is drawn, and one delivered by URL is refused", async ({ page }) => {
    await page.goto("./headless.html?lang=en");
    test.skip(!(await playable(page)), "this browser cannot play VP8 WebM");
    await page.getByTestId("file-input").setInputFiles({ name: "clip.webm", mimeType: "video/webm", buffer: clip() });
    await expect
      .poll(() => page.evaluate(() => (window as unknown as { headless: { session(): { status: { get(): { phase: string } } } | null } }).headless.session()?.status.get().phase), { timeout: 60_000 })
      .toBe("ready");
    await expect.poll(() => controllers<boolean>(page, `(c) => !!c.pictures`, "headless")).toBe(true);
    // A video with no frame yet is refused ("failed"): Firefox and WebKit take longer to decode the first.
    await expect.poll(() => page.frameLocator("#stage iframe").locator("video").evaluate((v: HTMLVideoElement) => v.readyState)).toBeGreaterThanOrEqual(2);
    const p = await raster(page, 1, { width: 64 }, "headless");
    expect(p.width).toBe(64);
    expect(find(p, (r, g, b) => r + g + b > 30).count).toBeGreaterThan(0);
  });

  // The frame's own origin is opaque, so a video it is given by address is another origin to it: unreadable, and said so.
  test("in the frame, a video delivered by URL is refused as unsupported, not drawn blank", async ({ page }) => {
    await page.goto("./?lang=en");
    test.skip(!(await playable(page)), "this browser cannot play VP8 WebM");
    await page.goto("./?lang=en&url=/e2e/clip.webm");
    await expect(page.locator(".demo-frame .exav-viewer-body")).toHaveAttribute("data-phase", "ready");
    const frame = page.frameLocator(".demo-frame iframe.exav-viewer-sandbox");
    await expect.poll(() => frame.locator("video").evaluate((v: HTMLVideoElement) => v.readyState)).toBeGreaterThanOrEqual(2);
    await expect.poll(() => controllers<boolean>(page, `(c) => !!c.pictures`)).toBe(true);
    expect(await refused(page, 1, { width: 64 })).toBe("unsupported");
  });
});
