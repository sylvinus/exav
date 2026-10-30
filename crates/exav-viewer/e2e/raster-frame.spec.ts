// Pictures of pages (`controllers.pictures`, `controllers.viewport`) for a PDF
// and an image, with each file in the sandboxed frame and with the engines in
// the page: the size and region asked for, the region drawn back, the
// viewport, the encoding done by the page, and the errors. The expectations
// come from how the samples were made (fixtures/make-samples.mjs): a PDF page
// of 595 x 842 points with a blue rule across it 750 points up, and a 640 x
// 420 picture with a sun of radius 55 at (480, 110).
import { expect, test, type Page } from "@playwright/test";

import { failOnViolations } from "./csp.js";
import { decodePng, find, type Pixels } from "./pixels.js";
import { openSample } from "./samples.js";

failOnViolations();

interface Drawn {
  width: number;
  height: number;
  page: number;
  space: string;
  region?: { x: number; y: number; width: number; height: number };
  layout?: string;
  pixels: Pixels;
}

type Failed = { error: string };

/** The rule's blue, or a lighter one where a thin line is anti-aliased into white. */
const blue = (r: number, _g: number, b: number) => b > 150 && b - r > 40;
const at = (p: Pixels, x: number, y: number): [number, number, number, number] => {
  const i = (y * p.width + x) * 4;
  return [p.data[i]!, p.data[i + 1]!, p.data[i + 2]!, p.data[i + 3]!];
};
const isWhite = (p: Pixels, x: number, y: number) => at(p, x, y).every((c) => c > 245);

/** `pictures.raster(page, options)`, the bitmap read back as pixels; or the code of its `RasterError`. */
async function raster(page: Page, n: number, options: Record<string, unknown>): Promise<Drawn | Failed> {
  const result = await page.evaluate(
    async ([n, options]) => {
      const pictures = (window as unknown as { exavDemo: { session(): { controllers: { get(): { pictures: { raster(n: number, o: unknown): Promise<any> } } } } } }).exavDemo.session().controllers.get().pictures;
      try {
        const { bitmap, ...rest } = await pictures.raster(n, options);
        const canvas = document.createElement("canvas");
        canvas.width = bitmap.width;
        canvas.height = bitmap.height;
        canvas.getContext("2d")!.drawImage(bitmap, 0, 0);
        bitmap.close();
        return { ...rest, png: canvas.toDataURL("image/png").split(",")[1] };
      } catch (e) {
        return { error: (e as { code?: string }).code ?? String(e) };
      }
    },
    [n, options] as const,
  );
  if ("error" in result) return result as Failed;
  const { png, ...rest } = result as { png: string };
  return { ...(rest as Omit<Drawn, "pixels">), pixels: decodePng(Buffer.from(png, "base64")) };
}

const ok = (r: Drawn | Failed): Drawn => {
  if ("error" in r) throw new Error(`the picture failed: ${r.error}`);
  return r;
};

/** The first and last row and column where `match` holds. */
const extent = (p: Pixels, match: (r: number, g: number, b: number) => boolean) => find(p, match).box;

for (const mode of ["sandbox", "page"] as const) {
  test.describe(mode, () => {
    async function open(page: Page, name: string) {
      await openSample(page, name, mode === "page" ? { mode } : {});
      await expect(page.locator(".demo-frame .exav-viewer-body")).toHaveAttribute("data-phase", "ready");
      await page.waitForFunction(() => !!(window as unknown as { exavDemo?: { session(): { controllers: { get(): { pictures?: unknown } } } | null } }).exavDemo?.session()?.controllers.get().pictures);
    }

    test("a PDF page is drawn to a longest side, whole, on white, with its region reported", async ({ page }) => {
      await open(page, "report.pdf");
      const r = ok(await raster(page, 1, { longEdge: 420 }));
      expect([r.width, r.height, r.page, r.space]).toEqual([297, 420, 1, "page"]);
      expect(r.region).toEqual({ x: 0, y: 0, width: 1, height: 1 });
      expect(at(r.pixels, 2, 2)).toEqual([255, 255, 255, 255]);
      // The rule 750 points up: 92 of 842 from the top, across 56 to 539 of 595.
      const rule = extent(r.pixels, blue)!;
      expect(rule.minY).toBeGreaterThan(420 * (91 / 842) - 3);
      expect(rule.minY).toBeLessThan(420 * (93 / 842) + 3);
      expect(rule.minX / 297).toBeCloseTo(56 / 595, 1);
      expect(rule.maxX / 297).toBeCloseTo(539 / 595, 1);
    });

    test("a region of a page is exactly that part, at the size asked for", async ({ page }) => {
      await open(page, "report.pdf");
      // A strip 0.02 of the page's height, from 0.1 down: 595 x 16.84 points at one pixel a point.
      const strip = ok(await raster(page, 1, { width: 595, region: { x: 0, y: 0.1, width: 1, height: 0.02 } }));
      expect([strip.width, strip.height]).toEqual([595, 17]);
      expect(strip.region).toEqual({ x: 0, y: 0.1, width: 1, height: 0.02 });
      // The rule is 7.8 points below the strip's top and 2 thick.
      const rule = extent(strip.pixels, blue)!;
      expect(rule.minY).toBeGreaterThanOrEqual(6);
      expect(rule.maxY).toBeLessThanOrEqual(10);
      expect(rule.minX).toBeGreaterThanOrEqual(54);
      expect(rule.minX).toBeLessThanOrEqual(58);
      expect(rule.maxX).toBeGreaterThanOrEqual(537);
      expect(rule.maxX).toBeLessThanOrEqual(541);
      expect(isWhite(strip.pixels, 20, 8)).toBe(true);
      expect(isWhite(strip.pixels, 300, 1)).toBe(true);
      // The same strip cut out of the whole page is the same picture.
      const whole = ok(await raster(page, 1, { width: 595 }));
      const y0 = Math.round(0.1 * whole.height);
      let worst = 0;
      for (let y = 0; y < strip.height; y++) for (let x = 0; x < 595; x += 3) worst = Math.max(worst, Math.abs(at(strip.pixels, x, y)[2] - at(whole.pixels, x, y0 + y)[2]));
      expect(worst).toBeLessThan(40);
    });

    test("a region of another shape than the picture is widened (contain) or cut (cover), never stretched, and the region drawn is reported", async ({ page }) => {
      await open(page, "report.pdf");
      const region = { x: 0.25, y: 0, width: 0.5, height: 0.5 };
      // 297.5 x 421 points into a square.
      const contain = ok(await raster(page, 1, { width: 200, height: 200, region }));
      expect(contain.region!.width).toBeCloseTo(421 / 595, 6);
      expect(contain.region!.height).toBeCloseTo(0.5, 6);
      expect(contain.region!.x + contain.region!.width / 2).toBeCloseTo(0.5, 6);
      const cover = ok(await raster(page, 1, { width: 200, height: 200, region, fit: "cover" }));
      expect(cover.region!.width).toBeCloseTo(0.5, 6);
      expect(cover.region!.height).toBeCloseTo(297.5 / 842, 6);
      expect(cover.region!.y + cover.region!.height / 2).toBeCloseTo(0.25, 6);
    });

    test("what the user sees is the viewport, and 'current' draws it", async ({ page }) => {
      await open(page, "report.pdf");
      const tools = page.locator(".demo-frame .exav-viewer-tools");
      for (let i = 0; i < 3; i++) await tools.getByRole("button", { name: "Zoom in" }).click();
      const viewport = () => page.evaluate(() => (window as unknown as { exavDemo: { session(): { controllers: { get(): { viewport: { get(): unknown } } } } } }).exavDemo.session().controllers.get().viewport.get());
      await expect.poll(async () => ((await viewport()) as { region: { width: number } } | null)?.region.width ?? 1).toBeLessThan(0.8);
      // Still: the last zoom has settled when two reads agree.
      let last = "";
      await expect
        .poll(async () => {
          const now = JSON.stringify(await viewport());
          const same = now === last;
          last = now;
          return same;
        })
        .toBe(true);
      const seen = (await viewport()) as { space: string; page: number; region: { x: number; y: number; width: number; height: number } };
      expect(seen.space).toBe("page");
      const r = ok(await raster(page, seen.page, { width: 400, region: "current" }));
      // The viewport can move between the two reads by a pixel or two of scrolling; it does not here.
      for (const k of ["x", "y", "width", "height"] as const) expect(r.region![k]).toBeCloseTo(seen.region[k], 2);
      expect(r.pixels.width).toBe(400);
      // It is a narrower part of the page than the whole of it.
      expect(r.region!.width).toBeLessThan(0.8);
    });

    test("a picture is drawn from the document again at any size, not read off the screen", async ({ page }) => {
      await open(page, "report.pdf");
      const small = ok(await raster(page, 1, { width: 300, region: { x: 0, y: 0.1, width: 0.2, height: 0.02 } }));
      const big = ok(await raster(page, 1, { width: 3000, region: { x: 0, y: 0.1, width: 0.2, height: 0.02 } }));
      expect(big.width).toBe(3000);
      // The region is 119 x 16.84 points.
      expect(Math.abs(big.height - 3000 / (119 / 16.84))).toBeLessThanOrEqual(1);
      // The rule is two points thick: about ten times as many pixels at ten times the size, with an edge as sharp.
      const thick = (p: Pixels) => {
        const column = Math.floor(p.width * 0.5);
        let n = 0;
        for (let y = 0; y < p.height; y++) if (blue(...(at(p, column, y).slice(0, 3) as [number, number, number]))) n++;
        return n;
      };
      expect(thick(big.pixels) / thick(small.pixels)).toBeGreaterThan(7);
      expect(thick(big.pixels) / thick(small.pixels)).toBeLessThan(13);
    });

    test("an image's region is pixels of the source, and what lies outside it takes the background", async ({ page }) => {
      await open(page, "landscape.png");
      const sun = ok(await raster(page, 1, { width: 110, height: 110, region: { x: 425, y: 55, width: 110, height: 110 } }));
      expect(sun.space).toBe("pixels");
      expect(sun.region).toEqual({ x: 425, y: 55, width: 110, height: 110 });
      expect(at(sun.pixels, 55, 55)).toEqual([250, 200, 80, 255]);
      expect(at(sun.pixels, 2, 2)[2]).toBeGreaterThan(150);
      // Twice as wide: contain widens the region about its centre, the sun stays in the middle.
      const wide = ok(await raster(page, 1, { width: 220, height: 110, region: { x: 425, y: 55, width: 110, height: 110 } }));
      expect(wide.region).toEqual({ x: 370, y: 55, width: 220, height: 110 });
      expect(at(wide.pixels, 110, 55)).toEqual([250, 200, 80, 255]);
      // Cover cuts the height instead.
      const cover = ok(await raster(page, 1, { width: 220, height: 110, fit: "cover", region: { x: 425, y: 55, width: 110, height: 110 } }));
      expect(cover.region).toEqual({ x: 425, y: 82.5, width: 110, height: 55 });
      // Past the left edge: transparent by default, any colour asked for, and the picture where it is.
      const past = ok(await raster(page, 1, { width: 740, region: { x: -100, y: 0, width: 740, height: 420 } }));
      expect(at(past.pixels, 50, 200)[3]).toBe(0);
      expect(at(past.pixels, 100 + 480, 110)).toEqual([250, 200, 80, 255]);
      const red = ok(await raster(page, 1, { width: 740, background: "#ff0000", region: { x: -100, y: 0, width: 740, height: 420 } }));
      expect(at(red.pixels, 50, 200)).toEqual([255, 0, 0, 255]);
    });

    test("an image is sharp when drawn larger than its pixels, from the source", async ({ page }) => {
      await open(page, "logo.svg");
      const r = ok(await raster(page, 1, { longEdge: 1600 }));
      expect(Math.max(r.width, r.height)).toBe(1600);
      // The whole drawing: its white circle in the middle of the green.
      expect(at(r.pixels, r.width / 2, r.height / 2)).toEqual([255, 255, 255, 255]);
      expect(at(r.pixels, r.width - 10, r.height - 10)).toEqual([0, 170, 119, 255]);
      // A vector drawing keeps hard edges at any size: a colour change over one pixel at most.
      let soft = 0;
      let hard = 0;
      for (let x = 1; x < r.width; x++) {
        const y = Math.floor(r.height / 2);
        const d = Math.abs(at(r.pixels, x, y)[0] - at(r.pixels, x - 1, y)[0]);
        if (d > 120) hard++;
        else if (d > 30) soft++;
      }
      expect(hard).toBeGreaterThan(0);
      expect(soft).toBeLessThanOrEqual(hard * 2 + 4);
    });

    test("toBlob encodes in the page, and says when a type cannot be", async ({ page }) => {
      await open(page, "report.pdf");
      const out = await page.evaluate(async () => {
        const pictures = (window as unknown as { exavDemo: { session(): { controllers: { get(): { pictures: { toBlob(n: number, o: unknown): Promise<any> } } } } } }).exavDemo.session().controllers.get().pictures;
        const one = async (type: string) => {
          try {
            const r = await pictures.toBlob(1, { longEdge: 200, type, quality: 0.8 });
            const bitmap = await createImageBitmap(r.blob);
            const info = { type: r.blob.type, size: r.blob.size, width: bitmap.width, height: bitmap.height, region: r.region, bitmap: "bitmap" in r };
            bitmap.close();
            return info;
          } catch (e) {
            return { error: (e as { code?: string }).code ?? String(e) };
          }
        };
        return { png: await one("png"), jpeg: await one("jpeg"), webp: await one("webp"), gif: await one("gif") };
      });
      expect(out.png).toMatchObject({ type: "image/png", width: 141, height: 200, region: { x: 0, y: 0, width: 1, height: 1 }, bitmap: false });
      expect(out.jpeg).toMatchObject({ type: "image/jpeg", width: 141, height: 200 });
      // Safari has no WebP encoder: it says so, and does not hand back a PNG.
      if ("error" in out.webp) expect(out.webp).toEqual({ error: "unsupported" });
      else expect(out.webp).toMatchObject({ type: "image/webp" });
      expect(out.gif).toEqual({ error: "invalid" });
    });

    test("a request that is none is refused, a picture too large is, and one aborted stops", async ({ page }) => {
      await open(page, "report.pdf");
      expect(await raster(page, 99, { longEdge: 100 })).toEqual({ error: "invalid" });
      expect(await raster(page, 1, {})).toEqual({ error: "invalid" });
      expect(await raster(page, 1, { longEdge: -5 })).toEqual({ error: "invalid" });
      expect(await raster(page, 1, { longEdge: 100, background: "url(https://example.test/x)" })).toEqual({ error: "invalid" });
      expect(await raster(page, 1, { longEdge: 100, fit: "stretch" })).toEqual({ error: "invalid" });
      expect(await raster(page, 1, { longEdge: 100, region: "current", layout: "x".repeat(2000) })).toEqual({ error: "invalid" });
      expect(await raster(page, 1, { width: 20_000, height: 20_000 })).toEqual({ error: "too-large" });
      expect(await raster(page, 1, { width: 16_384, height: 16_384 })).toEqual({ error: "too-large" });
      const code = await page.evaluate(async () => {
        const pictures = (window as unknown as { exavDemo: { session(): { controllers: { get(): { pictures: { raster(n: number, o: unknown): Promise<unknown> } } } } } }).exavDemo.session().controllers.get().pictures;
        const abort = new AbortController();
        const drawn = pictures.raster(1, { longEdge: 4000, signal: abort.signal }).then(
          () => "drawn",
          (e: { code?: string }) => e.code,
        );
        abort.abort();
        return drawn;
      });
      expect(code).toBe("aborted");
    });

    test("text has no pictures", async ({ page }) => {
      await openSample(page, "notes.txt", mode === "page" ? { mode } : {});
      await expect(page.locator(".demo-frame .exav-viewer-body")).toHaveAttribute("data-phase", "ready");
      expect(await page.evaluate(() => (window as unknown as { exavDemo: { session(): { controllers: { get(): { pictures?: unknown } } } } }).exavDemo.session().controllers.get().pictures === undefined)).toBe(true);
    });

    test("the demo's Export image control saves what the options say", async ({ page }) => {
      await open(page, "report.pdf");
      // The host's own control, beside the file's name and not over the viewer, and opening a dialog.
      await expect(page.locator(".demo-frame").getByTestId("export-open")).toHaveCount(0);
      await page.locator(".demo-bar").getByTestId("export-open").click();
      await expect(page.getByRole("dialog", { name: "Export image" })).toBeVisible();
      await page.getByTestId("export-long-edge").fill("500");
      await page.getByTestId("export-type").selectOption("jpeg");
      await page.getByTestId("export-run").click();
      await expect(page.getByTestId("export-result")).toHaveAttribute("download", "report-1.jpg");
      await expect(page.getByTestId("export-info")).toContainText("353 x 500 px, page 1");
      const href = await page.getByTestId("export-result").getAttribute("href");
      const type = await page.evaluate(async (u) => (await (await fetch(u!)).blob()).type, href);
      expect(type).toBe("image/jpeg");
    });
  });
}
