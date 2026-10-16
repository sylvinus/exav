// What the DWG and DXF renderer draws its own way, on exav-render's drawings
// built to show each thing (its tests/fixtures/dwg/make.py, copied as
// cad-*.dxf by make-samples.mjs), measured on the picture. In the page: the
// sandboxed frame draws the same pixels (demo.spec.ts compares the two).
import { fileURLToPath } from "node:url";

import { expect, test, type Locator, type Page } from "@playwright/test";

import { failOnViolations } from "./csp.js";
import { bands, decodePng, difference, find, type Pixels } from "./pixels.js";
import { openSample } from "./samples.js";

failOnViolations();

const ink = (r: number, g: number, b: number) => r < 160 && g < 160 && b < 160;

/** One of the demo's example drawings (demo/examples/generate/make-cad.py). */
const HOUSE = fileURLToPath(new URL("../demo/examples/files/cad/house-plan.dxf", import.meta.url));

async function shot(target: Locator): Promise<Pixels> {
  const page = target.page();
  // The viewer's tools float over the canvas.
  const tools = page.locator(".exav-viewer-tools");
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

async function open(page: Page, name: string): Promise<Locator> {
  await openSample(page, name, { mode: "page" });
  await expect(page.locator(".demo-frame .exav-viewer-body")).toHaveAttribute("data-phase", "ready");
  return page.locator(".demo-frame .exav-viewer-cad-canvas");
}

async function layout(page: Page, name: string): Promise<void> {
  await page.locator(".exav-viewer-layouts").getByRole("button", { name }).click();
  await expect(page.locator(".demo-frame .exav-viewer-body")).toHaveAttribute("data-phase", "ready");
}

test.describe("clipping", () => {
  // A viewport onto model x -10 to 30 of a text 5 high running from 0 to
  // about 66: 30 of it shows, some 6 times its height, not 13.
  test("text crossing a viewport's edge is cut at the edge", async ({ page }) => {
    const canvas = await open(page, "cad-viewport_text.dxf");
    await layout(page, "Sheet");
    const box = find(await settled(canvas), ink).box!;
    expect(box.width / box.height).toBeGreaterThan(4.5);
    expect(box.width / box.height).toBeLessThan(7);
  });
});

type Test = (r: number, g: number, b: number) => boolean;

/** The pixels `test` accepts inside `box`, less `inset` on every side. */
function countIn(p: Pixels, box: { minX: number; minY: number; maxX: number; maxY: number }, inset: number, test: Test): number {
  let n = 0;
  for (let y = box.minY + inset; y <= box.maxY - inset; y++)
    for (let x = box.minX + inset; x <= box.maxX - inset; x++) {
      const i = (y * p.width + x) * 4;
      if (test(p.data[i]!, p.data[i + 1]!, p.data[i + 2]!)) n++;
    }
  return n;
}

const near = (v: number, to: number) => Math.abs(v - to) < 32;

test.describe("transparency", () => {
  // Each at half opacity: a red hatch over a green line, a blue V, a cyan
  // hatch over magenta text, each drawn after what it covers.
  test("an opaque line behind a translucent hatch shows through it", async ({ page }) => {
    const p = await settled(await open(page, "cad-transparency.dxf"));
    const pink = find(p, (r, g, b) => r > 220 && near(g, 128) && near(b, 128)).box!;
    expect(countIn(p, pink, 2, (r, g, b) => near(r, 128) && near(g, 128) && b < 40)).toBeGreaterThan(0);
    expect(countIn(p, pink, 2, (r, g, b) => g > 200 && r < 60 && b < 60)).toBe(0);
  });

  test("a translucent polyline is no darker where its segments meet", async ({ page }) => {
    const p = await settled(await open(page, "cad-transparency.dxf"));
    expect(find(p, (r, g, b) => near(r, 128) && near(g, 128) && b > 220).count).toBeGreaterThan(0);
    expect(find(p, (r, g, b) => r < 90 && g < 90 && b > 200).count).toBe(0);
  });

  test("text behind a translucent hatch is tinted by it", async ({ page }) => {
    const p = await settled(await open(page, "cad-transparency.dxf"));
    const cyan = find(p, (r, g, b) => near(r, 128) && g > 220 && b > 220).box!;
    expect(countIn(p, cyan, 2, (r, g, b) => near(r, 128) && near(g, 128) && b > 220)).toBeGreaterThan(0);
    expect(countIn(p, cyan, 2, (r, g, b) => r > 200 && g < 60 && b > 200)).toBe(0);
  });
});

test.describe("what is not drawn", () => {
  test("is said by type, and the files the drawing points at by name", async ({ page }) => {
    await open(page, "cad-not_drawn.dxf");
    const warnings = page.locator(".demo-frame .exav-viewer-warnings");
    await expect(warnings).toContainText("3 objects are of a kind not drawn here. 3DSOLID (2), REGION");
    await expect(warnings).toContainText("3 external references are not drawn. photo.png, walls.dwg");
  });

  test("a drawing with nothing drawn here keeps the thumbnail it was saved with", async ({ page }) => {
    await open(page, "cad-solid_only.dxf");
    const preview = page.locator(".demo-frame .exav-viewer-cad-preview");
    await expect(preview).toHaveCount(1);
    expect(await preview.evaluate((img: HTMLImageElement) => [img.naturalWidth, img.naturalHeight])).toEqual([8, 8]);
    await expect(page.locator(".demo-frame .exav-viewer-warnings")).toContainText("the picture saved with it is shown");
  });
});

test.describe("antialiasing", () => {
  // A thin dark line drawn before the wide red one it crosses in front of:
  // its anti-aliased edges blend over the red, not over the paper.
  test("a line's soft edge shows what lies behind it, not the background", async ({ page }) => {
    const p = await settled(await open(page, "cad-halo.dxf"));
    const band = find(p, (r, g, b) => r > 200 && g < 80 && b < 80).box!;
    const grey = (r: number, g: number, b: number) =>
      Math.max(r, g, b) - Math.min(r, g, b) < 30 && r > 70 && r < 235;
    expect(countIn(p, band, 2, grey)).toBe(0);
    // The dark line is there, across the band: red darkened by it.
    expect(countIn(p, band, 2, (r, g, b) => r < 210 && g < 70 && b < 70)).toBeGreaterThan(0);
  });

  // Nothing but filled bands: ink and paper only, but where a pixel is part
  // of each, which a slanted or curved edge has all along it.
  test("a fill's edge is anti-aliased, and no wider for it", async ({ page }) => {
    const p = await settled(await open(page, "cad-wide.dxf"));
    const grey = (r: number, g: number, b: number) => r > 60 && r < 200 && Math.max(r, g, b) - Math.min(r, g, b) < 30;
    const dark = (r: number, g: number, b: number) => r < 60 && g < 60 && b < 60;
    expect(find(p, grey).count).toBeGreaterThan(60);
    // Partly covered pixels outside the bands, at most half each: the ink
    // stays where it was.
    expect(find(p, grey).count).toBeLessThan(find(p, dark).count / 2);
  });
});

test.describe("curves", () => {
  // Zoomed thirtyfold onto a circle's rightmost point, its edge runs down
  // the canvas: a true arc leaves the vertical by about six pixels by the
  // canvas's top and bottom, the seventy-sided polygon it used to be by
  // fifteen on at least one side. Deeper, the pixel the zoom anchors on
  // sends the edge off the canvas.
  test("a circle stays round however close the view", async ({ page }) => {
    const canvas = await open(page, "cad-circle.dxf");
    const fitted = await settled(canvas);
    const ring = find(fitted, ink).box!;
    const box = (await canvas.boundingBox())!;
    const right = { x: ring.maxX, y: Math.round((ring.minY + ring.maxY) / 2) };
    await page.mouse.move(box.x + right.x, box.y + right.y);
    await page.mouse.wheel(0, -1100);
    const p = await settled(canvas);
    const inkAt = (y: number) => {
      let x = -1;
      for (let i = 0; i < p.width; i++) {
        const o = (y * p.width + i) * 4;
        if (ink(p.data[o]!, p.data[o + 1]!, p.data[o + 2]!)) x = i;
      }
      return x;
    };
    const middle = inkAt(right.y);
    const top = inkAt(4);
    const bottom = inkAt(p.height - 5);
    expect(middle).toBeGreaterThan(0);
    expect(top).toBeGreaterThan(0);
    expect(bottom).toBeGreaterThan(0);
    expect(middle - top).toBeLessThan(10);
    expect(middle - bottom).toBeLessThan(10);
  });
});

test.describe("colours", () => {
  const brightYellow = (r: number, g: number, b: number) => r > 220 && g > 220 && b < 90;
  const darkYellow = (r: number, g: number, b: number) => r > 110 && g > 110 && b < 60 && r < 200;
  const cyan = (r: number, g: number, b: number) => r < 60 && g > 220 && b > 220;
  const red = (r: number, g: number, b: number) => r > 200 && g < 60 && b < 60;

  test("a yellow line on white is darkened to be seen; a fill keeps its colour", async ({ page }) => {
    const p = await settled(await open(page, "cad-colours.dxf"));
    expect(find(p, brightYellow).count).toBe(0);
    expect(find(p, darkYellow).count).toBeGreaterThan(100);
    expect(find(p, cyan).count).toBeGreaterThan(1000);
  });

  test("monochrome draws everything in ink", async ({ page }) => {
    await openSample(page, "cad-colours.dxf", { mode: "page", cad: "monochrome" });
    await expect(page.locator(".demo-frame .exav-viewer-body")).toHaveAttribute("data-phase", "ready");
    const p = await settled(page.locator(".demo-frame .exav-viewer-cad-canvas"));
    expect(find(p, red).count + find(p, cyan).count + find(p, darkYellow).count).toBe(0);
    expect(find(p, (r, g, b) => r < 40 && g < 40 && b < 40).count).toBeGreaterThan(1000);
  });
});

test.describe("context", () => {
  test("a lost GL context comes back with the drawing on it", async ({ page }) => {
    const canvas = await open(page, "cad-halo.dxf");
    const before = await settled(canvas);
    await canvas.evaluate(async (c: HTMLCanvasElement) => {
      const lose = c.getContext("webgl2")!.getExtension("WEBGL_lose_context")!;
      lose.loseContext();
      await new Promise((r) => setTimeout(r, 300));
      lose.restoreContext();
    });
    await page.waitForTimeout(1500);
    expect(difference(before, await settled(canvas))).toBeLessThan(1);
  });
});

test.describe("text", () => {
  // Twelve faces' worth of characters, more than the atlas budget affords
  // at the em a close view wants: "HE" in the middle, zoomed into, keeps
  // edges a pixel or two wide rather than the blur of a magnified bitmap.
  test("a character set too large for the atlas stays sharp zoomed in", async ({ page }) => {
    const canvas = await open(page, "cad-text_many.dxf");
    const box = (await canvas.boundingBox())!;
    await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2);
    await page.mouse.wheel(0, -1400);
    await page.waitForTimeout(1000);
    const p = await settled(canvas);
    const lum = (r: number, g: number, b: number) => (r + g + b) / 3;
    const dark = find(p, (r, g, b) => lum(r, g, b) < 80).count;
    const edge = find(p, (r, g, b) => lum(r, g, b) >= 80 && lum(r, g, b) < 200).count;
    expect(dark).toBeGreaterThan(2000);
    expect(edge / dark).toBeLessThan(0.15);
  });

  // A drawing of a house, zoomed into by ten: the glyph page for that view is
  // made of distance fields, which take the better part of a second. Made a
  // slice at a time, the page keeps answering while they are (the longest
  // wait was 940 ms in one piece, 95 ms in slices, in software GL).
  test("the glyph page made for a closer view does not stop the page", async ({ page }) => {
    await page.goto("./?lang=en&mode=page");
    await page.getByTestId("file-input").setInputFiles(HOUSE);
    await expect(page.locator(".demo-frame .exav-viewer-body")).toHaveAttribute("data-phase", "ready");
    const canvas = page.locator(".demo-frame .exav-viewer-cad-canvas");
    // What loading left to do is done.
    await settled(canvas);
    const box = (await canvas.boundingBox())!;
    await page.mouse.move(box.x + box.width * 0.6, box.y + box.height * 0.45);
    await page.evaluate(() => {
      const w = window as unknown as { gaps: number[] };
      w.gaps = [];
      let last = performance.now();
      setInterval(() => {
        const now = performance.now();
        w.gaps.push(now - last);
        last = now;
      }, 5);
    });
    await page.mouse.wheel(0, -1000);
    await page.waitForTimeout(2500);
    const gaps = await page.evaluate(() => (window as unknown as { gaps: number[] }).gaps);
    expect(gaps.length).toBeGreaterThan(100);
    expect(Math.max(...gaps)).toBeLessThan(300);
  });
});

test.describe("paper", () => {
  test("a layout is drawn on its sheet of paper, model space on the ground", async ({ page }) => {
    const canvas = await open(page, "cad-sheets.dxf");
    const surround = (r: number, g: number, b: number) => Math.abs(r - 224) < 8 && Math.abs(g - 224) < 8 && Math.abs(b - 224) < 8;
    const white = (r: number, g: number, b: number) => r > 250 && g > 250 && b > 250;
    expect(find(await settled(canvas), surround).count).toBe(0);
    await layout(page, "Metric");
    const p = await settled(canvas);
    expect(find(p, surround).count).toBeGreaterThan(1000);
    // A4 in landscape: the white sheet is 297 by 210.
    const sheet = find(p, white).box!;
    expect(sheet.width / sheet.height).toBeGreaterThan(1.37);
    expect(sheet.width / sheet.height).toBeLessThan(1.46);
  });
});

test.describe("sheets", () => {
  // Each layout has a square an inch across and, below it, a line 2.11 mm
  // wide: a twelfth of the square on either sheet, whatever its units.
  for (const name of ["Metric", "Imperial"]) {
    test(`a lineweight on a sheet in ${name.toLowerCase()} units is millimetres on the page`, async ({ page }) => {
      const canvas = await open(page, "cad-sheets.dxf");
      await layout(page, name);
      const p = await settled(canvas);
      // Rows with ink most of the way across: the square's two edges and the line.
      const rows = bands(p, ink, 20);
      expect(rows.length).toBe(3);
      const [top, bottom, line] = rows as [{ from: number; to: number }, { from: number; to: number }, { from: number; to: number }];
      const side = bottom.from - top.from;
      const width = line.to - line.from + 1;
      expect(width / side).toBeGreaterThan(0.05);
      expect(width / side).toBeLessThan(0.13);
    });
  }
});
