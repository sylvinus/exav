// Camera RAW files in the demo, decoded in WebAssembly: each is a synthetic
// container of its family (exav-render's tests/fixtures/raw/make.py) that
// carries a JPEG of four colour quadrants, so that what is on screen says which
// preview was chosen and how it was turned.
//
// Every test runs twice: with each file in the sandboxed frame (the demo's
// default) and with the engines in the page (`?mode=page`).
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { expect, test, type Locator, type Page } from "@playwright/test";

import { failOnViolations } from "./csp.js";
import { decodePng, find, type Pixels } from "./pixels.js";

const FIXTURES = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "exav-render", "tests", "fixtures", "raw");

const COLOURS = {
  red: (r: number, g: number, b: number) => r > 200 && g < 70 && b < 70,
  green: (r: number, g: number, b: number) => g > 200 && r < 70 && b < 70,
  blue: (r: number, g: number, b: number) => b > 200 && r < 70 && g < 70,
  yellow: (r: number, g: number, b: number) => r > 200 && g > 200 && b < 70,
};

/** The four colours in the order they sit on screen: top left, top right, bottom left, bottom right. */
function layout(p: Pixels): { order: string[]; width: number; height: number } {
  const found = Object.entries(COLOURS).map(([name, test]) => ({ name, ...find(p, test) }));
  for (const c of found) expect(c.count, `${c.name} is on screen`).toBeGreaterThan(100);
  const centre = (c: (typeof found)[number]) => ({ x: (c.box!.minX + c.box!.maxX) / 2, y: (c.box!.minY + c.box!.maxY) / 2 });
  const byY = [...found].sort((a, b) => centre(a).y - centre(b).y);
  const rows = [byY.slice(0, 2), byY.slice(2)].map((row) => row.sort((a, b) => centre(a).x - centre(b).x));
  const [minX, maxX] = [Math.min(...found.map((c) => c.box!.minX)), Math.max(...found.map((c) => c.box!.maxX))];
  const [minY, maxY] = [Math.min(...found.map((c) => c.box!.minY)), Math.max(...found.map((c) => c.box!.maxY))];
  return { order: rows.flat().map((c) => c.name), width: maxX - minX + 1, height: maxY - minY + 1 };
}

failOnViolations();

for (const mode of ["sandbox", "page"] as const) {
  const query = mode === "page" ? "&mode=page" : "";

  /** Gives the demo a fixture under `name` (which the type is left out of, as a desktop often does). */
  async function show(page: Page, fixture: string, name = fixture): Promise<void> {
    await page.goto(`./?lang=en${query}`);
    await page.getByTestId("file-input").setInputFiles({ name, mimeType: "", buffer: fs.readFileSync(path.join(FIXTURES, fixture)) });
  }

  async function picture(page: Page, what = "the file"): Promise<Pixels> {
    const body = page.locator(".demo-frame .exav-viewer-body");
    await expect(body, what).toHaveAttribute("data-phase", "ready");
    const surface: Locator = page.locator(".demo-frame .exav-viewer-surface");
    // The surface is drawn once the canvas has its pixels: read until two screenshots agree.
    let last = decodePng(await surface.screenshot({ animations: "disabled" }));
    for (let i = 0; i < 20; i++) {
      await page.waitForTimeout(150);
      const next = decodePng(await surface.screenshot({ animations: "disabled" }));
      if (next.data.length === last.data.length && next.data.every((v, k) => v === last.data[k])) return next;
      last = next;
    }
    return last;
  }

  test.describe(mode, () => {
    test("a CR2 shows its largest preview, as it was stored", async ({ page }) => {
      await show(page, "canon.cr2", "IMG_0001.CR2");
      const p = layout(await picture(page));
      expect(p.order).toEqual(["red", "green", "blue", "yellow"]);
      // 96 by 64: the JPEG of the first directory, not the thumbnail or the RGB preview.
      expect(p.width / p.height).toBeCloseTo(96 / 64, 1);
    });

    test("a RAF is turned by the orientation its JPEG carries", async ({ page }) => {
      await show(page, "fujifilm-o6.raf", "DSCF0001.RAF");
      const p = layout(await picture(page));
      expect(p.order).toEqual(["blue", "red", "yellow", "green"]);
      // 64 by 48 stored, turned a quarter.
      expect(p.width / p.height).toBeCloseTo(48 / 64, 1);
    });

    test("a CR3 is turned by the orientation of its metadata boxes", async ({ page }) => {
      await show(page, "canon-o8.cr3", "IMG_0002.CR3");
      const p = layout(await picture(page));
      expect(p.order).toEqual(["green", "yellow", "red", "blue"]);
      // The full-size JPEG, 128 by 96 stored, turned a quarter.
      expect(p.width / p.height).toBeCloseTo(96 / 128, 1);
    });

    test("every family opens: the preview is where the maker keeps it", async ({ page }) => {
      const files: [string, string][] = [
        ["preview-jpeg.dng", "a.DNG"],
        ["preview-rgb.dng", "b.dng"],
        ["nikon.nef", "DSC_0001.NEF"],
        ["sony.arw", "DSC00001.ARW"],
        ["pentax.pef", "IMGP0001.PEF"],
        ["samsung.srw", "SAM_0001.SRW"],
        ["hasselblad.3fr", "B0001.3FR"],
        ["kodak16-be.dcr", "K0001.DCR"],
        ["olympus.orf", "P1000001.ORF"],
        ["panasonic.rw2", "P1000001.RW2"],
        ["phaseone.iiq", "C0001.IIQ"],
        ["sigma.x3f", "SDIM0001.X3F"],
        ["canon.crw", "IMG_0003.CRW"],
      ];
      for (const [fixture, name] of files) {
        await show(page, fixture, name);
        const p = layout(await picture(page, name));
        // Turned or not, the four quadrants sit in the corners of a rectangle.
        expect(p.order.length, name).toBe(4);
      }
    });

    test("a RAW file is a RAW file whatever its name says", async ({ page }) => {
      // The name says nothing, the type says RAW: the bytes of an Olympus file.
      await page.goto(`./?lang=en${query}`);
      await page.getByTestId("file-input").setInputFiles({ name: "photo", mimeType: "image/x-olympus-orf", buffer: fs.readFileSync(path.join(FIXTURES, "olympus-be.orf")) });
      expect(layout(await picture(page)).order).toEqual(["red", "green", "blue", "yellow"]);
    });

    test("a RAW file with no preview says so", async ({ page }) => {
      await show(page, "no-preview.dng", "phone.dng");
      await expect(page.locator(".demo-frame .exav-viewer-body")).toHaveAttribute("data-phase", "error");
      await expect(page.locator(".exav-viewer-status-error")).toHaveText("This camera RAW file holds no preview to show.");
    });

    test("a damaged RAW file is an image that could not be shown", async ({ page }) => {
      // The first directory only: no preview in it, and the JPEG streams are cut.
      const raw = fs.readFileSync(path.join(FIXTURES, "nikon.nef"));
      await page.goto(`./?lang=en${query}`);
      await page.getByTestId("file-input").setInputFiles({ name: "cut.NEF", mimeType: "", buffer: raw.subarray(0, 40) });
      await expect(page.locator(".demo-frame .exav-viewer-body")).toHaveAttribute("data-phase", "error");
      await expect(page.locator(".exav-viewer-status-error")).toHaveText("The image could not be shown.");
    });
  });
}
