// The converted Office formats of `@exav/viewer/office` (`rtf()`, `doc()`...)
// with a real external converter, shown by the viewer's PDF and XLSX plugins,
// in the page and in the sandboxed frame. The converter is a package that
// exports the contract (see `ExternalConverter`) and carries its fixtures in
// `tests/fixtures`: name it in EXAV_EXTERNAL_CONVERTER when you build the demo
// (`EXAV_EXTERNAL_CONVERTER=<package> npm run demo:build`) and run these tests.
// Skipped, saying why, when it is not set or the demo was built without it;
// external.spec.ts checks the contract itself with a converter of its own.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { expect, test, type FrameLocator, type Locator, type Page } from "@playwright/test";

import { failOnViolations, screenshotting } from "./csp.js";
import { decodePng, find } from "./pixels.js";

const CONVERTER = process.env.EXAV_EXTERNAL_CONVERTER;

/** The converter's own fixtures: a short letter, a two-slide presentation, a two-page drawing, a small table, and Keynote, Numbers and CorelDRAW files. */
const FIXTURES = CONVERTER ? path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "node_modules", ...CONVERTER.split("/"), "tests", "fixtures") : "";

failOnViolations();

test.beforeEach(async ({ page }) => {
  test.skip(!CONVERTER, "no real external converter: set EXAV_EXTERNAL_CONVERTER to an installed converter package, and build the demo with it");
  await page.goto("./?lang=en");
  const manifest = await page.evaluate(() => fetch("./exav-viewer/manifest.json").then((r) => r.json()));
  test.skip(!manifest.converters?.[CONVERTER!], `the demo was built without ${CONVERTER}: build it with EXAV_EXTERNAL_CONVERTER=${CONVERTER}`);
});

const ink = (r: number, g: number, b: number) => r < 160 && g < 160 && b < 160;

for (const mode of ["sandbox", "page"] as const) {
  async function open(page: Page, name: string, as = name, params: Record<string, string> = {}) {
    await page.goto(`./?${new URLSearchParams({ lang: "en", ...params, ...(mode === "page" && { mode }) })}`);
    await page.getByTestId("file-input").setInputFiles({ name: as, mimeType: "", buffer: fs.readFileSync(path.join(FIXTURES, name)) });
    await expect(page.locator(".demo-frame .exav-viewer-body")).toHaveAttribute("data-phase", "ready", { timeout: 60_000 });
  }

  /** Dark pixels on the surface: the document is drawn, not a blank page. */
  const drawn = async (page: Page) => {
    screenshotting(page);
    return find(decodePng(await page.locator(".demo-frame .exav-viewer-surface").screenshot()), ink).count;
  };

  /** What the engine put on screen: in the frame's document, or in the page's. */
  const engine = (page: Page): FrameLocator | Locator =>
    mode === "sandbox" ? page.frameLocator(".demo-frame iframe.exav-viewer-sandbox") : page.locator(".demo-frame");

  test.describe(mode, () => {
    test("a Word 97 document is converted to PDF and shown page by page", async ({ page }) => {
      await open(page, "sample.doc");
      await expect(engine(page).locator(".exav-viewer-pdf-page")).toHaveCount(2);
      await expect.poll(() => drawn(page)).toBeGreaterThan(200);
    });

    test("a conversion shows its steps, with a bar for those it counts", async ({ page }) => {
      await page.goto(`./?${new URLSearchParams({ lang: "en", ...(mode === "page" && { mode }) })}`);
      // Every message the status overlay shows, and whether a bar came with it.
      await page.evaluate(() => {
        const seen = new Set<string>();
        (window as unknown as { steps: Set<string> }).steps = seen;
        new MutationObserver(() => {
          const status = document.querySelector(".demo-frame .exav-viewer-status");
          const text = status?.querySelector("p")?.textContent;
          if (text) seen.add(`${text}${status!.querySelector('[role="progressbar"]') ? " [bar]" : ""}`);
        }).observe(document.body, { subtree: true, childList: true, characterData: true, attributes: true });
      });
      await page.getByTestId("file-input").setInputFiles({ name: "sample.doc", mimeType: "", buffer: fs.readFileSync(path.join(FIXTURES, "sample.doc")) });
      await expect(page.locator(".demo-frame .exav-viewer-body")).toHaveAttribute("data-phase", "ready", { timeout: 60_000 });
      const steps = await page.evaluate(() => [...(window as unknown as { steps: Set<string> }).steps]);
      expect(steps).toContain("Downloading the viewer… [bar]");
      expect(steps).toContain("Starting the viewer…");
      expect(steps).toContain("Converting the document… [bar]");
    });

    test("an RTF saved under .doc is read as the RTF it is", async ({ page }) => {
      await open(page, "sample.rtf", "letter.doc");
      await expect(engine(page).locator(".exav-viewer-pdf-page")).toHaveCount(2);
    });

    test("an OpenDocument presentation is converted by exav-render's slides and shown as slides", async ({ page }) => {
      await open(page, "sample.odp");
      await expect(engine(page).locator(".exav-viewer-pdf-page")).toHaveCount(0);
      await expect(engine(page).locator("canvas").first()).toBeVisible();
      await expect.poll(() => drawn(page)).toBeGreaterThan(200);
    });

    test("a Keynote 1 presentation is converted by exav-render's slides and shown as slides, not as PDF", async ({ page }) => {
      await open(page, "keynote1.key");
      await expect(engine(page).locator(".exav-viewer-pdf-page")).toHaveCount(0);
      await expect(page.locator(".exav-viewer-pager span")).toHaveText("Slide 1 / 2");
      await expect.poll(() => drawn(page)).toBeGreaterThan(200);
    });

    test("an OpenDocument drawing is converted by exav-render's slides, a page to a slide, not to PDF", async ({ page }) => {
      await open(page, "sample.odg");
      await expect(engine(page).locator(".exav-viewer-pdf-page")).toHaveCount(0);
      await expect(page.locator(".exav-viewer-pager span")).toHaveText("Slide 1 / 2");
      await expect.poll(() => drawn(page)).toBeGreaterThan(50);
    });

    test("an OpenDocument drawing is converted to PDF, a page per page, when the external converter is asked for", async ({ page }) => {
      await open(page, "sample.odg", "sample.odg", { converter: "external" });
      await expect(engine(page).locator(".exav-viewer-pdf-page")).toHaveCount(2);
      await expect.poll(() => drawn(page)).toBeGreaterThan(50);
    });

    test("a CorelDRAW drawing is converted to PDF", async ({ page }) => {
      await open(page, "corel.cdr");
      await expect(engine(page).locator(".exav-viewer-pdf-page")).toHaveCount(1);
      await expect.poll(() => drawn(page)).toBeGreaterThan(200);
    });

    test("a Numbers spreadsheet is converted to XLSX and shown as a workbook", async ({ page }) => {
      await open(page, "sample.numbers");
      await expect(engine(page).locator("canvas").first()).toBeVisible();
      await expect.poll(() => drawn(page)).toBeGreaterThan(200);
    });

    test("an Excel 97 workbook is converted to XLSX and shown as a workbook", async ({ page }) => {
      await open(page, "sample.xls");
      await expect(engine(page).locator("canvas").first()).toBeVisible();
      await expect(engine(page).locator(".exav-viewer-pdf-page")).toHaveCount(0);
      await expect.poll(() => drawn(page)).toBeGreaterThan(200);
    });

    test("an XLSX named .xls is shown as it is", async ({ page }) => {
      await open(page, "sample.xlsx", "renamed.xls");
      await expect.poll(() => drawn(page)).toBeGreaterThan(200);
    });
  });
}
