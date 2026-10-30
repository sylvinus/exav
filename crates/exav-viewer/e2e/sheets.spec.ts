// Spreadsheets converted by exav-render's `sheets` (exav_viewer_sheets.wasm),
// shown by the XLSX plugin, in the page and in the sandboxed frame: an Excel
// 97 workbook, an OpenDocument spreadsheet, Numbers documents, and an XML
// Spreadsheet, an HTML table and a SYLK file named .xls, with nothing of an
// external converter fetched.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { expect, test, type Page } from "@playwright/test";

import { failOnViolations, screenshotting } from "./csp.js";
import { decodePng, find } from "./pixels.js";

/** exav-render's `sheets` fixtures (see their README for where they come from). */
const FIXTURES = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "exav-render", "tests", "fixtures", "office", "sheets");

failOnViolations();

const ink = (r: number, g: number, b: number) => r < 160 && g < 160 && b < 160;

for (const mode of ["sandbox", "page"] as const) {
  test.describe(mode, () => {
    /** Opens a fixture; returns the URLs the page and its frames fetched for it. */
    async function open(page: Page, name: string, as = name): Promise<string[]> {
      const fetched: string[] = [];
      page.on("request", (r) => fetched.push(r.url()));
      await page.goto(`./?${new URLSearchParams({ lang: "en", ...(mode === "page" && { mode }) })}`);
      fetched.length = 0;
      await page.getByTestId("file-input").setInputFiles({ name: as, mimeType: "", buffer: fs.readFileSync(path.join(FIXTURES, name)) });
      await expect(page.locator(".demo-frame .exav-viewer-body")).toHaveAttribute("data-phase", "ready", { timeout: 60_000 });
      return fetched;
    }

    /** Dark pixels on the surface: the sheet is drawn, not a blank canvas. */
    const drawn = async (page: Page) => {
      screenshotting(page);
      return find(decodePng(await page.locator(".demo-frame .exav-viewer-surface").screenshot()), ink).count;
    };

    const byExav = (fetched: string[]) => {
      expect(fetched.some((u) => /exav_viewer_sheets_bg[^/]*\.wasm/.test(u))).toBe(true);
      expect(fetched.filter((u) => /converters\/|exav_office_/.test(u))).toEqual([]);
    };

    test("an Excel 97 workbook is converted and shown with its two sheets", async ({ page }) => {
      byExav(await open(page, "sample.xls"));
      await expect(page.locator(".exav-viewer-sheet-tab")).toHaveText(["Budget", "Notes"]);
      await expect.poll(() => drawn(page)).toBeGreaterThan(200);
      await page.locator(".exav-viewer-sheet-tab", { hasText: "Notes" }).click();
      await expect(page.locator(".exav-viewer-sheet-tab", { hasText: "Notes" })).toHaveAttribute("aria-selected", "true");
    });

    test("an OpenDocument spreadsheet is converted and shown with its two sheets", async ({ page }) => {
      byExav(await open(page, "sample.ods"));
      await expect(page.locator(".exav-viewer-sheet-tab")).toHaveText(["Budget", "Notes"]);
      await expect.poll(() => drawn(page)).toBeGreaterThan(200);
    });

    test("a Numbers document is converted and its table shown", async ({ page }) => {
      byExav(await open(page, "sample.numbers"));
      await expect.poll(() => drawn(page)).toBeGreaterThan(100);
    });

    test("a Numbers '09 document is converted with its tables as sheets", async ({ page }) => {
      byExav(await open(page, "numbers09.numbers"));
      await expect(page.locator(".exav-viewer-sheet-tab")).toHaveText(["Checking - Account Categories", "Checking - Transactions", "Second sheet"]);
      await expect.poll(() => drawn(page)).toBeGreaterThan(200);
    });

    // A workbook of one sheet shows no tabs.
    for (const [name, tabs] of [
      ["sample-2003.xml", ["Budget", "Notes"]],
      ["sample.html", []],
      ["sample.slk", []],
    ] as const) {
      test(`${name} saved as .xls is converted by exav-render's sheets`, async ({ page }) => {
        byExav(await open(page, name, "budget.xls"));
        await expect(page.locator(".exav-viewer-sheet-tab")).toHaveText([...tabs]);
        await expect.poll(() => drawn(page)).toBeGreaterThan(200);
      });
    }
  });
}
