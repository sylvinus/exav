// Text documents converted by exav-render's `docs` (exav_viewer_docs.wasm)
// when the page asks for `converter: "exav"` (`?converter=exav` in the demo),
// shown by the DOCX plugin, in the page and in the sandboxed frame: a Word 97
// file, an OpenDocument text, a flat one and an RTF, with nothing of an
// external converter fetched.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { expect, test, type Page } from "@playwright/test";

import { failOnViolations, screenshotting } from "./csp.js";
import { decodePng, find } from "./pixels.js";

/** exav-render's `docs` fixtures (see their README for where they come from). */
const FIXTURES = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "exav-render", "tests", "fixtures", "office", "docs");

failOnViolations();

const ink = (r: number, g: number, b: number) => r < 160 && g < 160 && b < 160;

for (const mode of ["sandbox", "page"] as const) {
  test.describe(mode, () => {
    /** Opens a fixture; returns the URLs the page and its frames fetched for it. */
    async function open(page: Page, name: string): Promise<string[]> {
      const fetched: string[] = [];
      page.on("request", (r) => fetched.push(r.url()));
      await page.goto(`./?${new URLSearchParams({ lang: "en", converter: "exav", ...(mode === "page" && { mode }) })}`);
      fetched.length = 0;
      await page.getByTestId("file-input").setInputFiles({ name, mimeType: "", buffer: fs.readFileSync(path.join(FIXTURES, name)) });
      await expect(page.locator(".demo-frame .exav-viewer-body")).toHaveAttribute("data-phase", "ready", { timeout: 60_000 });
      return fetched;
    }

    /** Dark pixels on the surface: the page is drawn, not a blank canvas. */
    const drawn = async (page: Page) => {
      screenshotting(page);
      return find(decodePng(await page.locator(".demo-frame .exav-viewer-surface").screenshot()), ink).count;
    };

    const byExav = (fetched: string[]) => {
      expect(fetched.some((u) => /exav_viewer_docs_bg[^/]*\.wasm/.test(u))).toBe(true);
      expect(fetched.filter((u) => /converters\/|exav_office_/.test(u))).toEqual([]);
    };

    for (const name of ["sample.doc", "sample.odt", "sample.fodt", "sample.rtf"]) {
      test(`${name} is converted and its page drawn`, async ({ page }) => {
        byExav(await open(page, name));
        await expect.poll(() => drawn(page)).toBeGreaterThan(300);
      });
    }
  });
}
