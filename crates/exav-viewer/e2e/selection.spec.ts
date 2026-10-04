// Selecting a document's text with the mouse, and copying a spreadsheet's
// cells, in each browser Playwright runs, in the sandboxed frame and in the
// page. The files are report.pdf, notes.docx, visit.pptx and quote.xlsx, as
// fixtures/make-samples.mjs writes them.
import { expect, test, type FrameLocator, type Locator, type Page } from "@playwright/test";

import { openSample } from "./samples.js";

interface Doc {
  file: string;
  /** A line of its first page, as written. */
  line: string;
  /** Where that line starts and ends, and its page. */
  find(root: FrameLocator | Locator): { start: Locator; end: Locator; sheet: Locator; ready: Locator };
}

const DOCS: Doc[] = [
  {
    file: "report.pdf",
    line: "The north facade, the roof and the stairwell were inspected.",
    find: (root) => {
      const run = root.locator(".exv-pdf-text span", { hasText: "The north facade" });
      // Laid out: its last element comes once every run is placed.
      return { start: run, end: run, sheet: root.locator(".exv-pdf-page").first(), ready: root.locator(".exv-pdf-text-end").first() };
    },
  },
  {
    file: "notes.docx",
    line: "1. The schedule is confirmed for the spring.",
    find: (root) => {
      // One run per word.
      const runs = root.locator("[data-ooxml-selection-run]");
      const start = runs.filter({ hasText: /^1\. $/ });
      return { start, end: runs.filter({ hasText: /^spring\.$/ }), sheet: root.locator('[data-ooxml-selection-surface][data-page-index="0"]'), ready: start };
    },
  },
  {
    file: "visit.pptx",
    line: "Roof inspected.",
    find: (root) => {
      // One run per run of the slide.
      const run = root.locator("[data-ooxml-selection-run]", { hasText: /^Roof inspected\.$/ });
      return { start: run, end: run, sheet: root.locator("[data-ooxml-selection-surface]").first(), ready: run };
    },
  },
];

// A spreadsheet has no text to select: its cells are, and Ctrl+C copies them.
for (const mode of ["sandbox", "page"] as const) {
  test(`quote.xlsx, ${mode}: cells dragged across copy as tab-separated rows, and paste so`, async ({ page, context, browserName }) => {
    // What Chromium grants a page on a key press, which its headless mode does not.
    if (browserName === "chromium") await context.grantPermissions(["clipboard-write"]);
    await openSample(page, "quote.xlsx", mode === "page" ? { mode } : {});
    await expect(page.locator(".demo-frame .exv-body")).toHaveAttribute("data-phase", "ready");
    await page.waitForTimeout(500);
    // Something else on the clipboard first: the browser keeps it from test to test.
    const paste = page.locator("#paste");
    await page.evaluate(() => {
      const box = document.createElement("textarea");
      box.id = "paste";
      box.value = "before";
      document.body.append(box);
    });
    await paste.selectText();
    await page.keyboard.press("ControlOrMeta+c");
    // From A1 to B3: past the row numbers and the column letters, then two columns across and three rows down.
    const s = (await page.locator(".demo-frame .exv-surface").boundingBox())!;
    await page.mouse.move(s.x + 80, s.y + 35);
    await page.mouse.down();
    await page.mouse.move(s.x + 300, s.y + 80, { steps: 8 });
    await page.mouse.up();
    // The key goes to the sheet, which the press has taken the focus to.
    await expect.poll(() => page.evaluate(() => document.activeElement?.id)).not.toBe("paste");
    await page.keyboard.press("ControlOrMeta+c");
    // Pasted into the page around the viewer, as a person would.
    await paste.fill("");
    await paste.focus();
    await page.keyboard.press("ControlOrMeta+v");
    await expect(paste).toHaveValue("Item\tQuantity\nRender\t120\nGutter joint\t1");
  });
}

for (const doc of DOCS) {
  for (const mode of ["sandbox", "page"] as const) {
    test.describe(`${doc.file}, ${mode}`, () => {
      async function open(page: Page) {
        await openSample(page, doc.file, mode === "page" ? { mode } : {});
        await expect(page.locator(".demo-frame .exv-body")).toHaveAttribute("data-phase", "ready");
        const root = mode === "sandbox" ? page.frameLocator(".demo-frame iframe.exv-sandbox") : page.locator(".demo-frame");
        const found = doc.find(root);
        await expect(found.start).toHaveCount(1);
        await expect(found.ready).toBeAttached();
        return found;
      }

      const selection = (inside: Locator) => inside.evaluate((el) => el.ownerDocument.getSelection()?.toString() ?? "");

      test("a line dragged across, from its first letter to its last, is selected as written", async ({ page }) => {
        const { start, end } = await open(page);
        const a = (await start.boundingBox())!;
        const b = (await end.boundingBox())!;
        const y = a.y + a.height / 2;
        await page.mouse.move(a.x + 1, y);
        await page.mouse.down();
        await page.mouse.move((a.x + b.x + b.width) / 2, y, { steps: 5 });
        await page.mouse.move(b.x + b.width - 1, y, { steps: 5 });
        await page.mouse.up();
        expect(await selection(start)).toBe(doc.line);
      });

      test("a selection dragged on into the blank beside the text keeps its start", async ({ page }) => {
        const { start, sheet } = await open(page);
        const a = (await start.boundingBox())!;
        const s = (await sheet.boundingBox())!;
        await page.mouse.move(a.x + 1, a.y + a.height / 2);
        await page.mouse.down();
        // Three lines down, at the right of the page, where there is no text.
        await page.mouse.move(s.x + s.width - 20, a.y + 3 * a.height * 1.6, { steps: 10 });
        const during = await selection(start);
        await page.mouse.up();
        // Not the page's top, as browsers otherwise jump to.
        expect(during.startsWith(doc.line.slice(0, 5))).toBe(true);
      });
    });
  }
}
