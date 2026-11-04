// A quote found in a PDF's text and highlighted (`ViewerFile.highlights`),
// in the sandboxed frame and in the page: report.pdf, as
// fixtures/make-samples.mjs writes it, has "Replace the gutter joint." on its
// third page. The demo highlights the quote of `?highlight=`.
import { expect, test } from "@playwright/test";

import { failOnViolations } from "./csp.js";
import { openSample } from "./samples.js";

failOnViolations();

for (const mode of ["sandbox", "page"] as const) {
  test(`report.pdf, ${mode}: the quote's box lies on its line of the third page, which is scrolled to`, async ({ page }) => {
    // Written otherwise than in the file: case, spaces, a hyphen.
    await openSample(page, "report.pdf", { highlight: "replace THE gutter-joint", ...(mode === "page" && { mode }) });
    await expect(page.locator(".demo-frame .exav-viewer-body")).toHaveAttribute("data-phase", "ready");
    const root = mode === "sandbox" ? page.frameLocator(".demo-frame iframe.exav-viewer-sandbox") : page.locator(".demo-frame");
    const thirdPage = root.locator('.exav-viewer-pdf-page[data-page="2"]');
    const mark = thirdPage.locator(".exav-viewer-highlight");
    await expect(mark).toHaveAttribute("aria-label", "replace THE gutter-joint");
    await expect(mark).toHaveClass(/exav-viewer-highlight-current/);
    const box = mark.locator(".exav-viewer-highlight-box");
    await expect(box).toHaveCount(1);
    // The text layer's run for that line, which pdf.js places over the drawn glyphs.
    const run = thirdPage.locator(".exav-viewer-pdf-text span", { hasText: "Replace the gutter joint." });
    await expect(run).toBeVisible();
    const b = (await box.boundingBox())!;
    const r = (await run.boundingBox())!;
    // The run's start, and most of its width: "Replace the gutter joint" without the full stop.
    expect(Math.abs(b.x - r.x)).toBeLessThan(2);
    expect(b.width).toBeGreaterThan(r.width * 0.85);
    expect(b.width).toBeLessThan(r.width);
    // The same line: most of the run's height covered, no more than a line's height.
    const overlap = Math.min(b.y + b.height, r.y + r.height) - Math.max(b.y, r.y);
    expect(overlap).toBeGreaterThan(r.height * 0.7);
    expect(b.height).toBeLessThan(r.height * 1.5);
    // Brought into view: within the scroller, which was scrolled down to the third page.
    const scroller = root.locator(".exav-viewer-pdf-scroller");
    await expect.poll(() => scroller.evaluate((s) => s.scrollTop)).toBeGreaterThan(0);
    const view = (await scroller.boundingBox())!;
    await expect
      .poll(async () => {
        const now = (await box.boundingBox())!;
        return now.y > view.y && now.y + now.height < view.y + view.height;
      })
      .toBe(true);
    // The text under the box is what the pointer reaches, to select it.
    const hit = await run.evaluate((el) => {
      const r = el.getBoundingClientRect();
      return document.elementFromPoint(r.x + 5, r.y + r.height / 2) === el;
    });
    expect(hit).toBe(true);
  });
}
