// The demo carries the Content-Security-Policy the documentation recommends,
// and its frame the frame's: whatever the viewer does, no policy may have had
// to refuse it. Violations are reported from every document of the page, the
// sandboxed frames included, as they happen: a frame is gone by the time a
// test ends.
import { expect, test, type Page } from "@playwright/test";

const seen = new WeakMap<Page, string[]>();

/** The violations reported so far on `page`. */
export function violations(page: Page): string[] {
  return seen.get(page) ?? [];
}

/** Installs the collection before each test and fails the test on any violation. */
export function failOnViolations(): void {
  test.beforeEach(async ({ page }) => {
    const list: string[] = [];
    seen.set(page, list);
    await page.exposeBinding("exavReportViolation", ({ frame }, v: string) => void list.push(`${frame.url()}: ${v}`));
    await page.addInitScript(() => {
      document.addEventListener("securitypolicyviolation", (e) => {
        const report = (window as unknown as { exavReportViolation?: (v: string) => void }).exavReportViolation;
        report?.(`${e.effectiveDirective} ${e.blockedURI} ${e.sample}`.trim());
      });
    });
  });
  test.afterEach(async ({ page }) => {
    expect(violations(page)).toEqual([]);
  });
}
