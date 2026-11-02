// The demo carries the Content-Security-Policy the documentation recommends,
// and its frame the frame's: whatever the viewer does, no policy may have had
// to refuse it. Violations are reported from every document of the page, the
// sandboxed frames included, as they happen: a frame is gone by the time a
// test ends.
import { expect, test, type Page } from "@playwright/test";

const seen = new WeakMap<Page, string[]>();
const screenshots = new WeakMap<Page, number>();

/** The violations reported so far on `page`. */
export function violations(page: Page): string[] {
  return seen.get(page) ?? [];
}

/**
 * Says a screenshot of `page` is taken. In WebKit, Playwright adds a
 * `<style>` to every frame and removes it first, to sync animations
 * (`shouldToggleStyleSheetToSyncAnimations`, screenshotter.ts), whatever the
 * options: a sandboxed frame's policy refuses it, twice a screenshot.
 */
export function screenshotting(page: Page): void {
  screenshots.set(page, (screenshots.get(page) ?? 0) + 1);
}

const SCREENSHOT_STYLE = /\/frame\/index\.html: style-src-elem inline$/;

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
  test.afterEach(async ({ page, browserName }) => {
    let allowed = browserName === "webkit" ? 2 * (screenshots.get(page) ?? 0) : 0;
    expect(violations(page).filter((v) => !(allowed > 0 && SCREENSHOT_STYLE.test(v) && allowed--))).toEqual([]);
  });
}
