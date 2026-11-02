// The external converter's contract, with a converter of its own
// (fixtures/fake-converter.js, served at /e2e/fake-converter.js): a module
// loaded from a URL, in the page and in the sandboxed frame, whose PDF is shown
// by the viewer's PDF plugin, with its progress, its errors, its abort, the
// timeout and the memory option. A format no converter of the package reads
// ends in the needs-converter error where none is set.
import { expect, test, type Page } from "@playwright/test";

import { failOnViolations } from "./csp.js";

failOnViolations();

const FAKE = "/e2e/fake-converter.js";

for (const mode of ["sandbox", "page"] as const) {
  test.describe(mode, () => {
    /** Opens `text` as a Visio file, which only an external converter reads. */
    async function open(page: Page, text: string, params: Record<string, string> = {}, name = "plan.vsd") {
      await page.goto(`./?${new URLSearchParams({ lang: "en", ...params, ...(mode === "page" && { mode }) })}`);
      await page.getByTestId("file-input").setInputFiles({ name, mimeType: "", buffer: Buffer.from(text) });
    }

    const body = (page: Page) => page.locator(".demo-frame .exav-viewer-body");
    const engine = (page: Page) => (mode === "sandbox" ? page.frameLocator(".demo-frame iframe.exav-viewer-sandbox") : page.locator(".demo-frame"));

    test("a format only an external converter reads is converted by it and shown as PDF", async ({ page }) => {
      await open(page, "hello visio", { externalConverter: FAKE });
      await expect(body(page)).toHaveAttribute("data-phase", "ready", { timeout: 30_000 });
      await expect(engine(page).locator(".exav-viewer-pdf-page")).toHaveCount(1);
      // The hint, the file's size, and no memory option.
      await expect(engine(page).locator(".exav-viewer-pdf-text span", { hasText: "fake converter: visio, 11 bytes, memory unset" })).toBeVisible();
    });

    test("is handed the memory option the host set", async ({ page }) => {
      await open(page, "hello", { externalConverter: FAKE, maxMemory: "5000000" });
      await expect(engine(page).locator(".exav-viewer-pdf-text span", { hasText: "visio, 5 bytes, memory 5000000" })).toBeVisible({ timeout: 30_000 });
    });

    test("shows the converter's steps while it works", async ({ page }) => {
      await page.goto(`./?${new URLSearchParams({ lang: "en", externalConverter: FAKE, ...(mode === "page" && { mode }) })}`);
      await page.evaluate(() => {
        const seen = new Set<string>();
        (window as unknown as { steps: Set<string> }).steps = seen;
        new MutationObserver(() => {
          const status = document.querySelector(".demo-frame .exav-viewer-status");
          const text = status?.querySelector("p")?.textContent;
          if (text) seen.add(`${text}${status!.querySelector('[role="progressbar"]') ? " [bar]" : ""}`);
        }).observe(document.body, { subtree: true, childList: true, characterData: true, attributes: true });
      });
      await page.getByTestId("file-input").setInputFiles({ name: "plan.vsd", mimeType: "", buffer: Buffer.from("hello") });
      await expect(body(page)).toHaveAttribute("data-phase", "ready", { timeout: 30_000 });
      const steps = await page.evaluate(() => [...(window as unknown as { steps: Set<string> }).steps]);
      expect(steps).toContain("Downloading the viewer… [bar]");
      expect(steps).toContain("Starting the viewer…");
      expect(steps).toContain("Converting the document… [bar]");
    });

    test("a converter that fails ends in the document's error, and the viewer goes on", async ({ page }) => {
      await open(page, "FAIL please", { externalConverter: FAKE });
      await expect(body(page)).toHaveAttribute("data-phase", "error", { timeout: 30_000 });
      await expect(page.locator(".demo-frame .exav-viewer-status")).toContainText("This document could not be shown.");
      // The next file opens.
      await page.getByTestId("file-input").setInputFiles({ name: "plan.vsd", mimeType: "", buffer: Buffer.from("fine") });
      await expect(body(page)).toHaveAttribute("data-phase", "ready", { timeout: 30_000 });
    });

    test("a converter that never answers is stopped at the timeout, even if it ignores its signal", async ({ page }) => {
      await open(page, "DEAF forever", { externalConverter: FAKE, timeoutMs: "700" });
      await expect(body(page)).toHaveAttribute("data-phase", "error", { timeout: 30_000 });
    });

    test("a converter that answers what the contract does not allow ends in the document's error", async ({ page }) => {
      await open(page, "BAD answer", { externalConverter: FAKE });
      await expect(body(page)).toHaveAttribute("data-phase", "error", { timeout: 30_000 });
    });

    test("without an external converter the format ends in the needs-converter error", async ({ page }) => {
      test.skip(!!process.env.EXAV_EXTERNAL_CONVERTER, "the demo was built with a default external converter");
      await open(page, "hello visio");
      await expect(body(page)).toHaveAttribute("data-phase", "error", { timeout: 30_000 });
      await expect(page.locator(".demo-frame .exav-viewer-status")).toContainText("only be shown with a converter that is not installed here");
    });

    test("with converter: external, a file the package reads goes to the external converter too", async ({ page }) => {
      await open(page, "not really a spreadsheet", { externalConverter: FAKE, converter: "external" }, "table.xls");
      await expect(engine(page).locator(".exav-viewer-pdf-text span", { hasText: "fake converter: xls," })).toBeVisible({ timeout: 30_000 });
    });
  });
}

test("closing the file aborts the converter's signal (in the page)", async ({ page }) => {
  await page.goto(`./?${new URLSearchParams({ lang: "en", externalConverter: FAKE, mode: "page" })}`);
  await page.getByTestId("file-input").setInputFiles({ name: "plan.vsd", mimeType: "", buffer: Buffer.from("HANG forever") });
  // It is waiting for its signal; open another file in its place.
  await expect.poll(() => page.evaluate(() => (window as unknown as { fakeConverterCalled?: number }).fakeConverterCalled ?? 0), { timeout: 10_000 }).toBe(1);
  expect(await page.evaluate(() => (window as unknown as { fakeConverterAborted?: number }).fakeConverterAborted ?? 0)).toBe(0);
  await page.getByTestId("file-input").setInputFiles({ name: "note.txt", mimeType: "text/plain", buffer: Buffer.from("plain") });
  await expect.poll(() => page.evaluate(() => (window as unknown as { fakeConverterAborted?: number }).fakeConverterAborted ?? 0), { timeout: 10_000 }).toBe(1);
});
