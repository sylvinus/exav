// The IFC and STL engine's worker: closing a model while it is still being
// read stops the worker then, not when it would have finished. The worker is
// made to never answer (its messages are held back), as a large or hostile
// file would keep it busy.
import { expect, test } from "@playwright/test";

import { failOnViolations } from "./csp.js";
import { openSample, pick } from "./samples.js";

declare global {
  interface Window {
    modelWorkers: () => { started: number; live: number };
  }
}

failOnViolations();

test.beforeEach(async ({ page }) => {
  await page.addInitScript(() => {
    let started = 0;
    const live = new Set<Worker>();
    const Native = window.Worker;
    window.Worker = class extends Native {
      constructor(url: string | URL, options?: WorkerOptions) {
        super(url, options);
        if (!String(url).includes("model.worker")) return;
        started += 1;
        live.add(this);
        // The request never reaches the engine: it stays busy for good.
        this.postMessage = () => {};
      }
      override terminate() {
        live.delete(this);
        super.terminate();
      }
    };
    window.modelWorkers = () => ({ started, live: live.size });
  });
});

for (const file of ["house.ifc", "house.stl"]) {
  test(`closing ${file} while it is read stops its worker`, async ({ page }) => {
    await openSample(page, file, { mode: "page" });
    await expect.poll(() => page.evaluate(() => window.modelWorkers().live)).toBe(1);
    await expect(page.locator(".demo-frame .exv-body")).toHaveAttribute("data-phase", "loading");
    // Another file, as the user picks one.
    await pick(page, "report.pdf");
    await expect(page.locator(".demo-frame .exv-body")).toHaveAttribute("data-phase", "ready");
    expect(await page.evaluate(() => window.modelWorkers())).toEqual({ started: 1, live: 0 });
  });
}
