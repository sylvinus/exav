// What a session leaves behind once the next file replaces it. A browser
// holds about sixteen WebGL contexts and then starts dropping the oldest, and
// a worker nobody terminates keeps its wasm memory: walking a folder of
// drawings with the arrow keys must not accumulate either.
import { expect, test, type Page } from "@playwright/test";

import { openSample, pick } from "./samples.js";

declare global {
  interface Window {
    live: () => { workers: number; contexts: number };
  }
}

test.beforeEach(async ({ page }) => {
  // Counted from outside the package: every worker built and not yet
  // terminated, and every WebGL context not yet lost.
  await page.addInitScript(() => {
    const workers = new Set<Worker>();
    const Native = window.Worker;
    window.Worker = class extends Native {
      constructor(url: string | URL, options?: WorkerOptions) {
        super(url, options);
        workers.add(this);
      }
      override terminate() {
        workers.delete(this);
        super.terminate();
      }
    };
    const contexts: (WebGLRenderingContext | WebGL2RenderingContext)[] = [];
    const getContext = HTMLCanvasElement.prototype.getContext;
    HTMLCanvasElement.prototype.getContext = function (this: HTMLCanvasElement, type: string, ...rest: unknown[]) {
      const context = (getContext as (...a: unknown[]) => unknown).call(this, type, ...rest);
      if (context && (type === "webgl" || type === "webgl2")) contexts.push(context as WebGL2RenderingContext);
      return context;
    } as typeof getContext;
    window.live = () => ({ workers: workers.size, contexts: contexts.filter((c) => !c.isContextLost()).length });
  });
});

async function show(page: Page, button: RegExp) {
  await page.getByRole("button", { name: button }).first().click();
  await expect(page.locator(".demo-frame .exv-body")).toHaveAttribute("data-phase", "ready");
}

const ROUND = [/plan\.dwg/, /house\.stl/, /plan\.dxf/, /house\.ifc/, /landscape\.tif/];

test("walking through drawings and models leaves one context and no stray worker", async ({ page }) => {
  test.setTimeout(240_000);
  // The engines in the page: in the sandboxed frame, a file's workers and
  // contexts go with its frame (frame.spec.ts).
  await openSample(page, "report.pdf", { mode: "page" });
  await expect(page.locator(".demo-frame .exv-body")).toHaveAttribute("data-phase", "ready");
  // Opened by the user, the files are listed in the sidebar, one button each.
  await pick(page, "plan.dwg", "house.stl", "plan.dxf", "house.ifc", "landscape.tif", "report.pdf");
  await expect(page.locator(".demo-frame .exv-body")).toHaveAttribute("data-phase", "ready");

  // One round first: each engine's lasting pieces (pdf.js's worker, which
  // every PDF shares) are then in place.
  for (const b of ROUND) await show(page, b);
  await show(page, /report\.pdf/);
  const after1 = await page.evaluate(() => window.live());
  // A PDF has no WebGL; the drawings and models before it gave theirs back.
  expect(after1.contexts).toBe(0);

  for (let i = 0; i < 4; i++) for (const b of ROUND) await show(page, b);
  await show(page, /plan\.dwg/);
  const during = await page.evaluate(() => window.live());
  expect(during.contexts).toBe(1);
  await show(page, /report\.pdf/);
  const after5 = await page.evaluate(() => window.live());
  expect(after5).toEqual(after1);
});
