// The buttons over the viewer's corner: the panel's toggle sits with the zoom
// buttons, and a touch screen keeps it while the buttons for a mouse go.
import { expect, test, type Page } from "@playwright/test";

import { openSample } from "./samples.js";

async function open(page: Page, mode: "page" | "sandbox") {
  await openSample(page, "plan.dwg", mode === "page" ? { mode } : {});
  await expect(page.locator(".demo-frame .exav-viewer-body")).toHaveAttribute("data-phase", "ready");
}

for (const mode of ["sandbox", "page"] as const) {
  test.describe(mode, () => {
    test("the panel toggle folds and unfolds the rail, and stays where the zoom buttons are", async ({ page }) => {
      await open(page, mode);
      const tools = page.locator(".demo-frame .exav-viewer-tools");
      const rail = page.locator(".demo-frame .exav-viewer-rail");
      await expect(rail).toBeVisible();
      const hide = tools.getByRole("button", { name: "Hide the panel" });
      await expect(hide).toBeVisible();
      // Next to the zoom buttons, on their right.
      const zoom = (await tools.getByRole("button", { name: "Zoom in" }).boundingBox())!;
      const toggle = (await hide.boundingBox())!;
      expect(toggle.x).toBeGreaterThan(zoom.x);
      expect(Math.abs(toggle.y - zoom.y)).toBeLessThan(2);
      // In a group with full screen, to its right.
      const full = (await tools.getByRole("button", { name: "Full screen" }).boundingBox())!;
      expect(full.x).toBeLessThan(toggle.x);
      expect(Math.abs(full.x - toggle.x)).toBeLessThan(60);
      await expect(tools.locator(".exav-viewer-tool-end button")).toHaveCount(2);
      await hide.click();
      await expect(rail).toHaveCount(0);
      await tools.getByRole("button", { name: "Drawing" }).click();
      await expect(rail).toBeVisible();
    });

    test.describe("a touch screen", () => {
      test.use({ hasTouch: true, isMobile: true });
      test("keeps the panel toggle and drops the buttons for a mouse", async ({ page }) => {
        await open(page, mode);
        const tools = page.locator(".demo-frame .exav-viewer-tools");
        await expect(tools.getByRole("button", { name: /Hide the panel|Drawing/ })).toBeVisible();
        await expect(tools.getByRole("button", { name: "Zoom in" })).toBeHidden();
        await expect(tools.getByRole("button", { name: "Full screen" })).toBeHidden();
      });

      test("shows no empty group when there is no panel", async ({ page }) => {
        await openSample(page, "notes.docx", mode === "page" ? { mode } : {});
        await expect(page.locator(".demo-frame .exav-viewer-body")).toHaveAttribute("data-phase", "ready");
        await expect(page.locator(".demo-frame .exav-viewer-tools .exav-viewer-tool-end")).toBeHidden();
      });
    });
  });
}
