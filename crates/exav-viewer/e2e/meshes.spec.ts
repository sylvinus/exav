// OBJ, PLY and glTF in the demo, in the sandboxed frame and in the page. The
// samples are one house (fixtures/make-samples.mjs): the STL's thirty
// triangles, written as polygons in Y-up coordinates for OBJ and PLY, and as
// two nodes of a glTF, one moved. Drawn by the same camera, each silhouette is
// the STL's: a transform read wrongly, a polygon left out or a Z-up file
// stood on its side would change it.
import { expect, test, type FrameLocator, type Locator, type Page } from "@playwright/test";

import { failOnViolations } from "./csp.js";
import { decodePng, difference, find, type Pixels } from "./pixels.js";
import { openSample, pick } from "./samples.js";

failOnViolations();

/** The triangle count the session reports (`controllers.info`), once it has. */
const triangles =(page: Page) =>
  page.evaluate(() => (window as unknown as { exavDemo: { session(): { controllers: { get(): { info?: { get(): { triangles: number } } } } } | null } }).exavDemo.session()?.controllers.get().info?.get().triangles);

async function shot(target: Locator): Promise<Pixels> {
  const set = (value: string) => target.page().locator(".exav-viewer-tools").evaluateAll((els, v) => els.forEach((e) => ((e as HTMLElement).style.visibility = v)), value);
  await set("hidden");
  try {
    return decodePng(await target.screenshot({ animations: "disabled" }));
  } finally {
    await set("");
  }
}

async function settled(target: Locator): Promise<Pixels> {
  let last = await shot(target);
  for (let i = 0; i < 20; i++) {
    await target.page().waitForTimeout(150);
    const next = await shot(target);
    if (difference(last, next) === 0) return next;
    last = next;
  }
  return last;
}

/** What differs from the ground by more than a shadow does. */
function body(p: Pixels) {
  const [r0, g0, b0] = [p.data[0]!, p.data[1]!, p.data[2]!];
  return find(p, (r, g, b) => Math.max(Math.abs(r - r0), Math.abs(g - g0), Math.abs(b - b0)) > 70);
}

for (const mode of ["sandbox", "page"] as const) {
  const engine = (page: Page): FrameLocator | Locator => (mode === "sandbox" ? page.frameLocator(".demo-frame iframe.exav-viewer-sandbox") : page.locator(".demo-frame"));
  const phase = (page: Page) => page.locator(".demo-frame .exav-viewer-body");

  async function open(page: Page, name: string) {
    await openSample(page, name, mode === "page" ? { mode } : {});
    await expect(phase(page)).toHaveAttribute("data-phase", "ready");
  }

  test.describe(mode, () => {
    for (const name of ["house.obj", "house.ply", "house.glb", "house.gltf"]) {
      test(`${name} has the house's thirty triangles and the STL's silhouette`, async ({ page }) => {
        await open(page, "house.stl");
        const reference = body(await settled(engine(page).locator(".exav-viewer-model-canvas")));
        expect(reference.count).toBeGreaterThan(10_000);

        await pick(page, name);
        await expect(phase(page)).toHaveAttribute("data-phase", "ready");
        await expect.poll(() => triangles(page)).toBe(30);
        // No warning: nothing was left out.
        await expect(page.locator(".exav-viewer-warnings")).toHaveCount(0);
        const canvas = engine(page).locator(".exav-viewer-model-canvas");
        const pixels = await settled(canvas);
        const found = body(pixels);
        // Framed whole: not cut by an edge (the camera frames as it does an STL's).
        const box = found.box!;
        expect(box.minX).toBeGreaterThan(pixels.width * 0.03);
        expect(box.minY).toBeGreaterThan(pixels.height * 0.03);
        expect(box.maxX).toBeLessThan(pixels.width * 0.97);
        expect(box.maxY).toBeLessThan(pixels.height - 1);
        // The STL's silhouette, give or take the edge pixels (another colour tests differently against the ground).
        const ref = reference.box!;
        for (const k of ["minX", "minY", "maxX", "maxY"] as const) expect(Math.abs(box[k] - ref[k]), k).toBeLessThanOrEqual(6);
        expect(found.count).toBeGreaterThan(10_000);
      });
    }

    test("vertex colours and material colours show, and a file with none is grey", async ({ page }) => {
      const warm = (r: number, g: number, b: number) => r - b > 60;
      const cool = (r: number, g: number, b: number) => b - r > 60;
      for (const [name, coloured] of [["house.ply", true], ["house.glb", true], ["house.obj", false]] as const) {
        await open(page, name === "house.ply" ? "house.obj" : name);
        if (name === "house.ply") {
          await pick(page, name);
          await expect(phase(page)).toHaveAttribute("data-phase", "ready");
        }
        const p = await settled(engine(page).locator(".exav-viewer-model-canvas"));
        expect(find(p, warm).count > 500, `${name} warm`).toBe(coloured);
        expect(find(p, cool).count > 500, `${name} cool`).toBe(coloured);
      }
    });

    test("a glTF whose buffer is another file is drawn when that file is given with it", async ({ page }) => {
      await page.goto(`./?${new URLSearchParams({ lang: "en", ...(mode === "page" ? { mode } : {}) })}`);
      await pick(page, "external.gltf", "house.bin");
      await expect(phase(page)).toHaveAttribute("data-phase", "ready");
      await expect.poll(() => triangles(page)).toBe(30);
    });

    test("a glTF in an archive is drawn from the buffer file in the archive, in a folder below it", async ({ page }) => {
      await openSample(page, "models.zip", mode === "page" ? { mode } : {});
      await expect(phase(page)).toHaveAttribute("data-phase", "ready");
      await page.locator(".demo-frame").getByRole("button", { name: /scene\.gltf/ }).click();
      await expect(engine(page).locator(".exav-viewer-model-canvas")).toHaveCount(1);
      const p = await settled(engine(page).locator(".exav-viewer-model-canvas"));
      // The house, as when it is opened on its own.
      expect(find(p, (r, g, b) => r < 200 || g < 200 || b < 200).count).toBeGreaterThan(500);
      await expect(page.locator(".demo-frame .exav-viewer-status-error")).toHaveCount(0);
    });

    for (const [name, why] of [
      ["external.gltf", "a glTF whose buffer is another file"],
      ["cloud.ply", "a PLY without faces"],
      ["object.obj", "an OBJ that is a binary file"],
    ] as const) {
      test(`${why} shows the error and the viewer goes on`, async ({ page }) => {
        const requests: string[] = [];
        page.on("request", (r) => requests.push(r.url()));
        await openSample(page, name, mode === "page" ? { mode } : {});
        await expect(phase(page)).toHaveAttribute("data-phase", "error");
        await expect(page.locator(".exav-viewer-status-error")).toHaveText("This model could not be shown.");
        // Nothing named by the file was asked for.
        expect(requests.filter((u) => u.includes("house.bin"))).toEqual([]);
        await pick(page, "house.obj");
        await expect(phase(page)).toHaveAttribute("data-phase", "ready");
        await expect.poll(() => triangles(page)).toBe(30);
      });
    }
  });
}
