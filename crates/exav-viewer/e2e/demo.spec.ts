// The demo, driven as a person would. The expectations come from how the
// samples were made (fixtures/make-samples.mjs and make-plan.py), or
// from a second, independent path to the same picture: the browser's own PNG
// decoder for the TIFF, the DXF for the DWG the ODA File Converter made of it.
//
// Every test runs twice: with each file in the sandboxed frame (the demo's
// default, under the frame's policy) and with the engines in the page
// (`?mode=page`, under the page's).
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import zlib from "node:zlib";

import { expect, test, type FrameLocator, type Locator, type Page } from "@playwright/test";

import { failOnViolations } from "./csp.js";
import { bands, decodePng, difference, find, type Pixels } from "./pixels.js";
import { openSample, pick, sample } from "./samples.js";
import { storedZip, tar } from "./zip.js";

/** The requests a page made, by URL. */
function recordRequests(page: Page): string[] {
  const urls: string[] = [];
  page.on("request", (r) => urls.push(r.url()));
  return urls;
}

/**
 * Runs `read` with the zoom buttons hidden: they sit over a corner of the
 * surface, which is not what the pixels are read for. Hidden through the
 * element's style, which the frame's policy has no say over (a `style` given to
 * the screenshot is an inline sheet it refuses).
 */
async function withoutTools<T>(page: Page, read: () => Promise<T>): Promise<T> {
  const set = (value: string) => page.locator(".exv-tools").evaluateAll((els, v) => els.forEach((e) => ((e as HTMLElement).style.visibility = v)), value);
  await set("hidden");
  try {
    return await read();
  } finally {
    await set("");
  }
}

async function shot(target: Locator): Promise<Pixels> {
  return withoutTools(target.page(), async () => decodePng(await target.screenshot({ animations: "disabled" })));
}

/** Waits for two screenshots in a row to agree: a canvas drawn over several frames has settled. */
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

failOnViolations();

const dark = (r: number, g: number, b: number) => r < 90 && g < 90 && b < 90;
const cyan = (r: number, g: number, b: number) => r < 120 && g > 160 && b > 160;
const ink = (r: number, g: number, b: number) => r < 160 && g < 160 && b < 160;

for (const mode of ["sandbox", "page"] as const) {
  const query = mode === "page" ? "&mode=page" : "";

  async function open(page: Page, name: string, lang = "en") {
    await openSample(page, name, { lang, ...(mode === "page" && { mode }) });
    await expect(page.locator(".demo-frame .exv-body")).toHaveAttribute("data-phase", "ready");
  }

  /** What the engine put on screen: in the frame's document, or in the page's. */
  const engine = (page: Page, within = ".demo-frame"): FrameLocator | Locator =>
    mode === "sandbox" ? page.frameLocator(`${within} iframe.exv-sandbox`) : page.locator(within);

  test.describe(mode, () => {
    test.describe("drawings", () => {
      test("a DWG plan is drawn whole, in its proportions, beside its rails", async ({ page }) => {
        await open(page, "plan.dwg");
        const canvas = engine(page).locator(".exv-cad-canvas");
        const p = await settled(canvas);
        // The outer walls are a 12 m by 8 m rectangle, black on the light ground:
        // the dark pixels' box is that rectangle.
        const walls = find(p, dark).box!;
        expect(walls.width / walls.height).toBeCloseTo(12 / 8, 1);
        // Fitted with a margin on every side, not cut by the rails that open
        // beside the canvas once the drawing is ready.
        expect(walls.minX).toBeGreaterThan(2);
        expect(walls.minY).toBeGreaterThan(2);
        expect(walls.maxX).toBeLessThan(p.width - 3);
        expect(walls.maxY).toBeLessThan(p.height - 3);
      });

      test("the layer rail lists the file's layer table, and a layer turned off is not drawn", async ({ page }) => {
        await open(page, "plan.dwg");
        const rows = page.locator(".exv-layer");
        await expect(rows).toHaveText(["0", "WALLS", "DOORS", "FURNITURE", "TEXT", "COLUMNS"]);
        const canvas = engine(page).locator(".exv-cad-canvas");
        // FURNITURE is colour 4, cyan, and the only cyan in the plan.
        expect(find(await settled(canvas), cyan).count).toBeGreaterThan(200);
        await rows.filter({ hasText: "FURNITURE" }).getByRole("checkbox").uncheck();
        await expect.poll(async () => find(await settled(canvas), cyan).count).toBe(0);
        await rows.filter({ hasText: "FURNITURE" }).getByRole("checkbox").check();
        await expect.poll(async () => find(await settled(canvas), cyan).count).toBeGreaterThan(200);
      });

      test("the DXF the DWG plan was converted from draws the same picture", async ({ page }) => {
        await open(page, "plan.dwg");
        const fromDwg = await settled(engine(page).locator(".exv-cad-canvas"));
        await open(page, "plan.dxf");
        const fromDxf = await settled(engine(page).locator(".exv-cad-canvas"));
        expect(find(fromDxf, dark).box).toEqual(find(fromDwg, dark).box);
        expect(difference(fromDwg, fromDxf)).toBeLessThan(1);
      });

      test("the thumbnail a drawing was saved with stands in for it until it is drawn", async ({ page }) => {
        // Every document (the page, the frame) logs, by the clock both share,
        // when a thumbnail is put up and taken down, and when the viewer says
        // the drawing is ready.
        await page.addInitScript(() => {
          const log: { event: string; at: number; width?: number; height?: number }[] = [];
          (window as unknown as { thumbnailLog: typeof log }).thumbnailLog = log;
          const at = () => performance.timeOrigin + performance.now();
          const thumbnail = (n: Node): n is HTMLImageElement => n instanceof HTMLImageElement && n.classList.contains("exv-cad-preview");
          new MutationObserver((records) => {
            for (const r of records) {
              if (r.type === "attributes" && r.target instanceof Element && r.target.getAttribute("data-phase") === "ready") log.push({ event: "ready", at: at() });
              for (const n of r.addedNodes) if (thumbnail(n)) log.push({ event: "shown", at: at(), width: n.naturalWidth, height: n.naturalHeight });
              for (const n of r.removedNodes) if (thumbnail(n)) log.push({ event: "gone", at: at() });
            }
          }).observe(document, { childList: true, subtree: true, attributes: true, attributeFilter: ["data-phase"] });
        });
        const logs = async () => {
          const all = await Promise.all(page.frames().map((f) => f.evaluate(() => (window as unknown as { thumbnailLog?: unknown[] }).thumbnailLog ?? []).catch(() => [])));
          return (all.flat() as { event: string; at: number; width?: number; height?: number }[]).sort((a, b) => a.at - b.at);
        };
        // exav-unpack's fixture: the converter made the 4 by 2 bitmap its
        // script gave it the DWG's preview.
        const dwg = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "exav-unpack", "tests", "fixtures", "dwg", "preview", "R2018.dwg.gz");
        await page.goto(`./?lang=en${query}`);
        await page.getByTestId("file-input").setInputFiles({ name: "thumbnail.dwg", mimeType: "", buffer: zlib.gunzipSync(fs.readFileSync(dwg)) });
        await expect(page.locator(".demo-frame .exv-body")).toHaveAttribute("data-phase", "ready");
        await expect.poll(async () => (await logs()).map((e) => e.event)).toEqual(["shown", "gone", "ready"]);
        const [shown] = await logs();
        expect([shown!.width, shown!.height]).toEqual([4, 2]);
        await expect(engine(page).locator(".exv-cad-preview")).toHaveCount(0);
        // A drawing saved without one shows none (in sandbox mode, in a frame
        // of its own).
        const before = Date.now();
        await pick(page, "plan.dwg");
        await expect(page.locator(".demo-frame .exv-body")).toHaveAttribute("data-phase", "ready");
        await expect.poll(async () => (await logs()).filter((e) => e.event === "ready").length).toBe(2);
        expect((await logs()).filter((e) => e.event === "shown" && e.at > before)).toHaveLength(0);
      });

      test("custom objects are drawn from their proxy graphics, and those saved without are counted", async ({ page }) => {
        // exav-render's fixture: custom entities with streams its make.py
        // wrote, two with none to draw, as the converter's 2018 DWG.
        const dwg = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "exav-render", "tests", "fixtures", "cad", "proxy", "dwg", "R2018", "proxy.dwg.gz");
        await page.goto(`./?lang=en${query}`);
        await page.getByTestId("file-input").setInputFiles({ name: "proxy.dwg", mimeType: "", buffer: zlib.gunzipSync(fs.readFileSync(dwg)) });
        await expect(page.locator(".demo-frame .exv-body")).toHaveAttribute("data-phase", "ready");
        await expect(page.locator(".exv-warnings")).toHaveText(
          "2 custom objects were saved without their graphics: only the application that made them can show them.",
        );
        expect(find(await settled(engine(page).locator(".exv-cad-canvas")), ink).count).toBeGreaterThan(100);
        // The notice covers a corner of the drawing: it can be put away.
        await page.getByRole("button", { name: "Close" }).and(page.locator(".exv-warnings button")).click();
        await expect(page.locator(".exv-warnings")).toHaveCount(0);
      });

      test("a truncated drawing is an error the page survives", async ({ page }) => {
        await page.goto(`./?lang=en${query}`);
        await page.getByTestId("file-input").setInputFiles({ name: "broken.dwg", mimeType: "", buffer: sample("plan.dwg").subarray(0, 3000) });
        await expect(page.locator(".demo-frame .exv-body")).toHaveAttribute("data-phase", "error");
        await expect(page.locator(".exv-status-error")).toHaveText("The drawing could not be shown.");
        // The next drawing opens.
        await pick(page, "plan.dwg");
        await expect(page.locator(".demo-frame .exv-body")).toHaveAttribute("data-phase", "ready");
        await expect(page.locator(".exv-layer")).toHaveCount(6);
      });

      test("a drawing older than R13 says so instead of failing to draw", async ({ page }) => {
        // exav-unpack's fixture: the converter's R12 DWG (AC1009) of an
        // ezdxf drawing.
        const dwg = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "exav-unpack", "tests", "fixtures", "dwg", "pre-r13", "R12.dwg.gz");
        await page.goto(`./?lang=en${query}`);
        await page.getByTestId("file-input").setInputFiles({ name: "r12.dwg", mimeType: "", buffer: zlib.gunzipSync(fs.readFileSync(dwg)) });
        await expect(page.locator(".demo-frame .exv-body")).toHaveAttribute("data-phase", "error");
        await expect(page.locator(".exv-status-error")).toHaveText(
          "This drawing is saved in a format older than AutoCAD R13, which cannot be shown here.",
        );
        // The next drawing opens.
        await pick(page, "plan.dwg");
        await expect(page.locator(".demo-frame .exv-body")).toHaveAttribute("data-phase", "ready");
      });

      test("switching the ground keeps the view the user zoomed to", async ({ page }) => {
        await open(page, "plan.dwg");
        // The column alone, found as whatever differs from the ground.
        await page.getByRole("button", { name: "None" }).click();
        await page.locator(".exv-layer", { hasText: "COLUMNS" }).getByRole("checkbox").check();
        const canvas = engine(page).locator(".exv-cad-canvas");
        /** The column's box, and the ground's brightness. */
        const look = async () => {
          // Inside the canvas's edge, which the frame's border reaches.
          await settled(canvas);
          const b = (await canvas.boundingBox())!;
          const p = await withoutTools(page, async () => decodePng(await page.screenshot({ clip: { x: b.x + 3, y: b.y + 3, width: b.width - 6, height: b.height - 6 } })));
          // The ground is the most common colour.
          const counts = new Map<number, number>();
          for (let i = 0; i < p.data.length; i += 4 * 97) {
            const c = (p.data[i]! << 16) | (p.data[i + 1]! << 8) | p.data[i + 2]!;
            counts.set(c, (counts.get(c) ?? 0) + 1);
          }
          const ground = [...counts].sort((a, b) => b[1] - a[1])[0]![0];
          const [r0, g0, b0] = [ground >> 16, (ground >> 8) & 0xff, ground & 0xff];
          return { box: find(p, (r, g, b) => Math.abs(r - r0) + Math.abs(g - g0) + Math.abs(b - b0) > 60).box!, ground: r0 + g0 + b0 };
        };
        const column = async () => (await look()).box;
        // One column on screen: the layer toggles above have been drawn.
        await expect.poll(async () => (await column()).width).toBeLessThan(40);
        const fitted = await column();
        const at = (await canvas.boundingBox())!;
        // Near the column, off its centre, so the view moves as well as grows.
        await page.mouse.move(at.x + fitted.minX - 30, at.y + fitted.minY - 30);
        for (let i = 0; i < 2; i++) await page.mouse.wheel(0, -120);
        // Wheel events are dispatched without waiting for them to be handled.
        await page.waitForTimeout(500);
        const zoomed = await column();
        expect(zoomed.width).toBeGreaterThan(fitted.width * 2);
        await page.getByRole("button", { name: "Dark" }).click();
        await expect(page.getByRole("button", { name: "Dark" })).toHaveAttribute("aria-pressed", "true");
        // The dark ground drawn, then the column measured on it.
        await expect.poll(async () => (await look()).ground).toBeLessThan(300);
        const dark = await column();
        expect(Math.abs(dark.minX - zoomed.minX)).toBeLessThan(3);
        expect(Math.abs(dark.minY - zoomed.minY)).toBeLessThan(3);
        expect(Math.abs(dark.width - zoomed.width)).toBeLessThan(3);
      });
    });

    test.describe("images", () => {
      test("the same picture given again replaces the one shown, in the page at the zoom it was at, and the frame starts over", async ({ page }) => {
        await open(page, "landscape.png");
        const tools = page.locator(".demo-frame .exv-tools");
        const stage = engine(page).locator(".exv-image-stage");
        await settled(page.locator(".demo-frame .exv-surface"));
        for (let i = 0; i < 2; i++) await tools.getByRole("button", { name: "Zoom in" }).click();
        const zoomed = await stage.evaluate((el) => el.style.transform);
        expect(zoomed).toMatch(/scale\(1\.56/);
        const picture = engine(page).locator(".exv-image-picture");
        const before = await picture.evaluate((el) => (el as HTMLImageElement).src);
        // The file again, as the user gives it: another object, the same name.
        await pick(page, "landscape.png");
        await expect.poll(async () => picture.evaluate((el) => (el as HTMLImageElement).src)).not.toBe(before);
        await settled(page.locator(".demo-frame .exv-surface"));
        const now = await stage.evaluate((el) => el.style.transform);
        if (mode === "page") expect(now).toBe(zoomed);
        else expect(now).toMatch(/scale\(1\)/);
      });

      test("a TIFF, decoded in WebAssembly, looks as the same picture as a PNG the browser decodes", async ({ page }) => {
        const requests = recordRequests(page);
        await open(page, "landscape.png");
        const surface = page.locator(".demo-frame .exv-surface");
        const png = await settled(surface);
        expect(requests.some((u) => u.includes("exav_viewer_image"))).toBe(false);
        await open(page, "landscape.tif");
        const tif = await settled(surface);
        expect(requests.some((u) => /exav_viewer_image_bg.*\.wasm/.test(u))).toBe(true);
        expect(difference(png, tif)).toBeLessThan(1);
        // And it is the picture: the sun, (250, 200, 80), is there.
        expect(find(tif, (r, g, b) => r > 235 && g > 185 && g < 215 && b < 100).count).toBeGreaterThan(1000);
      });

      test("JPEG 2000 and JBIG2 files, decoded in WebAssembly, look as the PNGs they were encoded from", async ({ page }) => {
        // exav-render's fixtures, encoded losslessly by opj_compress and jbig2enc
        // (crates/exav-render/tests/fixtures/images/make.py).
        const fixtures = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "exav-render", "tests", "fixtures", "images");
        const surface = page.locator(".demo-frame .exv-surface");
        const show = async (name: string) => {
          await page.getByTestId("file-input").setInputFiles({ name, mimeType: "", buffer: fs.readFileSync(path.join(fixtures, name)) });
          await expect(page.locator(".demo-frame .exv-body")).toHaveAttribute("data-phase", "ready");
          return settled(surface);
        };
        await page.goto(`./?lang=en${query}`);
        for (const [png, others] of [
          ["rgb.png", ["rgb.jp2", "rgb.j2k"]],
          ["bilevel.png", ["generic.jb2"]],
        ] as const) {
          const want = await show(png);
          for (const name of others) expect(difference(await show(name), want), name).toBeLessThan(1);
        }
      });
    });

    test.describe("documents", () => {
      test("a PDF zoomed with the buttons is moved by dragging the page, and selects text once the toggle says so", async ({ page }) => {
        await open(page, "report.pdf");
        const tools = page.locator(".demo-frame .exv-tools");
        const hand = tools.getByRole("button", { name: "Move the page" });
        const text = tools.getByRole("button", { name: "Select text" });
        const scroller = engine(page).locator(".exv-pdf-scroller");
        const position = () => scroller.evaluate((el) => [el.scrollLeft, el.scrollTop]);
        const selection = () => scroller.evaluate((el) => el.ownerDocument.getSelection()?.toString() ?? "");
        // The page fits: nothing to choose, and the zoom buttons are there.
        await expect(tools.getByRole("button", { name: "Zoom in" })).toBeVisible();
        await expect(hand).toHaveCount(0);
        await expect(tools.getByRole("button", { name: "Zoom out" })).toBeDisabled();
        for (let i = 0; i < 3; i++) await tools.getByRole("button", { name: "Zoom in" }).click();
        await expect(hand).toBeVisible();
        await expect(hand).toHaveAttribute("aria-pressed", "true");
        await expect(tools.getByRole("button", { name: "Zoom out" })).toBeEnabled();
        // A drag moves the page, and selects nothing.
        await settled(scroller);
        const r = (await scroller.boundingBox())!;
        const before = await position();
        await page.mouse.move(r.x + r.width / 2, r.y + r.height / 2);
        await page.mouse.down();
        await page.mouse.move(r.x + r.width / 2 - 120, r.y + r.height / 2 - 90, { steps: 6 });
        await page.mouse.up();
        const after = await position();
        expect(after[0]! - before[0]!).toBeGreaterThan(60);
        expect(after[1]! - before[1]!).toBeGreaterThan(40);
        expect(await selection()).toBe("");
        // Chosen to select, the same drag, across the first line, selects it and moves nothing.
        await text.click();
        await expect(text).toHaveAttribute("aria-pressed", "true");
        const run = engine(page).locator(".exv-pdf-text span", { hasText: "The north facade" });
        await run.scrollIntoViewIfNeeded();
        const a = (await run.boundingBox())!;
        const held = await position();
        // The part of the line in view: the page is wider than the viewer.
        const from = Math.max(a.x, r.x) + 4;
        const to = Math.min(a.x + a.width, r.x + r.width - 24) - 4;
        await page.mouse.move(from, a.y + a.height / 2);
        await page.mouse.down();
        await page.mouse.move(to, a.y + a.height / 2, { steps: 6 });
        await page.mouse.up();
        expect(await selection()).toContain("The north facade");
        expect(await position()).toEqual(held);
        // Fitted again, there is nothing to choose.
        await tools.getByRole("button", { name: "Fit to the window" }).click();
        await expect(hand).toHaveCount(0);
      });

      test("the same file given again replaces the document: in the page a zoomed PDF keeps its zoom and place, and the frame starts over", async ({ page }) => {
        await open(page, "report.pdf");
        const tools = page.locator(".demo-frame .exv-tools");
        const pages = engine(page).locator(".exv-pdf-page");
        const scroller = engine(page).locator(".exv-pdf-scroller");
        const position = () => scroller.evaluate((el) => [el.scrollLeft, el.scrollTop]);
        await expect(pages).toHaveCount(3);
        for (let i = 0; i < 3; i++) await tools.getByRole("button", { name: "Zoom in" }).click();
        // The three zooms have all been laid out (in the frame they are commands still on their way): about 1.95 times as wide as the viewer.
        await expect.poll(() => scroller.evaluate((el) => el.scrollWidth / el.clientWidth)).toBeGreaterThan(1.85);
        await scroller.evaluate((el) => {
          el.scrollLeft = 60;
          el.scrollTop = 200;
        });
        await expect.poll(position).toEqual([60, 200]);
        // Another document, twelve pages, under the same name.
        const longer = fs.readFileSync(path.join(path.dirname(fileURLToPath(import.meta.url)), ".out", "big.pdf"));
        await page.getByTestId("file-input").setInputFiles({ name: "report.pdf", mimeType: "", buffer: longer });
        await expect(pages).toHaveCount(12);
        if (mode === "page") {
          await expect.poll(position).toEqual([60, 200]);
          await expect(tools.getByRole("button", { name: "Zoom out" })).toBeEnabled();
        } else {
          await expect(tools.getByRole("button", { name: "Zoom out" })).toBeDisabled();
        }
      });

      test("a PDF opens on its first page, and its outline goes to the page of each section", async ({ page }) => {
        await open(page, "report.pdf");
        const outline = page.locator(".exv-outline-entry");
        await expect(outline).toHaveText(["Scope", "Findings", "Actions"]);
        // Scope, Findings and Actions start pages 1, 2 and 3.
        const pages = engine(page).locator(".exv-pdf-page");
        await expect(pages).toHaveCount(3);
        await expect(pages.nth(0)).toBeInViewport({ ratio: 0.5 });
        await outline.filter({ hasText: "Actions" }).click();
        await expect(pages.nth(2)).toBeInViewport({ ratio: 0.5 });
        await outline.filter({ hasText: "Findings" }).click();
        await expect(pages.nth(1)).toBeInViewport({ ratio: 0.5 });
        await expect(pages.nth(2)).not.toBeInViewport({ ratio: 0.5 });
      });

      // Selecting it: selection.spec.ts, in each browser.
      test("a PDF's text lies over the drawn text, at any zoom", async ({ page }) => {
        await open(page, "report.pdf");
        const sentence = "The north facade, the roof and the stairwell were inspected.";
        const run = engine(page).locator(".exv-pdf-text span", { hasText: sentence });
        /** The drawn ink beside the run, in the run's band: it starts and ends where the run does. */
        const lined = async () => {
          let width = 0;
          // Until the page is drawn: a slow machine is still at it when the PDF is `ready`.
          await expect(async () => {
            const r = (await run.boundingBox())!;
            const margin = 40;
            const strip = await withoutTools(page, async () => decodePng(await page.screenshot({ clip: { x: r.x - margin, y: r.y, width: r.width + 2 * margin, height: r.height } })));
            const ink = find(strip, dark).box!;
            expect(Math.abs(ink.minX - margin), "the run starts where the ink does").toBeLessThan(4);
            expect(Math.abs(ink.maxX + 1 - (margin + r.width)), "the run ends where the ink does").toBeLessThan(6);
            width = r.width;
          }).toPass({ timeout: 15_000 });
          return width;
        };
        await expect(run).toHaveCount(1);
        await page.waitForTimeout(500);
        const before = await lined();
        // A trackpad pinch, as Chrome reports it: about one and a half times,
        // about the run's start, so that it grows to the right, on screen.
        const r = (await run.boundingBox())!;
        await page.mouse.move(r.x + 2, r.y + r.height / 2);
        await page.keyboard.down("Control");
        await page.mouse.wheel(0, -40);
        await page.keyboard.up("Control");
        await page.waitForTimeout(800);
        expect(await lined()).toBeGreaterThan(before * 1.2);
      });

      test("a PDF's links go to their place in it, or open their address as any link the document follows", async ({ page, context }) => {
        await context.route("https://example.com/**", (route) => route.fulfill({ contentType: "text/plain", body: "guide" }));
        await open(page, "report.pdf");
        const pages = engine(page).locator(".exv-pdf-page");
        const links = pages.nth(0).locator(".exv-pdf-link");
        await expect(links).toHaveCount(2);
        // "See 3. Actions": to the third page's heading.
        await links.nth(0).click();
        await expect(pages.nth(2)).toBeInViewport({ ratio: 0.5 });
        await page.locator(".exv-outline-entry", { hasText: "Scope" }).click();
        await expect(pages.nth(0)).toBeInViewport({ ratio: 0.5 });
        // The address: in the frame, the host asks first; in the page, it opens as any link would.
        const asked: string[] = [];
        page.on("dialog", (d) => {
          asked.push(d.message());
          void d.accept();
        });
        const popup = context.waitForEvent("page");
        await links.nth(1).click();
        const opened = await popup;
        expect(opened.url()).toBe("https://example.com/guide");
        expect(await opened.evaluate(() => window.opener)).toBeNull();
        expect(asked).toEqual(mode === "sandbox" ? ["The document links to https://example.com/guide. Open it in a new tab?"] : []);
        await opened.close();
      });

      test("a Word document shows the seven paragraphs of its first page", async ({ page }) => {
        await open(page, "notes.docx");
        const p = await settled(page.locator(".demo-frame .exv-surface"));
        // One band of ink per paragraph, title included.
        expect(bands(p, ink, 3).length).toBe(7);
      });

      // Selecting it: selection.spec.ts, in each browser.
      test("a Word document's text lies over the drawn text", async ({ page }) => {
        await open(page, "notes.docx");
        const runs = engine(page).locator("[data-ooxml-selection-run]");
        const first = runs.filter({ hasText: /^1\. $/ });
        const last = runs.filter({ hasText: /^spring\.$/ });
        await expect(first).toHaveCount(1);
        await settled(page.locator(".demo-frame .exv-surface"));
        const a = (await first.boundingBox())!;
        const b = (await last.boundingBox())!;
        // The ink of the line, in its runs' band: it starts and ends where they do.
        const margin = 40;
        const strip = decodePng(await page.screenshot({ clip: { x: a.x - margin, y: a.y, width: b.x + b.width - a.x + 2 * margin, height: a.height } }));
        const line = find(strip, dark).box!;
        expect(Math.abs(line.minX - margin), "the runs start where the ink does").toBeLessThan(4);
        expect(Math.abs(line.maxX + 1 - (b.x + b.width - a.x + margin)), "the runs end where the ink does").toBeLessThan(6);
      });

      test("two paragraphs of a Word document copy as two lines", async ({ page, context }) => {
        await context.grantPermissions(["clipboard-read", "clipboard-write"]);
        await open(page, "notes.docx");
        const runs = engine(page).locator("[data-ooxml-selection-run]");
        const a = (await runs.filter({ hasText: /^1\. $/ }).boundingBox())!;
        const b = (await runs.filter({ hasText: /^week\.$/ }).boundingBox())!;
        await page.mouse.move(a.x + 1, a.y + a.height / 2);
        await page.mouse.down();
        await page.mouse.move(b.x + b.width - 1, b.y + b.height / 2, { steps: 10 });
        await page.mouse.up();
        await page.keyboard.press("ControlOrMeta+C");
        expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(
          "1. The schedule is confirmed for the spring.\n2. Samples of the facade render are expected next week.",
        );
      });

      test("a Word document's links go to their place in it, or open their address as any link the document follows", async ({ page, context }) => {
        await context.route("https://example.com/**", (route) => route.fulfill({ contentType: "text/plain", body: "minutes" }));
        await open(page, "notes.docx");
        const runs = engine(page).locator("[data-ooxml-selection-run]");
        const second = engine(page).locator('[data-ooxml-selection-surface][data-page-index="1"]');
        await expect(second).not.toBeInViewport();
        // "See the actions on the next page": to the second page's heading.
        await runs.filter({ hasText: /^actions $/ }).click();
        await expect(second).toBeInViewport();
        // The address: in the frame, the host asks first; in the page, it opens as any link would.
        const asked: string[] = [];
        page.on("dialog", (d) => {
          asked.push(d.message());
          void d.accept();
        });
        const link = runs.filter({ hasText: /^https:\/\/example\.com\/minutes$/ });
        await link.scrollIntoViewIfNeeded();
        const popup = context.waitForEvent("page");
        await link.click();
        const opened = await popup;
        expect(opened.url()).toBe("https://example.com/minutes");
        expect(await opened.evaluate(() => window.opener)).toBeNull();
        expect(asked).toEqual(mode === "sandbox" ? ["The document links to https://example.com/minutes. Open it in a new tab?"] : []);
        await opened.close();
      });

      test("a slide's text lies over the drawn text, and its two points copy as two lines", async ({ page, context }) => {
        await context.grantPermissions(["clipboard-read", "clipboard-write"]);
        await open(page, "visit.pptx");
        const runs = engine(page).locator("[data-ooxml-selection-run]");
        const first = runs.filter({ hasText: /^Roof inspected\.$/ });
        const second = runs.filter({ hasText: /^Gutter replaced\.$/ });
        await expect(first).toHaveCount(1);
        await settled(page.locator(".demo-frame .exv-surface"));
        const a = (await first.boundingBox())!;
        const b = (await second.boundingBox())!;
        // The ink of the first point, in its run's band: it starts and ends where the run does.
        const margin = 40;
        const strip = decodePng(await page.screenshot({ clip: { x: a.x - margin, y: a.y, width: a.width + 2 * margin, height: a.height } }));
        const line = find(strip, dark).box!;
        expect(Math.abs(line.minX - margin), "the run starts where the ink does").toBeLessThan(4);
        expect(Math.abs(line.maxX + 1 - (margin + a.width)), "the run ends where the ink does").toBeLessThan(6);
        // Both points, dragged across and copied.
        await page.mouse.move(a.x + 1, a.y + a.height / 2);
        await page.mouse.down();
        await page.mouse.move(b.x + b.width - 1, b.y + b.height / 2, { steps: 10 });
        await page.mouse.up();
        await page.keyboard.press("ControlOrMeta+c");
        expect(await page.evaluate(() => navigator.clipboard.readText())).toBe("Roof inspected.\nGutter replaced.");
      });

      test("a deck with a byte after its end record, which the engine's strict check refuses, still opens", async ({ page }) => {
        await page.goto(`./?lang=en${query}`);
        await page.getByTestId("file-input").setInputFiles({ name: "tail.pptx", mimeType: "", buffer: Buffer.concat([sample("visit.pptx"), Buffer.from("\n")]) });
        await expect(page.locator(".demo-frame .exv-body")).toHaveAttribute("data-phase", "ready");
        await expect(engine(page).locator("[data-ooxml-selection-run]", { hasText: /^Roof inspected\.$/ })).toHaveCount(1);
      });

      test("a slide is shown whole, at its own proportions, centred on the surface, and fitted again when the view changes size", async ({ page }) => {
        await open(page, "visit.pptx");
        const slide = engine(page).locator("canvas.exv-office-canvas");
        const surface = page.locator(".demo-frame .exv-surface");
        const check = async () => {
          const s = (await slide.boundingBox())!;
          const v = (await surface.boundingBox())!;
          // 32 by 18 cm, as visit.pptx says (make-samples.mjs).
          expect(s.width / s.height).toBeCloseTo(32 / 18, 1);
          // Centred across, the surface showing on every side.
          expect(Math.abs(s.x + s.width / 2 - (v.x + v.width / 2))).toBeLessThan(3);
          expect(s.x - v.x).toBeGreaterThan(14);
          expect(s.y - v.y).toBeGreaterThan(14);
          expect(v.x + v.width - (s.x + s.width)).toBeGreaterThan(14);
          expect(v.y + v.height - (s.y + s.height)).toBeGreaterThan(14);
          // Grey around it, not the slide's white.
          const around = decodePng(await page.screenshot({ clip: { x: v.x + 2, y: s.y + s.height / 2, width: 4, height: 4 } }));
          expect(around.data[0]).toBeLessThan(250);
        };
        await expect.poll(async () => (await slide.boundingBox())?.width ?? 0).toBeGreaterThan(100);
        await check();
        await page.setViewportSize({ width: 1000, height: 900 });
        await expect.poll(async () => (await slide.boundingBox())!.width).toBeLessThan((await surface.boundingBox())!.width - 28);
        await check();
      });

      test("a slide's links go to the slide they name, or open their address as any link the document follows", async ({ page, context }) => {
        await context.route("https://example.com/**", (route) => route.fulfill({ contentType: "text/plain", body: "photos" }));
        await open(page, "visit.pptx");
        const runs = engine(page).locator("[data-ooxml-selection-run]");
        // The address first: the slide changes after the other.
        const asked: string[] = [];
        page.on("dialog", (d) => {
          asked.push(d.message());
          void d.accept();
        });
        const popup = context.waitForEvent("page");
        await runs.filter({ hasText: /^Photos: / }).click();
        const opened = await popup;
        expect(opened.url()).toBe("https://example.com/photos");
        expect(await opened.evaluate(() => window.opener)).toBeNull();
        expect(asked).toEqual(mode === "sandbox" ? ["The document links to https://example.com/photos. Open it in a new tab?"] : []);
        await opened.close();
        // "See the actions": to the second slide.
        await runs.filter({ hasText: /^See the actions$/ }).click();
        await expect(page.getByText("Slide 2 / 2")).toBeVisible();
        await expect(runs.filter({ hasText: /^Actions$/ })).toHaveCount(1);
      });

      test("a spreadsheet and a semicolon CSV of the same quote both render", async ({ page }) => {
        await open(page, "quote.xlsx");
        expect(find(await settled(page.locator(".demo-frame .exv-surface")), ink).count).toBeGreaterThan(500);
        await open(page, "quote.csv");
        expect(find(await settled(page.locator(".demo-frame .exv-surface")), ink).count).toBeGreaterThan(500);
      });
    });

    test.describe("models and media", () => {
      test("an IFC model is drawn, lists its categories, and names what is tapped", async ({ page }) => {
        await open(page, "house.ifc");
        await expect(page.locator(".exv-layer")).toHaveText(["IFCSLAB", "IFCWALL"]);
        const canvas = engine(page).locator(".exv-model-canvas");
        // The house fills a good part of the view in its categories'
        // colours (the file gives none), framed whole: the ground shows on
        // every side. The ground, the grid and the outline are greys.
        const coloured = (r: number, g: number, b: number) => Math.max(r, g, b) - Math.min(r, g, b) > 50;
        const p = await settled(canvas);
        const house = find(p, coloured);
        expect(house.count).toBeGreaterThan(p.width * p.height * 0.1);
        expect(house.box!.minX).toBeGreaterThan(2);
        expect(house.box!.maxX).toBeLessThan(p.width - 3);
        expect(house.box!.minY).toBeGreaterThan(2);
        expect(house.box!.maxY).toBeLessThan(p.height - 3);
        // Seen from above the walls, the middle of the view is the slab's top.
        await canvas.click();
        const rail = page.locator(".exv-rail-section", { hasText: "Element" });
        await expect(rail.locator(".exv-strong")).toHaveText("Ground slab");
        await expect(rail.locator(".exv-muted")).toHaveText(["IFCSLAB", "Ground floor"]);
        // Hidden, the slab is not drawn and cannot be tapped: the ray goes
        // through to nothing.
        await page.locator(".exv-layer", { hasText: "IFCSLAB" }).getByRole("checkbox").uncheck();
        await canvas.click();
        await expect(rail.getByText("Tap an element to identify it.")).toBeVisible();
        // Everything hidden: only the grey floor grid is left.
        await page.locator(".exv-layer", { hasText: "IFCWALL" }).getByRole("checkbox").uncheck();
        expect(find(await settled(canvas), coloured).count).toBe(0);
      });

      test("an IFC model with a beam left a kilometre away is framed on the house, and zooms where the pointer is", async ({ page }) => {
        await open(page, "stray.ifc");
        const canvas = engine(page).locator(".exv-model-canvas");
        const coloured = (r: number, g: number, b: number) => Math.max(r, g, b) - Math.min(r, g, b) > 50;
        // Framed as the house alone is (above): it fills a good part of the view, whole.
        const p = await settled(canvas);
        const house = find(p, coloured);
        expect(house.count).toBeGreaterThan(p.width * p.height * 0.1);
        expect(house.box!.minX).toBeGreaterThan(2);
        expect(house.box!.maxX).toBeLessThan(p.width - 3);
        // The wheel at the house's left edge: it grows about that edge, which
        // stays under the pointer. Measured by its top, which the view does
        // not cut (its right and bottom go past the view's edges).
        const at = (await canvas.boundingBox())!;
        const y = (house.box!.minY + house.box!.maxY) / 2;
        await page.mouse.move(at.x + house.box!.minX + 3, at.y + y);
        for (let i = 0; i < 4; i++) await page.mouse.wheel(0, -100);
        const after = find(await settled(canvas), coloured);
        expect((y - after.box!.minY) / (y - house.box!.minY)).toBeGreaterThan(1.1);
        expect(Math.abs(after.box!.minX - house.box!.minX)).toBeLessThan(12);
      });

      test("an STL zooms where the pointer is, as an IFC model does", async ({ page }) => {
        await open(page, "house.stl");
        const canvas = engine(page).locator(".exv-model-canvas");
        // The grey of the surface against the light ground, which is lighter everywhere.
        const surface = (r: number) => r < 180;
        const first = find(await settled(canvas), (r) => surface(r));
        expect(first.count).toBeGreaterThan(10_000);
        // The wheel at the model's left edge: it grows about that edge, which stays under the pointer.
        const at = (await canvas.boundingBox())!;
        const y = (first.box!.minY + first.box!.maxY) / 2;
        await page.mouse.move(at.x + first.box!.minX + 3, at.y + y);
        for (let i = 0; i < 4; i++) await page.mouse.wheel(0, -100);
        const after = find(await settled(canvas), (r) => surface(r));
        expect((y - after.box!.minY) / (y - first.box!.minY)).toBeGreaterThan(1.1);
        expect(Math.abs(after.box!.minX - first.box!.minX)).toBeLessThan(12);
      });

      test("an STL reports its triangle count", async ({ page }) => {
        await open(page, "house.stl");
        // Two boxes of twelve, two gable ends, two roof slopes of two.
        await expect(page.locator(".exv-badge")).toHaveText("30 triangles");
      });

      test("a WAV plays for the two seconds it holds", async ({ page }) => {
        await open(page, "chime.wav");
        const duration = await engine(page)
          .locator("audio")
          .evaluate((a: HTMLAudioElement) => new Promise<number>((done) => (a.readyState >= 1 ? done(a.duration) : a.addEventListener("loadedmetadata", () => done(a.duration)))));
        expect(duration).toBeCloseTo(2, 2);
      });
    });

    test.describe("archives", () => {
      test("members open in place, an archive inside an archive too, with their own rails", async ({ page }) => {
        await open(page, "delivery.zip");
        const frame = page.locator(".demo-frame");
        await expect(frame.locator(".exv-archive-head")).toHaveText("4 files");
        const names = frame.locator(".exv-member-name > .exv-truncate:first-child");
        await expect(names).toHaveText(["report.pdf", "quote.csv", "plan.dwg", "photos.zip"]);
        await expect(frame.locator(".exv-member-folder")).toHaveText(["documents", "documents", "drawings"]);

        await frame.getByRole("button", { name: /report\.pdf/ }).click();
        // The member's outline goes to the rail, one level down.
        await expect(frame.locator(".exv-outline-entry")).toHaveText(["Scope", "Findings", "Actions"]);
        await frame.getByRole("button", { name: "Back to the archive" }).click();

        await frame.getByRole("button", { name: /photos\.zip/ }).click();
        await expect(names).toHaveText(["landscape.tif"]);
        await frame.getByRole("button", { name: /landscape\.tif/ }).click();
        const back = frame.getByRole("button", { name: "Back to the archive" });
        await expect(back).toHaveCount(2);
        // The sun of the landscape, drawn two archives down.
        await expect.poll(async () => find(await shot(frame.locator(".exv-stage")), (r, g, b) => r > 235 && g > 185 && g < 215 && b < 100).count).toBeGreaterThan(1000);
        await back.last().click();
        await expect(names).toHaveText(["landscape.tif"]);
        // Out of the inner archive, whose list fills the stage, by the outer bar.
        await back.click();
        await expect(names).toHaveCount(4);
      });

      test("a .tar.gz lists the files of its tar, and a .gz the file it holds, by its name", async ({ page }) => {
        await page.goto(`./?lang=en${query}`);
        const frame = page.locator(".demo-frame");
        const names = frame.locator(".exv-member-name > .exv-truncate:first-child");
        const tarball = zlib.gzipSync(tar([["documents/report.pdf", sample("report.pdf")], ["quote.csv", sample("quote.csv")]]));
        await page.getByTestId("file-input").setInputFiles({ name: "bundle.tar.gz", mimeType: "application/gzip", buffer: tarball });
        await expect(names).toHaveText(["report.pdf", "quote.csv"]);
        await expect(frame.locator(".exv-member-folder")).toHaveText(["documents"]);
        await frame.getByRole("button", { name: /report\.pdf/ }).click();
        await expect(frame.locator(".exv-outline-entry")).toHaveText(["Scope", "Findings", "Actions"]);

        await page.getByTestId("file-input").setInputFiles({ name: "quote.csv.gz", mimeType: "application/gzip", buffer: zlib.gzipSync(sample("quote.csv")) });
        await expect(names).toHaveText(["quote.csv"]);
        await frame.getByRole("button", { name: /quote\.csv/ }).click();
        await expect(frame.getByRole("button", { name: "Back to the archive" })).toBeVisible();
        await expect(frame.locator(".exv-body").last()).toHaveAttribute("data-phase", "ready");
      });

      test("a member that cannot be shown leaves the way back to the archive open", async ({ page }) => {
        await page.goto(`./?lang=en${query}`);
        const zip = storedZip([
          ["broken.dwg", sample("plan.dwg").subarray(0, 3000)],
          ["plan.dxf", sample("plan.dxf")],
        ]);
        await page.getByTestId("file-input").setInputFiles({ name: "mixed.zip", mimeType: "application/zip", buffer: zip });
        const frame = page.locator(".demo-frame");
        await frame.getByRole("button", { name: /broken\.dwg/ }).click();
        await expect(frame.locator(".exv-status-error")).toHaveText("The drawing could not be shown.");
        await frame.getByRole("button", { name: "Back to the archive" }).click();
        await frame.getByRole("button", { name: /plan\.dxf/ }).click();
        await expect(frame.locator(".exv-layer")).toHaveCount(6);
      });
    });

    test.describe("the page", () => {
      test("a file the user opens is viewed without being sent anywhere", async ({ page }) => {
        const requests = recordRequests(page);
        await page.goto(`./?lang=en${query}`);
        await page.getByTestId("file-input").setInputFiles({ name: "mine.dxf", mimeType: "", buffer: sample("plan.dxf") });
        await expect(page.locator(".demo-frame .exv-body")).toHaveAttribute("data-phase", "ready");
        await expect(page.getByRole("heading", { name: "Your files" })).toBeVisible();
        await expect(page.locator(".exv-layer")).toHaveCount(6);
        // Every request went to the demo's own origin, or to an object URL
        // the page or the frame made, and none carried the file.
        const origin = `${new URL(page.url()).origin}/`;
        expect(requests.filter((u) => !u.startsWith(origin) && !u.startsWith(`blob:${origin}`) && !u.startsWith("blob:null/"))).toEqual([]);
        expect(requests.filter((u) => u.includes("mine.dxf"))).toEqual([]);
      });

      test("each engine is fetched when its first file opens, not before", async ({ page }) => {
        // Script bodies, searched for a string only each engine's code holds:
        // chunk names are the bundler's to choose.
        const scripts: Promise<string>[] = [];
        page.on("response", (r) => {
          if (/javascript/.test(r.headers()["content-type"] ?? "")) scripts.push(r.text().catch(() => ""));
        });
        const loaded = async (marker: string) => (await Promise.all(scripts)).some((s) => s.includes(marker));
        const requests = recordRequests(page);
        await open(page, "report.pdf");
        for (const marker of ["exv-cad-canvas", "exv-model-canvas", "exv-archive-member", "exv-office exv-office-"]) expect(await loaded(marker), marker).toBe(false);
        expect(requests.filter((u) => /\.wasm$/.test(u) && !u.includes("/pdfjs/"))).toEqual([]);
        await pick(page, "plan.dwg");
        await expect(page.locator(".demo-frame .exv-body")).toHaveAttribute("data-phase", "ready");
        expect(await loaded("exv-cad-canvas")).toBe(true);
        expect(requests.some((u) => /exav_viewer_dwg_bg.*\.wasm/.test(u))).toBe(true);
        for (const marker of ["exv-model-canvas", "exv-archive-member", "exv-office exv-office-"]) expect(await loaded(marker), marker).toBe(false);
      });

      test("the French locale translates the viewer's own strings", async ({ page }) => {
        await open(page, "plan.dwg", "fr");
        await expect(page.locator(".exv-rail-label", { hasText: "Calques" })).toBeVisible();
      });
    });
  });
}

test("the sidebar lists each sample of samples.json once, and each is served and credited", async ({ page, request }) => {
  const dir = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "demo", "public", "showcase");
  const json = path.join(dir, "samples.json");
  expect(fs.existsSync(json), "no samples: run npm run demo:showcase").toBe(true);
  const samples = (JSON.parse(fs.readFileSync(json, "utf8")) as { samples: { file: string }[] }).samples.map((s) => s.file).sort();
  // Every file copied in is in the list, and nothing else is.
  expect(fs.readdirSync(dir).filter((f) => !f.startsWith(".") && f !== "samples.json").sort()).toEqual(samples);
  await page.goto("./?lang=en");
  await expect(page.locator(".demo-side .demo-file")).toHaveCount(samples.length);
  const listed = (await page.locator(".demo-side .demo-file").allTextContents()).sort();
  expect(listed).toEqual(samples);
  const credits = await (await request.get("licenses/README.txt")).text();
  for (const name of samples) {
    const served = await request.get(`showcase/${name}`);
    expect(served.ok(), name).toBe(true);
    expect((await served.body()).length, name).toBe(fs.statSync(path.join(dir, name)).size);
    expect(credits, name).toContain(`\n${name}\n`);
  }
});

test("the demo ships every notice its frame ships", async ({ request }) => {
  // The frame app bundles a subset of the demo's engines, so each licence
  // text it carries (scripts/build-frame.mjs) applies to the demo too.
  const frame = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "dist", "frame", "app", "licenses");
  const files = (fs.readdirSync(frame, { recursive: true }) as string[]).filter((f) => f !== "README.txt" && fs.statSync(path.join(frame, f)).isFile());
  expect(files.length).toBeGreaterThan(0);
  const missing: string[] = [];
  for (const f of files) {
    const served = await request.get(`licenses/${f.split(path.sep).join("/")}`);
    if (!(await served.body()).equals(fs.readFileSync(path.join(frame, f)))) missing.push(f);
  }
  expect(missing).toEqual([]);
});
