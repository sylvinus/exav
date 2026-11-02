// A host that draws its own controls (demo/headless.html): every button is
// the page's, driven by the session's controllers; the frame draws the
// document alone, takes the page's colours, and hands back the keys the
// document does not use.
import { expect, test, type Frame, type Page } from "@playwright/test";

import { failOnViolations } from "./csp.js";
import { sample } from "./samples.js";

failOnViolations();

type Phase = "loading" | "ready" | "error" | "empty" | "none";

const phase = (page: Page) =>
  page.evaluate(() => {
    const s = (window as unknown as { headless: { session(): { status: { get(): { phase: string } } } | null } }).headless.session();
    return (s?.status.get().phase ?? "none") as Phase;
  });

async function open(page: Page, name: string, mimeType = ""): Promise<Frame> {
  await page.goto("./headless.html?lang=en");
  await page.getByTestId("file-input").setInputFiles({ name, mimeType, buffer: sample(name) });
  await expect.poll(() => phase(page), { timeout: 30_000 }).toBe("ready");
  const frame = await (await page.locator("#stage iframe").elementHandle())!.contentFrame();
  if (!frame) throw new Error("no frame");
  return frame;
}

const heard = (page: Page) => page.locator("#keys li");

test("a PDF: the page's page field, zoom and thumbnails drive it", async ({ page }) => {
  const frame = await open(page, "report.pdf");
  const field = page.locator('#controls input[type="number"]');
  await expect(field).toHaveValue("1");
  await expect(page.locator("#controls")).toContainText("/ 3");
  // A picture of each page, from the frame, drawn on this page's canvases.
  await expect(page.locator("#thumbs canvas")).toHaveCount(3);
  const size = await page.locator("#thumbs canvas").first().evaluate((c: HTMLCanvasElement) => [c.width, c.height]);
  expect(size[1]).toBeGreaterThan(size[0]!);
  await page.locator("#thumbs button").nth(2).click();
  await expect(field).toHaveValue("3");
  await field.fill("2");
  await field.dispatchEvent("change");
  await expect(field).toHaveValue("2");
  const zoom = page.locator("#controls .zoom");
  const before = await zoom.textContent();
  await page.getByTitle("Zoom in").click();
  await expect(zoom).not.toHaveText(before!);
  await expect(frame.locator(".exav-viewer-pdf-page").first()).toBeVisible();
});

test("keys the document does not use reach the page; those it uses stay in the frame", async ({ page }) => {
  const frame = await open(page, "report.pdf");
  // The focus in the frame, on the document.
  await frame.locator(".exav-viewer-pdf-page").first().click();
  await page.keyboard.press("ArrowDown");
  await page.keyboard.press("ArrowRight");
  await expect(heard(page)).toHaveText(["ArrowRight (from the frame)"]);
  // Down is the document's while it can scroll: it scrolled.
  expect(await frame.locator(".exav-viewer-pdf-scroller").evaluate((s) => s.scrollTop)).toBeGreaterThan(0);
  // Never a key that types or a shortcut.
  await page.keyboard.press("Delete");
  await page.keyboard.press("Control+ArrowLeft");
  await expect(heard(page)).toHaveCount(1);
  // Escape closes the file, as the page's own listener does.
  await page.keyboard.press("Escape");
  await expect(page.locator("#stage iframe")).toHaveCount(0);
  await expect(heard(page).last()).toHaveText("Escape (from the frame)");
});

test("the frame takes the page's colours, and again when they change", async ({ page }) => {
  const frame = await open(page, "notes.txt");
  const look = () =>
    frame.locator(".exav-viewer-text").evaluate((e) => {
      const s = getComputedStyle(e);
      return [s.backgroundColor, s.color, getComputedStyle(document.documentElement).colorScheme];
    });
  expect(await look()).toEqual(["rgb(255, 253, 248)", "rgb(29, 27, 23)", "light"]);
  await page.locator("#scheme").click();
  await expect.poll(look).toEqual(["rgb(42, 41, 48)", "rgb(244, 242, 250)", "dark"]);
});

test("a player with no controls of its own, played and paused by the page's", async ({ page }) => {
  const frame = await open(page, "chime.wav");
  const audio = frame.locator("audio");
  expect(await audio.evaluate((a: HTMLAudioElement) => a.controls)).toBe(false);
  await expect(page.locator("#controls .clock")).toHaveText("0:00 / 0:02");
  await page.getByTestId("play").click();
  await expect(page.getByTestId("play")).toHaveText("⏸");
  expect(await audio.evaluate((a: HTMLAudioElement) => a.paused)).toBe(false);
  await page.getByTestId("play").click();
  await expect(page.getByTestId("play")).toHaveText("▶");
  await page.locator('#controls input[type="range"]').fill("1");
  await expect.poll(() => audio.evaluate((a: HTMLAudioElement) => Math.round(a.currentTime))).toBe(1);
});

test("a workbook's sheets are the page's tabs", async ({ page }) => {
  await open(page, "book.xlsx");
  const tabs = page.locator("#sheets button");
  await expect(tabs).toHaveText(["Quote", "Notes"]);
  await expect(tabs.first()).toHaveAttribute("aria-selected", "true");
  await tabs.nth(1).click();
  await expect(tabs.nth(1)).toHaveAttribute("aria-selected", "true");
  await expect(tabs.first()).toHaveAttribute("aria-selected", "false");
});

test("an SVG is drawn, its script not run and its image not fetched", async ({ page }) => {
  const messages: unknown[] = [];
  await page.exposeFunction("heardMessage", (m: unknown) => void messages.push(m));
  await page.addInitScript(() => addEventListener("message", (e) => (window as unknown as { heardMessage(m: unknown): void }).heardMessage(e.data)));
  const requests: string[] = [];
  page.on("request", (r) => requests.push(r.url()));
  // Typed as nothing in particular: the name says SVG, and an `<img>` draws SVG only when typed so.
  const frame = await open(page, "logo.svg", "application/octet-stream");
  const drawn = await frame.locator(".exav-viewer-image-picture").evaluate((img: HTMLImageElement) => [img.tagName, img.naturalWidth > 0 || img.complete]);
  expect(drawn).toEqual(["IMG", true]);
  // Its size is its viewBox's: a picture of it has its proportions.
  const picture = await page.evaluate(async () => {
    const s = (window as unknown as { headless: { session(): { controllers: { get(): { pictures?: { render(p: number, e: number): Promise<ImageBitmap | null> } } } } } }).headless.session();
    const b = await s.controllers.get().pictures!.render(1, 400);
    return b && [b.width, b.height];
  });
  expect(picture).toEqual([400, 200]);
  expect(messages).not.toContain("pwned");
  expect(requests.filter((u) => u.includes("evil.example"))).toEqual([]);
});
