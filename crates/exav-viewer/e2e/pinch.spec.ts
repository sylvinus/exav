// Two-finger zoom, as a phone sends it: the point under the fingers stays
// under them, and what is there grows by the ratio the fingers spread. Each
// test pinches about a feature of a sample whose colour is known (the sun of
// the landscape, the blue rule of the report, the column of the plan) and
// finds it again in the picture afterwards.
import { expect, test, type Locator, type Page } from "@playwright/test";

import { decodePng, find } from "./pixels.js";
import { openSample } from "./samples.js";

test.use({ hasTouch: true });

type Test = (r: number, g: number, b: number) => boolean;
const SUN: Test = (r, g, b) => r > 235 && g > 185 && g < 215 && b < 100;
const RULE: Test = (r, g, b) => r < 90 && g > 80 && g < 130 && b > 180;
const COLUMN: Test = (r, g, b) => r < 160 && g < 160 && b < 160;

async function open(page: Page, name: string) {
  // The engines in the page, whose elements the tests read.
  await openSample(page, name, { mode: "page" });
  await expect(page.locator(".demo-frame .exav-viewer-body")).toHaveAttribute("data-phase", "ready");
  await page.waitForTimeout(500);
}

/**
 * The feature's box, in page coordinates. Waited for: a PDF is `ready` before
 * its first page is drawn, and a slow machine takes its time.
 */
async function locate(frame: Locator, test: Test) {
  const at = (await frame.boundingBox())!;
  // Without the zoom buttons, which sit over its corner.
  const tools = frame.page().locator(".exav-viewer-tools");
  const hide = (v: string) => tools.evaluateAll((els, value) => els.forEach((e) => ((e as HTMLElement).style.visibility = value)), v);
  const until = Date.now() + 15_000;
  let box: ReturnType<typeof find>["box"] = null;
  for (;;) {
    await hide("hidden");
    const shot = await frame.screenshot();
    await hide("");
    box = find(decodePng(shot), test).box;
    if (box || Date.now() > until) break;
    await frame.page().waitForTimeout(250);
  }
  if (!box) throw new Error("feature not on screen");
  const x = at.x + box.minX;
  const y = at.y + box.minY;
  return { x, y, cx: x + box.width / 2, cy: y + box.height / 2, width: box.width, height: box.height };
}

/** Two fingers on either side of (cx, cy), spreading from `from` to `to` px apart. */
async function pinch(page: Page, cx: number, cy: number, from: number, to: number) {
  const cdp = await page.context().newCDPSession(page);
  const fingers = (d: number) => [
    { x: cx - d / 2, y: cy, id: 0 },
    { x: cx + d / 2, y: cy, id: 1 },
  ];
  await cdp.send("Input.dispatchTouchEvent", { type: "touchStart", touchPoints: fingers(from) });
  for (let i = 1; i <= 10; i++) {
    await cdp.send("Input.dispatchTouchEvent", { type: "touchMove", touchPoints: fingers(from + ((to - from) * i) / 10) });
    await page.waitForTimeout(16);
  }
  await cdp.send("Input.dispatchTouchEvent", { type: "touchEnd", touchPoints: [] });
  await cdp.detach();
}

/**
 * Pinches to twice the spread about a point `dx` px into the feature, and
 * checks the feature's top-left corner went where scaling by two about that
 * point puts it: the point stayed under the fingers, and the scale is the
 * fingers'. With `whole`, the feature is on screen whole after, and twice as
 * wide.
 */
async function zoomsAbout(page: Page, frame: Locator, feature: Test, dx: number, whole: boolean) {
  const before = await locate(frame, feature);
  const ax = before.x + dx;
  const ay = before.cy;
  await pinch(page, ax, ay, 60, 120);
  // Settled: the same picture twice in a row.
  await expect
    .poll(async () => {
      const a = await locate(frame, feature);
      await page.waitForTimeout(200);
      const b = await locate(frame, feature);
      return Math.abs(a.x - b.x) + Math.abs(a.y - b.y);
    })
    .toBeLessThan(1);
  const after = await locate(frame, feature);
  expect(after.x, "the anchor drifted across").toBeCloseTo(ax - 2 * (ax - before.x), -1);
  expect(after.y, "the anchor drifted up or down").toBeCloseTo(ay - 2 * (ay - before.y), -1);
  if (whole) {
    expect(after.width / before.width).toBeGreaterThan(1.85);
    expect(after.width / before.width).toBeLessThan(2.15);
  }
}

test("a pinch on an image zooms about the fingers", async ({ page }) => {
  await open(page, "landscape.png");
  const frame = page.locator(".demo-frame .exav-viewer-surface");
  const sun = await locate(frame, SUN);
  await zoomsAbout(page, frame, SUN, sun.width / 2, true);
});

test("a pinch on a PDF zooms about the fingers", async ({ page }) => {
  await open(page, "report.pdf");
  await zoomsAbout(page, page.locator(".demo-frame .exav-viewer-surface"), RULE, 30, false);
});

test("a pinch on a drawing zooms about the fingers", async ({ page }) => {
  await open(page, "plan.dwg");
  // The column alone: the walls' antialiased edges are as grey as it is.
  await page.getByRole("button", { name: "None" }).click();
  await page.locator(".exav-viewer-layer", { hasText: "COLUMNS" }).getByRole("checkbox").check();
  await page.waitForTimeout(300);
  // About a point well left of the column, which sits near the middle of the
  // canvas, where zooming about the fingers and about the centre agree.
  await zoomsAbout(page, page.locator(".demo-frame .exav-viewer-cad-canvas"), COLUMN, -150, true);
});

// A frame drawn per event queues behind the last on a large drawing, and the
// zoom lags seconds behind the fingers: while the events go on the canvas is
// scaled where it is (a CSS transform), and a sharp frame follows the pause.
test("a ctrl and wheel zoom on a drawing scales the canvas, and draws sharp once it pauses", async ({ page }) => {
  await open(page, "plan.dwg");
  const result = await page.evaluate(async () => {
    const canvas = document.querySelector<HTMLCanvasElement>(".demo-frame .exav-viewer-cad-canvas")!;
    const gl = canvas.getContext("webgl2")!;
    // A frame clears colour and depth together; nothing else here does.
    let frames = 0;
    const clear = gl.clear.bind(gl);
    gl.clear = (mask: number) => {
      if (mask & gl.DEPTH_BUFFER_BIT) frames++;
      clear(mask);
    };
    const at = canvas.getBoundingClientRect();
    const init = { deltaY: -3, ctrlKey: true, clientX: at.left + at.width / 2, clientY: at.top + at.height / 2, bubbles: true, cancelable: true };
    // A third of a second of events, a frame apart: short of the pause after which a sharp frame is drawn anyway.
    for (let i = 0; i < 20; i++) {
      canvas.dispatchEvent(new WheelEvent("wheel", init));
      await new Promise((r) => setTimeout(r, 17));
    }
    const during = { frames, transform: canvas.style.transform };
    await new Promise((r) => setTimeout(r, 500));
    return { during, after: { frames, transform: canvas.style.transform } };
  });
  // Not a frame per event, but the canvas moved to where the camera is.
  expect(result.during.frames).toBeLessThanOrEqual(2);
  expect(result.during.transform).toMatch(/^translate\(.*\) scale\(1\.[0-9]+\)$/);
  // Then one sharp frame, and the canvas as drawn.
  expect(result.after.frames - result.during.frames).toBeGreaterThanOrEqual(1);
  expect(result.after.frames - result.during.frames).toBeLessThanOrEqual(2);
  expect(result.after.transform).toBe("");
});

// Safari reports a trackpad pinch as gesture events, whose scale is the total
// since the start, and may send ctrl+wheel events for the same pinch.
test("Safari's gesture events zoom a drawing by their scale, once", async ({ page }) => {
  await open(page, "plan.dwg");
  const scale = await page.evaluate(async () => {
    const canvas = document.querySelector<HTMLCanvasElement>(".demo-frame .exav-viewer-cad-canvas")!;
    const at = canvas.getBoundingClientRect();
    const pos = { clientX: at.left + at.width / 2, clientY: at.top + at.height / 2, bubbles: true, cancelable: true };
    const gesture = (type: string, scale: number) =>
      canvas.dispatchEvent(Object.assign(new Event(type, { bubbles: true, cancelable: true }), { scale, clientX: pos.clientX, clientY: pos.clientY }));
    gesture("gesturestart", 1);
    for (let i = 1; i <= 10; i++) {
      gesture("gesturechange", 1 + i * 0.1);
      canvas.dispatchEvent(new WheelEvent("wheel", { ...pos, deltaY: -3, ctrlKey: true }));
      await new Promise((r) => setTimeout(r, 17));
    }
    const k = /scale\(([0-9.]+)\)/.exec(canvas.style.transform)?.[1];
    gesture("gestureend", 2);
    return Number(k);
  });
  expect(scale).toBeGreaterThan(1.9);
  expect(scale).toBeLessThan(2.1);
});

test("ctrl and the wheel, a desktop trackpad's pinch, zoom a PDF about the cursor and not the page", async ({ page }) => {
  await open(page, "report.pdf");
  const frame = page.locator(".demo-frame .exav-viewer-surface");
  const before = await locate(frame, RULE);
  await page.mouse.move(before.cx, before.cy);
  await page.keyboard.down("Control");
  for (let i = 0; i < 5; i++) await page.mouse.wheel(0, -40);
  await page.keyboard.up("Control");
  await page.waitForTimeout(800);
  const after = await locate(frame, RULE);
  expect(Math.abs(after.cx - before.cx)).toBeLessThan(8);
  expect(Math.abs(after.cy - before.cy)).toBeLessThan(8);
  expect(after.width).toBeGreaterThan(before.width * 1.2);
  // The page around the viewer did not zoom.
  expect(await page.evaluate(() => window.visualViewport?.scale ?? 1)).toBe(1);
});
