// Messages over the sandboxed frame's port that the other specs do not see.
// The viewport is worked out only while something follows or reads it: a
// session that does not use it costs nothing for it (no second copy of the
// workbook, no layout measured), and the host asks the frame to follow it
// (`watch`) from the first listener to the last (`unwatch`). A request for a
// picture that is none is answered `invalid`.
//
// The host's side of the port is recorded from the page: every message it
// sends and every message it gets.
import { expect, test, type Frame, type Page } from "@playwright/test";

import { failOnViolations } from "./csp.js";
import { openSample } from "./samples.js";

failOnViolations();

interface Message {
  type?: string;
  key?: string;
  session?: number;
  id?: number;
  result?: { ok: boolean; code?: string };
}
interface Recorded {
  __sent: Message[];
  __got: Message[];
  __port: MessagePort | undefined;
  __seen: unknown[];
  __stops: (() => void)[];
  exavDemo: { session(): { controllers: { get(): Controllers } } };
}
interface Controllers {
  viewport: { get(): Viewport; subscribe(f: (v: Viewport) => void): () => void };
  zoom?: { setScale(n: number): void };
}
type Viewport = { space: string; page: number; region: { x: number; y: number; width: number; height: number } } | null;

test.beforeEach(async ({ page }) => {
  await page.addInitScript(() => {
    // The page only: the frame has the same script run in it.
    if (window !== window.top) return;
    const w = window as unknown as Recorded;
    w.__sent = [];
    w.__got = [];
    w.__seen = [];
    w.__stops = [];
    const post = MessagePort.prototype.postMessage as (this: MessagePort, ...a: unknown[]) => void;
    const listening = new WeakSet<MessagePort>();
    (MessagePort.prototype as unknown as { postMessage: unknown }).postMessage = function (this: MessagePort, ...args: unknown[]) {
      const m = args[0] as Message | null;
      if (m && typeof m === "object" && typeof m.type === "string") {
        w.__sent.push({ type: m.type, key: m.key, session: m.session, id: m.id });
        w.__port = this;
        if (!listening.has(this)) {
          listening.add(this);
          this.addEventListener("message", (e) => {
            const d = e.data as Message | null;
            if (d && typeof d === "object") w.__got.push({ type: d.type, key: d.key, session: d.session, id: d.id, result: d.result });
          });
        }
      }
      return post.apply(this, args);
    };
  });
});

/** What the host sent of `types`, with the frame's numbers. */
const sent = (page: Page, ...types: string[]) =>
  page.evaluate((types) => (window as unknown as Recorded).__sent.filter((m) => types.includes(m.type!)).map((m) => `${m.type}:${m.session}:${m.key}`), types);

/** The `state` messages for the viewport the frame has sent. */
const reported = (page: Page) => page.evaluate(() => (window as unknown as Recorded).__got.filter((m) => m.type === "state" && m.key === "viewport").length);

async function open(page: Page, name: string): Promise<void> {
  await openSample(page, name);
  await expect(page.locator(".demo-frame .exav-viewer-body")).toHaveAttribute("data-phase", "ready");
  await page.waitForFunction(() => !!(window as unknown as Recorded).exavDemo?.session()?.controllers.get().viewport);
}

const frameOf = async (page: Page): Promise<Frame> => {
  const frame = await (await page.locator(".demo-frame iframe.exav-viewer-sandbox").elementHandle())!.contentFrame();
  if (!frame) throw new Error("no frame");
  return frame;
};

/** Follows the viewport as a consumer would; `n` is the listener's number. */
const follow = (page: Page) =>
  page.evaluate(() => {
    const w = window as unknown as Recorded;
    w.__stops.push(w.exavDemo.session().controllers.get().viewport.subscribe((v) => w.__seen.push(v)));
    return w.__stops.length;
  });
const leave = (page: Page, n: number) => page.evaluate((n) => (window as unknown as Recorded).__stops[n - 1]!(), n);
const zoom = (page: Page, scale: number) => page.evaluate((scale) => (window as unknown as Recorded).exavDemo.session().controllers.get().zoom!.setScale(scale), scale);

const FILES = ["report.pdf", "notes.docx", "visit.pptx", "quote.xlsx", "quote.csv", "landscape.png", "plan.dxf"];

for (const name of FILES) {
  test(`${name}: a session that does not use the viewport never watches it`, async ({ page }) => {
    await open(page, name);
    await page.waitForTimeout(1000);
    expect(await sent(page, "watch", "unwatch")).toEqual([]);
    expect(await reported(page)).toBe(0);
  });
}

test("a spreadsheet opens no second copy of the workbook until its viewport is wanted", async ({ page }) => {
  const workers: string[] = [];
  page.on("worker", (w) => workers.push(w.url()));
  await open(page, "quote.xlsx");
  await page.waitForTimeout(1500);
  await zoom(page, 1.5);
  await page.waitForTimeout(500);
  expect(workers).toHaveLength(1);
  await follow(page);
  await expect.poll(() => workers.length).toBe(2);
});

test("a Word document measures no page until its viewport is wanted", async ({ page }) => {
  await open(page, "notes.docx");
  const frame = await frameOf(page);
  // The text layers the view is read from.
  await frame.evaluate(() => {
    const w = window as unknown as { __reads: number };
    w.__reads = 0;
    const original = Element.prototype.getBoundingClientRect;
    Element.prototype.getBoundingClientRect = function (this: Element) {
      if ((this as HTMLElement).dataset?.overlay === "text") w.__reads++;
      return original.call(this);
    };
  });
  const reads = () => frame.evaluate(() => (window as unknown as { __reads: number }).__reads);
  await zoom(page, 1.5);
  await frame.evaluate(() => document.querySelector(".exav-viewer-office")!.dispatchEvent(new Event("scroll")));
  await page.waitForTimeout(500);
  expect(await reads()).toBe(0);
  const stop = await follow(page);
  await expect.poll(reads).toBeGreaterThan(0);
  await leave(page, stop);
  await expect.poll(() => sent(page, "unwatch")).toHaveLength(1);
  const after = await reads();
  await zoom(page, 1);
  await frame.evaluate(() => document.querySelector(".exav-viewer-office")!.dispatchEvent(new Event("scroll")));
  await page.waitForTimeout(500);
  expect(await reads()).toBe(after);
});

test("the frame follows the viewport from the first listener to the last, and not after", async ({ page }) => {
  await open(page, "quote.xlsx");
  const first = await follow(page);
  await expect.poll(() => sent(page, "watch", "unwatch")).toEqual(["watch:0:viewport"]);
  // Measured on the second copy, then reported.
  await expect.poll(() => page.evaluate(() => (window as unknown as Recorded).__seen.at(-1) as Viewport)).toMatchObject({ space: "page", page: 1 });
  const second = await follow(page);
  await page.waitForTimeout(300);
  expect(await sent(page, "watch", "unwatch")).toEqual(["watch:0:viewport"]);
  // Followed: the zoom moves the view, and the host hears of it.
  const before = await reported(page);
  await zoom(page, 2);
  await expect.poll(() => reported(page)).toBeGreaterThan(before);
  await leave(page, first);
  await page.waitForTimeout(300);
  expect(await sent(page, "unwatch")).toEqual([]);
  await leave(page, second);
  await expect.poll(() => sent(page, "watch", "unwatch")).toEqual(["watch:0:viewport", "unwatch:0:viewport"]);
  // Nobody follows: the frame says nothing more of it.
  await page.waitForTimeout(500);
  const quiet = await reported(page);
  await zoom(page, 1);
  await page.waitForTimeout(1000);
  expect(await reported(page)).toBe(quiet);
  // Followed again later: watched again.
  await follow(page);
  await expect.poll(() => sent(page, "watch")).toHaveLength(2);
});

test("a read with no listener has the viewport, each read asking the frame for the next", async ({ page }) => {
  await open(page, "report.pdf");
  const read = () => page.evaluate(() => (window as unknown as Recorded).exavDemo.session().controllers.get().viewport.get());
  // The first read has what the frame has not told yet; the next has the answer.
  await expect.poll(read).toMatchObject({ space: "page", page: 1 });
  const view = (await read())!;
  expect(view.region.x).toBeGreaterThanOrEqual(0);
  expect(view.region.y).toBeGreaterThanOrEqual(0);
  expect(view.region.width).toBeGreaterThan(0);
  expect(view.region.x + view.region.width).toBeLessThanOrEqual(1.0001);
  expect(view.region.y + view.region.height).toBeLessThanOrEqual(1.0001);
  const told = await sent(page, "watch", "unwatch");
  expect(told.length).toBeGreaterThanOrEqual(2);
  expect(told.length % 2).toBe(0);
  // Each read asked and let go at once: they pair up.
  expect(told.filter((m) => m.startsWith("watch")).length).toBe(told.filter((m) => m.startsWith("unwatch")).length);
  expect(told.every((m, i) => m === (i % 2 === 0 ? "watch:0:viewport" : "unwatch:0:viewport"))).toBe(true);
  expect(await reported(page)).toBeGreaterThan(0);
});

test("a request for a picture that is none is answered invalid, not left waiting", async ({ page }) => {
  await open(page, "report.pdf");
  const answers = await page.evaluate(async () => {
    const w = window as unknown as Recorded;
    const port = w.__port!;
    const ask = (id: number, message: Record<string, unknown>) =>
      new Promise<string>((resolve) => {
        const timer = setTimeout(() => resolve("no answer"), 5000);
        port.addEventListener("message", function listener(e) {
          const d = e.data as Message;
          if (d?.type !== "rastered" || d.id !== id) return;
          clearTimeout(timer);
          port.removeEventListener("message", listener);
          resolve(d.result!.ok ? "drawn" : d.result!.code!);
        });
        port.postMessage({ type: "raster", id, session: 0, page: 1, ...message });
      });
    return {
      size: await ask(9001, { options: { longEdge: -5 } }),
      colour: await ask(9002, { options: { longEdge: 100, background: "url(https://example.test/x)" } }),
      none: await ask(9003, {}),
      page: await ask(9004, { page: 0, options: { longEdge: 100 } }),
      fine: await ask(9005, { options: { longEdge: 100 } }),
    };
  });
  expect(answers).toEqual({ size: "invalid", colour: "invalid", none: "invalid", page: "invalid", fine: "drawn" });
});
