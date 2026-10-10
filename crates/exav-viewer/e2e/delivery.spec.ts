// How a file's bytes reach the sandboxed frame (ts/frame/delivery.ts), seen
// from the network: who fetched what, in which ranges, how much of the file.
// The files are made by delivery-setup.ts and served by the demo's `vite
// preview` under /e2e/, with range requests (/e2e/whole/: without; /e2e/paced/:
// slowly).
import fs from "node:fs";
import path from "node:path";

import { expect, test, type Frame, type Page } from "@playwright/test";

import { failOnViolations, violations } from "./csp.js";
import { OUT, PDF_PAGES, SPACED_MEMBERS, ZIP_PICTURE } from "./delivery-setup.js";

failOnViolations();

const size = (name: string) => fs.statSync(path.join(OUT, name)).size;

/** Another origin than the demo's: the same server under its other loopback name. */
function elsewhere(): string {
  const url = new URL(test.info().project.use.baseURL!);
  url.hostname = url.hostname === "127.0.0.1" ? "localhost" : "127.0.0.1";
  return url.origin;
}

interface Fetched {
  url: string;
  status: number;
  range: string | undefined;
  /** Bytes the response carried, by its Content-Length. */
  length: number;
  /** Asked by the frame's document, not the host page's. */
  byFrame: boolean;
}

/** Every response for the path `pathname`, as it arrives. */
function record(page: Page, pathname: string): Fetched[] {
  const seen: Fetched[] = [];
  page.on("response", async (r) => {
    if (new URL(r.url()).pathname !== pathname) return;
    const request = r.request();
    const headers = await request.allHeaders().catch(() => request.headers());
    seen.push({
      url: r.url(),
      status: r.status(),
      range: headers.range,
      length: Number(r.headers()["content-length"] ?? 0),
      byFrame: request.frame().url().includes("/frame/"),
    });
  });
  return seen;
}

const total = (seen: Fetched[]) => seen.reduce((n, f) => n + f.length, 0);

async function open(page: Page, query: string, phase = "ready"): Promise<void> {
  await page.goto(`./?lang=en&${query}`);
  await expect(page.locator(".demo-frame .exv-body")).toHaveAttribute("data-phase", phase);
}

async function inside(page: Page): Promise<Frame> {
  const frame = await (await page.locator(".demo-frame iframe.exv-sandbox").elementHandle())!.contentFrame();
  if (!frame) throw new Error("no frame");
  return frame;
}

/** The first page's bitmap, once pdf.js has drawn into it (300 x 150 is a new canvas's size). */
async function firstPageDrawn(page: Page): Promise<void> {
  const frame = page.frameLocator(".demo-frame iframe.exv-sandbox");
  const canvas = frame.locator(".exv-pdf-bitmap").first();
  await expect.poll(() => canvas.evaluate((c: HTMLCanvasElement) => `${c.width}x${c.height}`)).not.toBe("300x150");
  await expect(frame.locator(".exv-pdf-page")).toHaveCount(PDF_PAGES);
}

test.describe("media by URL", () => {
  const playable = (frame: Frame) => frame.evaluate(() => document.createElement("video").canPlayType('video/webm; codecs="vp8"') !== "");

  /** Plays, then seeks near the end and plays on. */
  async function playAndSeek(frame: Frame): Promise<void> {
    const video = frame.locator(".exv-media video");
    await expect.poll(() => video.evaluate((v: HTMLVideoElement) => v.readyState)).toBeGreaterThanOrEqual(1);
    const duration = await video.evaluate((v: HTMLVideoElement) => v.duration);
    expect(duration).toBeGreaterThan(8);
    // A click is the user activation the frame's policy asks of a player.
    await video.click();
    await video.evaluate((v: HTMLVideoElement) => {
      v.muted = true;
      return v.play();
    });
    await expect.poll(() => video.evaluate((v: HTMLVideoElement) => v.currentTime)).toBeGreaterThan(0.3);
    await video.evaluate(
      (v: HTMLVideoElement) =>
        new Promise((resolve) => {
          v.addEventListener("seeked", resolve, { once: true });
          v.currentTime = v.duration - 3;
        }),
    );
    const at = await video.evaluate((v: HTMLVideoElement) => v.currentTime);
    expect(at).toBeGreaterThan(duration - 4);
    await expect.poll(() => video.evaluate((v: HTMLVideoElement) => v.currentTime)).toBeGreaterThan(at + 0.3);
  }

  test("a video on the media origin plays and seeks, fetched by the frame's player in ranges", async ({ page }) => {
    // Paced: from loopback the player can get the whole file before it reads
    // the end, and then asks no range at all.
    const seen = record(page, "/e2e/paced/clip.webm");
    await open(page, "url=/e2e/paced/clip.webm");
    const frame = await inside(page);
    test.skip(!(await playable(frame)), "this browser plays no VP8");
    expect(await frame.locator(".exv-media video").evaluate((v: HTMLVideoElement) => v.src)).toBe(new URL("/e2e/paced/clip.webm", page.url()).href);
    await playAndSeek(frame);
    expect(seen.length).toBeGreaterThan(0);
    for (const f of seen) {
      expect(f.byFrame, f.url).toBe(true);
      expect(new URL(f.url).origin).toBe(new URL(page.url()).origin);
      // WebKit's player starts with a plain request; every range asked is answered as one.
      if (f.range) expect(f.status, f.range).toBe(206);
    }
    // Bytes past the start were asked in a range: the seek index at the end of
    // the file (Chromium, Firefox), or the seek's target (WebKit).
    const pastStart = (f: Fetched) => f.status === 206 && Number(/^bytes=(\d+)-/.exec(f.range ?? "")?.[1]) > 0;
    expect(seen.some(pastStart), JSON.stringify(seen)).toBe(true);
  });

  test('with "blob" delivery, the host downloads it and the frame plays its copy', async ({ page }) => {
    const seen = record(page, "/e2e/clip.webm");
    await open(page, "url=/e2e/clip.webm&delivery=media:blob");
    const frame = await inside(page);
    test.skip(!(await playable(frame)), "this browser plays no VP8");
    expect(await frame.locator(".exv-media video").evaluate((v: HTMLVideoElement) => v.src)).toMatch(/^blob:/);
    await playAndSeek(frame);
    expect(seen.map((f) => [f.byFrame, f.status])).toEqual([[false, 200]]);
    expect(total(seen)).toBe(size("clip.webm"));
  });

  test("a URL on another origin is refused by the host, and blocked by the frame's policy if tried", async ({ page }) => {
    const other = elsewhere();
    const asked: string[] = [];
    page.on("request", (r) => r.url().startsWith(other) && asked.push(r.url()));
    await open(page, `url=${other}/e2e/clip.webm&delivery=media:url`, "error");
    await expect(page.locator(".demo-frame iframe.exv-sandbox")).toHaveCount(0);
    expect(asked).toEqual([]);

    // Given to an element in the frame all the same, it is not fetched.
    await open(page, "url=/e2e/clip.webm");
    const frame = await inside(page);
    await frame.evaluate((u) => {
      const v = document.createElement("video");
      v.src = u;
      document.body.append(v);
    }, `${other}/e2e/clip.webm`);
    await page.waitForTimeout(1000);
    expect(asked).toEqual([]);
    const blocked = violations(page).splice(0);
    expect(blocked.length).toBeGreaterThan(0);
    expect(blocked.every((v) => v.includes("media-src") && v.includes(new URL(other).host))).toBe(true);
  });

  test("an image by URL is shown without CORS, unreadable in the frame, and zooms", async ({ page }) => {
    const seen = record(page, "/e2e/samples/landscape.png");
    await open(page, "url=/e2e/samples/landscape.png");
    const frame = await inside(page);
    const img = frame.locator(".exv-image-picture");
    expect(await img.evaluate((i: HTMLImageElement) => [i.src, i.crossOrigin, i.naturalWidth > 0])).toEqual([new URL("/e2e/samples/landscape.png", page.url()).href, null, true]);
    expect(seen.map((f) => f.byFrame)).toEqual([true]);
    // Drawn into a canvas, it taints it: nothing in the frame reads its pixels.
    const read = await frame.evaluate(() => {
      const i = document.querySelector<HTMLImageElement>(".exv-image-picture")!;
      const c = document.createElement("canvas");
      c.width = c.height = 4;
      const ctx = c.getContext("2d")!;
      ctx.drawImage(i, 0, 0, 4, 4);
      try {
        ctx.getImageData(0, 0, 1, 1);
        return "read";
      } catch (e) {
        return (e as Error).name;
      }
    });
    expect(read).toBe("SecurityError");
    // The surface zooms it as any picture.
    const scale = () => img.evaluate((i) => getComputedStyle(i.parentElement!).transform);
    const before = await scale();
    const box = (await page.locator(".demo-frame iframe.exv-sandbox").boundingBox())!;
    await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2);
    await page.mouse.wheel(0, -300);
    await expect.poll(scale).not.toBe(before);
  });
});

test.describe("PDF", () => {
  test("by ranges: page 1 shows after the host has read part of the file", async ({ page }) => {
    const seen = record(page, "/e2e/big.pdf");
    await open(page, "url=/e2e/big.pdf");
    await firstPageDrawn(page);
    // pdf.js asks for nothing it does not draw: still part of the file a moment later.
    await page.waitForTimeout(1000);
    expect(seen.every((f) => !f.byFrame && f.status === 206 && /^bytes=\d+-\d+$/.test(f.range ?? ""))).toBe(true);
    expect(total(seen)).toBeLessThan(size("big.pdf") * 0.4);
  });

  test("from a server that answers no range request, the host downloads it whole and says so", async ({ page }) => {
    const warned: string[] = [];
    page.on("console", (m) => m.type() === "warning" && warned.push(m.text()));
    const seen = record(page, "/e2e/whole/big.pdf");
    await open(page, "url=/e2e/whole/big.pdf");
    await firstPageDrawn(page);
    expect(seen.map((f) => [f.byFrame, f.status])).toEqual([[false, 200]]);
    expect(total(seen)).toBe(size("big.pdf"));
    expect(warned.some((w) => w.includes("does not answer range requests"))).toBe(true);
    await expect(page.locator(".demo-frame .exv-warnings")).toHaveText("The server does not send parts of the file: all of it was downloaded.");
  });

  test('by "url": pdf.js in the frame fetches it from the connect origin', async ({ page }) => {
    const seen = record(page, "/e2e/big.pdf");
    await open(page, "url=/e2e/big.pdf&delivery=pdf:url");
    await firstPageDrawn(page);
    expect(seen.length).toBeGreaterThan(0);
    expect(seen.every((f) => f.byFrame)).toBe(true);
  });

  test('by "url", an address on another origin is refused by the host', async ({ page }) => {
    const other = elsewhere();
    const asked: string[] = [];
    page.on("request", (r) => r.url().startsWith(other) && asked.push(r.url()));
    await open(page, `url=${other}/e2e/big.pdf&delivery=pdf:url`, "error");
    expect(asked).toEqual([]);
  });

  test("the host refuses reads past the file or the limits, and answers the others", async ({ page }) => {
    // The frame's end of the port, kept where the test can reach it.
    await page.addInitScript(() => {
      if (self.origin !== "null") return;
      const add = window.addEventListener.bind(window);
      window.addEventListener = ((type: string, listener: EventListener, options?: AddEventListenerOptions) =>
        add(
          type,
          type === "message"
            ? (e: Event) => {
                const port = (e as MessageEvent).ports?.[0];
                if (port) (window as unknown as { testPort: MessagePort }).testPort = port;
                listener(e);
              }
            : listener,
          options,
        )) as typeof window.addEventListener;
    });
    await open(page, "url=/e2e/big.pdf");
    const frame = await inside(page);
    const file = size("big.pdf");
    const answers = await frame.evaluate(
      ([file]) =>
        new Promise<Record<string, string>>((resolve) => {
          const port = (window as unknown as { testPort: MessagePort }).testPort;
          const reads: [number, number, number][] = [
            [9001, -1, 10],
            [9002, 0, 0],
            [9003, file - 10, 11],
            [9004, file, 1],
            [9005, 0, 4 * 1024 * 1024 + 1],
            [9006, 2 ** 40, 1],
            [9010, 2 ** 60, 1],
            [9007, 0.5, 10],
            [9008, file - 10, 10],
          ];
          const out: Record<string, string> = {};
          port.addEventListener("message", (e: MessageEvent) => {
            const m = e.data as { type: string; id: number; data?: ArrayBuffer; error?: string };
            if (m.type !== "bytes" || m.id < 9000) return;
            out[m.id] = m.data ? `${m.data.byteLength} bytes` : m.error!;
            if (Object.keys(out).length === 6) setTimeout(() => resolve(out), 300);
          });
          for (const [id, offset, length] of reads) port.postMessage({ type: "read", id, offset, length });
        }),
      [file],
    );
    // Not whole numbers within 2^53 (-1, 0.5, 2^60): not even a message the host reads.
    expect(answers).toEqual({ 9002: "refused", 9003: "refused", 9004: "refused", 9005: "refused", 9008: "10 bytes", 9006: "refused" });
  });
});

test.describe("archives", () => {
  test("by ranges: a ZIP is listed, and a member opened, without the host reading the archive", async ({ page }) => {
    const seen = record(page, "/e2e/big.zip");
    await open(page, "url=/e2e/big.zip");
    const body = page.locator(".demo-frame");
    await expect(body.locator(".exv-archive-head")).toHaveText("16 files");
    expect(seen.every((f) => !f.byFrame && f.status === 206)).toBe(true);
    // Its start, its end, the 64 KiB block of each member's local header.
    expect(total(seen)).toBeLessThan(size("big.zip") * 0.1);
    await body.getByRole("button", { name: new RegExp(ZIP_PICTURE.replace(".", "\\.")) }).click();
    await expect(page.locator(".demo-frame .exv-body").last()).toHaveAttribute("data-phase", "ready");
    await expect(page.frameLocator(".demo-frame iframe.exv-sandbox").locator(".exv-image-picture")).toHaveCount(1);
    expect(total(seen)).toBeLessThan(size("big.zip") * 0.2);
    await expect(page.locator(".demo-frame .exv-warnings")).toHaveCount(0);
  });

  test("a ZIP the ranged reader cannot list is read whole instead, and listed", async ({ page }) => {
    const warned: string[] = [];
    page.on("console", (m) => m.type() === "warning" && warned.push(m.text()));
    const seen = record(page, "/e2e/spaced.zip");
    await open(page, "url=/e2e/spaced.zip");
    await expect(page.locator(".demo-frame .exv-archive-head")).toHaveText(`${SPACED_MEMBERS} files`);
    expect(warned.some((w) => w.includes("could not be read by ranges"))).toBe(true);
    // Still read by the host, by ranges: the server answers them. All of it, this time.
    expect(seen.every((f) => !f.byFrame && f.status === 206)).toBe(true);
    expect(total(seen)).toBeGreaterThanOrEqual(size("spaced.zip"));
  });
});
