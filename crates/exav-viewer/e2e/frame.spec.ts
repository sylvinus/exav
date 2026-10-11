// The sandboxed frame's guarantees, asserted from inside it: what a hostile
// file's code would find if it ran there. Run in every browser Playwright has
// here (playwright.config.ts), with the frame served with its headers and
// again with its meta policy alone, as a static host without headers
// (GitHub Pages) serves it.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { expect, test, type Frame, type Page } from "@playwright/test";

import { failOnViolations, violations } from "./csp.js";
import { decodePng, difference, type Pixels } from "./pixels.js";
import { openSample, pick } from "./samples.js";

const here = path.dirname(fileURLToPath(import.meta.url));

/** Another origin than the demo's: the same server under its other loopback name. */
function elsewhere(page: Page): string {
  const url = new URL(page.url());
  url.hostname = url.hostname === "127.0.0.1" ? "localhost" : "127.0.0.1";
  return url.origin;
}

failOnViolations();

async function open(page: Page, name: string): Promise<Frame> {
  await openSample(page, name);
  await expect(page.locator(".demo-frame .exv-body")).toHaveAttribute("data-phase", "ready");
  return inside(page);
}

/** The document of the frame the demo shows. */
async function inside(page: Page): Promise<Frame> {
  const frame = await (await page.locator(".demo-frame iframe.exv-sandbox").elementHandle())!.contentFrame();
  if (!frame) throw new Error("no frame");
  return frame;
}

/**
 * Runs `f(arg)` in the frame, in a task of the frame's own (code evaluated by
 * the test driver is exempt from the policy's eval rules), and returns what
 * it threw, by name, or "ran".
 */
const attempt = (frame: Frame, f: (arg: string) => unknown, arg = "") =>
  frame.evaluate(
    `new Promise((done) => setTimeout(async () => { try { await (${f.toString()})(${JSON.stringify(arg)}); done("ran"); } catch (e) { done((e && e.name) || String(e)); } }, 0))`,
  ) as Promise<string>;

for (const served of ["headers", "meta"] as const) {
  test.describe(served === "headers" ? "served with its headers" : "served with its meta policy alone", () => {
    if (served === "meta") {
      test.beforeEach(async ({ page }) => {
        await page.route(/\/frame\//, async (route) => {
          try {
            const response = await route.fetch();
            const headers = response.headers();
            for (const h of ["content-security-policy", "permissions-policy", "referrer-policy"]) delete headers[h];
            await route.fulfill({ response, headers });
          } catch {
            // The frame went away while its file was in flight (a navigation
            // of the page): nothing is waiting for it.
          }
        });
      });
    }

    test("the frame is an iframe sandboxed to scripts, in an opaque origin", async ({ page }) => {
      const frame = await open(page, "report.pdf");
      const iframe = page.locator(".demo-frame iframe.exv-sandbox");
      await expect(iframe).toHaveAttribute("sandbox", "allow-scripts");
      await expect(iframe).toHaveAttribute("allow", "");
      await expect(iframe).toHaveAttribute("referrerpolicy", "no-referrer");
      expect(await frame.evaluate(() => [self.origin, document.referrer])).toEqual(["null", ""]);
    });

    test("it holds nothing of the page: no cookie, no storage, no access to its parent", async ({ page }) => {
      await page.goto("./?lang=en");
      await page.evaluate(() => {
        document.cookie = "session=secret; path=/";
        localStorage.setItem("token", "secret");
      });
      const frame = await open(page, "report.pdf");
      expect(await attempt(frame, () => document.cookie)).toBe("SecurityError");
      expect(await attempt(frame, () => localStorage.getItem("token"))).toBe("SecurityError");
      expect(await attempt(frame, () => sessionStorage.length)).toBe("SecurityError");
      expect(await attempt(frame, () => parent.document.title)).toBe("SecurityError");
      expect(await attempt(frame, () => parent.location.href)).toBe("SecurityError");
      expect(
        await attempt(
          frame,
          () =>
            new Promise((resolve, reject) => {
              const r = indexedDB.open("x");
              r.onsuccess = resolve;
              r.onerror = () => reject(r.error);
            }),
        ),
      ).not.toBe("ran");
    });

    test("it runs no code made of strings", async ({ page }) => {
      const frame = await open(page, "report.pdf");
      expect(await attempt(frame, () => eval("1"))).toBe("EvalError");
      expect(await attempt(frame, () => new Function("return 1")())).toBe("EvalError");
      expect(
        await attempt(frame, () => {
          const url: string = "data:text/javascript,export default 1";
          return import(url);
        }),
      ).not.toBe("ran");
      // Refused, by throwing (Trusted Types) or quietly (the policy alone).
      await attempt(frame, () => setTimeout("window.ranFromString = true", 0));
      await page.waitForTimeout(300);
      expect(await frame.evaluate(() => (window as unknown as { ranFromString?: boolean }).ranFromString ?? false)).toBe(false);
      // Refused, and reported: these violations are the test's own.
      const ours = violations(page).splice(0);
      expect(ours.filter((v) => !/script-src|eval|trusted-types-sink/.test(v))).toEqual([]);
    });

    test("Trusted Types let no markup or script URL into the frame's sinks", async ({ page }) => {
      const frame = await open(page, "report.pdf");
      expect(await attempt(frame, () => (document.body.innerHTML = '<img src="x" onerror="window.pwned = true">'))).toBe("TypeError");
      expect(await attempt(frame, () => document.body.insertAdjacentHTML("beforeend", "<b>x</b>"))).toBe("TypeError");
      expect(await attempt(frame, () => (document.createElement("script").src = "/x.js"))).toBe("TypeError");
      expect(await attempt(frame, () => new DOMParser().parseFromString("<b>x</b>", "text/html"))).toBe("TypeError");
      // A worker only from the frame's own scripts, through its policy.
      expect(await attempt(frame, () => new Worker("/e2e/big.pdf"))).toBe("TypeError");
      expect(await attempt(frame, () => new (Object.getPrototypeOf(Worker) as typeof Worker)("/frame/cad.worker.js"))).toBe("TypeError");
      // What the engines write is let through: inert SVG.
      expect(await attempt(frame, () => (document.createElement("div").innerHTML = '<svg viewBox="0 0 1 1"><path d="M0 0"/></svg>'))).toBe("ran");
      expect(await frame.evaluate(() => (window as unknown as { pwned?: boolean }).pwned ?? false)).toBe(false);
      const ours = violations(page).splice(0);
      expect(ours.filter((v) => !/trusted-types/.test(v))).toEqual([]);
    });

    test("nothing is fetched from another origin", async ({ page }) => {
      const frame = await open(page, "report.pdf");
      // Requests answered: one the policy blocks is reported as failed (and
      // Chromium reports it started). The URLs are the frame's own files,
      // served with CORS, under another host name: only the policy stands
      // between them and the frame.
      const other = elsewhere(page);
      const sent: string[] = [];
      page.on("requestfinished", (r) => r.url().startsWith(other) && sent.push(r.url()));
      const file = `${other}/frame/licenses/README.txt`;
      expect(await attempt(frame, (u) => fetch(u), file)).toBe("TypeError");
      expect(await attempt(frame, (u) => new Promise((resolve, reject) => Object.assign(new Image(), { onload: resolve, onerror: reject, src: u })), file)).not.toBe("ran");
      expect(await attempt(frame, (u) => new FontFace("x", `url(${u})`).load(), `${other}/frame/fonts/Arimo-wght.woff2`)).not.toBe("ran");
      expect(await attempt(frame, (u) => new Promise((resolve, reject) => Object.assign(new WebSocket(u), { onopen: resolve, onerror: reject })), other.replace("http", "ws"))).not.toBe("ran");
      // A beacon is queued and refused later, without a word to the caller.
      await attempt(frame, (u) => navigator.sendBeacon(u, "x"), file);
      await page.waitForTimeout(500);
      expect(sent).toEqual([]);
      const ours = violations(page).splice(0);
      expect(ours.filter((v) => !v.includes(new URL(other).host))).toEqual([]);
      expect(ours.length).toBeGreaterThan(0);
    });

    test("no popup, no navigation of the page, no download, no form", async ({ page, context }) => {
      const frame = await open(page, "report.pdf");
      const opened: string[] = [];
      context.on("page", (p) => opened.push(p.url()));
      const downloads: string[] = [];
      page.on("download", (d) => downloads.push(d.url()));
      const other = `${elsewhere(page)}/`;
      const before = page.url();
      expect(await attempt(frame, (u) => (top!.location.href = u), other)).toBe("SecurityError");
      // In a task of the frame's: WebKit navigates the frame to the
      // download's blob, and the frame is gone before an evaluation returns.
      await frame.evaluate((u) => {
        setTimeout(() => {
          const a = Object.assign(document.createElement("a"), { href: u, target: "_blank" });
          document.body.append(a);
          a.click();
          const form = Object.assign(document.createElement("form"), { action: u, method: "post", target: "_blank" });
          document.body.append(form);
          form.submit();
          const d = Object.assign(document.createElement("a"), { href: URL.createObjectURL(new Blob(["x"])), download: "x.txt" });
          document.body.append(d);
          d.click();
        }, 0);
      }, other);
      await page.waitForTimeout(1000);
      expect(opened).toEqual([]);
      expect(downloads).toEqual([]);
      expect(page.url()).toBe(before);
      // Refused by the policies too: the form by the frame's, and the
      // download, which Firefox and WebKit turn into a navigation of the
      // frame to its blob, by the page's (a frame that did navigate is
      // dropped by the host, as the next test shows).
      expect(violations(page).splice(0).filter((v) => !/form-action|frame-src blob/.test(v))).toEqual([]);
    });
  });
}

test.describe("the host", () => {
  test("a link followed in a document is the host's to open, after asking", async ({ page, context }) => {
    const frame = await open(page, "report.pdf");
    const asked: string[] = [];
    let answer = false;
    page.on("dialog", (d) => {
      asked.push(d.message());
      void (answer ? d.accept() : d.dismiss());
    });
    // An engine opens a link: the frame asks the host.
    await frame.evaluate(() => window.open("https://example.com/a"));
    await expect.poll(() => asked).toEqual(["The document links to https://example.com/a. Open it in a new tab?"]);
    // Declined: nothing opened. Accepted: opened, without access back.
    answer = true;
    const popup = context.waitForEvent("page");
    await frame.evaluate(() => window.open("https://example.com/b"));
    const opened = await popup;
    expect(opened.url()).toBe("https://example.com/b");
    expect(await opened.evaluate(() => window.opener)).toBeNull();
    await opened.close();
    // Not http(s), relative, or sent around the port: never asked.
    await frame.evaluate(() => {
      window.open("javascript:alert(1)");
      window.open("/e2e/big.pdf");
      parent.postMessage({ type: "link", url: "https://example.com/c" }, "*");
    });
    await page.waitForTimeout(500);
    expect(asked).toHaveLength(2);
  });

  test("a frame that navigates itself away is dropped", async ({ page }) => {
    const frame = await open(page, "report.pdf");
    await frame.evaluate(() => (location.href = "/frame/licenses/README.txt"));
    await expect(page.locator(".demo-frame .exv-body")).toHaveAttribute("data-phase", "error");
  });

  test("one frame per file: the next file gets a new one, the last is gone", async ({ page }) => {
    await open(page, "report.pdf");
    const first = await inside(page);
    await pick(page, "landscape.tif");
    await expect(page.locator(".demo-frame .exv-body")).toHaveAttribute("data-phase", "ready");
    await expect(page.locator("iframe.exv-sandbox")).toHaveCount(1);
    expect(first.isDetached()).toBe(true);
  });
});

test.describe("formats", () => {
  // WebGL is not there in every headless browser (Firefox on arm64 Linux).
  const webgl = (page: Page) => page.evaluate(() => !!document.createElement("canvas").getContext("webgl2"));
  const SAMPLES = [
    ["report.pdf", false],
    ["landscape.tif", false],
    ["notes.docx", false],
    ["visit.pptx", false],
    ["quote.xlsx", false],
    ["quote.csv", false],
    ["chime.wav", false],
    ["delivery.zip", false],
    ["plan.dwg", true],
    ["plan.dxf", true],
    ["house.ifc", true],
    ["house.stl", true],
  ] as const;
  for (const [name, gl] of SAMPLES) {
    test(`${name} opens in the frame`, async ({ page }) => {
      await page.goto("./?lang=en");
      test.skip(gl && !(await webgl(page)), "no WebGL2 in this browser");
      await open(page, name);
    });
  }

  test("pdf.js's image decoders, replaced, draw in the frame as in the page", async ({ page }) => {
    const fixtures = path.join(here, "fixtures", "pdf-images");
    // The first page's bitmap, read off its canvas: what pdf.js drew, before
    // any compositing (and without a screenshot, which in WebKit adds a
    // style to each frame that the frame's policy refuses).
    const draw = async (pdf: string, query: string, inFrame: boolean): Promise<Pixels> => {
      await page.goto(`./?lang=en${query}`);
      await page.getByTestId("file-input").setInputFiles({ name: pdf, mimeType: "application/pdf", buffer: fs.readFileSync(path.join(fixtures, pdf)) });
      await expect(page.locator(".demo-frame .exv-body")).toHaveAttribute("data-phase", "ready");
      const canvas = (inFrame ? page.frameLocator(".demo-frame iframe.exv-sandbox") : page.locator(".demo-frame")).locator(".exv-pdf-bitmap").first();
      const read = async () => decodePng(Buffer.from((await canvas.evaluate((c: HTMLCanvasElement) => c.toDataURL("image/png"))).split(",")[1]!, "base64"));
      // Sized once pdf.js has drawn into it: 300 x 150 is a new canvas's.
      await expect.poll(() => canvas.evaluate((c: HTMLCanvasElement) => `${c.width}x${c.height}`)).not.toBe("300x150");
      let last = await read();
      for (let i = 0; i < 20; i++) {
        await page.waitForTimeout(150);
        const next = await read();
        if (next.width > 1 && next.width === last.width && next.height === last.height && difference(last, next) === 0) return next;
        last = next;
      }
      return last;
    };
    for (const pdf of ["jpx-grey.pdf", "jbig2-generic.pdf", "ccitt-g4.pdf"]) {
      const fallbacks: string[] = [];
      const listen = (r: { url(): string }) => /_nowasm_fallback\.js$/.test(r.url()) && fallbacks.push(r.url());
      page.on("request", listen);
      const framed = await draw(pdf, "", true);
      page.off("request", listen);
      // Imported by pdf.js's worker, a classic script in the frame.
      expect(fallbacks.filter((u) => u.includes("/frame/")), pdf).toHaveLength(1);
      const inPage = await draw(pdf, "&mode=page", false);
      expect([framed.width, framed.height], pdf).toEqual([inPage.width, inPage.height]);
      expect(difference(framed, inPage), pdf).toBe(0);
    }
  });
});
