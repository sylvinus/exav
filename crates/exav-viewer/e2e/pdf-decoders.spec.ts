// The PDF images pdf.js 6 decodes with C and C++ (JPXDecode with OpenJPEG,
// JBIG2Decode and CCITTFaxDecode with PDFium's decoders), drawn by the demo
// with this package's decoders in their place, and again with pdf.js's own
// .wasm served where pdf.js looks for it: the two pictures must agree. The
// PDFs and how each was made: e2e/fixtures/pdf-images/make.py. With the
// engines in the page (`?mode=page`); frame.spec.ts draws some of them in the
// sandboxed frame too.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { expect, test, type Locator, type Page } from "@playwright/test";

import { failOnViolations } from "./csp.js";
import { decodePng, difference, type Pixels } from "./pixels.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const FIXTURES = path.join(here, "fixtures", "pdf-images");
const PDFJS_WASM = path.join(here, "..", "node_modules", "pdfjs-dist", "wasm");
const DIST = path.join(here, "..", "demo", "dist");

interface Case {
  pdf: string;
  filter: "jpx" | "jbig2" | "ccitt";
}
const cases: Case[] = JSON.parse(fs.readFileSync(path.join(FIXTURES, "cases.json"), "utf8"));

const DECODER = /\/wasm-[0-9a-f]{10}\/(openjpeg|jbig2)\.wasm$/;
const FALLBACK = /\/wasm-[0-9a-f]{10}\/(openjpeg|jbig2)_nowasm_fallback\.js$/;

async function shot(target: Locator): Promise<Pixels> {
  return decodePng(await target.screenshot({ animations: "disabled" }));
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

/**
 * The PDF's page as the demo draws it. With `original`, pdf.js is handed
 * its own openjpeg.wasm or jbig2.wasm where the demo serves an empty one.
 */
async function draw(page: Page, pdf: string, original: boolean) {
  const requests: string[] = [];
  page.on("request", (r) => requests.push(r.url()));
  let served = 0;
  if (original) {
    await page.route(DECODER, (route) => {
      served++;
      const file = path.basename(new URL(route.request().url()).pathname);
      return route.fulfill({ body: fs.readFileSync(path.join(PDFJS_WASM, file)), contentType: "application/wasm" });
    });
  }
  await page.goto("./?lang=en&mode=page");
  await page.getByTestId("file-input").setInputFiles({ name: pdf, mimeType: "application/pdf", buffer: fs.readFileSync(path.join(FIXTURES, pdf)) });
  await expect(page.locator(".demo-frame .exv-body")).toHaveAttribute("data-phase", "ready");
  const pixels = await settled(page.locator(".demo-frame .exv-pdf-page").first());
  return { pixels, requests, served };
}

failOnViolations();

test.describe("pdf.js's image decoders, replaced", () => {
  for (const c of cases) {
    test(`${c.pdf} is drawn as pdf.js's own decoder draws it`, async ({ page, context }) => {
      const ours = await draw(page, c.pdf, false);
      // pdf.js tried the .wasm it was given, then imported this package's
      // module in its place.
      expect(ours.requests.filter((u) => DECODER.test(u)).length).toBe(1);
      expect(ours.requests.filter((u) => FALLBACK.test(u)).length).toBe(1);

      const other = await context.newPage();
      const theirs = await draw(other, c.pdf, true);
      // pdf.js instantiated its own module, and did not fall back.
      expect(theirs.served).toBe(1);
      expect(theirs.requests.filter((u) => FALLBACK.test(u))).toEqual([]);
      await other.close();

      // A picture, not a blank page.
      const blank = theirs.pixels.data.every((v, i) => i % 4 === 3 || v === theirs.pixels.data[0]);
      expect(blank).toBe(false);
      // Lossy JPEG 2000: rounding sets a few samples one level apart (0.0007
      // on average here).
      expect(difference(ours.pixels, theirs.pixels)).toBeLessThanOrEqual(c.pdf === "jpx-lossy.pdf" ? 0.01 : 0);
    });
  }

  test("pdf.js still loads its ICC engine from the same directory", async ({ page }) => {
    // The status and type: a static server may answer a missing file with
    // its index.html.
    const qcms: string[] = [];
    page.on("requestfinished", async (r) => {
      if (!/\/wasm-[0-9a-f]{10}\/qcms_bg\.wasm$/.test(r.url())) return;
      const res = await r.response();
      qcms.push(`${res?.status()} ${res?.headers()["content-type"]}`);
    });
    await page.goto("./?lang=en&mode=page");
    await page.getByTestId("file-input").setInputFiles({ name: "icc.pdf", mimeType: "application/pdf", buffer: fs.readFileSync(path.join(FIXTURES, "icc.pdf")) });
    await expect(page.locator(".demo-frame .exv-body")).toHaveAttribute("data-phase", "ready");
    await settled(page.locator(".demo-frame .exv-pdf-page").first());
    await expect.poll(() => qcms).toEqual(["200 application/wasm"]);
  });

  test("the built demo carries no OpenJPEG or PDFium code", () => {
    const files: string[] = [];
    const walk = (dir: string) => {
      for (const e of fs.readdirSync(dir, { withFileTypes: true })) (e.isDirectory() ? walk : (f: string) => files.push(f))(path.join(dir, e.name));
    };
    walk(DIST);
    const named = files.filter((f) => /openjpeg|jbig2|pdfium/i.test(path.basename(f))).map((f) => path.relative(DIST, f));
    // The two empty .wasm pdf.js tries first, and the two fallbacks: the
    // page's, and the sandboxed frame's.
    const four = ["jbig2.wasm", "jbig2_nowasm_fallback.js", "openjpeg.wasm", "openjpeg_nowasm_fallback.js"];
    expect(named.map((f) => path.basename(f)).sort()).toEqual(four.flatMap((f) => [f, f]));
    expect(named.filter((f) => f.startsWith("frame/")).length).toBe(4);
    for (const f of named) {
      const bytes = fs.readFileSync(path.join(DIST, f));
      if (f.endsWith(".wasm")) expect(bytes.length, f).toBe(0);
      else expect(bytes.toString("utf8", 0, 60), f).toMatch(/^\/\/ @exav\/viewer: pdf\.js's decoder fallback/);
    }
    // And none of pdf.js's decoder builds by content either.
    const theirs = ["openjpeg.wasm", "openjpeg_nowasm_fallback.js", "jbig2.wasm", "jbig2_nowasm_fallback.js"].map((f) => fs.readFileSync(path.join(PDFJS_WASM, f)));
    for (const f of files) {
      const bytes = fs.readFileSync(f);
      expect(theirs.some((t) => t.length === bytes.length && t.equals(bytes)), path.relative(DIST, f)).toBe(false);
    }
  });
});
