// Text documents converted by exav-render's `docs` (exav_viewer_docs.wasm)
// when the page asks for `converter: "exav"` (`?converter=exav` in the demo),
// shown by the DOCX plugin, in the page and in the sandboxed frame: a Word 97
// file, an OpenDocument text, a flat one, an RTF and a Pages 5 one, with nothing of an
// external converter fetched.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { expect, test, type Page } from "@playwright/test";

import { failOnViolations, screenshotting } from "./csp.js";
import { decodePng, find } from "./pixels.js";
import { storedZip } from "./zip.js";

/** exav-render's `docs` fixtures (see their README for where they come from). */
const FIXTURES = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "exav-render", "tests", "fixtures", "office", "docs");

/**
 * A Pages 5 package of one paragraph, "Title" in bold 20 pt, built as
 * exav-render's tests build it (office_docs_formats.rs): a protocol buffer
 * archive of three objects in an IWA stream, one Snappy block of literals.
 */
function pagesPackage(): Buffer {
  const varint = (n: number): number[] => (n < 0x80 ? [n] : [(n & 0x7f) | 0x80, ...varint(n >>> 7)]);
  const uint = (field: number, v: number) => [...varint(field << 3), ...varint(v)];
  const bytes = (field: number, b: number[]) => [...varint((field << 3) | 2), ...varint(b.length), ...b];
  const float = (field: number, v: number) => [...varint((field << 3) | 5), ...new Uint8Array(new Float32Array([v]).buffer)];
  const text = [...new TextEncoder().encode("Title\nBody words here")];
  const objects: [number, number, number[]][] = [
    [1, 10000, [...bytes(4, uint(1, 2)), ...float(30, 595), ...float(31, 842), ...float(32, 72), ...float(33, 36), ...float(34, 72), ...float(35, 36)]],
    [2, 2001, [...bytes(3, text), ...bytes(5, [...bytes(1, [...uint(1, 0), ...bytes(2, uint(1, 3))]), ...bytes(1, [...uint(1, 6), ...bytes(2, uint(1, 4))])])]],
    [3, 2022, [...bytes(11, [...uint(1, 1), ...float(3, 20)]), ...bytes(12, uint(1, 2))]],
    [4, 2022, [...bytes(11, float(3, 12)), ...bytes(12, uint(1, 0))]],
  ];
  const raw = objects.flatMap(([id, type, message]) => {
    const info = [...uint(1, id), ...bytes(2, [...uint(1, type), ...uint(3, message.length)])];
    return [...varint(info.length), ...info, ...message];
  });
  const block = [...varint(raw.length)];
  for (let i = 0; i < raw.length; i += 60) {
    const chunk = raw.slice(i, i + 60);
    block.push((chunk.length - 1) << 2, ...chunk);
  }
  return storedZip([["Index/Document.iwa", Uint8Array.from([0, block.length & 255, (block.length >> 8) & 255, block.length >> 16, ...block])]]);
}

failOnViolations();

const ink = (r: number, g: number, b: number) => r < 160 && g < 160 && b < 160;

for (const mode of ["sandbox", "page"] as const) {
  test.describe(mode, () => {
    /** Opens a fixture, or `buffer` under `name`; returns the URLs the page and its frames fetched for it. */
    async function open(page: Page, name: string, buffer?: Buffer): Promise<string[]> {
      const fetched: string[] = [];
      page.on("request", (r) => fetched.push(r.url()));
      await page.goto(`./?${new URLSearchParams({ lang: "en", converter: "exav", ...(mode === "page" && { mode }) })}`);
      fetched.length = 0;
      await page.getByTestId("file-input").setInputFiles({ name, mimeType: "", buffer: buffer ?? fs.readFileSync(path.join(FIXTURES, name)) });
      await expect(page.locator(".demo-frame .exav-viewer-body")).toHaveAttribute("data-phase", "ready", { timeout: 60_000 });
      return fetched;
    }

    /** Dark pixels on the surface: the page is drawn, not a blank canvas. */
    const drawn = async (page: Page) => {
      screenshotting(page);
      return find(decodePng(await page.locator(".demo-frame .exav-viewer-surface").screenshot()), ink).count;
    };

    const byExav = (fetched: string[]) => {
      expect(fetched.some((u) => /exav_viewer_docs_bg[^/]*\.wasm/.test(u))).toBe(true);
      expect(fetched.filter((u) => /converters\/|exav_office_/.test(u))).toEqual([]);
    };

    for (const name of ["sample.doc", "sample.odt", "sample.fodt", "sample.rtf"]) {
      test(`${name} is converted and its page drawn`, async ({ page }) => {
        byExav(await open(page, name));
        await expect.poll(() => drawn(page)).toBeGreaterThan(300);
      });
    }

    test("a Pages document (2013 and later) is converted and its page drawn", async ({ page }) => {
      byExav(await open(page, "notes.pages", pagesPackage()));
      await expect.poll(() => drawn(page)).toBeGreaterThan(300);
    });
  });
}
