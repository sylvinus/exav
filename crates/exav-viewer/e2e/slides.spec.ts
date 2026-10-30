// Presentations and drawings converted by exav-render's `slides`
// (exav_viewer_slides.wasm), shown by the PPTX plugin, in the page and in the
// sandboxed frame: a PowerPoint 97 file, an OpenDocument presentation and a
// Keynote document, an OpenDocument drawing, a Visio drawing, with nothing of an external
// converter fetched.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { expect, test, type Page } from "@playwright/test";

import { failOnViolations, screenshotting } from "./csp.js";
import { decodePng, find } from "./pixels.js";
import { storedZip } from "./zip.js";

/** exav-render's `slides` fixtures (see their README for where they come from). */
const FIXTURES = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "exav-render", "tests", "fixtures", "office", "slides");

/** The drawing fixtures (a flat one, and the ODG saved from it). */
const DRAW = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "exav-render", "tests", "fixtures", "office", "draw");

failOnViolations();

/**
 * A Keynote 2 to 5 package of one slide: a 400 by 300 point page, a black
 * square and a title, in `index.apxl`. The format is not documented: this
 * is the smallest document the converter reads (see
 * tests/office_slides_keynote_xml.rs in exav-render, which builds a fuller
 * one).
 */
function keynoteXml(): Buffer {
  const color = (v: number) => `<sf:color sfa:r="${v}" sfa:g="${v}" sfa:b="${v}" sfa:a="1"/>`;
  const geometry = (x: number, y: number, w: number, h: number) => `<sf:geometry><sf:size sfa:w="${w}" sfa:h="${h}"/><sf:position sfa:x="${x}" sfa:y="${y}"/></sf:geometry>`;
  const xml = `<?xml version="1.0" encoding="UTF-8"?>
<key:presentation xmlns:key="http://developer.apple.com/namespaces/keynote2" xmlns:sf="http://developer.apple.com/namespaces/sf" xmlns:sfa="http://developer.apple.com/namespaces/sfa">
 <key:size sfa:w="400" sfa:h="300"/>
 <key:theme-list><key:theme sfa:ID="th"><key:stylesheet sfa:ID="ss"><sf:styles>
  <sf:shape-style sfa:ID="black" sf:ident="black"><sf:property-map><sf:fill>${color(0)}</sf:fill></sf:property-map></sf:shape-style>
  <sf:paragraphstyle sfa:ID="big" sf:ident="big"><sf:property-map><sf:fontSize><sf:number sfa:number="48"/></sf:fontSize><sf:fontColor>${color(0)}</sf:fontColor></sf:property-map></sf:paragraphstyle>
 </sf:styles></key:stylesheet></key:theme></key:theme-list>
 <key:slide-list><key:slide sfa:ID="s1"><key:page><sf:layers><sf:layer><sf:drawables>
  <sf:shape sfa:ID="sq">${geometry(40, 150, 100, 100)}<sf:style><sf:shape-style-ref sfa:IDREF="black"/></sf:style></sf:shape>
  <sf:shape sfa:ID="tx">${geometry(40, 30, 320, 80)}<sf:text><sf:text-storage><sf:stylesheet-ref sfa:IDREF="ss"/><sf:text-body><sf:p sf:style="big">Title<sf:br/></sf:p></sf:text-body></sf:text-storage></sf:text></sf:shape>
 </sf:drawables></sf:layer></sf:layers></key:page></key:slide></key:slide-list>
</key:presentation>`;
  return storedZip([["index.apxl", new TextEncoder().encode(xml)]]);
}

const ink = (r: number, g: number, b: number) => r < 160 && g < 160 && b < 160;

for (const mode of ["sandbox", "page"] as const) {
  test.describe(mode, () => {
    /** Opens a fixture; returns the URLs the page and its frames fetched for it. */
    async function open(page: Page, name: string, buffer?: Buffer, phase = "ready"): Promise<string[]> {
      const fetched: string[] = [];
      page.on("request", (r) => fetched.push(r.url()));
      await page.goto(`./?${new URLSearchParams({ lang: "en", ...(mode === "page" && { mode }) })}`);
      fetched.length = 0;
      await page.getByTestId("file-input").setInputFiles({ name, mimeType: "", buffer: buffer ?? fs.readFileSync(path.join(FIXTURES, name)) });
      await expect(page.locator(".demo-frame .exav-viewer-body")).toHaveAttribute("data-phase", phase, { timeout: 60_000 });
      return fetched;
    }

    /** Dark pixels on the surface: the slide is drawn, not a blank canvas. */
    const drawn = async (page: Page) => {
      screenshotting(page);
      return find(decodePng(await page.locator(".demo-frame .exav-viewer-surface").screenshot()), ink).count;
    };

    const byExav = (fetched: string[]) => {
      expect(fetched.some((u) => /exav_viewer_slides_bg[^/]*\.wasm/.test(u))).toBe(true);
      expect(fetched.filter((u) => /converters\/|exav_office_/.test(u))).toEqual([]);
    };

    test("a PowerPoint 97 presentation is converted and shown with its two slides", async ({ page }) => {
      byExav(await open(page, "sample.ppt"));
      await expect(page.locator(".exav-viewer-pager span")).toHaveText("Slide 1 / 2");
      await expect.poll(() => drawn(page)).toBeGreaterThan(200);
      await page.locator(".exav-viewer-pager button").last().click();
      await expect(page.locator(".exav-viewer-pager span")).toHaveText("Slide 2 / 2");
    });

    test("an OpenDocument presentation is converted and shown with its two slides", async ({ page }) => {
      byExav(await open(page, "sample.odp"));
      await expect(page.locator(".exav-viewer-pager span")).toHaveText("Slide 1 / 2");
      await expect.poll(() => drawn(page)).toBeGreaterThan(200);
    });

    test("a Keynote document is converted and its slide shown", async ({ page }) => {
      byExav(await open(page, "sample.key"));
      await expect.poll(() => drawn(page)).toBeGreaterThan(100);
    });

    test("a Keynote 2 to 5 document (XML in a package) is converted and its slide shown", async ({ page }) => {
      byExav(await open(page, "xml.key", keynoteXml()));
      // The black square and the title's text.
      await expect.poll(() => drawn(page)).toBeGreaterThan(500);
    });

    test("a Visio drawing (VSDX) is converted and shown a page to a slide", async ({ page }) => {
      byExav(await open(page, "sample.vsdx", fs.readFileSync(path.join(DRAW, "sample.vsdx"))));
      // The background page is not a slide.
      await expect(page.locator(".exav-viewer-pager span")).toHaveText("Slide 1 / 2");
      await expect.poll(() => drawn(page)).toBeGreaterThan(200);
      await page.locator(".exav-viewer-pager button").last().click();
      await expect(page.locator(".exav-viewer-pager span")).toHaveText("Slide 2 / 2");
    });

    for (const name of ["sample.fodg", "sample.odg"]) {
      test(`${name}, an OpenDocument drawing, is converted and shown a page to a slide`, async ({ page }) => {
        byExav(await open(page, name, fs.readFileSync(path.join(DRAW, name))));
        await expect(page.locator(".exav-viewer-pager span")).toHaveText("Slide 1 / 2");
        await expect.poll(() => drawn(page)).toBeGreaterThan(200);
        await page.locator(".exav-viewer-pager button").last().click();
        await expect(page.locator(".exav-viewer-pager span")).toHaveText("Slide 2 / 2");
      });
    }

    test("a Visio file, which no converter of the package reads, says it needs a converter", async ({ page }) => {
      const fetched = await open(page, "plan.vsd", Buffer.from("Visio (TM) Drawing\r\n"), "error");
      await expect(page.locator(".demo-frame .exav-viewer-status")).toContainText("only be shown with a converter that is not installed here");
      expect(fetched.filter((u) => /converters\/|exav_office_/.test(u))).toEqual([]);
    });

    test("a PowerPoint 3 file is reported as unsupported, not handed to an external converter", async ({ page }) => {
      const header = Buffer.from([0xed, 0xde, 0xad, 0x0b, 3, 0, 0, 0, ...new Array(64).fill(1)]);
      const fetched = await open(page, "old.ppt", header, "error");
      expect(fetched.filter((u) => /converters\/|exav_office_/.test(u))).toEqual([]);
    });
  });
}
