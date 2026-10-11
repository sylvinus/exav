// @vitest-environment node
// The links read from a PDF made here, through pdf.js itself: where each one
// lies on the page shown follows from the numbers written in the file and the
// page's rotation, worked out by hand below.
import { createRequire } from "node:module";
import { pathToFileURL } from "node:url";

// The legacy build: the other one needs what browsers have and Node lacks.
import { AnnotationType, getDocument, GlobalWorkerOptions } from "pdfjs-dist/legacy/build/pdf.mjs";
import { describe, expect, it } from "vitest";

import { MAX_LINK_AREAS, readLinks } from "./engine.js";

GlobalWorkerOptions.workerSrc = pathToFileURL(createRequire(import.meta.url).resolve("pdfjs-dist/legacy/build/pdf.worker.min.mjs")).href;

/** A PDF whose pages are `[extra page dictionary entries, annotation dictionaries]`; `{page N}` is page N's reference. */
function makePdf(pages: [string, string[]][]): Uint8Array {
  const objects: string[] = [];
  const add = (body: string) => objects.push(body);
  const pagesId = 1;
  const first = 2;
  const ref = (body: string) => body.replace(/\{page (\d+)\}/g, (_, n: string) => `${first + Number(n) - 1} 0 R`);
  add(`<< /Type /Pages /Kids [${pages.map((_, i) => `${first + i} 0 R`).join(" ")}] /Count ${pages.length} >>`);
  for (const [extra, annots] of pages) {
    add(`<< /Type /Page /Parent ${pagesId} 0 R /MediaBox [0 0 600 800] ${extra} /Annots [${annots.map((a) => `<< /Type /Annot /Subtype /Link /Border [0 0 0] ${ref(a)} >>`).join(" ")}] >>`);
  }
  add(`<< /Names [(sec) [${first} 0 R /XYZ 0 500 0]] >>`);
  const names = objects.length;
  add(`<< /Type /Catalog /Pages ${pagesId} 0 R /Names << /Dests ${names} 0 R >> >>`);
  let body = "%PDF-1.7\n";
  const offsets: number[] = [];
  objects.forEach((o, i) => {
    offsets.push(body.length);
    body += `${i + 1} 0 obj\n${o}\nendobj\n`;
  });
  const start = body.length;
  body += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n${offsets.map((x) => `${String(x).padStart(10, "0")} 00000 n \n`).join("")}`;
  body += `trailer\n<< /Size ${objects.length + 1} /Root ${objects.length} 0 R >>\nstartxref\n${start}\n%%EOF\n`;
  return new Uint8Array(Buffer.from(body, "latin1"));
}

async function linksOf(pdf: Uint8Array, pageNumber: number) {
  const doc = await getDocument({ data: pdf }).promise;
  try {
    const page = await doc.getPage(pageNumber);
    return readLinks(await page.getAnnotations({ intent: "display" }), page.getViewport({ scale: 1 }), AnnotationType.LINK);
  } finally {
    await doc.loadingTask.destroy();
  }
}

const close = (actual: { x: number; y: number; width: number; height: number }, want: [number, number, number, number]) => {
  expect(actual.x).toBeCloseTo(want[0], 6);
  expect(actual.y).toBeCloseTo(want[1], 6);
  expect(actual.width).toBeCloseTo(want[2], 6);
  expect(actual.height).toBeCloseTo(want[3], 6);
};

describe("readLinks", () => {
  it("keeps http(s) addresses and destinations, each where it lies on the page", async () => {
    const links = await linksOf(
      makePdf([
        [
          "",
          [
            "/Rect [100 700 300 720] /A << /S /URI /URI (https://example.com/a) >>",
            "/Rect [100 650 300 670] /A << /S /URI /URI (javascript:alert\\(1\\)) >>",
            "/Rect [100 600 300 620] /A << /S /URI /URI (mailto:someone@example.com) >>",
            "/Rect [100 550 300 570] /A << /S /Named /N /NextPage >>",
            // Two lines: one area each, not the rectangle around both.
            "/Rect [50 300 550 340] /QuadPoints [50 340 550 340 50 320 550 320 50 320 200 320 50 300 200 300] /Dest [{page 2} /XYZ 0 800 0]",
            "/Rect [100 200 300 220] /Dest (sec)",
            // Partly off the page: what is on it.
            "/Rect [500 -10 700 10] /A << /S /URI /URI (https://example.com/edge) >>",
            // Nothing to click.
            "/Rect [100 100 100 120] /A << /S /URI /URI (https://example.com/empty) >>",
          ],
        ],
        ["", []],
      ]),
      1,
    );
    // The page is 600 x 800 points; y counts up from the bottom in the file, down from the top on screen.
    expect(links.map((l) => ("url" in l ? l.url : l.dest))).toEqual([
      "https://example.com/a",
      [expect.objectContaining({ num: 3 }), { name: "XYZ" }, 0, 800, 0],
      "sec",
      "https://example.com/edge",
    ]);
    expect(links.map((l) => l.areas.length)).toEqual([1, 2, 1, 1]);
    close(links[0]!.areas[0]!, [100 / 600, 80 / 800, 200 / 600, 20 / 800]);
    close(links[1]!.areas[0]!, [50 / 600, 460 / 800, 500 / 600, 20 / 800]);
    close(links[1]!.areas[1]!, [50 / 600, 480 / 800, 150 / 600, 20 / 800]);
    close(links[2]!.areas[0]!, [100 / 600, 580 / 800, 200 / 600, 20 / 800]);
    close(links[3]!.areas[0]!, [500 / 600, 790 / 800, 100 / 600, 10 / 800]);
  });

  it("follows the page's rotation", async () => {
    // Turned a quarter clockwise, the page shows 800 x 600: its bottom-left
    // corner is now the top-left one, its bottom edge runs down the left.
    const [link] = await linksOf(makePdf([["/Rotate 90", ["/Rect [0 0 100 50] /A << /S /URI /URI (https://example.com/b) >>"]]]), 1);
    close(link!.areas[0]!, [0, 0, 50 / 800, 100 / 600]);
  });

  it(`keeps at most ${MAX_LINK_AREAS} areas of a page`, async () => {
    const many = Array.from({ length: MAX_LINK_AREAS + 5 }, (_, i) => `/Rect [${i % 500} ${i % 700} ${(i % 500) + 10} ${(i % 700) + 10}] /A << /S /URI /URI (https://example.com/${i}) >>`);
    const links = await linksOf(makePdf([["", many]]), 1);
    expect(links.length).toBe(MAX_LINK_AREAS);
    expect(links.at(-1)).toMatchObject({ url: `https://example.com/${MAX_LINK_AREAS - 1}` });
  });
});
