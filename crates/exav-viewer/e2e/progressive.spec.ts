// A long Word document is laid out progressively: the viewer is ready on its
// first pages, and the page count grows as the rest is laid out. Opened
// through the headless demo, whose page field shows the count the session
// reports.
import { expect, test, type Page } from "@playwright/test";

import { failOnViolations } from "./csp.js";
import { storedZip } from "./zip.js";

failOnViolations();

const PAGES = 200;

/** A document of `pages` pages: a heading and five paragraphs on each, then a page break. */
function longDocument(pages: number): Buffer {
  const WORDS = "the quick brown fox jumps over the lazy dog while a gentle breeze moves across quiet fields and distant hills".split(" ");
  const paragraph = (seed: number) => `<w:p><w:r><w:t xml:space="preserve">${Array.from({ length: 90 }, (_, i) => WORDS[(seed * 7 + i * 3) % WORDS.length]).join(" ")}.</w:t></w:r></w:p>`;
  const body = Array.from(
    { length: pages },
    (_, p) => `<w:p><w:r><w:rPr><w:b/><w:sz w:val="32"/></w:rPr><w:t>Section ${p}</w:t></w:r></w:p>${[0, 1, 2, 3, 4].map((k) => paragraph(p + k)).join("")}<w:p><w:r><w:br w:type="page"/></w:r></w:p>`,
  ).join("");
  const text = (s: string) => new TextEncoder().encode(s);
  return storedZip([
    ["[Content_Types].xml", text(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>`)],
    ["_rels/.rels", text(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>`)],
    ["word/document.xml", text(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>${body}<w:sectPr><w:pgSz w:w="11906" w:h="16838"/><w:pgMar w:top="1440" w:right="1440" w:bottom="1440" w:left="1440" w:header="708" w:footer="708" w:gutter="0"/></w:sectPr></w:body></w:document>`)],
  ]);
}

/** A deck of `slides` slides, one line of text on each. */
function longDeck(slides: number): Buffer {
  const XML = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>';
  const R = "http://schemas.openxmlformats.org/officeDocument/2006/relationships";
  const NS = `xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:r="${R}" xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"`;
  const rels = (list: [string, string, string][]) =>
    `${XML}<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">${list.map(([id, type, target]) => `<Relationship Id="${id}" Type="${R}/${type}" Target="${target}"/>`).join("")}</Relationships>`;
  const tree = (shapes: string) => `<p:cSld><p:spTree><p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr><p:grpSpPr/>${shapes}</p:spTree></p:cSld>`;
  const box = (text: string) =>
    `<p:sp><p:nvSpPr><p:cNvPr id="2" name="Text"/><p:cNvSpPr txBox="1"/><p:nvPr/></p:nvSpPr><p:spPr><a:xfrm><a:off x="720000" y="720000"/><a:ext cx="7200000" cy="1440000"/></a:xfrm><a:prstGeom prst="rect"><a:avLst/></a:prstGeom></p:spPr><p:txBody><a:bodyPr/><a:lstStyle/><a:p><a:r><a:rPr lang="en-GB" sz="2400"/><a:t>${text}</a:t></a:r></a:p></p:txBody></p:sp>`;
  const n = Array.from({ length: slides }, (_, i) => i + 1);
  const text = (s: string) => new TextEncoder().encode(s);
  return storedZip([
    [
      "[Content_Types].xml",
      text(
        `${XML}<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/ppt/presentation.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml"/><Override PartName="/ppt/slideMasters/slideMaster1.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.slideMaster+xml"/><Override PartName="/ppt/slideLayouts/slideLayout1.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.slideLayout+xml"/>${n.map((i) => `<Override PartName="/ppt/slides/slide${i}.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.slide+xml"/>`).join("")}</Types>`,
      ),
    ],
    ["_rels/.rels", text(rels([["rId1", "officeDocument", "ppt/presentation.xml"]]))],
    [
      "ppt/presentation.xml",
      text(
        `${XML}<p:presentation ${NS}><p:sldMasterIdLst><p:sldMasterId id="2147483648" r:id="rId1"/></p:sldMasterIdLst><p:sldIdLst>${n.map((i) => `<p:sldId id="${255 + i}" r:id="rId${i + 1}"/>`).join("")}</p:sldIdLst><p:sldSz cx="9144000" cy="5143500"/><p:notesSz cx="6858000" cy="9144000"/></p:presentation>`,
      ),
    ],
    ["ppt/_rels/presentation.xml.rels", text(rels([["rId1", "slideMaster", "slideMasters/slideMaster1.xml"], ...n.map((i): [string, string, string] => [`rId${i + 1}`, "slide", `slides/slide${i}.xml`])]))],
    [
      "ppt/slideMasters/slideMaster1.xml",
      text(
        `${XML}<p:sldMaster ${NS}>${tree("")}<p:clrMap bg1="lt1" tx1="dk1" bg2="lt2" tx2="dk2" accent1="accent1" accent2="accent2" accent3="accent3" accent4="accent4" accent5="accent5" accent6="accent6" hlink="hlink" folHlink="folHlink"/><p:sldLayoutIdLst><p:sldLayoutId id="2147483649" r:id="rId1"/></p:sldLayoutIdLst></p:sldMaster>`,
      ),
    ],
    ["ppt/slideMasters/_rels/slideMaster1.xml.rels", text(rels([["rId1", "slideLayout", "../slideLayouts/slideLayout1.xml"]]))],
    ["ppt/slideLayouts/slideLayout1.xml", text(`${XML}<p:sldLayout ${NS}>${tree("")}<p:clrMapOvr><a:masterClrMapping/></p:clrMapOvr></p:sldLayout>`)],
    ["ppt/slideLayouts/_rels/slideLayout1.xml.rels", text(rels([["rId1", "slideMaster", "../slideMasters/slideMaster1.xml"]]))],
    ...n.flatMap((i): [string, Uint8Array][] => [
      [`ppt/slides/slide${i}.xml`, text(`${XML}<p:sld ${NS}>${tree(box(`Slide ${i}`))}<p:clrMapOvr><a:masterClrMapping/></p:clrMapOvr></p:sld>`)],
      [`ppt/slides/_rels/slide${i}.xml.rels`, text(rels([["rId1", "slideLayout", "../slideLayouts/slideLayout1.xml"]]))],
    ]),
  ]);
}

/** The page count the headless demo's page field reports. */
const total = async (page: Page) => Number(/\/ (\d+)/.exec(await page.locator("#controls").innerText())?.[1] ?? 0);

test("a long document is ready on its first pages and the page count grows as the rest is laid out", async ({ page }) => {
  test.setTimeout(240_000);
  await page.goto("./headless.html?lang=en");
  await page.getByTestId("file-input").setInputFiles({ name: "long.docx", mimeType: "", buffer: longDocument(PAGES) });
  await expect
    .poll(() => page.evaluate(() => (window as unknown as { headless: { session(): { status: { get(): { phase: string } } } | null } }).headless.session()?.status.get().phase), { timeout: 120_000 })
    .toBe("ready");
  const first = await total(page);
  expect(first).toBeGreaterThan(0);
  expect(first).toBeLessThan(PAGES);
  await expect.poll(() => total(page), { timeout: 180_000 }).toBeGreaterThanOrEqual(PAGES);
});

test("a long deck's directory is read by the ZIP module, and the deck opens on its first of 40 slides", async ({ page }) => {
  test.setTimeout(120_000);
  const fetched: string[] = [];
  page.on("request", (r) => fetched.push(r.url()));
  await page.goto("./headless.html?lang=en");
  await page.getByTestId("file-input").setInputFiles({ name: "long.pptx", mimeType: "", buffer: Buffer.concat([longDeck(40), Buffer.from("\n")]) });
  await expect
    .poll(() => page.evaluate(() => (window as unknown as { headless: { session(): { status: { get(): { phase: string } } } | null } }).headless.session()?.status.get().phase), { timeout: 60_000 })
    .toBe("ready");
  await expect.poll(() => total(page), { timeout: 60_000 }).toBe(40);
  expect(fetched.some((u) => /exav_viewer_sniff_bg[^/]*\.wasm/.test(u))).toBe(true);
});
