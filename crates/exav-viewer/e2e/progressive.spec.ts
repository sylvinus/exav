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
