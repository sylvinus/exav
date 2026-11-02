// A split archive opens when the files given with it have its other parts: the
// parts of a set are told by their names, in the same folder, and the set is
// the archive (fixtures/make-samples.mjs writes the sets).
import fs from "node:fs";
import path from "node:path";

import { expect, test, type Page } from "@playwright/test";

import { failOnViolations } from "./csp.js";
import { SAMPLES, sample } from "./samples.js";

failOnViolations();

async function give(page: Page, mode: "page" | "sandbox", names: string[]) {
  await page.goto(`./?${new URLSearchParams({ lang: "en", ...(mode === "page" ? { mode } : {}) })}`);
  await page.getByTestId("file-input").setInputFiles(names.map((name) => ({ name, mimeType: "", buffer: sample(name) })));
  await expect(page.locator(".demo-frame .exav-viewer-body")).toHaveAttribute("data-phase", "ready");
}

const members = (page: Page) => page.locator(".demo-frame .exav-viewer-member-name > .exav-viewer-truncate:first-child");

// The members, and the size of one that a part alone cannot give: a RAR member
// that continues in the next volume has none until the set is joined.
const SETS: [string, string[], string[], [string, string]][] = [
  ["RAR volumes, part1 to part3", ["set5.part1.rar", "set5.part2.rar", "set5.part3.rar"], ["noise.bin", "text.txt"], ["noise.bin", "20 KB"]],
  ["RAR volumes, .rar then .r00 and .r01", ["set4.rar", "set4.r00", "set4.r01"], ["noise.bin", "text.txt"], ["noise.bin", "20 KB"]],
  ["a ZIP cut in two by bytes", ["docs.zip.001", "docs.zip.002"], ["one.txt", "two.txt"], ["two.txt", "5 B"]],
  ["a ZIP spanned over three files", ["span.z01", "span.z02", "span.zip"], ["big.bin", "small.txt"], ["big.bin", "293 KB"]],
];

for (const mode of ["page", "sandbox"] as const) {
  test.describe(`in the ${mode}: split archives`, () => {
    for (const [what, parts, listed, [member, size]] of SETS) {
      test(`${what}: opens as the one archive`, async ({ page }) => {
        test.skip(!parts.every((p) => fs.existsSync(path.join(SAMPLES, p))), "no sample: there is no `zip` here");
        await give(page, mode, parts);
        await expect(page.locator(".demo-frame .exav-viewer-archive-head")).toHaveText(`${listed.length} files`);
        // In the order of the archive, whichever it is.
        await expect(members(page)).toHaveCount(listed.length);
        expect((await members(page).allInnerTexts()).sort()).toEqual([...listed].sort());
        await expect(page.locator(".demo-frame .exav-viewer-member", { hasText: member }).locator(".exav-viewer-member-size")).toHaveText(size);
      });
    }
  });
}
