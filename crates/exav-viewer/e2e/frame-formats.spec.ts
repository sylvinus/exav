// A sandboxed frame published for some formats only (`formats` of the
// Vite plugin): the formats of its engines open, with no file missing, and the
// others end in an error rather than a hang. Run against a demo built with
// EXAV_FRAME_FORMATS, a comma separated list (scripts/test-viewer.sh builds
// one); skipped without it.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { expect, test } from "@playwright/test";

import { shippedFormats } from "../dist/frame/engines.js";
import type { BuiltinFormat } from "../dist/core/types.js";
import { failOnViolations } from "./csp.js";
import { sample } from "./samples.js";

const listed = process.env.EXAV_FRAME_FORMATS?.split(",") as BuiltinFormat[] | undefined;
const converted = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "demo", "examples", "files", "converted");

failOnViolations();

test.beforeEach(() => {
  test.skip(!listed, "the demo was not built with EXAV_FRAME_FORMATS");
});

/** One file for each engine that has a format a host might leave out. */
const FILES: [string, BuiltinFormat][] = [
  ["report.pdf", "pdf"],
  ["landscape.tif", "image"],
  ["notes.docx", "docx"],
  ["quote.xlsx", "xlsx"],
  ["handbook.rtf", "rtf"],
  ["workbook.xls", "xls"],
  ["deck.ppt", "ppt"],
  ["delivery.zip", "archive"],
  ["house.stl", "stl"],
];

for (const [name, format] of FILES) {
  test(`${name} in a frame published for ${listed?.join(", ") ?? "some formats"}`, async ({ page }) => {
    const opens = new Set(shippedFormats(listed ?? [])).has(format);
    const missing: string[] = [];
    page.on("response", (r) => r.status() >= 400 && missing.push(`${r.status()} ${r.url()}`));
    await page.goto("./?lang=en");
    const buffer = ["handbook.rtf", "workbook.xls", "deck.ppt"].includes(name) ? fs.readFileSync(path.join(converted, name)) : sample(name);
    await page.getByTestId("file-input").setInputFiles({ name, mimeType: "", buffer });
    // The frame's own error ends the wait; a missing file would not.
    await expect(page.locator(".demo-frame .exav-viewer-body")).toHaveAttribute("data-phase", opens ? "ready" : "error", { timeout: 60_000 });
    expect(missing).toEqual([]);
  });
}
