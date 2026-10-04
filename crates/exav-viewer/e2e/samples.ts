// The sample files the tests open (fixtures/make-samples.mjs writes them into
// e2e/.out/samples/ before the run) and the way they are opened: given to the
// demo as a person would, through its file input.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import type { Page } from "@playwright/test";

export const SAMPLES = path.join(path.dirname(fileURLToPath(import.meta.url)), ".out", "samples");

export const sample = (name: string): Buffer => fs.readFileSync(path.join(SAMPLES, name));

/** Gives the demo these files, as the user picks them; the first one is shown. */
export const pick = (page: Page, ...names: string[]) =>
  page.getByTestId("file-input").setInputFiles(names.map((name) => ({ name, mimeType: "", buffer: sample(name) })));

/** Opens the demo (relative, as it may be served under a base path) and gives it a sample. `params` are query parameters, such as `mode: "page"`. */
export async function openSample(page: Page, name: string, params: Record<string, string> = {}): Promise<void> {
  await page.goto(`./?${new URLSearchParams({ lang: "en", ...params })}`);
  await pick(page, name);
}
