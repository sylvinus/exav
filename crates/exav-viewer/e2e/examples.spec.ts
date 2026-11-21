// Every file the demo lists, opened from its sidebar as a visitor opens it:
// each example of examples/examples.json and each sample of
// showcase/samples.json not replaced by an example of the same name. A file
// of the "unsupported" group must end in an error; any other must be shown,
// with no error on the console and none left uncaught, in the sandboxed frame
// and in the page. `EXAV_EXAMPLES_MODES=sandbox` runs the frame's half alone,
// as CI does; the release runs both.
//
// Needs the demo built with its files (`npm run demo:showcase`, then
// `npm run demo:build`). The release runs it against the deployed demo too:
//
//     E2E_BASE_URL=https://exav.org/viewer/demo/ npx playwright test e2e/examples.spec.ts --project=chromium
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { expect, test, type Page } from "@playwright/test";

import { failOnViolations } from "./csp.js";

const pub = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "demo", "public");
const read = <T>(file: string): T | null => (fs.existsSync(file) ? (JSON.parse(fs.readFileSync(file, "utf8")) as T) : null);
const examples = read<{ examples: { file: string; group: string }[] }>(path.join(pub, "examples", "examples.json"))?.examples ?? [];
const samples = read<{ samples: { file: string; group: string }[] }>(path.join(pub, "showcase", "samples.json"))?.samples ?? [];
const named = new Set(examples.map((e) => e.file));
const FILES = [
  ...samples.filter((s) => !named.has(s.file)).map((s) => ({ id: `showcase:${s.file}`, ...s })),
  ...examples.map((e) => ({ id: `example:${e.file}`, ...e })),
];

/**
 * What a file of this name needs the browser to play, for the formats a
 * browser may lack (Playwright's Chromium has no H.264 or AAC): its media
 * type for `canPlayType`.
 */
const PLAYED: Record<string, string> = {
  mp4: 'video/mp4; codecs="avc1.42E01E, mp4a.40.2"',
  m4a: 'audio/mp4; codecs="mp4a.40.2"',
  m4v: 'video/mp4; codecs="avc1.42E01E"',
  mov: 'video/mp4; codecs="avc1.42E01E"',
};

failOnViolations();

test("the demo lists files to open", () => {
  expect(examples.length, "no examples: run npm run demo:build").toBeGreaterThan(0);
  expect(samples.length, "no samples: run npm run demo:showcase").toBeGreaterThan(0);
});

const MODES = ["sandbox", "page"] as const;
const asked = (process.env.EXAV_EXAMPLES_MODES || MODES.join(",")).split(",");
for (const m of asked) if (!(MODES as readonly string[]).includes(m)) throw new Error(`EXAV_EXAMPLES_MODES: no mode ${m}`);

for (const mode of MODES.filter((m) => asked.includes(m))) {
  test.describe(mode, () => {
    for (const f of FILES) {
      test(f.file, async ({ page }) => {
        // A large file in the frame, through a software GPU, under load.
        test.setTimeout(120_000);
        const problems = collect(page);
        await page.goto(`./?${new URLSearchParams({ lang: "en", file: f.id, ...(mode === "page" && { mode }) })}`);
        const body = page.locator(".demo-frame .exav-viewer-body");
        await expect(body).toHaveAttribute("data-phase", /^(ready|empty|error)$/, { timeout: 100_000 });
        // What a late failure would change, a page drawn after the first.
        await page.waitForTimeout(1000);
        const phase = await body.getAttribute("data-phase");
        const said = (await page.locator(".demo-frame .exav-viewer-status").allInnerTexts()).join(" ");
        const type = PLAYED[path.extname(f.file).slice(1).toLowerCase()];
        const unplayable = type !== undefined && (await page.evaluate((t) => document.createElement("video").canPlayType(t) === "", type));
        if (f.group === "unsupported" || unplayable) expect(phase, said).toBe("error");
        else expect(phase, said).toBe("ready");
        expect(problems).toEqual([]);
      });
    }
  });
}

/** Errors on the console and uncaught ones, from the page, its frames and their workers. */
function collect(page: Page): string[] {
  const seen: string[] = [];
  page.on("pageerror", (e) => seen.push(`uncaught: ${e.message}`));
  page.on("console", (m) => {
    if (m.type() === "error") seen.push(`console: ${m.text()}`);
  });
  page.on("worker", (w) => w.on("console", (m) => m.type() === "error" && seen.push(`worker console: ${m.text()}`)));
  return seen;
}
