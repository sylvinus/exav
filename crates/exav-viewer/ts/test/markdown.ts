// The Markdown reader as the tests run it: the wasm module in this process,
// where the page has it in a worker (jsdom has none).
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import init, { parseMarkdown } from "../../wasm/exav_viewer_text.js";
import type { Parsed } from "../text/markdown.js";

const wasm = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "wasm", "exav_viewer_text_bg.wasm");
let ready: Promise<unknown> | null = null;

export async function readMarkdown(source: string): Promise<Parsed> {
  ready ??= init({ module_or_path: fs.readFileSync(wasm) });
  await ready;
  return JSON.parse(parseMarkdown(source)) as Parsed;
}
