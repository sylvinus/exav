// The text module as the tests run it: the wasm module in this process, where
// the page has it in a worker (jsdom has none).
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import init, { fileReading, formatDiff, formatJson, formatXml, pageReading, parseMarkdown } from "../../wasm/exav_viewer_text.js";
import type { Decoded, FormatKind } from "../text/engine.js";
import type { Formatted } from "../text/lines.js";
import type { Parsed } from "../text/markdown.js";
import { type Reading, readText } from "../text/read.js";

const wasm = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "wasm", "exav_viewer_text_bg.wasm");
let ready: Promise<unknown> | null = null;

async function load(): Promise<void> {
  ready ??= init({ module_or_path: fs.readFileSync(wasm) });
  await ready;
}

export async function readMarkdown(source: string): Promise<Parsed> {
  await load();
  return JSON.parse(parseMarkdown(source)) as Parsed;
}

/** How the module says `bytes` are read, or null when they are not text; `page`: as a page's source. */
export async function readingOf(bytes: Uint8Array, partial = false, page = false): Promise<Reading | null> {
  await load();
  const reading = (page ? pageReading : fileReading)(bytes, partial);
  if (!reading) return null;
  try {
    return { encoding: reading.encoding, start: reading.start, end: reading.end };
  } finally {
    reading.free();
  }
}

export async function decodeText(bytes: Uint8Array, partial = false, page = false): Promise<Decoded | null> {
  const reading = await readingOf(bytes, partial, page);
  return reading && { text: readText(bytes, reading), encoding: reading.encoding };
}

export async function formatLines(kind: FormatKind, text: string, maxLines: number): Promise<Formatted | null> {
  await load();
  const json = kind === "json" ? formatJson(text, maxLines) : kind === "xml" ? formatXml(text, maxLines) : formatDiff(text, maxLines);
  return json === undefined ? null : (JSON.parse(json) as Formatted);
}
