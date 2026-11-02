/**
 * `@exav/viewer/text`: plain text, Markdown, JSON, XML, and the text
 * formats that need nothing more than a monospace page (YAML, TOML, INI,
 * source code, subtitles, diffs). HTML is shown as its source, never
 * drawn. Written in TypeScript here with no dependency, except Markdown,
 * which exav-render reads in WebAssembly (`exav_viewer_text.wasm`, loaded
 * when one is opened). What each name and type is shown as is `TEXT_KINDS`
 * in the core.
 *
 * The file is read up to 2 MiB and 50,000 lines (the rest is left out, and
 * the warning `text_truncated` says so); a file that is not text is refused
 * (`text_binary`).
 */
import { MATCHERS } from "../core/formats.js";
import type { FormatPlugin } from "../core/types.js";

export const text = (): FormatPlugin<Record<string, never>> => ({
  id: "text",
  match: MATCHERS.text,
  capabilities: [],
  options: {},
  load: () => import("./renderer.js").then((m) => m.renderer),
});

export { MAX_BYTES, MAX_LINES, MAX_LINE } from "./decode.js";
