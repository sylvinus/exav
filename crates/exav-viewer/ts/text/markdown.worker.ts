// exav-render's Markdown reader (exav_viewer_text.wasm): the page gets back
// the finished tree as JSON, never the parser's state.
import init, { parseMarkdown } from "../../wasm/exav_viewer_text.js";

import { serve } from "../core/worker-host.js";

let ready: Promise<unknown> | null = null;

serve<string, string>(async (source) => {
  ready ??= init();
  await ready;
  return { value: parseMarkdown(source) };
});
