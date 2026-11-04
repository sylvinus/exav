// The text module (exav_viewer_text.wasm): exav-unpack's rule for what bytes
// are as text, exav-render's Markdown reader, and its JSON, XML and diff
// lines. The page gets back text or finished data, never the readers' state.
import init, { fileReading, formatDiff, formatJson, formatXml, pageReading, parseMarkdown } from "../../wasm/exav_viewer_text.js";

import { serve } from "../core/worker-host.js";
import type { Reply, Request } from "./engine.js";
import { readText } from "./read.js";

let ready: Promise<unknown> | null = null;

serve<Request, Reply>(async (request) => {
  ready ??= init();
  await ready;
  if (request.op === "markdown") return { value: { op: "markdown", json: parseMarkdown(request.source) } };
  if (request.op === "format") {
    const { kind, text, maxLines } = request;
    const json = kind === "json" ? formatJson(text, maxLines) : kind === "xml" ? formatXml(text, maxLines) : formatDiff(text, maxLines);
    return { value: { op: "format", json: json ?? null } };
  }
  const reading = (request.page ? pageReading : fileReading)(request.bytes, request.partial);
  if (!reading) return { value: { op: "decode", decoded: null } };
  try {
    const encoding = reading.encoding;
    return { value: { op: "decode", decoded: { text: readText(request.bytes, { encoding, start: reading.start, end: reading.end }), encoding } } };
  } finally {
    reading.free();
  }
});
