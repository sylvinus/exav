// exav-render's docs module (exav_viewer_docs.wasm): the page gets back the DOCX.
import init, { convertDocs } from "../../wasm/exav_viewer_docs.js";

import { serve } from "../core/worker-host.js";
import type { DocRequest, DocResult } from "./docs.js";

let ready: Promise<unknown> | null = null;

serve<DocRequest, DocResult>(async ({ bytes, format, maxParagraphs, maxMemory }) => {
  ready ??= init();
  await ready;
  const converted = convertDocs(new Uint8Array(bytes), format, maxParagraphs, maxMemory);
  try {
    const docx = converted.takeDocx();
    return {
      value: { docx: docx.buffer as ArrayBuffer, paragraphs: converted.paragraphs, warnings: converted.warnings },
      transfer: [docx.buffer as ArrayBuffer],
    };
  } finally {
    converted.free();
  }
});
