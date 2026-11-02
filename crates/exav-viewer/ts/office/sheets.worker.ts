// exav-render's sheets module (exav_viewer_sheets.wasm): the page gets back the XLSX.
import init, { convertSheets } from "../../wasm/exav_viewer_sheets.js";

import { serve } from "../core/worker-host.js";
import type { SheetRequest, SheetResult } from "./sheets.js";

let ready: Promise<unknown> | null = null;

serve<SheetRequest, SheetResult>(async ({ bytes, format, maxCells, maxMemory }) => {
  ready ??= init();
  await ready;
  const converted = convertSheets(new Uint8Array(bytes), format, maxCells, maxMemory);
  try {
    const xlsx = converted.takeXlsx();
    return {
      value: { xlsx: xlsx.buffer as ArrayBuffer, warnings: converted.warnings },
      transfer: [xlsx.buffer as ArrayBuffer],
    };
  } finally {
    converted.free();
  }
});
