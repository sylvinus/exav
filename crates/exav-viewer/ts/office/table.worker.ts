// exav-render's CSV reader and XLSX writer (exav_viewer_table.wasm): the page gets back the XLSX.
import init, { convertTable } from "../../wasm/exav_viewer_table.js";

import { serve } from "../core/worker-host.js";
import type { TableRequest } from "./table-engine.js";

let ready: Promise<unknown> | null = null;

serve<TableRequest, ArrayBuffer>(async ({ bytes, maxCells, maxMemory }) => {
  ready ??= init();
  await ready;
  const xlsx = convertTable(new Uint8Array(bytes), maxCells, maxMemory);
  return { value: xlsx.buffer as ArrayBuffer, transfer: [xlsx.buffer as ArrayBuffer] };
});
