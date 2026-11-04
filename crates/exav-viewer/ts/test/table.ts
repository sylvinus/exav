// exav_viewer_table.wasm as the tests run it: the module in this process,
// where the page has it in a worker (jsdom has none). Stands in for
// `ts/office/table-engine.ts` (`convertTable`).
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import init, { convertTable as convertTableInProcess } from "../../wasm/exav_viewer_table.js";
import type { TableLimits } from "../office/table-engine.js";

const wasm = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "wasm", "exav_viewer_table_bg.wasm");
let ready: Promise<unknown> | null = null;

/** The XLSX of a CSV or TSV, as `ts/office/table-engine.ts` (`convertTable`) makes it. */
export async function convertTable(bytes: Uint8Array, limits: TableLimits): Promise<ArrayBuffer> {
  await (ready ??= init({ module_or_path: fs.readFileSync(wasm) }));
  return convertTableInProcess(bytes, limits.maxCells, limits.maxMemory).buffer as ArrayBuffer;
}
