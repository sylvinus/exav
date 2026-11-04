/**
 * A CSV or TSV as a one-sheet XLSX, every field a text cell. `@silurus/ooxml`
 * draws a delimited text only through its sheet viewer, which has no workbook
 * to draw pictures with, so the screen and the pictures both open this
 * workbook. exav-render reads the table (encoding and separator off the
 * bytes) and writes the XLSX, in exav_viewer_table.wasm.
 */
import { SheetConversionError } from "./sheets.js";
import { convertTable, type TableLimits } from "./table-engine.js";

/**
 * What a table is read with. The most fields (empty ones included) is the
 * engine's own limit on the cells of a sheet, which it refuses a larger one
 * for. The memory is for the input, and for the text, cells and XLSX
 * exav-render counts, in a module that may grow to 256 MiB.
 */
export const TABLE_LIMITS: TableLimits = { maxCells: 250_000, maxMemory: 64 << 20 };

/**
 * The XLSX of the delimited text `bytes`. Rejects with a
 * `SheetConversionError` ("csv"): "not-format" for what is not text,
 * "too-large" past the limits, "timeout" or "crashed".
 */
export async function xlsxOfTable(bytes: Uint8Array, options: { signal?: AbortSignal; timeoutMs?: number } = {}): Promise<ArrayBuffer> {
  try {
    return await convertTable(bytes, TABLE_LIMITS, options);
  } catch (error) {
    if (options.signal?.aborted) throw error;
    throw new SheetConversionError("csv", error);
  }
}
