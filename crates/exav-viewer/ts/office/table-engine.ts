import { createWorkerHost } from "../core/worker-host.js";

export interface TableRequest {
  bytes: ArrayBuffer;
  maxCells: number;
  maxMemory: number;
}

/** What a table is read with: the most fields it may hold, empty ones included, and the memory the conversion may count. */
export interface TableLimits {
  maxCells: number;
  maxMemory: number;
}

/**
 * The XLSX of a CSV or TSV, made by `convertTable` of exav_viewer_table.wasm
 * in a worker of its own for this one file, terminated when it is done: a
 * wasm instance's memory never shrinks. Rejects with the converter's error
 * kind as message ("not-format", "too-large"), "no answer within" when it
 * did not answer in time, or what the worker threw when its module trapped.
 * `signal` (the session's) stops it at once.
 */
export async function convertTable(bytes: Uint8Array, limits: TableLimits, options: { signal?: AbortSignal; timeoutMs?: number } = {}): Promise<ArrayBuffer> {
  const host = createWorkerHost<TableRequest, ArrayBuffer>(() => new Worker(new URL("./table.worker.js", import.meta.url), { type: "module" }));
  const stop = () => host.destroy();
  options.signal?.addEventListener("abort", stop, { once: true });
  try {
    // A copy: the caller keeps its bytes.
    const copy = bytes.slice().buffer as ArrayBuffer;
    return await host.call({ bytes: copy, ...limits }, [copy], options.timeoutMs ?? 120_000);
  } finally {
    options.signal?.removeEventListener("abort", stop);
    host.destroy();
  }
}
