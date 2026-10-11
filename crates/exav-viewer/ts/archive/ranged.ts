import type { ByteRanges } from "../core/types.js";
import type { RangedReply, RangedRequest } from "./ranged-protocol.js";

/** An operation, before it is numbered. */
type Operation = RangedRequest extends infer R ? (R extends { id: number } ? Omit<R, "id"> : never) : never;

export interface RangedEntry {
  name: string;
  bytes: Uint8Array;
  encrypted: boolean;
  unsupported: string;
}

/** What the renderer uses of an archive: @exav/unpack-wasm's `Archive` has it too. */
export interface RangedArchive {
  list(): Promise<{ index: number; name: string; uncompressedSize: number; encrypted: boolean }[]>;
  extract(index: number): Promise<RangedEntry>;
  close(): Promise<void>;
}

/** A ZIP: local headers start with "PK\x03\x04", an empty one with its end record. */
export function isZip(head: Uint8Array): boolean {
  return head.length >= 4 && head[0] === 0x50 && head[1] === 0x4b && ((head[2] === 3 && head[3] === 4) || (head[2] === 5 && head[3] === 6));
}

/**
 * Opens a ZIP read by ranges in a worker of its own, which asks for the
 * bytes it needs. `signal` stops the reads and the worker.
 */
export async function openRanged(ranges: ByteRanges, limits: Record<string, number>, signal: AbortSignal): Promise<RangedArchive> {
  const worker = new Worker(new URL("./ranges.worker.js", import.meta.url), { type: "module" });
  let next = 1;
  const pending = new Map<number, { resolve: (v: unknown) => void; reject: (e: Error) => void }>();
  const stop = (reason: string) => {
    worker.terminate();
    for (const p of pending.values()) p.reject(new Error(reason));
    pending.clear();
  };
  signal.addEventListener("abort", () => stop("aborted"), { once: true });
  worker.onerror = (e) => stop(e.message || "the archive worker stopped");
  worker.onmessage = (e: MessageEvent<RangedReply>) => {
    const m = e.data;
    if ("need" in m) {
      ranges.read(m.offset, m.length, signal).then(
        (bytes) => {
          const own = bytes.byteOffset === 0 && bytes.byteLength === bytes.buffer.byteLength ? bytes : bytes.slice();
          const buffer = own.buffer as ArrayBuffer;
          worker.postMessage({ need: m.need, bytes: buffer } satisfies RangedRequest, [buffer]);
        },
        (error) => worker.postMessage({ need: m.need, error: String((error as Error)?.message ?? error) } satisfies RangedRequest),
      );
      return;
    }
    const p = pending.get(m.id);
    pending.delete(m.id);
    if (!p) return;
    if (m.ok) p.resolve(m.value);
    else p.reject(new Error(m.error));
  };
  const call = <T>(request: Operation): Promise<T> =>
    signal.aborted
      ? Promise.reject(new DOMException("aborted", "AbortError"))
      : new Promise<T>((resolve, reject) => {
          const id = next++;
          pending.set(id, { resolve: resolve as (v: unknown) => void, reject });
          worker.postMessage({ ...request, id } as RangedRequest);
        });

  try {
    await call<string>({ op: "open", size: ranges.size, limits });
  } catch (error) {
    stop("closed");
    throw error;
  }
  return {
    list: () => call({ op: "list" }),
    extract: (index) => call({ op: "extract", index }),
    async close() {
      await call({ op: "close" }).catch(() => undefined);
      stop("closed");
    },
  };
}
