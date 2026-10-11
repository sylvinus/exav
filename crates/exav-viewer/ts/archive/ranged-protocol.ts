/** How the ranged worker reads (`ranges.worker.ts`). */
export const RANGED_ARCHIVE = {
  /** Bytes fetched and kept per piece. */
  chunk: 65_536,
  /** Most restarts of one operation. */
  maxRounds: 64,
  /** Bytes kept between operations: the central directory, mostly. */
  keepBytes: 64 * 1024 * 1024,
  /** Most bytes one operation may need at once. */
  maxOpBytes: 512 * 1024 * 1024,
};

/** To the worker: an operation, or the bytes it asked for. */
export type RangedRequest =
  | { id: number; op: "open"; size: number; limits: Record<string, number> }
  | { id: number; op: "list" }
  | { id: number; op: "extract"; index: number }
  | { id: number; op: "close" }
  | { need: number; bytes?: ArrayBuffer; error?: string };

/** From the worker: an operation's result, or bytes it needs. */
export type RangedReply = { id: number; ok: true; value: unknown } | { id: number; ok: false; error: string } | { need: number; offset: number; length: number };
