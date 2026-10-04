// A ZIP read by ranges, in a worker of its own.
//
// @exav/unpack-wasm reads synchronously, and the bytes of a file read by
// ranges arrive asynchronously. So each operation runs against what is
// already here: a read of anything else records where it was and fails, the
// operation is dropped, the missing bytes are fetched, and the operation runs
// again on a fresh archive (the library's reader keeps a failed read for
// good). The library reads by blocks of `CHUNK`, so that is what is fetched
// and kept. A ZIP needs few rounds: its start and end, the chunks of its
// local headers (fetched together, from its central directory), then one or
// two per member opened.
import { Archive, type MemberInfo } from "@exav/unpack-wasm";

import { RANGED_ARCHIVE, type RangedReply, type RangedRequest } from "./ranged-protocol.js";

const { chunk: CHUNK, maxRounds: MAX_ROUNDS, keepBytes: KEEP_BYTES, maxOpBytes: MAX_OP_BYTES } = RANGED_ARCHIVE;

let size = 0;
let limits: Record<string, number> = {};
let archive: Archive | null = null;
/** As the library names it. */
let format = "";
let members: MemberInfo[] = [];
/** Bytes extracted so far: a reopened archive gets what is left of the budget. */
let extracted = 0;

/** By chunk index; the last chunk of the file may be short. Oldest first. */
const cache = new Map<number, Uint8Array>();
let cached = 0;
/** The chunks the current operation read. */
let used = new Set<number>();
/** The first chunk the current operation found missing. */
let miss: number | null = null;

/** What is here from `offset` on, up to `length` bytes, and the chunks it came from. */
function gather(offset: number, length: number): { bytes: Uint8Array; chunks: number[] } {
  const end = Math.min(size, offset + length);
  const parts: Uint8Array[] = [];
  const chunks: number[] = [];
  let at = offset;
  while (at < end) {
    const index = Math.floor(at / CHUNK);
    const bytes = cache.get(index);
    if (!bytes) break;
    const from = at - index * CHUNK;
    const to = Math.min(bytes.length, end - index * CHUNK);
    if (to <= from) break;
    chunks.push(index);
    parts.push(bytes.subarray(from, to));
    at = index * CHUNK + to;
  }
  if (parts.length === 1) return { bytes: parts[0]!, chunks };
  const out = new Uint8Array(at - offset);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return { bytes: out, chunks };
}

/** The archive's source: what is here, short where it ends; a miss, which fails the read, where nothing is. */
const reader = {
  get size() {
    return size;
  },
  read(offset: number, length: number): Uint8Array {
    const { bytes, chunks } = gather(offset, length);
    for (const c of chunks) used.add(c);
    if (!bytes.length && offset < size && length > 0) {
      miss ??= Math.floor(offset / CHUNK);
      throw new Error("not fetched yet");
    }
    return bytes;
  },
};

let nextNeed = 1;
const needs = new Map<number, { resolve: (b: ArrayBuffer) => void; reject: (e: Error) => void }>();

/** Asks the page for bytes. */
function need(offset: number, length: number): Promise<ArrayBuffer> {
  const need = nextNeed++;
  return new Promise((resolve, reject) => {
    needs.set(need, { resolve, reject });
    post({ need, offset, length });
  });
}

const post = (m: RangedReply, transfer: Transferable[] = []) => (self as unknown as Worker).postMessage(m, transfer);

/** Fetches the chunks of `wanted` not here, each run of consecutive ones in one request, all at once. */
async function fetchChunks(wanted: Iterable<number>): Promise<void> {
  const last = Math.ceil(size / CHUNK);
  const missing = [...new Set(wanted)].filter((i) => i >= 0 && i < last && !cache.has(i)).sort((a, b) => a - b);
  const runs: [number, number][] = [];
  for (const i of missing) {
    const run = runs[runs.length - 1];
    if (run && run[1] === i) run[1] = i + 1;
    else runs.push([i, i + 1]);
  }
  await Promise.all(
    runs.map(async ([i, j]) => {
      const offset = i * CHUNK;
      const length = Math.min(size, j * CHUNK) - offset;
      const bytes = new Uint8Array(await need(offset, length));
      if (bytes.length !== length) throw new Error(`asked for ${length} bytes at ${offset}, given ${bytes.length}`);
      for (let k = i; k < j; k++) {
        if (cache.has(k)) continue;
        // A buffer of its own: dropping it frees it.
        const piece = bytes.slice((k - i) * CHUNK, Math.min(bytes.length, (k - i + 1) * CHUNK));
        cache.set(k, piece);
        cached += piece.length;
      }
    }),
  );
}

/** The chunks under bytes `offset` to `offset + length`. */
function chunksOf(offset: number, length: number): number[] {
  const out: number[] = [];
  for (let i = Math.floor(offset / CHUNK); i * CHUNK < Math.min(size, offset + length); i++) out.push(i);
  return out;
}

/** `length` bytes here at `offset`, or null. */
function here(offset: number, length: number): DataView | null {
  const { bytes } = gather(offset, length);
  return bytes.length === length ? new DataView(bytes.buffer, bytes.byteOffset, length) : null;
}

/**
 * Where a ZIP's members' local headers are, read from its central directory,
 * so that their chunks are fetched in one go rather than one round each: the
 * library reads every local header to list the members. A hint only: what it
 * gets wrong is fetched by the rounds, and the library reads the archive
 * itself.
 */
async function zipHeaders(): Promise<number[]> {
  const tail = Math.min(size, 65_557);
  await fetchChunks(chunksOf(size - tail, tail));
  const end = here(size - tail, tail);
  if (!end) return [];
  let at = -1;
  for (let i = tail - 22; i >= 0; i--) {
    if (end.getUint32(i, true) === 0x06054b50) {
      at = i;
      break;
    }
  }
  if (at < 0) return [];
  let entries = end.getUint16(at + 10, true);
  let cdSize = end.getUint32(at + 12, true);
  let cdOffset = end.getUint32(at + 16, true);
  if ((entries === 0xffff || cdSize === 0xffffffff || cdOffset === 0xffffffff) && at >= 20 && end.getUint32(at - 20, true) === 0x07064b50) {
    const z = Number(end.getBigUint64(at - 12, true));
    await fetchChunks(chunksOf(z, 56));
    const z64 = here(z, 56);
    if (!z64 || z64.getUint32(0, true) !== 0x06064b50) return [];
    entries = Number(z64.getBigUint64(32, true));
    cdSize = Number(z64.getBigUint64(40, true));
    cdOffset = Number(z64.getBigUint64(48, true));
  }
  if (cdOffset + cdSize > size || cdSize > 64 * 1024 * 1024) return [];
  await fetchChunks(chunksOf(cdOffset, cdSize));
  const cd = here(cdOffset, cdSize);
  if (!cd) return [];
  const offsets: number[] = [];
  for (let p = 0, n = 0; n < entries && p + 46 <= cdSize; n++) {
    if (cd.getUint32(p, true) !== 0x02014b50) break;
    const nameLength = cd.getUint16(p + 28, true);
    const extraLength = cd.getUint16(p + 30, true);
    let offset = cd.getUint32(p + 42, true);
    if (offset === 0xffffffff) {
      // The zip64 field holds the sizes first, those that overflowed.
      let q = p + 46 + nameLength;
      const stop = q + extraLength;
      while (q + 4 <= stop && q + 4 <= cdSize) {
        const id = cd.getUint16(q, true);
        const length = cd.getUint16(q + 2, true);
        if (id === 1) {
          const skip = (cd.getUint32(p + 24, true) === 0xffffffff ? 8 : 0) + (cd.getUint32(p + 20, true) === 0xffffffff ? 8 : 0);
          if (skip + 8 <= length && q + 4 + skip + 8 <= cdSize) offset = Number(cd.getBigUint64(q + 4 + skip, true));
          break;
        }
        q += 4 + length;
      }
    }
    if (offset < size) offsets.push(offset);
    p += 46 + nameLength + extraLength + cd.getUint16(p + 32, true);
  }
  return offsets;
}

/** Fetches the chunks of every member's local header, once. */
let hinted = false;
async function prefetchHeaders(): Promise<void> {
  if (hinted || format.toLowerCase() !== "zip") return;
  hinted = true;
  const offsets = await zipHeaders().catch(() => []);
  // A local header and its name, and the extra field, which is short.
  const wanted = new Set(offsets.flatMap((o) => chunksOf(o, 30 + 1024)));
  // Headers spread over more than an operation may hold: the rounds will
  // fail, and the archive is read whole instead.
  if (wanted.size * CHUNK <= MAX_OP_BYTES) await fetchChunks(wanted);
}

/** Drops the oldest chunks the last operation did not read, down to `KEEP_BYTES`. */
function trim() {
  for (const [index, bytes] of cache) {
    if (cached <= KEEP_BYTES) return;
    if (used.has(index)) continue;
    cache.delete(index);
    cached -= bytes.length;
  }
}

async function reopen(): Promise<Archive> {
  const left = { ...limits };
  if (left.maxExtractedBytes !== undefined) left.maxExtractedBytes = Math.max(0, left.maxExtractedBytes - extracted);
  return Archive.open(reader, left);
}

/**
 * Runs `op` until it reads nothing missing. `hint`: the bytes the first miss
 * is likely followed by (a member's compressed size). A miss right after
 * the last fetch is a walk forward: twice as much is fetched each time.
 */
async function attempt<T>(op: (a: Archive) => Promise<T>, hint = 0): Promise<T> {
  let ahead = 0;
  let next = -1;
  for (let round = 0; ; round++) {
    miss = null;
    used = new Set();
    let value: T | undefined;
    let error: unknown = null;
    let failed = false;
    try {
      archive ??= await reopen();
      value = await op(archive);
    } catch (e) {
      failed = true;
      error = e;
    }
    // After a failure the archive is not used again: its reader keeps the
    // failure, and a trap leaves it on a module that is gone.
    if (failed || miss !== null) {
      archive?.close().catch(() => {});
      archive = null;
    }
    if (miss === null) {
      trim();
      if (failed) throw error;
      return value as T;
    }
    // Whatever it returned was read short.
    if (round >= MAX_ROUNDS) throw new Error(`the archive needed more than ${MAX_ROUNDS} rounds of reads`);
    const first: number = miss;
    ahead = round === 0 && hint ? Math.ceil(hint / CHUNK) + 1 : first === next ? Math.min(ahead * 2, 64) : 1;
    next = first + ahead;
    let usedBytes = 0;
    for (const index of used) usedBytes += cache.get(index)?.length ?? 0;
    if (usedBytes + ahead * CHUNK > MAX_OP_BYTES) throw new Error("the archive needs too much at once to be read by ranges");
    await fetchChunks(Array.from({ length: ahead }, (_, i) => first + i));
  }
}

async function run(r: Extract<RangedRequest, { id: number }>): Promise<{ value: unknown; transfer?: Transferable[] }> {
  switch (r.op) {
    case "open":
      size = r.size;
      limits = r.limits;
      // Its start and its end, where formats begin and a ZIP's directory ends.
      await fetchChunks([0, Math.ceil(size / CHUNK) - 1]);
      format = await attempt(async (a) => a.format());
      return { value: format };
    case "list":
      await prefetchHeaders();
      members = await attempt((a) => a.list());
      return { value: members };
    case "extract": {
      const hint = members.find((m) => m.index === r.index)?.compressedSize ?? 0;
      const entry = await attempt((a) => a.extract(r.index), hint + 65_536);
      extracted += entry.bytes.length;
      const bytes = entry.bytes.byteOffset === 0 && entry.bytes.byteLength === entry.bytes.buffer.byteLength ? entry.bytes : entry.bytes.slice();
      return {
        value: { name: entry.name, bytes, encrypted: entry.encrypted, unsupported: entry.unsupported },
        transfer: [bytes.buffer as ArrayBuffer],
      };
    }
    case "close":
      await archive?.close();
      archive = null;
      cache.clear();
      cached = 0;
      return { value: null };
  }
}

/** One operation at a time: each may restart the archive. */
let queue: Promise<unknown> = Promise.resolve();

self.onmessage = (e: MessageEvent<RangedRequest>) => {
  const r = e.data;
  if ("need" in r) {
    const waiting = needs.get(r.need);
    needs.delete(r.need);
    if (!waiting) return;
    if (r.bytes) waiting.resolve(r.bytes);
    else waiting.reject(new Error(r.error ?? "the read failed"));
    return;
  }
  queue = queue.then(() =>
    run(r).then(
      ({ value, transfer }) => post({ id: r.id, ok: true, value }, transfer),
      (error) => post({ id: r.id, ok: false, error: String((error as Error)?.message ?? error) }),
    ),
  );
};
