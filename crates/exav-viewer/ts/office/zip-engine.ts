import { createWorkerHost } from "../core/worker-host.js";
import { packNames } from "./pack-names.js";

/** What the reader is asked: a file's end for its ZIP directory, or its bytes and the member names (`packNames`) for the Office formats they may be. */
export type ZipRequest = { tail: ArrayBuffer; size: number } | { bytes: ArrayBuffer; names: ArrayBuffer };

/** What the ZIP reader made of a file's end (`ZipTail` of exav_viewer_sniff.wasm). */
export interface ZipTailRead {
  found: boolean;
  /** The offset from which the reader needs more bytes, else -1. */
  needs: number;
  /** Where the archive ends, else -1. */
  end: number;
  names: string[];
  sizes: number[];
}

/** One file's reader: its calls, then `close`. */
export interface TailReader {
  read(tail: Uint8Array, size: number): Promise<ZipTailRead>;
  /**
   * The Office formats the file may be (`officeKinds` of exav_viewer_sniff.wasm):
   * `bytes` is the whole file when it is a compound file, else its start, and
   * `names` the members of its ZIP directory.
   */
  kinds(bytes: Uint8Array, names: readonly string[]): Promise<string[]>;
  close(): void;
}

/** A directory is read in moments; a worker that has not answered in this time is not waited for. */
const TIMEOUT_MS = 30_000;

/**
 * exav-unpack's ZIP reader, in a worker of its own for this one file,
 * terminated when it is done: a wasm instance's memory never shrinks, and one
 * that trapped is unusable, so no file reuses another's.
 */
export function openTailReader(): TailReader {
  const host = createWorkerHost<ZipRequest, ZipTailRead | string[]>(() => new Worker(new URL("./zip.worker.js", import.meta.url), { type: "module" }));
  return {
    read(tail, size) {
      // A copy: the caller keeps its bytes.
      const copy = tail.slice().buffer as ArrayBuffer;
      return host.call({ tail: copy, size }, [copy], TIMEOUT_MS) as Promise<ZipTailRead>;
    },
    kinds(bytes, names) {
      const copy = bytes.slice().buffer as ArrayBuffer;
      const packed = packNames(names).buffer;
      return host.call({ bytes: copy, names: packed }, [copy, packed], TIMEOUT_MS) as Promise<string[]>;
    },
    close: () => host.destroy(),
  };
}
