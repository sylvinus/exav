/**
 * What the Office page needs to know of a DOCX or a PPTX's ZIP, read by
 * exav-unpack's ZIP reader (exav_viewer_sniff.wasm, in a worker): where the
 * archive ends, and how large its members are once inflated. Nothing is
 * inflated, and only the end of the file is copied to the reader.
 */
import { FIRST_TAIL, readFromTail } from "../core/zip-tail.js";
import { openTailReader, type TailReader } from "./zip-engine.js";

export interface ZipDirectory {
  /** Each member's uncompressed size, by name. */
  members: Map<string, number>;
  /** Where the archive ends, comment included, when the reader is sure of it. */
  end: number | null;
}

/**
 * The central directory of `bytes`, or `null` for what the reader does not
 * open as a ZIP. Rejects when the reader fails (its module trapped, or it
 * did not answer): the next file has a reader of its own. `signal` (the
 * session's) stops it at once.
 */
export async function zipDirectory(bytes: Uint8Array, signal?: AbortSignal): Promise<ZipDirectory | null> {
  return withReader(signal, (reader) => directoryOf(reader, bytes));
}

/** Runs `use` on a reader of this one file, closed when it is done or `signal` aborts. */
async function withReader<T>(signal: AbortSignal | undefined, use: (reader: TailReader) => Promise<T>): Promise<T> {
  const reader = openTailReader();
  const stop = () => reader.close();
  signal?.addEventListener("abort", stop, { once: true });
  try {
    return await use(reader);
  } finally {
    signal?.removeEventListener("abort", stop);
    reader.close();
  }
}

async function directoryOf(reader: TailReader, bytes: Uint8Array): Promise<ZipDirectory | null> {
  // `null` for what is not a ZIP, and for a directory too far back to be asked for.
  return readFromTail<ZipDirectory | null>(
    FIRST_TAIL,
    async (length) => ({ bytes: bytes.subarray(Math.max(0, bytes.length - length)), size: bytes.length }),
    async ({ bytes: tail, size }) => {
      const read = await reader.read(tail, size);
      if (read.found) {
        const members = new Map<string, number>();
        read.names.forEach((name, i) => members.set(name, read.sizes[i]!));
        return { done: true, value: { members, end: read.end < 0 ? null : read.end } };
      }
      return read.needs < 0 ? { done: true, value: null } : { done: false, needs: read.needs };
    },
  );
}

/** Whether `bytes` start as a ZIP does. */
export const isZip = (bytes: Uint8Array) => bytes[0] === 0x50 && bytes[1] === 0x4b;

/** Whether `bytes` start as a compound file does. */
export const isCompound = (bytes: Uint8Array) => bytes[0] === 0xd0 && bytes[1] === 0xcf && bytes[2] === 0x11 && bytes[3] === 0xe0;

/** What the reader is given of a file that is not a compound file: more than any container's signature or header needs. */
const HEAD = 4096;

/**
 * The Office formats the container of `bytes` says it may be, by the id of the
 * converter for each (`officeKinds` of exav_viewer_sniff.wasm): a compound
 * file by the streams of its directory, a ZIP by the members of its
 * directory, PowerPoint 2 to 4 by its start. The converters tell a file by
 * them. None for what is neither, or that the reader fails on, unless
 * `signal` aborted; `null` for a compound file the reader could not take
 * (one past its memory), which the converter its name chose then reads.
 */
export async function officeKinds(bytes: Uint8Array, signal?: AbortSignal): Promise<readonly string[] | null> {
  try {
    return await withReader(signal, async (reader) => {
      const names = isZip(bytes) ? [...((await directoryOf(reader, bytes).catch(() => null))?.members.keys() ?? [])] : [];
      // A compound file's directory can be anywhere in it.
      return reader.kinds(isCompound(bytes) ? bytes : bytes.subarray(0, HEAD), names);
    });
  } catch (error) {
    if (signal?.aborted) throw error;
    return isCompound(bytes) ? null : [];
  }
}

/**
 * `bytes` without what follows the end of its ZIP. Some files come with
 * bytes after the end record (a newline a tool appended, say); `unzip` and
 * most libraries read them, the Office engines' strict check refuses them
 * ("ZIP central directory preflight failed"). Only an end the reader is sure
 * of is trimmed; anything else is returned as it came, for the engine to
 * judge.
 */
export function trimZipTail(bytes: Uint8Array, directory: ZipDirectory | null): Uint8Array {
  const end = directory?.end;
  return end == null || end >= bytes.length ? bytes : bytes.subarray(0, end);
}
