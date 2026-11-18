/**
 * How the viewer asks exav-unpack's ZIP reader for a directory it is not given
 * whole: the reader is handed the last bytes of the file, and when it needs
 * bytes from earlier it says from where. Every read of a ZIP directory in the
 * package (Office, archives read by ranges, the checks of `Detector`) goes
 * through `readFromTail`, so that they ask for the same bytes in the same way.
 */
import type { FilePart } from "./source.js";

/** Bytes from the end handed first to the reader of a file in memory: the longest end record comment, and a directory of some size. */
export const FIRST_TAIL = 1 << 20;

/**
 * Bytes from the end asked for first when each is a request: the end record
 * and the longest comment it may carry. A longer directory is asked for in
 * the rounds that follow.
 */
export const END_TAIL = 65_557;

/** The most bytes from the end handed to it: a directory that starts earlier is left to the engine. */
export const MAX_TAIL = 64 << 20;

/** Rounds of "needs earlier bytes" before the reader is given up on: an end record, a ZIP64 one, the directory, with room to spare. */
export const MAX_ROUNDS = 8;

/** What the ZIP reader made of a tail: an answer, or the offset from which it needs the bytes. */
export type TailStep<T> = { done: true; value: T } | { done: false; needs: number };

/**
 * The reader's answer for a file, asking `fetch` for the last `length` bytes
 * (null: it cannot) and giving them to `read`, each round with the bytes from
 * where the reader said it needs them. `first` is the length of the first
 * round. null when the file's end cannot be had, when the reader asks for
 * more than `MAX_TAIL` bytes or needs more than `MAX_ROUNDS` rounds, or when
 * it asks for bytes it was already given.
 */
export async function readFromTail<T>(first: number, fetch: (length: number) => Promise<FilePart | null>, read: (tail: FilePart) => Promise<TailStep<T>>): Promise<T | null> {
  let length = first;
  for (let round = 0; round < MAX_ROUNDS; round++) {
    const end = await fetch(length);
    if (!end) return null;
    const step = await read(end);
    if (step.done) return step.value;
    const wanted = end.size - step.needs;
    // Each round starts earlier, so this ends; the reader asking for what it has is a loop to cut.
    if (!(wanted > end.bytes.length) || wanted > MAX_TAIL) return null;
    length = wanted;
  }
  return null;
}
