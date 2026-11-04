import { HEAD_BYTES } from "./detect.js";
import type { Detector, FormatId, ViewerFile } from "./types.js";

/**
 * Thrown by a renderer's `mount` when the bytes it was given are another
 * format, which the session then shows the file as. The session does this
 * once per file: a second refusal, a mismatch included, ends in an error.
 */
export class FormatMismatch extends Error {
  readonly format: FormatId;

  constructor(format: FormatId) {
    super(`the bytes are ${format}`);
    this.name = "FormatMismatch";
    this.format = format;
  }
}

/**
 * The mismatch for `bytes`, a file the engine of format `own` could not read,
 * or null where the detection finds nothing else (or fails): the engine's own
 * error stands. For an engine that holds the whole file only after reading
 * it, as for a file given by an address, which the session could not type
 * before.
 */
export async function mismatchOf(detector: Detector, file: ViewerFile, bytes: Uint8Array, own: FormatId, signal?: AbortSignal): Promise<FormatMismatch | null> {
  try {
    const found = await detector.detectFile(file, bytes.subarray(0, HEAD_BYTES), bytes.length, signal, async (n) => ({ bytes: bytes.subarray(Math.max(0, bytes.length - n)), size: bytes.length }));
    return found && found !== own ? new FormatMismatch(found) : null;
  } catch {
    return null;
  }
}
