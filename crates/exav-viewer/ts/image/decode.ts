import { createWorkerHost, type WorkerHost } from "../core/worker-host.js";

export interface DecodeRequest {
  bytes: ArrayBuffer;
  maxBytes: number;
}

export interface DecodeResult {
  width: number;
  height: number;
  rgba: ArrayBuffer;
}

/**
 * Decodes with exav-render in a worker of its own for this one image,
 * terminated when it is done: a wasm instance's memory never shrinks, and
 * the largest image decoded would otherwise stay held for the life of the
 * page. `signal` (the session's) stops it at once.
 */
export async function decodeInWorker(bytes: ArrayBuffer, maxBytes: number, signal?: AbortSignal): Promise<DecodeResult> {
  const host: WorkerHost<DecodeRequest, DecodeResult> = createWorkerHost(
    () => new Worker(new URL("./decode.worker.js", import.meta.url), { type: "module" }),
  );
  const stop = () => host.destroy();
  signal?.addEventListener("abort", stop, { once: true });
  try {
    // A decode the size limit allows takes seconds; a decoder kept busy by a
    // damaged file is stopped.
    return await host.call({ bytes, maxBytes }, [bytes], 60_000);
  } finally {
    signal?.removeEventListener("abort", stop);
    host.destroy();
  }
}

/** The pixels as a canvas the surface can show. */
export function toCanvas(d: DecodeResult): HTMLCanvasElement {
  const canvas = document.createElement("canvas");
  canvas.width = d.width;
  canvas.height = d.height;
  const ctx = canvas.getContext("2d");
  if (!ctx) throw new Error("no 2d context");
  ctx.putImageData(new ImageData(new Uint8ClampedArray(d.rgba), d.width, d.height), 0, 0);
  return canvas;
}
