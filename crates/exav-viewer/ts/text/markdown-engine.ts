import { createWorkerHost } from "../core/worker-host.js";
import type { Parsed } from "./markdown.js";

/** The reader is linear; a document it cannot finish in this time is not waited for. */
const TIMEOUT_MS = 30_000;

/**
 * Reads Markdown with exav-render in a worker of its own for this one
 * document, terminated when it is done: a wasm instance's memory never
 * shrinks. `signal` (the session's) stops it at once.
 */
export async function readMarkdown(source: string, signal?: AbortSignal): Promise<Parsed> {
  const host = createWorkerHost<string, string>(() => new Worker(new URL("./markdown.worker.js", import.meta.url), { type: "module" }));
  const stop = () => host.destroy();
  signal?.addEventListener("abort", stop, { once: true });
  try {
    return JSON.parse(await host.call(source, [], TIMEOUT_MS)) as Parsed;
  } finally {
    signal?.removeEventListener("abort", stop);
    host.destroy();
  }
}
