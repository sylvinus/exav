import { createWorkerHost } from "../core/worker-host.js";
import type { Formatted } from "./lines.js";
import type { Parsed } from "./markdown.js";

/** The readers are linear; a file they cannot finish in this time is not waited for. */
const TIMEOUT_MS = 30_000;

export interface Decoded {
  text: string;
  /** The WHATWG label of the encoding the bytes were read in. */
  encoding: string;
}

/** What `format` makes lines of. */
export type FormatKind = "json" | "xml" | "diff";

export type Request =
  | { op: "decode"; bytes: Uint8Array; partial: boolean; page: boolean }
  | { op: "markdown"; source: string }
  | { op: "format"; kind: FormatKind; text: string; maxLines: number };

export type Reply = { op: "decode"; decoded: Decoded | null } | { op: "markdown"; json: string } | { op: "format"; json: string | null };

export interface TextEngine {
  /**
   * `bytes` as text by exav-unpack's rule, or `null` when they are not text.
   * `partial`: they are the start of a longer file. `page`: a page shown as
   * its source, read in the encoding the scanner reads a page in (its
   * `<meta charset>` too). `bytes` is handed over to the worker.
   */
  decode(bytes: Uint8Array, partial: boolean, page: boolean): Promise<Decoded | null>;
  /** Markdown read into a tree of data (exav-render). */
  markdown(source: string): Promise<Parsed>;
  /**
   * `text` as at most `maxLines` lines of coloured pieces (exav-render's
   * `text_view`), or `null` when it is not JSON, or does not start with
   * markup for XML. A diff always gives lines.
   */
  format(kind: FormatKind, text: string, maxLines: number): Promise<Formatted | null>;
  /** Stops the worker. */
  close(): void;
}

/**
 * The text module (`exav_viewer_text.wasm`) in a worker of its own for one
 * file, stopped by `close`: a wasm instance's memory never shrinks. `signal`
 * (the session's) stops it at once.
 */
export function openTextEngine(signal?: AbortSignal): TextEngine {
  const host = createWorkerHost<Request, Reply>(() => new Worker(new URL("./text.worker.js", import.meta.url), { type: "module" }));
  const stop = () => host.destroy();
  signal?.addEventListener("abort", stop, { once: true });
  return {
    async decode(bytes, partial, page) {
      const reply = await host.call({ op: "decode", bytes, partial, page }, [bytes.buffer], TIMEOUT_MS);
      if (reply.op !== "decode") throw new Error("unexpected reply");
      return reply.decoded;
    },
    async markdown(source) {
      const reply = await host.call({ op: "markdown", source }, [], TIMEOUT_MS);
      if (reply.op !== "markdown") throw new Error("unexpected reply");
      return JSON.parse(reply.json) as Parsed;
    },
    async format(kind, text, maxLines) {
      const reply = await host.call({ op: "format", kind, text, maxLines }, [], TIMEOUT_MS);
      if (reply.op !== "format") throw new Error("unexpected reply");
      return reply.json === null ? null : (JSON.parse(reply.json) as Formatted);
    },
    close() {
      signal?.removeEventListener("abort", stop);
      host.destroy();
    },
  };
}
