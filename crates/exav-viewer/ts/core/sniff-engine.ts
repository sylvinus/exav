import { checkSniffTimeout, type Finding, type Inspector, type OfficeFinding, type Officer, type Sniffer } from "./detect.js";
import type { PackageLimits } from "./types.js";
import { createWorkerHost } from "./worker-host.js";

/** The start of a file, and its whole size. */
export interface SniffRequest {
  head: ArrayBuffer;
  size: number;
}

/** What `inspect` of exav_viewer_sniff.wasm is asked about a file named as format `kind`. */
export interface InspectRequest extends SniffRequest {
  kind: string;
  tail: ArrayBuffer;
  limits: PackageLimits;
}

/** What `zipOfficeKinds` of exav_viewer_sniff.wasm is asked about a ZIP. */
export interface OfficeRequest extends SniffRequest {
  office: true;
  tail: ArrayBuffer;
}

/**
 * One request to exav's detection (exav_viewer_sniff.wasm) in a worker of
 * its own, terminated when it is done: a wasm instance's memory never
 * shrinks, and one that trapped is unusable, so no call reuses another's. It
 * rejects when the worker fails or has not answered in `timeoutMs` (0: it is
 * waited for); `signal` (the session's) stops it at once. Where there are no
 * workers (a test environment, server-side rendering) the bytes say nothing.
 */
async function inWorker<T extends string | Finding | OfficeFinding>(request: SniffRequest | InspectRequest | OfficeRequest, transfer: ArrayBuffer[], timeoutMs: number, signal: AbortSignal | undefined, none: T): Promise<T> {
  if (typeof Worker === "undefined") return none;
  if (signal?.aborted) throw new DOMException("aborted", "AbortError");
  const host = createWorkerHost<SniffRequest | InspectRequest | OfficeRequest, T>(() => new Worker(new URL("./sniff.worker.js", import.meta.url), { type: "module" }));
  const stop = () => host.destroy();
  signal?.addEventListener("abort", stop, { once: true });
  try {
    return await host.call(request, transfer, timeoutMs || undefined);
  } finally {
    signal?.removeEventListener("abort", stop);
    host.destroy();
  }
}

/** The content type exav's detection gives the start of a file (`contentType`). */
export function createSniffer(timeoutMs?: number): Sniffer {
  const timeout = checkSniffTimeout(timeoutMs);
  // A copy: the caller keeps its bytes.
  return (head, size, signal) => {
    const copy = head.slice().buffer as ArrayBuffer;
    return inWorker({ head: copy, size }, [copy], timeout, signal, "");
  };
}

/** What the members of a ZIP say it may be, by its first and last bytes (`zipOfficeKinds`). */
export function createOfficer(timeoutMs?: number): Officer {
  const timeout = checkSniffTimeout(timeoutMs);
  return async (head, tail, size, signal) => {
    const h = head.slice().buffer as ArrayBuffer;
    const t = tail.slice().buffer as ArrayBuffer;
    return inWorker<OfficeFinding>({ head: h, tail: t, size, office: true }, [h, t], timeout, signal, { needs: -1, kinds: [] });
  };
}

/** What exav's readers find of a file by its first and last bytes (`inspect`). */
export function createInspector(timeoutMs?: number): Inspector {
  const timeout = checkSniffTimeout(timeoutMs);
  return async (kind, head, tail, size, limits, signal) => {
    const h = head.slice().buffer as ArrayBuffer;
    const t = tail.slice().buffer as ArrayBuffer;
    return inWorker<Finding>({ kind, head: h, tail: t, size, limits }, [h, t], timeout, signal, { verdict: "not-inspected", needs: -1, reason: "" });
  };
}
