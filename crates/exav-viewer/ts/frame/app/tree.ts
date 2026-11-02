/**
 * The files around the one shown, in the frame: it was told their paths, and
 * asks the host for the bytes of one when a format needs it. The host answers
 * only for a path it listed.
 */
import type { FileTree } from "../../core/types.js";
import type { BytesMessage, FrameMessage } from "../protocol.js";
import { takeId } from "./ranges.js";

export interface PortTree {
  tree: FileTree;
  /** A `bytes` message from the host. */
  receive(m: BytesMessage): void;
}

export function portTree(post: (m: FrameMessage) => void, listed: { path: string; paths: string[] }): PortTree {
  const asked = new Map<number, { resolve(b: Uint8Array): void; reject(e: Error): void }>();
  return {
    tree: {
      path: listed.path,
      paths: listed.paths,
      open(path, signal) {
        return new Promise((resolve, reject) => {
          if (signal.aborted) return reject(new DOMException("aborted", "AbortError"));
          const id = takeId();
          const abort = () => {
            if (asked.delete(id)) post({ type: "cancel", id });
            reject(new DOMException("aborted", "AbortError"));
          };
          signal.addEventListener("abort", abort, { once: true });
          asked.set(id, {
            resolve: (bytes) => (signal.removeEventListener("abort", abort), resolve({ bytes })),
            reject: (e) => (signal.removeEventListener("abort", abort), reject(e)),
          });
          post({ type: "fetch", id, path });
        });
      },
    },
    receive(m) {
      const p = asked.get(m.id);
      if (!p) return;
      asked.delete(m.id);
      if ("error" in m) p.reject(new Error(`the host ${m.error === "refused" ? "refused" : "could not read"} the file`));
      else p.resolve(new Uint8Array(m.data));
    },
  };
}
