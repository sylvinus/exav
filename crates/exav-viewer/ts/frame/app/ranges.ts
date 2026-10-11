/**
 * A file read by ranges, in the frame: its first bytes came with it, the
 * rest is asked of the host over the port. Reads are cut to the host's
 * limits and queued within them (`READS`), so that the host never has a
 * reason to refuse one.
 */
import type { ByteRanges } from "../../core/types.js";
import { READS, type BytesMessage, type FrameMessage } from "../protocol.js";

export interface PortRanges extends ByteRanges {
  /** A `bytes` message from the host. */
  receive(m: BytesMessage): void;
}

interface Piece {
  id: number;
  offset: number;
  length: number;
  sent: boolean;
  resolve(b: Uint8Array): void;
  reject(e: Error): void;
}

export function portRanges(post: (m: FrameMessage) => void, size: number, head: Uint8Array): PortRanges {
  let next = 1;
  const queue: Piece[] = [];
  const sent = new Map<number, Piece>();
  let bytes = 0;

  const pump = () => {
    while (queue.length && sent.size < READS.maxReads && bytes + queue[0]!.length <= READS.maxBytes) {
      const p = queue.shift()!;
      p.sent = true;
      sent.set(p.id, p);
      bytes += p.length;
      post({ type: "read", id: p.id, offset: p.offset, length: p.length });
    }
  };

  const piece = (offset: number, length: number, signal: AbortSignal) =>
    new Promise<Uint8Array>((resolve, reject) => {
      const p: Piece = { id: next++, offset, length, sent: false, resolve, reject };
      const abort = () => {
        if (p.sent) post({ type: "cancel", id: p.id });
        else queue.splice(queue.indexOf(p), 1);
        reject(new DOMException("aborted", "AbortError"));
      };
      if (signal.aborted) return abort();
      signal.addEventListener("abort", abort, { once: true });
      p.resolve = (b) => (signal.removeEventListener("abort", abort), resolve(b));
      p.reject = (e) => (signal.removeEventListener("abort", abort), reject(e));
      queue.push(p);
      pump();
    });

  return {
    size,
    async read(offset, length, signal) {
      if (!Number.isSafeInteger(offset) || !Number.isSafeInteger(length) || offset < 0 || length < 0) throw new RangeError(`no bytes ${offset}+${length}`);
      const end = Math.min(size, offset + length);
      if (end <= offset) return new Uint8Array(0);
      // A copy: pdf.js may transfer what it is given.
      if (end <= head.length) return head.slice(offset, end);
      const parts: Promise<Uint8Array>[] = [];
      for (let at = offset; at < end; at += READS.maxLength) parts.push(piece(at, Math.min(READS.maxLength, end - at), signal));
      const got = await Promise.all(parts);
      if (got.length === 1) return got[0]!;
      const out = new Uint8Array(end - offset);
      let at = 0;
      for (const g of got) {
        out.set(g, at);
        at += g.length;
      }
      return out;
    },
    receive(m) {
      const p = sent.get(m.id);
      if (!p) return;
      sent.delete(m.id);
      bytes -= p.length;
      pump();
      if ("error" in m) p.reject(new Error(`the host ${m.error === "refused" ? "refused" : "could not read"} bytes ${p.offset}-${p.offset + p.length - 1}`));
      else if (m.data.byteLength !== p.length) p.reject(new Error(`asked for ${p.length} bytes, given ${m.data.byteLength}`));
      else p.resolve(new Uint8Array(m.data));
    },
  };
}
