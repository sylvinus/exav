// The frame's end of a file read by ranges: it asks the host for no more
// than the host takes, and answers from the first bytes it was given.
import { describe, expect, it } from "vitest";

import { READS, type FrameMessage } from "../protocol.js";
import { portRanges } from "./ranges.js";

function setup(size: number, headLength = Math.min(size, READS.head)) {
  const sent: Extract<FrameMessage, { type: "read" | "cancel" }>[] = [];
  const head = Uint8Array.from({ length: headLength }, (_, i) => i & 0xff);
  const r = portRanges((m) => sent.push(m as (typeof sent)[number]), size, head);
  const reads = () => sent.filter((m): m is Extract<FrameMessage, { type: "read" }> => m.type === "read");
  const answer = (id: number) => {
    const m = reads().find((x) => x.id === id)!;
    r.receive({ type: "bytes", id, data: new Uint8Array(m.length).fill(m.offset & 0xff).buffer });
  };
  return { r, sent, reads, answer };
}

const tick = () => new Promise((resolve) => setTimeout(resolve, 0));
const signal = new AbortController().signal;

describe("a file read by ranges, in the frame", () => {
  it("answers from its first bytes without asking", async () => {
    const { r, sent } = setup(1_000_000);
    const got = await r.read(10, 20, signal);
    expect([...got]).toEqual(Array.from({ length: 20 }, (_, i) => 10 + i));
    expect(await r.read(999_990, 0, signal)).toHaveLength(0);
    expect(sent).toEqual([]);
  });

  it("asks in pieces of one read at most, within the reads and bytes outstanding, and joins them", async () => {
    const size = 64 * 1024 * 1024;
    const { r, reads, answer } = setup(size);
    const length = 6 * READS.maxLength + 10;
    let done = false;
    const whole = r.read(READS.head, length, signal).finally(() => (done = true));
    const answered = new Set<number>();
    let rounds = 0;
    for (; !done && rounds < 20; rounds++) {
      await tick();
      // What is out at once stays within the limits; answered, the next goes out.
      const out = reads().filter((m) => !answered.has(m.id));
      expect(out.every((m) => m.length <= READS.maxLength)).toBe(true);
      expect(out.length).toBeLessThanOrEqual(READS.maxReads);
      expect(out.reduce((n, m) => n + m.length, 0)).toBeLessThanOrEqual(READS.maxBytes);
      for (const m of out) {
        answered.add(m.id);
        answer(m.id);
      }
    }
    expect(rounds).toBeGreaterThan(1);
    const got = await whole;
    expect(got.length).toBe(length);
    expect(reads().map((m) => m.offset)).toEqual(Array.from({ length: 7 }, (_, i) => READS.head + i * READS.maxLength));
    // Each piece where it belongs.
    expect(got[READS.maxLength]).toBe((READS.head + READS.maxLength) & 0xff);
  });

  it("keeps to the number of reads outstanding", async () => {
    const { r, reads } = setup(10 * 1024 * 1024);
    for (let i = 0; i < READS.maxReads + 3; i++) void r.read(READS.head + i * 100, 10, signal);
    await tick();
    expect(reads()).toHaveLength(READS.maxReads);
  });

  it("cancels what it no longer wants, and fails a short or refused answer", async () => {
    const { r, sent, reads } = setup(10 * 1024 * 1024);
    const abort = new AbortController();
    const cancelled = r.read(READS.head, 10, abort.signal);
    abort.abort();
    await expect(cancelled).rejects.toThrow();
    expect(sent.at(-1)).toEqual({ type: "cancel", id: reads()[0]!.id });

    const short = r.read(READS.head + 100, 10, signal);
    r.receive({ type: "bytes", id: reads()[1]!.id, data: new ArrayBuffer(9) });
    await expect(short).rejects.toThrow();
    const refused = r.read(READS.head + 200, 10, signal);
    r.receive({ type: "bytes", id: reads()[2]!.id, error: "refused" });
    await expect(refused).rejects.toThrow(/refused/);
  });
});
