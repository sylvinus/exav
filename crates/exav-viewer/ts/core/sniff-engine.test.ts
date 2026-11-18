// `sniffTimeoutMs` reaches the worker: one that has not answered by then is
// stopped, and the call rejects.
import { afterEach, describe, expect, it, vi } from "vitest";

import { checkSniffTimeout, DEFAULT_SNIFF_TIMEOUT_MS } from "./detect.js";
import { createSniffer } from "./sniff-engine.js";
import { createViewer } from "./viewer.js";

/** A `Worker` that never answers, and records being started and terminated. */
function silentWorkers() {
  const started: { terminated: boolean }[] = [];
  vi.stubGlobal(
    "Worker",
    class {
      terminated = false;
      onmessage = null;
      onerror = null;
      constructor() {
        started.push(this);
      }
      postMessage() {}
      terminate() {
        this.terminated = true;
      }
    },
  );
  return started;
}

afterEach(() => vi.unstubAllGlobals());

describe("the detection's timeout", () => {
  it("stops a worker that has not answered within sniffTimeoutMs, and the call fails", async () => {
    const started = silentWorkers();
    const sniff = createSniffer(30);
    const t0 = performance.now();
    await expect(sniff(new Uint8Array(4), 4)).rejects.toThrow(/no answer within 30 ms/);
    expect(performance.now() - t0).toBeLessThan(2000);
    expect(started).toHaveLength(1);
    expect(started[0]!.terminated).toBe(true);
  });

  it("is 30 seconds by default, and what createViewer is given reaches the detection", async () => {
    expect(DEFAULT_SNIFF_TIMEOUT_MS).toBe(30_000);
    expect(checkSniffTimeout(undefined)).toBe(30_000);
    const started = silentWorkers();
    const viewer = createViewer({ plugins: [], sniffTimeoutMs: 30 });
    await expect(viewer.sniff(new Uint8Array(4), 4)).rejects.toThrow(/no answer within 30 ms/);
    expect(started[0]!.terminated).toBe(true);
  });

  it("is a number of milliseconds, 0 for none", () => {
    for (const bad of [-1, Number.NaN, Number.POSITIVE_INFINITY]) {
      expect(() => createSniffer(bad), String(bad)).toThrow(RangeError);
      expect(() => createViewer({ plugins: [], sniffTimeoutMs: bad }), String(bad)).toThrow(RangeError);
    }
    expect(checkSniffTimeout(0)).toBe(0);
  });

  it("is waited for as long as it takes with 0", async () => {
    const started = silentWorkers();
    const pending = createSniffer(0)(new Uint8Array(4), 4);
    const settled = vi.fn();
    pending.then(settled, settled);
    // Past the time a timeout of a few milliseconds would have stopped it.
    await new Promise((r) => setTimeout(r, 150));
    expect(started).toHaveLength(1);
    expect(started[0]!.terminated).toBe(false);
    expect(settled).not.toHaveBeenCalled();
  });
});
