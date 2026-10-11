import { describe, expect, it } from "vitest";

import { createWorkerHost } from "./worker-host.js";

/** A worker that answers only when told to, and records being terminated. */
function fakeWorker() {
  const w = {
    onmessage: null as ((e: MessageEvent) => void) | null,
    onerror: null as ((e: ErrorEvent) => void) | null,
    sent: [] as { id: number; request: unknown }[],
    terminated: false,
    postMessage(message: { id: number; request: unknown }) {
      w.sent.push(message);
    },
    terminate() {
      w.terminated = true;
    },
    answer(id: number, value: unknown) {
      w.onmessage?.({ data: { id, ok: true, value } } as MessageEvent);
    },
  };
  return w;
}

describe("createWorkerHost", () => {
  it("stops a worker that does not answer in time, and starts a fresh one for the next request", async () => {
    const started: ReturnType<typeof fakeWorker>[] = [];
    const host = createWorkerHost<string, string>(() => {
      const w = fakeWorker();
      started.push(w);
      return w as unknown as Worker;
    });
    await expect(host.call("stuck", [], 30)).rejects.toThrow(/no answer within 30 ms/);
    expect(started).toHaveLength(1);
    expect(started[0]!.terminated).toBe(true);

    const next = host.call("fine", [], 1000);
    expect(started).toHaveLength(2);
    started[1]!.answer(started[1]!.sent[0]!.id, "drawn");
    await expect(next).resolves.toBe("drawn");
    expect(started[1]!.terminated).toBe(false);
  });

  it("leaves a worker that answered in time alone, its timer included", async () => {
    let worker: ReturnType<typeof fakeWorker> | null = null;
    const host = createWorkerHost<string, string>(() => (worker = fakeWorker()) as unknown as Worker);
    const call = host.call("quick", [], 20);
    worker!.answer(worker!.sent[0]!.id, "done");
    await expect(call).resolves.toBe("done");
    // Past the deadline the answered request must not terminate the worker.
    await new Promise((r) => setTimeout(r, 60));
    expect(worker!.terminated).toBe(false);
  });

  it("starts no worker once destroyed", async () => {
    let started = 0;
    const host = createWorkerHost<string, string>(() => (started++, fakeWorker() as unknown as Worker));
    host.destroy();
    await expect(host.call("late")).rejects.toThrow(/destroyed/);
    expect(started).toBe(0);
  });

  it("without a timeout, waits", async () => {
    let worker: ReturnType<typeof fakeWorker> | null = null;
    const host = createWorkerHost<string, string>(() => (worker = fakeWorker()) as unknown as Worker);
    let settled = false;
    const done = () => (settled = true);
    void host.call("slow").then(done, done);
    await new Promise((r) => setTimeout(r, 60));
    expect(settled).toBe(false);
    expect(worker!.terminated).toBe(false);
    host.destroy();
  });
});
