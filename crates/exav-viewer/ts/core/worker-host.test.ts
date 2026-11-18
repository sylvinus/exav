import { afterEach, describe, expect, it, vi } from "vitest";

import { createWorkerHost, serve } from "./worker-host.js";

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

describe("serve", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  /** What `serve` posts for one request that `handle` fails with `error`. */
  async function replyTo(error: unknown) {
    const scope = {
      onmessage: null as ((e: MessageEvent) => void) | null,
      posted: [] as { ok: boolean; fatal?: boolean }[],
      postMessage(message: { ok: boolean; fatal?: boolean }) {
        scope.posted.push(message);
      },
    };
    vi.stubGlobal("self", scope);
    serve<string, string>(async () => {
      throw error;
    });
    scope.onmessage?.({ data: { id: 1, request: "x" } } as MessageEvent);
    await vi.waitFor(() => expect(scope.posted).toHaveLength(1));
    return scope.posted[0]!;
  }

  it("reports a trap and an exhausted stack as fatal, so the worker is replaced", async () => {
    expect((await replyTo(new WebAssembly.RuntimeError("unreachable"))).fatal).toBe(true);
    expect((await replyTo(new RangeError("Maximum call stack size exceeded"))).fatal).toBe(true);
    expect((await replyTo(new Error("not a drawing"))).fatal).toBe(false);
  });
});
