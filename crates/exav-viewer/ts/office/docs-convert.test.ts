/**
 * What convertDocs asks of its worker: a copy of the file, the memory the
 * module may take, the time it has, and the worker's end with the call or the
 * session.
 */
import { afterEach, describe, expect, it, vi } from "vitest";

const host = { call: vi.fn(), destroy: vi.fn() };
vi.mock("../core/worker-host.js", () => ({ createWorkerHost: () => host }));

import { convertDocs, DOC_LIMITS } from "./docs.js";

afterEach(() => {
  host.call.mockReset();
  host.destroy.mockReset();
  vi.unstubAllGlobals();
});

const answer = { docx: new ArrayBuffer(1), paragraphs: 1, warnings: "" };

describe("convertDocs", () => {
  it("sends a copy, so that the caller keeps its bytes", async () => {
    host.call.mockResolvedValue(answer);
    const bytes = new Uint8Array([1, 2, 3]);
    await convertDocs(bytes, "doc");
    const [request, transfer] = host.call.mock.calls[0] as [{ bytes: ArrayBuffer; format: string }, ArrayBuffer[]];
    expect(request.format).toBe("doc");
    expect(request.bytes).not.toBe(bytes.buffer);
    expect([...new Uint8Array(request.bytes)]).toEqual([1, 2, 3]);
    expect(transfer).toEqual([request.bytes]);
    expect(bytes.byteLength).toBe(3);
  });

  it("limits the paragraphs, the memory and the time", async () => {
    host.call.mockResolvedValue(answer);
    await convertDocs(new Uint8Array(1), "odt");
    let [request, , timeout] = host.call.mock.calls[0] as [{ maxParagraphs: number; maxMemory: number }, unknown, number];
    expect(request.maxParagraphs).toBe(DOC_LIMITS.maxParagraphs);
    expect(request.maxMemory).toBe(DOC_LIMITS.maxMemory);
    expect(timeout).toBe(120_000);
    // More than the module can hold is cut to what it can; less is kept.
    await convertDocs(new Uint8Array(1), "odt", { maxMemory: 2 ** 40, timeoutMs: 5 });
    [request, , timeout] = host.call.mock.calls[1] as [{ maxParagraphs: number; maxMemory: number }, unknown, number];
    expect(request.maxMemory).toBe(1.5 * 2 ** 30);
    expect(timeout).toBe(5);
    await convertDocs(new Uint8Array(1), "odt", { maxMemory: 1 << 20 });
    expect((host.call.mock.calls[2] as [{ maxMemory: number }])[0].maxMemory).toBe(1 << 20);
  });

  it("ends its worker with the call, whether it answered or not", async () => {
    host.call.mockResolvedValue(answer);
    await convertDocs(new Uint8Array(1), "rtf");
    expect(host.destroy).toHaveBeenCalledTimes(1);
    host.call.mockRejectedValue(new Error("malformed"));
    await expect(convertDocs(new Uint8Array(1), "rtf")).rejects.toThrow("malformed");
    expect(host.destroy).toHaveBeenCalledTimes(2);
  });

  it("ends its worker at once when the session aborts", async () => {
    let finish: (v: typeof answer) => void = () => {};
    host.call.mockReturnValue(new Promise((resolve) => (finish = resolve)));
    const abort = new AbortController();
    const done = convertDocs(new Uint8Array(1), "doc", { signal: abort.signal });
    expect(host.destroy).not.toHaveBeenCalled();
    abort.abort();
    expect(host.destroy).toHaveBeenCalledTimes(1);
    finish(answer);
    await done;
  });
});
