import { describe, expect, it } from "vitest";

import type { FrameMessage } from "../protocol.js";
import { portRanges } from "./ranges.js";
import { portTree } from "./tree.js";

function setup() {
  const sent: FrameMessage[] = [];
  const port = portTree((m) => sent.push(m), { path: "a/plan.dwg", paths: ["a/plan.dwg", "a/title.dwg"] });
  const fetches = () => sent.filter((m): m is Extract<FrameMessage, { type: "fetch" }> => m.type === "fetch");
  return { sent, port, fetches };
}

describe("the files around the one shown, in the frame", () => {
  it("are listed as the host listed them", () => {
    const { port } = setup();
    expect(port.tree.path).toBe("a/plan.dwg");
    expect(port.tree.paths).toEqual(["a/plan.dwg", "a/title.dwg"]);
  });

  it("are asked of the host one fetch each, and come back as bytes", async () => {
    const { port, fetches } = setup();
    const signal = new AbortController().signal;
    const one = port.tree.open("a/title.dwg", signal);
    const two = port.tree.open("a/title.dwg", signal);
    expect(fetches().map((f) => f.path)).toEqual(["a/title.dwg", "a/title.dwg"]);
    expect(fetches()[0]!.id).not.toBe(fetches()[1]!.id);
    // The answers come in any order, each to the one that asked.
    port.receive({ type: "bytes", id: fetches()[1]!.id, data: new Uint8Array([2]).buffer });
    port.receive({ type: "bytes", id: fetches()[0]!.id, data: new Uint8Array([1]).buffer });
    expect(await one).toEqual({ bytes: new Uint8Array([1]) });
    expect(await two).toEqual({ bytes: new Uint8Array([2]) });
  });

  it("fail with the host's reason", async () => {
    const { port, fetches } = setup();
    const refused = port.tree.open("a/title.dwg", new AbortController().signal);
    port.receive({ type: "bytes", id: fetches()[0]!.id, error: "refused" });
    await expect(refused).rejects.toThrow("refused");
    const failed = port.tree.open("a/title.dwg", new AbortController().signal);
    port.receive({ type: "bytes", id: fetches()[1]!.id, error: "failed" });
    await expect(failed).rejects.toThrow("could not read");
  });

  it("are cancelled with the signal, and an answer that comes after is ignored", async () => {
    const { port, sent, fetches } = setup();
    const control = new AbortController();
    const asked = port.tree.open("a/title.dwg", control.signal);
    control.abort();
    await expect(asked).rejects.toThrow("aborted");
    expect(sent.at(-1)).toEqual({ type: "cancel", id: fetches()[0]!.id });
    port.receive({ type: "bytes", id: fetches()[0]!.id, data: new ArrayBuffer(1) });
    // Already aborted: nothing is asked.
    const late = new AbortController();
    late.abort();
    await expect(port.tree.open("a/title.dwg", late.signal)).rejects.toThrow("aborted");
    expect(fetches()).toHaveLength(1);
  });

  it("share their ids with the reads of a file by ranges, which never repeat over the frame's life", () => {
    const { port, fetches, sent } = setup();
    void port.tree.open("a/title.dwg", new AbortController().signal);
    const ranges = portRanges((m) => sent.push(m), 1_000_000, new Uint8Array(10));
    void ranges.read(500_000, 10, new AbortController().signal);
    const ids = sent.map((m) => ("id" in m ? m.id : -1));
    expect(new Set(ids).size).toBe(ids.length);
    expect(fetches()).toHaveLength(1);
  });
});
