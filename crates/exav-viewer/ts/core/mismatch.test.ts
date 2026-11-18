// An engine that finds the bytes are another format says so (`FormatMismatch`),
// and the session shows the file as that format: once.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { FormatMismatch } from "./mismatch.js";
import { MATCHERS } from "./formats.js";
import type { FormatPlugin, RenderContext, RendererHandle } from "./types.js";
import { createViewer } from "./viewer.js";

const tick = () => new Promise((r) => setTimeout(r, 25));

/** A built-in format's plugin, whose renderer does what `engine` says with each file it is given. */
function plugin(id: "pdf" | "image", engine: () => void) {
  const mounted: string[] = [];
  const p: FormatPlugin = {
    id,
    match: MATCHERS[id],
    capabilities: [],
    options: {},
    load: async () => ({
      mount(host: HTMLElement, c: RenderContext): RendererHandle {
        mounted.push(c.file.name);
        engine();
        c.status({ phase: "ready" });
        return { controllers: {}, destroy() {} };
      },
    }),
  };
  return { plugin: p, mounted };
}

// An address: its first bytes are asked for (a range request), then the engine's turn. The server says nothing of them.
beforeEach(() => void vi.stubGlobal("fetch", async () => new Response(new Uint8Array(4), { status: 206, headers: { "content-range": "bytes 0-3/4" } })));
afterEach(() => vi.unstubAllGlobals());

const mount = (viewer: ReturnType<typeof createViewer>) =>
  viewer.mount(document.createElement("div"), { id: "a", name: "plan.png", type: "image/png", source: { url: "https://example.test/plan.png" } });

describe("a file an engine says is another format", () => {
  it("is shown as that format, by that format's engine", async () => {
    const images = plugin("image", () => {
      throw new FormatMismatch("pdf");
    });
    const pdfs = plugin("pdf", () => {});
    const session = mount(createViewer({ plugins: [pdfs.plugin, images.plugin] }));
    expect(session.format).toBe("image");
    await tick();
    expect(images.mounted).toEqual(["plan.png"]);
    expect(pdfs.mounted).toEqual(["plan.png"]);
    expect(session.format).toBe("pdf");
    expect(session.status.get()).toEqual({ phase: "ready" });
  });

  it("is routed once: a file every engine refuses ends in an error after one more try", async () => {
    vi.spyOn(console, "warn").mockImplementation(() => {});
    const images = plugin("image", () => {
      throw new FormatMismatch("pdf");
    });
    const pdfs = plugin("pdf", () => {
      throw new FormatMismatch("image");
    });
    const session = mount(createViewer({ plugins: [pdfs.plugin, images.plugin] }));
    await tick();
    expect(images.mounted).toEqual(["plan.png"]);
    expect(pdfs.mounted).toEqual(["plan.png"]);
    expect(session.status.get()).toMatchObject({ phase: "error", error: { code: "pdf", cause: expect.any(FormatMismatch) } });
  });

  it("is an error when no plugin opens the format the engine names, and for any other refusal", async () => {
    vi.spyOn(console, "warn").mockImplementation(() => {});
    for (const refusal of [new FormatMismatch("stl"), new Error("undecodable")]) {
      const images = plugin("image", () => {
        throw refusal;
      });
      const pdfs = plugin("pdf", () => {});
      const session = mount(createViewer({ plugins: [pdfs.plugin, images.plugin] }));
      await tick();
      expect(images.mounted).toEqual(["plan.png"]);
      expect(pdfs.mounted).toEqual([]);
      expect(session.status.get()).toMatchObject({ phase: "error", error: { code: "image", cause: refusal } });
    }
  });
});
