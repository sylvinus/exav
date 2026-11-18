import { beforeAll, describe, expect, it, vi } from "vitest";

import { createHighlights } from "../core/highlights.js";
import type { Highlight, RenderContext } from "../core/types.js";
import "../test/blob.js";
import { textHighlights } from "./highlights.js";
import { renderer } from "./renderer.js";

// The page decodes and formats in a worker, which jsdom has not: the same module, in this process.
vi.mock("./engine.js", async () => {
  const real = await import("../test/text-wasm.js");
  return {
    openTextEngine: () => ({
      decode: (bytes: Uint8Array, partial: boolean, page: boolean) => real.decodeText(bytes, partial, page),
      format: (kind: "json" | "xml" | "diff", text: string, maxLines: number) => real.formatLines(kind, text, maxLines),
      markdown: async (source: string) => real.readMarkdown(source),
      close: () => {},
    }),
  };
});

const settle = () => new Promise((r) => setTimeout(r, 0));

// jsdom has no scrolling.
beforeAll(() => {
  HTMLElement.prototype.scrollTo ??= () => {};
});

function page(html: string) {
  const root = document.createElement("div");
  root.innerHTML = html;
  document.body.append(root);
  return root;
}

describe("highlights in a text", () => {
  it("wraps a quote in marks, over the elements its text crosses, and leaves the text as it was", async () => {
    const root = page('<pre>"montant": <span class="n">1250000</span>,\n"délai": "12 mois"</pre>');
    const before = root.textContent;
    const h = createHighlights(textHighlights(root, Promise.resolve()), [{ id: "q", text: "Montant : 1 250 000", label: "Montant" }]);
    await settle();
    expect(h.controller.get().items[0]).toMatchObject({ id: "q", state: "shown", page: null, rects: [] });
    const marks = [...root.querySelectorAll<HTMLElement>("mark.exav-viewer-highlight-text")];
    expect(marks.map((m) => m.textContent).join("")).toBe('montant": 1250000');
    expect(marks.every((m) => m.dataset.highlight === "q" && m.title === "Montant")).toBe(true);
    expect(marks[0]!.classList.contains("exav-viewer-highlight-current")).toBe(true);
    expect(root.querySelector(".n mark")?.textContent).toBe("1250000");
    expect(root.textContent).toBe(before);
    // Replaced: the old marks go, the text stays whole.
    h.controller.set([{ id: "d", text: "délai" }]);
    await settle();
    expect([...root.querySelectorAll("mark")].map((m) => m.textContent)).toEqual(["délai"]);
    expect(root.querySelector("pre")!.childNodes[0]!.nodeType).toBe(Node.TEXT_NODE);
    expect(root.textContent).toBe(before);
  });

  it("does not draw boxes, which need pages, nor a quote the text does not have", async () => {
    const root = page("<p>Rien</p>");
    const h = createHighlights(textHighlights(root, Promise.resolve()), [{ page: 1, rects: [{ x: 0, y: 0, width: 1, height: 1 }] }, { text: "autre chose" }]);
    await settle();
    expect(h.controller.get().items.map((i) => i.state)).toEqual(["missing", "missing"]);
    expect(root.querySelector("mark")).toBeNull();
  });

  it("scrolls the marks to the middle of the text's box", async () => {
    const root = page("<p>a</p><p>b</p><p>cible</p>");
    const scrollTo = vi.fn();
    root.scrollTo = scrollTo as typeof root.scrollTo;
    Object.defineProperty(root, "clientHeight", { value: 400 });
    root.getBoundingClientRect = () => ({ top: 100, bottom: 500, height: 400 }) as DOMRect;
    const original = HTMLElement.prototype.getBoundingClientRect;
    HTMLElement.prototype.getBoundingClientRect = function (this: HTMLElement) {
      return (this.localName === "mark" ? { top: 1100, bottom: 1120, height: 20 } : original.call(this)) as DOMRect;
    };
    try {
      createHighlights(textHighlights(root, Promise.resolve()), [{ text: "cible" }]);
      await settle();
      // 1000px into the text, its middle 10px further, at the middle of 400px.
      expect(scrollTo).toHaveBeenCalledWith({ top: 1010 - 200, behavior: "auto" });
    } finally {
      HTMLElement.prototype.getBoundingClientRect = original;
    }
  });
});

describe("the text plugin", () => {
  it("publishes the highlights of the file it opens, found once the text is drawn", async () => {
    const host = document.createElement("div");
    document.body.append(host);
    const bytes = new TextEncoder().encode('{"objet": "Travaux de rénovation", "lots": 3}');
    const blob = new Blob([bytes as BlobPart]);
    const highlights: Highlight[] = [{ id: "objet", text: "travaux de renovation" }];
    const ctx = {
      file: { id: "1", name: "offre.json", source: null, highlights, focusHighlight: "objet" },
      options: {},
      source: { blob: async () => blob, bytes: async () => bytes, url: async () => "", progress: { get: () => null, subscribe: () => () => {} } },
      signal: new AbortController().signal,
      assetBase: "",
      status() {},
      controllers() {},
    } as unknown as RenderContext<Record<string, never>>;
    const handle = await renderer.mount(host, ctx);
    await settle();
    expect(handle.controllers.highlights?.get()).toMatchObject({ items: [{ id: "objet", state: "shown" }], current: "objet" });
    expect(host.querySelector("mark")?.textContent).toBe("Travaux de rénovation");
    handle.destroy();
  });
});
