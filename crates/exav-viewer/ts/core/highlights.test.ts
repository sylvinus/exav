import { describe, expect, it, vi } from "vitest";

import { clipRect, createHighlights, findQuote, fold, mergeLines, type HighlightTarget } from "./highlights.js";
import type { PlacedHighlight } from "./types.js";

describe("fold", () => {
  it("keeps letters and digits, lower case, without accents, ligatures split", () => {
    expect(fold("Délai d'exécution : 12 MOIS.").chars).toBe("delaidexecution12mois");
    expect(fold("ﬁnancière").chars).toBe("financiere");
    expect(fold("Œuvre").chars).toBe("oeuvre");
  });

  it("traces each character back to the one it comes from", () => {
    const f = fold("a é-ﬁ");
    expect(f.chars).toBe("aefi");
    expect(f.from).toEqual([0, 2, 4, 4]);
  });
});

describe("findQuote", () => {
  const page = fold("Le montant total du marché est de 1 250 000 € HT. Les pénalités de re-\ntard sont fixées à 1/1000e par jour.").chars;

  it("finds a quote whatever its case, accents, spaces and punctuation", () => {
    expect(findQuote(page, "MONTANT TOTAL du marche est de 1250000€")).not.toBeNull();
  });

  it("finds a word cut by a hyphen at the end of a line", () => {
    expect(findQuote(page, "pénalités de retard")).not.toBeNull();
  });

  it("finds the parts of a quote with text left out, in order", () => {
    const parts = findQuote(page, "Le montant total ... par jour");
    expect(parts).toHaveLength(2);
    expect(parts![0]!.end).toBeLessThan(parts![1]!.start);
    expect(findQuote(page, "par jour … Le montant")).toBeNull();
  });

  it("is null for what the text does not have, or a quote of punctuation alone", () => {
    expect(findQuote(page, "délai de paiement")).toBeNull();
    expect(findQuote(page, "... !")).toBeNull();
  });
});

describe("boxes", () => {
  it("are clipped to the page, and refused when not boxes", () => {
    expect(clipRect({ x: -0.1, y: 0.9, width: 0.3, height: 0.5 })).toEqual({ x: 0, y: 0.9, width: expect.closeTo(0.2), height: expect.closeTo(0.1) });
    expect(clipRect({ x: 2, y: 0, width: 1, height: 1 })).toBeNull();
    expect(clipRect({ x: "0", y: 0, width: 1, height: 1 })).toBeNull();
    expect(clipRect(null)).toBeNull();
  });

  it("on one line that nearly touch are one", () => {
    const words = [
      { x: 0.1, y: 0.1, width: 0.1, height: 0.02 },
      { x: 0.205, y: 0.1, width: 0.1, height: 0.02 },
      // The next line.
      { x: 0.1, y: 0.13, width: 0.1, height: 0.02 },
    ];
    const lines = mergeLines(words);
    expect(lines).toHaveLength(2);
    expect(lines[0]!.x).toBe(0.1);
    expect(lines[0]!.width).toBeCloseTo(0.205);
  });
});

/** A target that finds the texts in `found`, when `release` is called for them. */
function fakeTarget(pages: number | null, found: Record<string, number> = {}) {
  const waiting = new Map<string, () => void>();
  const target = {
    pageCount: () => pages,
    locate: vi.fn(
      (h: { text: string }) =>
        new Promise<{ page: number | null; rects: { x: number; y: number; width: number; height: number }[] } | null>((resolve) => {
          waiting.set(h.text, () => resolve(h.text in found ? { page: found[h.text]!, rects: [{ x: 0.1, y: 0.4, width: 0.2, height: 0.02 }] } : null));
        }),
    ),
    draw: vi.fn<(items: readonly PlacedHighlight[], current: string | null) => void>(),
    reveal: vi.fn<(item: PlacedHighlight, smooth: boolean) => void>(),
  } satisfies HighlightTarget;
  const release = async (text: string) => {
    for (let i = 0; i < 5 && !waiting.has(text); i++) await Promise.resolve();
    waiting.get(text)?.();
    for (let i = 0; i < 5; i++) await Promise.resolve();
  };
  return { target, release };
}

describe("createHighlights", () => {
  it("shows boxes at once, and goes to the first on open", () => {
    const { target } = fakeTarget(3);
    const h = createHighlights(target, [
      { page: 2, rects: [{ x: 0.1, y: 0.2, width: 0.3, height: 0.1 }], label: "Price" },
      { page: 9, rects: [{ x: 0, y: 0, width: 1, height: 1 }] },
    ]);
    const { items, current } = h.controller.get();
    expect(items.map((i) => [i.id, i.state, i.page])).toEqual([
      ["0", "shown", 2],
      // A page the document does not have.
      ["1", "missing", null],
    ]);
    expect(items[0]!.label).toBe("Price");
    expect(current).toBe("0");
    expect(target.reveal).toHaveBeenCalledWith(expect.objectContaining({ id: "0" }), false);
    expect(target.draw).toHaveBeenLastCalledWith(items, "0");
  });

  it("looks for the focused text first, and goes to it once found", async () => {
    const { target, release } = fakeTarget(10, { "second quote": 7 });
    const h = createHighlights(target, [{ id: "a", text: "first quote" }, { id: "b", text: "second quote", page: 7 }], "b");
    expect(h.controller.get().items.map((i) => i.state)).toEqual(["pending", "pending"]);
    await release("second quote");
    expect(target.locate.mock.calls[0]![0]).toMatchObject({ text: "second quote" });
    expect(h.controller.get().items[1]).toMatchObject({ state: "shown", page: 7 });
    expect(target.reveal).toHaveBeenCalledTimes(1);
    expect(target.reveal).toHaveBeenLastCalledWith(expect.objectContaining({ id: "b", page: 7 }), false);
    expect(h.controller.get().current).toBe("b");
    await release("first quote");
    expect(h.controller.get().items[0]!.state).toBe("missing");
    // A text not found, with no page: nowhere to go.
    h.controller.goTo("a");
    expect(target.reveal).toHaveBeenCalledTimes(1);
  });

  it("goes to the page of a text it did not find, when the highlight names one", async () => {
    const { target, release } = fakeTarget(10);
    const h = createHighlights(target, [{ id: "a", text: "nowhere", page: 4 }]);
    await release("nowhere");
    expect(target.reveal).toHaveBeenLastCalledWith(expect.objectContaining({ id: "a", page: 4, rects: [] }), false);
    h.controller.goTo("a");
    expect(target.reveal).toHaveBeenLastCalledWith(expect.objectContaining({ id: "a", page: 4 }), true);
  });

  it("replaces the list without moving the view, and forgets what was being looked for", async () => {
    const { target, release } = fakeTarget(3, { old: 1, fresh: 2 });
    const h = createHighlights(target, [{ id: "x", text: "old" }]);
    h.controller.set([{ id: "y", text: "fresh" }]);
    await release("old");
    await release("fresh");
    expect(h.controller.get().items.map((i) => [i.id, i.state])).toEqual([["y", "shown"]]);
    // Only the opening focus moved it, and "x" was never found before it was replaced.
    expect(target.reveal).not.toHaveBeenCalled();
    h.controller.goTo("y");
    expect(target.reveal).toHaveBeenLastCalledWith(expect.objectContaining({ id: "y", page: 2 }), true);
  });

  it("draws no boxes in a format without pages", () => {
    const { target } = fakeTarget(null);
    const h = createHighlights(target, [{ page: 1, rects: [{ x: 0, y: 0, width: 1, height: 1 }] }]);
    expect(h.controller.get().items[0]).toMatchObject({ state: "missing", page: null });
  });

  it("stops looking once destroyed", async () => {
    const { target, release } = fakeTarget(3, { q: 1 });
    const h = createHighlights(target, [{ text: "q" }]);
    h.destroy();
    await release("q");
    expect(h.controller.get().items[0]!.state).toBe("pending");
  });

  it("gives the page a turn between slices of a long search", async () => {
    vi.useFakeTimers();
    try {
      let clock = 0;
      const now = vi.spyOn(performance, "now").mockImplementation(() => clock);
      const located: string[] = [];
      const target: HighlightTarget = {
        pageCount: () => 1,
        // Each quote takes 10 ms of the page's time, without leaving the microtask queue.
        locate: async (h) => {
          clock += 10;
          located.push(h.text);
          return null;
        },
        draw: () => {},
        reveal: () => {},
      };
      createHighlights(target, [{ text: "a" }, { text: "b" }, { text: "c" }]);
      for (let i = 0; i < 20; i++) await Promise.resolve();
      // Two quotes fit in a slice; the third waits for a task.
      expect(located).toEqual(["a", "b"]);
      await vi.runAllTimersAsync();
      expect(located).toEqual(["a", "b", "c"]);
      now.mockRestore();
    } finally {
      vi.useRealTimers();
    }
  });
});
