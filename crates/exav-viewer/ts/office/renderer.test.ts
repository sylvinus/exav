/**
 * Large decks and documents are laid out progressively by the engines (the
 * first slides or pages show while the rest is laid out); short ones are
 * not, and a layout that fails once something is on screen leaves it there.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { RenderContext, Status } from "../core/types.js";
import { deckOf, documentOf } from "../test/zip-members.js";
import { DEFAULT_MAX_ARCHIVE_ENTRIES, type OfficeOptions } from "./index.js";
import { PROGRESSIVE_DOCUMENT_BYTES, PROGRESSIVE_SLIDES } from "./progressive.js";

type Options = Record<string, unknown>;

/** The options each engine was constructed with, in order. */
const made: { engine: "pptx" | "docx"; options: Options }[] = [];

/** What the engine reports to `onLayoutComplete` while it loads, if anything. */
let duringLoad: Error | undefined;

vi.mock("@silurus/ooxml/pptx", () => ({
  PptxViewer: class {
    constructor(_canvas: HTMLCanvasElement, options: Options) {
      made.push({ engine: "pptx", options });
    }
    async load() {
      if (duringLoad) (made.at(-1)!.options.onLayoutComplete as (e: Error) => void)(duringLoad);
    }
    async fitPage() {}
    destroy() {}
  },
}));

vi.mock("@silurus/ooxml/docx", () => ({
  DocxScrollViewer: class {
    constructor(_root: HTMLElement, options: Options) {
      made.push({ engine: "docx", options });
    }
    async load() {}
    getScale() {
      return 1;
    }
    destroy() {}
  },
}));

beforeEach(() => {
  vi.stubGlobal("ResizeObserver", class { observe() {} disconnect() {} });
  vi.spyOn(console, "warn").mockImplementation(() => {});
});

afterEach(() => {
  made.length = 0;
  duringLoad = undefined;
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

async function mount(kind: "pptx" | "docx", bytes: Uint8Array, given: OfficeOptions = {}) {
  const { rendererFor } = await import("./renderer.js");
  const statuses: Status[] = [];
  const ctx = {
    options: given,
    source: { bytes: async () => bytes },
    signal: new AbortController().signal,
    status: (s: Status) => statuses.push(s),
  } as unknown as RenderContext<OfficeOptions>;
  const mounted = await rendererFor(kind).mount(document.createElement("div"), ctx);
  return { mounted, statuses, options: made.at(-1)!.options };
}

describe("a deck", () => {
  it("is laid out progressively from PROGRESSIVE_SLIDES slides", async () => {
    const { options } = await mount("pptx", deckOf(PROGRESSIVE_SLIDES));
    expect(options.progressiveLayout).toBe(true);
    expect(options.onLayoutComplete).toBeTypeOf("function");
  });

  it("is laid out whole below that", async () => {
    const { options } = await mount("pptx", deckOf(PROGRESSIVE_SLIDES - 1));
    expect(options.progressiveLayout).toBeUndefined();
    expect(options.onLayoutComplete).toBeUndefined();
  });

  it("stays on screen, flagged partial, when its layout fails afterwards", async () => {
    const { statuses, options } = await mount("pptx", deckOf(PROGRESSIVE_SLIDES));
    expect(statuses.at(-1)).toEqual({ phase: "ready" });
    (options.onLayoutComplete as (e?: unknown) => void)(new Error("slide 40 is damaged"));
    expect(statuses.at(-1)).toEqual({ phase: "ready", partial: true });
    expect(console.warn).toHaveBeenCalledWith("office: pptx", expect.any(Error));
  });

  it("is flagged partial too when its layout fails before the viewer is ready", async () => {
    duringLoad = new Error("slide 2 is damaged");
    const { statuses } = await mount("pptx", deckOf(PROGRESSIVE_SLIDES));
    expect(statuses).toEqual([{ phase: "loading" }, { phase: "ready", partial: true }]);
  });

  it("is not flagged when its layout completes", async () => {
    const { statuses, options } = await mount("pptx", deckOf(PROGRESSIVE_SLIDES));
    (options.onLayoutComplete as (e?: unknown) => void)();
    expect(statuses).toEqual([{ phase: "loading" }, { phase: "ready" }]);
  });
});

describe("a document", () => {
  it("is laid out progressively from PROGRESSIVE_DOCUMENT_BYTES of body", async () => {
    const { options } = await mount("docx", documentOf(PROGRESSIVE_DOCUMENT_BYTES));
    expect(options.progressiveLayout).toBe(true);
    expect(options.onLayoutComplete).toBeTypeOf("function");
  });

  it("is laid out whole below that", async () => {
    const { options } = await mount("docx", documentOf(PROGRESSIVE_DOCUMENT_BYTES - 1));
    expect(options.progressiveLayout).toBeUndefined();
  });

  it("stays on screen, flagged partial, when its layout fails afterwards", async () => {
    const { statuses, options } = await mount("docx", documentOf(PROGRESSIVE_DOCUMENT_BYTES));
    (options.onLayoutComplete as (e?: unknown) => void)(new Error("layout failed"));
    expect(statuses.at(-1)).toEqual({ phase: "ready", partial: true });
  });
});

describe("the archive entry limit", () => {
  it("is DEFAULT_MAX_ARCHIVE_ENTRIES unless the host gives one", async () => {
    const { options } = await mount("pptx", deckOf(1));
    expect(options.resourceLimits).toEqual({ maxArchiveEntries: DEFAULT_MAX_ARCHIVE_ENTRIES });
  });

  it("is the host's maxArchiveEntries, for decks and documents", async () => {
    const deck = await mount("pptx", deckOf(1), { maxArchiveEntries: 50000 });
    expect(deck.options.resourceLimits).toEqual({ maxArchiveEntries: 50000 });
    const doc = await mount("docx", documentOf(1), { maxArchiveEntries: 50000 });
    expect(doc.options.resourceLimits).toEqual({ maxArchiveEntries: 50000 });
  });
});
