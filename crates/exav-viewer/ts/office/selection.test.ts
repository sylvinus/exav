// The text a copy of a Word or PowerPoint selection gives: what is selected
// of each run, with a line break between paragraphs. The runs are laid out as
// the engines write them (Word: one per word, the paragraph named by its
// story and path; PowerPoint: one per run, named by its shape only).
import { afterEach, describe, expect, it } from "vitest";

import { selectedText, textSelection } from "./selection.js";

/** A page of paragraphs, each a list of words. */
function page(paragraphs: string[][], extra: Record<string, string> = {}) {
  const root = document.createElement("div");
  const surface = document.createElement("div");
  surface.dataset.ooxmlSelectionSurface = "docx";
  paragraphs.forEach((words, p) =>
    words.forEach((word) => {
      const run = document.createElement("span");
      run.dataset.ooxmlSelectionRun = "docx";
      Object.assign(run.dataset, { sourceStory: "body", sourceStoryInstance: "body", sourcePath: `[${p}]`, ...extra });
      run.textContent = word;
      surface.append(run);
    }),
  );
  root.append(surface);
  document.body.append(root);
  return { root, runs: [...surface.querySelectorAll("span")] };
}

/** Selects from `offset` into run `from` to `endOffset` into run `to`. */
function select(runs: HTMLElement[], from: number, offset: number, to: number, endOffset: number) {
  const range = document.createRange();
  range.setStart(runs[from]!.firstChild!, offset);
  range.setEnd(runs[to]!.firstChild!, endOffset);
  const selection = document.getSelection()!;
  selection.removeAllRanges();
  selection.addRange(range);
  return selection;
}

afterEach(() => {
  document.getSelection()?.removeAllRanges();
  document.body.replaceChildren();
});

describe("selectedText", () => {
  it("puts a line break between paragraphs, and cuts the first and last runs where the selection does", () => {
    const { root, runs } = page([["Meeting ", "notes"], ["Present: ", "the ", "client."]]);
    // From "tes" of "notes" to "cli" of "client.".
    expect(selectedText(root, select(runs, 1, 2, 4, 3))).toBe("tes\nPresent: the cli");
  });

  it("joins the runs of one paragraph as they are", () => {
    const { root, runs } = page([["1. ", "The ", "schedule ", "is ", "confirmed."]]);
    expect(selectedText(root, select(runs, 0, 0, 4, 10))).toBe("1. The schedule is confirmed.");
  });

  it("takes the paragraph's id where the engine gives one", () => {
    // Every run the same path, two ids: two paragraphs.
    const { root, runs } = page([["One "], ["two"]], { sourcePath: "[0]" });
    runs[0]!.dataset.paragraphId = "a";
    runs[1]!.dataset.paragraphId = "b";
    expect(selectedText(root, select(runs, 0, 0, 1, 3))).toBe("One \ntwo");
  });

  it("is null for a selection elsewhere, or none", () => {
    const { root } = page([["Inside"]]);
    const other = document.createElement("p");
    other.textContent = "Outside";
    document.body.append(other);
    const range = document.createRange();
    range.selectNodeContents(other);
    const selection = document.getSelection()!;
    selection.removeAllRanges();
    selection.addRange(range);
    expect(selectedText(root, selection)).toBeNull();
    selection.removeAllRanges();
    expect(selectedText(root, selection)).toBeNull();
  });
});

describe("selectedText, on slides", () => {
  /** A slide's runs: [shape, text, top] each, 20 px high, laid out with those tops. */
  function slide(runs: [string, string, number][]) {
    const root = document.createElement("div");
    const surface = document.createElement("div");
    surface.dataset.ooxmlSelectionSurface = "pptx";
    for (const [shape, text, top] of runs) {
      const run = document.createElement("span");
      Object.assign(run.dataset, { ooxmlSelectionRun: "pptx", shapeId: shape });
      run.textContent = text;
      // jsdom lays nothing out.
      run.getBoundingClientRect = () => ({ top, bottom: top + 20, height: 20, left: 0, right: 100, width: 100, x: 0, y: top, toJSON: () => ({}) });
      surface.append(run);
    }
    root.append(surface);
    document.body.append(root);
    return { root, runs: [...surface.querySelectorAll("span")] };
  }

  it("breaks the line between shapes, and where a run starts lower in the same shape", () => {
    const { root, runs } = slide([
      ["2", "Title", 0],
      ["3", "First ", 50],
      ["3", "point", 50],
      ["3", "Second point", 75],
    ]);
    expect(selectedText(root, select(runs, 0, 0, 3, 12))).toBe("Title\nFirst point\nSecond point");
  });
});

describe("textSelection", () => {
  const copy = () => {
    // jsdom has no DataTransfer: what a copy handler calls of it.
    const store = new Map<string, string>();
    const data = { setData: (type: string, value: string) => void store.set(type, value), getData: (type: string) => store.get(type) ?? "" };
    const event = new Event("copy", { bubbles: true, cancelable: true }) as ClipboardEvent;
    Object.defineProperty(event, "clipboardData", { value: data });
    document.body.dispatchEvent(event);
    return { text: data.getData("text/plain"), handled: event.defaultPrevented };
  };

  it("copies the paragraphs apart while it is on, and leaves copies alone once removed", () => {
    const { root, runs } = page([["First."], ["Second."]]);
    const stop = textSelection(root);
    select(runs, 0, 0, 1, 7);
    expect(copy()).toEqual({ text: "First.\nSecond.", handled: true });
    stop();
    expect(copy()).toEqual({ text: "", handled: false });
  });

  it("covers each page under its runs from a press on a run until the pointer is up", () => {
    const { root, runs } = page([["Word"]]);
    const stop = textSelection(root);
    const surface = root.firstElementChild!;
    // A press elsewhere: no cover.
    root.dispatchEvent(new MouseEvent("mousedown", { bubbles: true }));
    expect(root.querySelector(".exv-office-text-end")).toBeNull();
    runs[0]!.dispatchEvent(new MouseEvent("mousedown", { bubbles: true }));
    expect(surface.firstElementChild?.className).toBe("exv-office-text-end");
    document.dispatchEvent(new Event("pointerup"));
    expect(root.querySelector(".exv-office-text-end")).toBeNull();
    stop();
  });

  it("covers a slide's shapes too, each under its own runs", () => {
    const root = document.createElement("div");
    const surface = document.createElement("div");
    surface.dataset.ooxmlSelectionSurface = "pptx";
    const shapes = [0, 1].map((i) => {
      const shape = document.createElement("div");
      const run = document.createElement("span");
      Object.assign(run.dataset, { ooxmlSelectionRun: "pptx", shapeId: String(i) });
      run.textContent = `Shape ${i}`;
      shape.append(run);
      surface.append(shape);
      return shape;
    });
    root.append(surface);
    document.body.append(root);
    const stop = textSelection(root);
    shapes[0]!.firstElementChild!.dispatchEvent(new MouseEvent("mousedown", { bubbles: true }));
    for (const holder of [surface, ...shapes]) expect(holder.firstElementChild?.className).toBe("exv-office-text-end");
    expect(root.querySelectorAll(".exv-office-text-end")).toHaveLength(3);
    stop();
  });
});
