import { describe, expect, it } from "vitest";

import { indexText, quoteAreas, type TextViewportLike } from "./engine.js";
import { searchOrder } from "./renderer.js";

// A page of 600 by 800 points, as pdf.js's viewport at scale 1 maps it: y down.
const viewport: TextViewportLike = { width: 600, height: 800, transform: [1, 0, 0, -1, 0, 800] };
const styles = { f1: { fontFamily: "sans-serif", ascent: 0.8, descent: -0.2 } };
/** A run of 10pt text, its baseline at `y` from the bottom of the page, 5pt a character. */
const run = (str: string, x: number, y: number) => ({ str, transform: [10, 0, 0, 10, x, y], width: str.length * 5, fontName: "f1", hasEOL: false });
// Every character as wide: the share of a run is its share of the characters.
const measure = (text: string) => text.length;

describe("quoteAreas", () => {
  it("boxes the characters of a run the quote covers", () => {
    const index = indexText([run("Le prix total est de 1 200 €.", 100, 700)], styles);
    const areas = quoteAreas(index, viewport, "prix total", measure)!;
    expect(areas).toHaveLength(1);
    const [a] = areas;
    // "prix total" is characters 3 to 13: 15pt to 65pt into the run; the ascent 8pt above the baseline (100 down), the descent 2 below.
    expect(a!.x * 600).toBeCloseTo(115);
    expect(a!.width * 600).toBeCloseTo(50);
    expect(a!.y * 800).toBeCloseTo(92);
    expect(a!.height * 800).toBeCloseTo(10);
  });

  it("follows a quote over a line cut by a hyphen, a box per line, and leaves out the spaces between", () => {
    const index = indexText([run("Les pénalités de re-", 100, 700), run(" ", 200, 700), run("tard sont fixées.", 100, 688)], styles);
    const areas = quoteAreas(index, viewport, "Pénalités de retard", measure)!;
    expect(areas).toHaveLength(2);
    expect(areas[0]!.x * 600).toBeCloseTo(120);
    expect(areas[0]!.y * 800).toBeCloseTo(92);
    expect(areas[1]!.x * 600).toBeCloseTo(100);
    expect(areas[1]!.width * 600).toBeCloseTo(20);
    expect(areas[1]!.y * 800).toBeCloseTo(104);
  });

  it("places a run on a rotated page as the page is shown", () => {
    // A page turned a quarter: pdf.js's viewport maps (x, y) to (y, x).
    const turned: TextViewportLike = { width: 800, height: 600, transform: [0, 1, 1, 0, 0, 0] };
    const index = indexText([run("abcd", 100, 300)], styles);
    const [a] = quoteAreas(index, turned, "abcd", measure)!;
    // Along the page's height, from 100pt down; across, the glyphs' tops to the right: the descent 2pt left of x = 300, the ascent 8pt right.
    expect(a!.y * 600).toBeCloseTo(100);
    expect(a!.height * 600).toBeCloseTo(20);
    expect(a!.x * 800).toBeCloseTo(298);
    expect(a!.width * 800).toBeCloseTo(10);
  });

  it("is null when the page does not have the quote, and skips items that are not text", () => {
    const index = indexText([{ type: "beginMarkedContent" }, run("Rien ici", 0, 0), { str: "x", transform: "nope" }], styles);
    expect(index.runs).toHaveLength(1);
    expect(quoteAreas(index, viewport, "délai", measure)).toBeNull();
  });
});

describe("searchOrder", () => {
  it("looks on the page named, then the nearest pages, then from the first without one", () => {
    expect(searchOrder(3, 6)).toEqual([3, 4, 2, 5, 1, 6]);
    expect(searchOrder(undefined, 3)).toEqual([1, 2, 3]);
    expect(searchOrder(9, 2)).toEqual([1, 2]);
  });
});
