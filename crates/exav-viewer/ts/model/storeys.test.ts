// @vitest-environment node
import { describe, expect, it } from "vitest";

import { createStoreys, storeyItems, storeyShown } from "./storeys.js";

const node = (name: string, elevation: number | null, cls = "IFCBUILDINGSTOREY") => ({ id: 1, class: cls, name, parent: null, elevation });
const element = (storey: number | null) => ({ id: 1, globalId: "", class: "IFCWALL", name: "w", node: storey, storey, ranges: [] as [number, number, number][] });

/** A project, three storeys (listed low to high, one without an elevation) and a room. */
const meta = {
  nodes: [node("Project", null, "IFCPROJECT"), node("Level 0", 0), node("Level 2", 6), node("Level 1", 3), node("Roof", null), node("Unused", 9)],
  elements: [element(1), element(1), element(2), element(3), element(4), element(null)],
};

describe("storeyItems", () => {
  it("lists the storeys that hold an element, highest first and those without an elevation last", () => {
    expect(storeyItems(meta).map((i) => [i.name, i.elevation])).toEqual([
      ["Level 2", 6],
      ["Level 1", 3],
      ["Level 0", 0],
      ["Roof", null],
    ]);
  });

  it("gives each its node index as its id, shown", () => {
    expect(storeyItems(meta).map((i) => [i.id, i.visible])).toEqual([
      ["2", true],
      ["3", true],
      ["1", true],
      ["4", true],
    ]);
  });

  it("has nothing to filter in a model of one storey, or none", () => {
    expect(storeyItems({ nodes: meta.nodes, elements: [element(1), element(1)] })).toEqual([]);
    expect(storeyItems({ nodes: meta.nodes, elements: [element(null)] })).toEqual([]);
    expect(createStoreys({ nodes: meta.nodes, elements: [] }, () => {})).toBeNull();
  });

  it("names a storey that has no name by its class", () => {
    const nameless = { nodes: [node("", 0), node("B", 3)], elements: [element(0), element(1)] };
    expect(storeyItems(nameless).map((i) => i.name)).toEqual(["B", "IFCBUILDINGSTOREY"]);
  });
});

describe("storeyShown", () => {
  it("draws what is in no storey, and what is in a storey that is not hidden", () => {
    const hidden = new Set([2]);
    expect(storeyShown(null, hidden)).toBe(true);
    expect(storeyShown(undefined, hidden)).toBe(true);
    expect(storeyShown(1, hidden)).toBe(true);
    expect(storeyShown(2, hidden)).toBe(false);
  });
});

describe("createStoreys", () => {
  it("hides and shows a storey, telling which are hidden", () => {
    const calls: number[][] = [];
    const c = createStoreys(meta, (h) => calls.push([...h].sort()))!;
    c.setVisible("3", false);
    expect(calls.at(-1)).toEqual([3]);
    expect(c.get().items.find((i) => i.id === "3")?.visible).toBe(false);
    expect(c.get().items.filter((i) => !i.visible)).toHaveLength(1);
    c.setVisible("2", false);
    expect(calls.at(-1)).toEqual([2, 3]);
    c.setVisible("3", true);
    expect(calls.at(-1)).toEqual([2]);
  });

  it("hides and shows them all", () => {
    const calls: number[][] = [];
    const c = createStoreys(meta, (h) => calls.push([...h].sort()))!;
    c.setAll(false);
    expect(calls.at(-1)).toEqual([1, 2, 3, 4]);
    expect(c.get().items.every((i) => !i.visible)).toBe(true);
    c.setAll(true);
    expect(calls.at(-1)).toEqual([]);
  });

  it("ignores a storey it does not have, and tells its listeners", () => {
    const seen: boolean[][] = [];
    const c = createStoreys(meta, () => {})!;
    c.subscribe((s) => seen.push(s.items.map((i) => i.visible)));
    c.setVisible("99", false);
    expect(c.get().items.every((i) => i.visible)).toBe(true);
    c.setVisible("2", false);
    expect(seen.at(-1)).toEqual([false, true, true, true]);
  });
});
