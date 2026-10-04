// The model module as the worker calls it, and what the plugins make of its
// answer: the budget reaches the reader, the warnings name what is missing.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { beforeAll, describe, expect, it } from "vitest";

import init, { parseIfc, parseStl } from "../../wasm/exav_viewer_model.js";
import { modelWarnings, type ModelMeta } from "./engine.js";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
// The house of the browser tests, as exav-render's tests keep it.
const sample = (name: string) => new Uint8Array(fs.readFileSync(path.join(root, "..", "exav-render", "tests", "fixtures", "viewer", name)));

beforeAll(async () => {
  await init({ module_or_path: fs.readFileSync(path.join(root, "wasm", "exav_viewer_model_bg.wasm")) });
});

describe("the model module", () => {
  it("reads the demo house whole, and within a budget leaves elements out and says how many", () => {
    const whole = parseIfc(sample("house.ifc"), 6e6);
    const meta = JSON.parse(whole.metaJson()) as ModelMeta;
    // Four walls and a slab, twelve triangles each.
    expect(meta.elements.map((e) => e.class).sort()).toEqual(["IFCSLAB", "IFCWALL", "IFCWALL", "IFCWALL", "IFCWALL"]);
    expect(whole.takeIndices().length / 3).toBe(60);
    expect(modelWarnings(meta, "ifc")).toEqual([]);
    whole.free();

    const part = parseIfc(sample("house.ifc"), 30);
    const cut = JSON.parse(part.metaJson()) as ModelMeta;
    expect(cut.elements).toHaveLength(2);
    expect(modelWarnings(cut, "ifc")).toEqual([{ key: "model_truncated", count: 3 }]);
    part.free();
  });

  it("hands over buffers that agree with the batches", () => {
    const m = parseIfc(sample("house.ifc"), 6e6);
    const meta = JSON.parse(m.metaJson()) as ModelMeta;
    const positions = m.takePositions();
    const indices = m.takeIndices();
    for (const b of meta.batches) {
      for (const i of indices.subarray(b.index, b.index + b.indices)) expect(i).toBeLessThan(b.vertices);
    }
    expect(positions.length / 3).toBe(meta.batches.reduce((n, b) => n + b.vertices, 0));
    m.free();
  });

  it("reads an STL, and refuses what is not one", () => {
    const m = parseStl(sample("house.stl"), 6e6);
    expect(m.takeIndices().length / 3).toBe(30);
    expect(modelWarnings(JSON.parse(m.metaJson()) as ModelMeta, "stl")).toEqual([]);
    m.free();
    const part = parseStl(sample("house.stl"), 10);
    expect(modelWarnings(JSON.parse(part.metaJson()) as ModelMeta, "stl")).toEqual([{ key: "model_partial", count: 1 }]);
    part.free();
    expect(() => parseStl(new Uint8Array([1, 2, 3]), 10)).toThrow("not an STL file");
    expect(() => parseIfc(new TextEncoder().encode("%PDF-1.7"), 10)).toThrow("not a STEP file");
  });
});
