// @vitest-environment node
// What an IFC model is framed by: its elements, less those far from all the
// others. The expectations are the boxes written here, and the generated
// house.ifc read by the model engine itself (made by e2e/fixtures/make-samples.mjs,
// and equal to the copy exav-render's tests read).
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { elementBoxes, framingBox, type Box } from "./framing.js";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");

/** A building: rooms of 4 x 4 x 3 m on a 5 m grid, `n` by `n`, on two floors. */
function building(n: number): Box[] {
  const boxes: Box[] = [];
  for (let i = 0; i < n; i++) for (let j = 0; j < n; j++) for (let f = 0; f < 2; f++) boxes.push([i * 5, j * 5, f * 3, i * 5 + 4, j * 5 + 4, f * 3 + 3]);
  return boxes;
}

describe("framingBox", () => {
  it("leaves out an element a kilometre from the building", () => {
    const house = building(4);
    const beam: Box = [1243, 148, 12, 1245, 148.5, 12.2];
    expect(framingBox([...house, beam])).toEqual([0, 0, 0, 19, 19, 6]);
  });

  it("keeps the whole of a model with nothing far out, its far wing and its terrain included", () => {
    const house = building(4);
    // A wing 30 m on, a terrain under all of it.
    const wing: Box[] = building(2).map(([a, b, c, d, e, f]) => [a + 50, b, c, d + 50, e, f]);
    const terrain: Box = [-20, -20, -1, 90, 40, 0];
    expect(framingBox([...house, ...wing, terrain])).toEqual([-20, -20, -1, 90, 40, 6]);
  });

  it("keeps the beams at the edge of a model whose columns all stand on one spot", () => {
    // 25 columns at the origin, and beams across 16 m, the farthest 14 m out.
    const columns: Box[] = Array.from({ length: 25 }, () => [-0.1, -0.1, 0, 0.1, 0.1, 2.8]);
    const beams: Box[] = [-14, -10, -6, -2, 2].map((x) => [x - 0.1, 4, 2.6, x + 0.1, 16, 2.8]);
    expect(framingBox([...columns, ...beams])).toEqual([-14.1, -0.1, 0, 2.1, 16, 2.8]);
  });

  it("leaves out a marker standing apart, as the geo-referencing proxies of buildingSMART's sample scenes do", () => {
    const scene = building(2);
    const marker: Box = [-36, -18, -1.3, -34, -16, -1.2];
    expect(framingBox([...scene, marker])).toEqual([0, 0, 0, 9, 9, 6]);
  });

  it("keeps a flat model whole: no spread in height is no reason to leave a slab out", () => {
    const slabs: Box[] = Array.from({ length: 10 }, (_, i) => [i * 6, 0, 0, i * 6 + 5, 5, 0.2]);
    expect(framingBox(slabs)).toEqual([0, 0, 0, 59, 5, 0.2]);
  });

  it("keeps everything when there are too few elements to tell", () => {
    const few: Box[] = [
      [0, 0, 0, 1, 1, 1],
      [2, 0, 0, 3, 1, 1],
      [5000, 0, 0, 5001, 1, 1],
    ];
    expect(framingBox(few)).toEqual([0, 0, 0, 5001, 1, 1]);
    expect(framingBox([])).toBeNull();
  });
});

describe("elementBoxes", () => {
  it("of the generated house.ifc, as the engine reads it, frame the whole of it", async () => {
    const wasm = path.join(root, "wasm");
    const { default: init, parseIfc } = await import(/* @vite-ignore */ path.join(wasm, "exav_viewer_model.js"));
    await init({ module_or_path: fs.readFileSync(path.join(wasm, "exav_viewer_model_bg.wasm")) });
    // As the browser tests get it, and as exav-render's tests keep it.
    execFileSync(process.execPath, [path.join(root, "e2e", "fixtures", "make-samples.mjs")], { stdio: "ignore" });
    const house = fs.readFileSync(path.join(root, "e2e", ".out", "samples", "house.ifc"));
    expect(house.equals(fs.readFileSync(path.join(root, "..", "exav-render", "tests", "fixtures", "viewer", "house.ifc")))).toBe(true);
    const model = parseIfc(new Uint8Array(house), 1_000_000);
    const positions: Float32Array = model.takePositions();
    const indices: Uint32Array = model.takeIndices();
    const meta = JSON.parse(model.metaJson());
    model.free();
    const boxes = elementBoxes(meta, positions, indices);
    // Four walls and a slab (make-samples.mjs).
    expect(boxes).toHaveLength(5);
    const framed = framingBox(boxes)!;
    // Everything there is, as the engine bounds it.
    framed.forEach((v, i) => expect(v).toBeCloseTo(meta.bounds[i], 4));
  });
});
