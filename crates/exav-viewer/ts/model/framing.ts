import type { ModelMeta } from "./engine.js";

/** min x, y, z, max x, y, z. */
export type Box = [number, number, number, number, number, number];

/** Below this many elements, every one counts: too few to tell a stray from the rest. */
const MIN_ELEMENTS = 8;

/** What is this close to the rest of a model belongs with it, however small the model. */
const REACH_METRES = 10;

/** Each element's box, in the buffers' coordinates; elements without triangles are left out. */
export function elementBoxes(meta: Pick<ModelMeta, "elements" | "batches">, positions: Float32Array, indices: Uint32Array): Box[] {
  const boxes: Box[] = [];
  for (const e of meta.elements) {
    const box: Box = [Infinity, Infinity, Infinity, -Infinity, -Infinity, -Infinity];
    for (const [b, first, count] of e.ranges) {
      const batch = meta.batches[b];
      if (!batch) continue;
      for (let k = first; k < first + count; k++) {
        const v = (batch.vertex + indices[batch.index + k]!) * 3;
        for (let a = 0; a < 3; a++) {
          const p = positions[v + a]!;
          if (p < box[a]!) box[a] = p;
          if (p > box[a + 3]!) box[a + 3] = p;
        }
      }
    }
    if (box[0] <= box[3]) boxes.push(box);
  }
  return boxes;
}

/**
 * The box to frame a model by: around its elements, less those far from
 * all the others, such as an object an export left a kilometre from the
 * building. The core is the elements whose centre is within Tukey's outer
 * fences on every axis (three interquartile ranges beyond the quartiles of
 * the centres, the range being at least the median element's size, as a
 * flat model has none on its height). The others count when they connect to
 * it: within reach of what already counts, the reach being half the core's
 * diagonal and at least `REACH_METRES`. Null without elements.
 */
export function framingBox(boxes: readonly Box[]): Box | null {
  if (!boxes.length) return null;
  const union = (list: readonly Box[]): Box =>
    list.reduce<Box>(
      (u, b) => [Math.min(u[0], b[0]), Math.min(u[1], b[1]), Math.min(u[2], b[2]), Math.max(u[3], b[3]), Math.max(u[4], b[4]), Math.max(u[5], b[5])],
      [Infinity, Infinity, Infinity, -Infinity, -Infinity, -Infinity],
    );
  if (boxes.length < MIN_ELEMENTS) return union(boxes);
  const sorted = (values: number[]) => values.sort((a, b) => a - b);
  const at = (values: number[], q: number) => values[Math.min(values.length - 1, Math.floor(q * values.length))]!;
  const sizes = sorted(boxes.map((b) => Math.max(b[3] - b[0], b[4] - b[1], b[5] - b[2])));
  const size = at(sizes, 0.5);
  const fences = [0, 1, 2].map((a) => {
    const centres = sorted(boxes.map((b) => (b[a]! + b[a + 3]!) / 2));
    const q1 = at(centres, 0.25);
    const q3 = at(centres, 0.75);
    const reach = 3 * Math.max(q3 - q1, size);
    return [q1 - reach, q3 + reach] as const;
  });
  const core = boxes.filter((b) =>
    fences.every(([low, high], a) => {
      const c = (b[a]! + b[a + 3]!) / 2;
      return c >= low && c <= high;
    }),
  );
  if (!core.length) return union(boxes);
  let region = union(core);
  const reach = Math.max(0.5 * Math.hypot(region[3] - region[0], region[4] - region[1], region[5] - region[2]), REACH_METRES);
  /** Distance between two boxes, 0 when they touch. */
  const gap = (a: Box, b: Box) => Math.hypot(...[0, 1, 2].map((i) => Math.max(0, a[i]! - b[i + 3]!, b[i]! - a[i + 3]!)));
  // Grown from the core by what is within reach of it, until nothing more is.
  let rest = boxes.filter((b) => !core.includes(b));
  for (let grew = true; grew; ) {
    grew = false;
    rest = rest.filter((b) => {
      if (gap(b, region) > reach) return true;
      region = union([region, b]);
      grew = true;
      return false;
    });
  }
  return region;
}
