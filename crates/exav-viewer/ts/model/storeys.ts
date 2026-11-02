/**
 * The storey filter of an IFC model: which building storeys have something
 * drawn, and a controller that shows or hides them. The reader puts the
 * elements of one storey in batches of their own (`BatchMeta.storey`), so
 * hiding a storey hides whole batches, outlines included.
 */
import { writable } from "../core/store.js";
import type { StoreyItem, StoreysController } from "../core/types.js";
import type { ModelMeta } from "./engine.js";

/**
 * The storeys that hold an element, highest first; those without an
 * elevation after them, by name. A model with fewer than two has nothing
 * to filter: the list is empty.
 */
export function storeyItems(meta: Pick<ModelMeta, "nodes" | "elements">): StoreyItem[] {
  const used = new Set<number>();
  for (const e of meta.elements) if (e.storey != null) used.add(e.storey);
  const items: StoreyItem[] = [];
  for (const index of used) {
    const node = meta.nodes[index];
    if (!node) continue;
    items.push({ id: String(index), name: node.name || node.class, elevation: node.elevation ?? null, visible: true });
  }
  if (items.length < 2) return [];
  return items.sort((a, b) => {
    if (a.elevation !== null && b.elevation !== null && a.elevation !== b.elevation) return b.elevation - a.elevation;
    if ((a.elevation === null) !== (b.elevation === null)) return a.elevation === null ? 1 : -1;
    return a.name.localeCompare(b.name);
  });
}

/** Whether a batch of storey `storey` is drawn when the storeys `hidden` are not. */
export function storeyShown(storey: number | null | undefined, hidden: ReadonlySet<number>): boolean {
  return storey == null || !hidden.has(storey);
}

/**
 * A controller over `meta`'s storeys, calling `apply` with the node indices
 * of those hidden after each change. `null` when there is nothing to filter.
 */
export function createStoreys(meta: Pick<ModelMeta, "nodes" | "elements">, apply: (hidden: ReadonlySet<number>) => void): StoreysController | null {
  const first = storeyItems(meta);
  if (first.length === 0) return null;
  const store = writable<{ items: readonly StoreyItem[] }>({ items: first });
  const change = (visible: (item: StoreyItem) => boolean) => {
    const items = store.get().items.map((i) => (visible(i) === i.visible ? i : { ...i, visible: visible(i) }));
    store.set({ items });
    apply(new Set(items.filter((i) => !i.visible).map((i) => Number(i.id))));
  };
  return {
    ...store,
    setVisible: (id, visible) => change((i) => (i.id === id ? visible : i.visible)),
    setAll: (visible) => change(() => visible),
  };
}
