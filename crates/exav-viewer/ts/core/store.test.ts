import { describe, expect, it } from "vitest";

import { derived, writable } from "./store.js";

describe("derived", () => {
  it("returns the same value until its source changes", () => {
    const source = writable({ pages: 3 });
    let runs = 0;
    const view = derived(source, (s) => (runs++, { label: `${s.pages} pages` }));
    const a = view.get();
    expect(view.get()).toBe(a);
    expect(runs).toBe(1);
    source.set({ pages: 4 });
    expect(view.get()).not.toBe(a);
    expect(view.get().label).toBe("4 pages");
    expect(runs).toBe(2);
  });

  it("tells its listeners the new value", () => {
    const source = writable(1);
    const seen: number[] = [];
    derived(source, (n) => n * 10).subscribe((v) => seen.push(v));
    source.set(2);
    source.set(3);
    expect(seen).toEqual([20, 30]);
  });
});
