import { describe, expect, it } from "vitest";

import { derived, onDemand, writable } from "./store.js";

describe("onDemand", () => {
  function make() {
    const source = writable(0);
    const log: string[] = [];
    const store = onDemand(source, {
      start() {
        log.push("start");
        return () => void log.push("stop");
      },
      once() {
        log.push("once");
        source.set(source.get() + 1);
      },
    });
    return { source, log, store };
  }

  it("does nothing until it is read or followed", () => {
    expect(make().log).toEqual([]);
  });

  it("works once for each read with no listener, and the read has its result", () => {
    const { store, log } = make();
    expect(store.get()).toBe(1);
    expect(store.get()).toBe(2);
    expect(log).toEqual(["once", "once"]);
  });

  it("starts with the first listener and stops with the last, however many come between", () => {
    const { store, source, log } = make();
    const seen: number[] = [];
    const a = store.subscribe((v) => seen.push(v));
    const b = store.subscribe(() => {});
    expect(log).toEqual(["start"]);
    source.set(10);
    expect(seen).toEqual([10]);
    a();
    a();
    expect(log).toEqual(["start"]);
    b();
    expect(log).toEqual(["start", "stop"]);
    // Followed again: a new start.
    store.subscribe(() => {})();
    expect(log).toEqual(["start", "stop", "start", "stop"]);
  });

  it("does not work for a read while it has a listener", () => {
    const { store, log } = make();
    const stop = store.subscribe(() => {});
    expect(store.get()).toBe(0);
    expect(log).toEqual(["start"]);
    stop();
    expect(store.get()).toBe(1);
    expect(log).toEqual(["start", "stop", "once"]);
  });
});

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
