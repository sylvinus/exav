import { act, createRef } from "react";
import { createRoot } from "react-dom/client";
import { describe, expect, it, vi } from "vitest";

import { writable } from "../core/store.js";
import type { FormatPlugin, Highlight, HighlightsController, PagesController, ViewerFile } from "../core/types.js";
import { ViewerProvider } from "./context.js";
import { ViewerBody, type ViewerBodyHandle } from "./ViewerBody.js";
import { ViewerDialog } from "./ViewerDialog.js";

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
};
HTMLDialogElement.prototype.showModal ??= function (this: HTMLDialogElement) {
  this.open = true;
};
HTMLDialogElement.prototype.close ??= function (this: HTMLDialogElement) {
  this.open = false;
};

/** A format with pages and highlights, whose controllers say what was asked of them; `ready` publishes them. */
function fakeFormat() {
  const calls: unknown[][] = [];
  let ready: () => void = () => {};
  const mounted: ViewerFile[] = [];
  const highlights: HighlightsController = {
    ...writable({ items: [], current: null }),
    set: (list: readonly Highlight[]) => void calls.push(["set", list]),
    goTo: (id: string) => void calls.push(["goTo", id]),
  };
  const pages: PagesController = { ...writable(null), goTo: (page: number) => void calls.push(["page", page]) };
  const plugin: FormatPlugin = {
    id: "fake",
    match: { extensions: [".fake"] },
    capabilities: ["pages", "highlights"],
    options: {},
    load: async () => ({
      mount(_host, c) {
        mounted.push(c.file);
        return new Promise((resolve) => {
          ready = () => {
            c.status({ phase: "ready" });
            resolve({ controllers: { highlights, pages }, destroy: () => {} });
          };
        });
      },
    }),
  };
  return { plugin, calls, mounted, ready: () => ready() };
}

// One source: another would be other bytes, which start the session over.
const source = { bytes: new Uint8Array([1]) };
const file = (over: Partial<ViewerFile> = {}): ViewerFile => ({ id: "f", name: "f.fake", source, ...over });

async function setup() {
  const fake = fakeFormat();
  const host = document.createElement("div");
  document.body.append(host);
  const root = createRoot(host);
  const ref = createRef<ViewerBodyHandle>();
  const render = (f: ViewerFile) =>
    act(async () =>
      root.render(
        <ViewerProvider plugins={[fake.plugin]}>
          <ViewerBody file={f} ref={ref} />
        </ViewerProvider>,
      ),
    );
  const done = async () => {
    await act(async () => root.unmount());
    host.remove();
  };
  return { ...fake, ref, render, done };
}

describe("highlights in the React layer", () => {
  const quote: Highlight = { id: "q", text: "prix" };

  it("gives the session the file's highlights when it is mounted, and no more for a new literal with the same ones", async () => {
    const t = await setup();
    await t.render(file({ highlights: [quote], focusHighlight: "q" }));
    await act(async () => t.ready());
    expect(t.mounted[0]).toMatchObject({ highlights: [quote], focusHighlight: "q" });
    await t.render(file({ highlights: [{ ...quote }], focusHighlight: "q" }));
    expect(t.calls).toEqual([]);
    await t.done();
  });

  it("sets a new list and goes to the new focus, on the same session", async () => {
    const t = await setup();
    await t.render(file({ highlights: [quote] }));
    await act(async () => t.ready());
    const next: Highlight[] = [quote, { id: "r", page: 2, rects: [{ x: 0, y: 0, width: 1, height: 0.1 }] }];
    await t.render(file({ highlights: next, focusHighlight: "r" }));
    expect(t.calls).toEqual([
      ["set", next],
      ["goTo", "r"],
    ]);
    expect(t.mounted).toHaveLength(1);
    // Without a focus: the first.
    await t.render(file({ highlights: [{ text: "délai" }] }));
    expect(t.calls.slice(2)).toEqual([
      ["set", [{ text: "délai" }]],
      ["goTo", "0"],
    ]);
    await t.done();
  });

  it("the handle goes to a page or a highlight, once the document is shown when called before", async () => {
    const t = await setup();
    await t.render(file({ highlights: [quote] }));
    t.ref.current!.goToHighlight("q");
    t.ref.current!.goToPage(3);
    expect(t.calls).toEqual([]);
    await act(async () => t.ready());
    expect(t.calls).toEqual([
      ["goTo", "q"],
      ["page", 3],
    ]);
    t.ref.current!.goToHighlight("q");
    expect(t.calls).toHaveLength(3);
    await t.done();
  });

  it("ViewerDialog hands its body's handle to the host", async () => {
    const fake = fakeFormat();
    const host = document.createElement("div");
    document.body.append(host);
    const root = createRoot(host);
    const ref = createRef<ViewerBodyHandle>();
    const items = [{ ...file({ highlights: [quote] }), title: "Offre" }];
    await act(async () =>
      root.render(
        <ViewerProvider plugins={[fake.plugin]}>
          <ViewerDialog items={items} index={0} onIndexChange={vi.fn()} ref={ref} />
        </ViewerProvider>,
      ),
    );
    await act(async () => fake.ready());
    ref.current!.goToHighlight("q");
    expect(fake.calls).toEqual([["goTo", "q"]]);
    await act(async () => root.unmount());
    host.remove();
  });
});
