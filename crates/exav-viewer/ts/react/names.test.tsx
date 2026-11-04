import { act } from "react";
import { createRoot } from "react-dom/client";
import { afterEach, describe, expect, it } from "vitest";

import { shownName } from "../core/names.js";
import { writable } from "../core/store.js";
import { ViewerProvider } from "./context.js";
import { Piece } from "./parts.js";

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

// What a document's names may hold: a right-to-left override, an isolate, a
// mark, a line separator, a C1 control and a C0 one.
const HOSTILE = "a\u{202e}b\u{2066}c\u{200f}d\u{2028}e\u{85}f\u{1}g";
const HIDDEN = /[\u{0}-\u{1f}\u{7f}-\u{9f}\u{61c}\u{200e}\u{200f}\u{2028}\u{2029}\u{202a}-\u{202e}\u{2066}-\u{2069}]/u;
const SHOWN = "a\u{fffd}b\u{fffd}c\u{fffd}d\u{fffd}e\u{fffd}f\u{fffd}g";

const none = () => {};
const hosts: HTMLElement[] = [];

async function render(props: Parameters<typeof Piece>[0]): Promise<HTMLElement> {
  const host = document.createElement("div");
  document.body.append(host);
  hosts.push(host);
  const root = createRoot(host);
  await act(async () =>
    root.render(
      <ViewerProvider plugins={[]}>
        <Piece {...props} />
      </ViewerProvider>,
    ),
  );
  return host;
}

/** Every piece of text and every title in `host`. */
function shown(host: HTMLElement): string[] {
  const out: string[] = [];
  const walk = (el: Element) => {
    const title = el.getAttribute("title");
    if (title) out.push(title);
    for (const n of el.childNodes) {
      if (n.nodeType === Node.TEXT_NODE && n.textContent) out.push(n.textContent);
      else if (n instanceof Element) walk(n);
    }
  };
  walk(host);
  return out;
}

afterEach(() => {
  for (const h of hosts.splice(0)) h.remove();
});

describe("shownName", () => {
  it("shows controls and bidirectional characters as U+FFFD, and leaves the rest", () => {
    expect(shownName(HOSTILE)).toBe(SHOWN);
    expect(shownName("report \u{5e9}\u{5dc}\u{5d5}\u{5dd}.pdf")).toBe("report \u{5e9}\u{5dc}\u{5d5}\u{5dd}.pdf");
  });
});

describe("the default pieces", () => {
  const expectShown = (host: HTMLElement) => {
    const texts = shown(host);
    expect(texts.filter((t) => t.includes(SHOWN)).length).toBeGreaterThan(0);
    for (const t of texts) expect(HIDDEN.test(t), JSON.stringify(t)).toBe(false);
  };

  it("show an archive's member names as the archive stores them", async () => {
    const archive = { ...writable({ members: [{ index: 0, name: `${HOSTILE}/${HOSTILE}.txt`, uncompressedSize: 1, encrypted: false }], opening: null, refused: null, opened: null }), open: async () => {}, back: none };
    expectShown(await render({ name: "ArchiveList", props: { archive: archive as never } }));
    expectShown(await render({ name: "ArchiveBack", props: { archive: archive as never, name: HOSTILE } }));
  });

  it("show a sheet's, a section's and a warning's names", async () => {
    const sheets = { ...writable({ items: [{ index: 0, name: HOSTILE }, { index: 1, name: "b" }], current: 0 }), select: async () => {} };
    expectShown(await render({ name: "SheetTabs", props: { sheets } }));
    const outline = { ...writable([{ title: HOSTILE, page: 1, depth: 0, offset: null }, { title: "b", page: 2, depth: 0, offset: null }]), goTo: none };
    expectShown(await render({ name: "OutlineRail", props: { outline } }));
    expectShown(await render({ name: "Warnings", props: { warnings: [{ key: "missing_xrefs", count: 1, names: [HOSTILE] }] } }));
  });

  it("show a drawing's layers, storeys, layouts and selection", async () => {
    const layers = { ...writable({ kind: "layers" as const, items: [{ id: "x", name: HOSTILE, color: "#fff", visible: true }] }), setVisible: none, setAll: none };
    expectShown(await render({ name: "DrawingRail", props: { layers } }));
    const storeys = { ...writable({ items: [{ id: "x", name: HOSTILE, elevation: null, visible: true }] }), setVisible: none, setAll: none };
    expectShown(await render({ name: "DrawingRail", props: { storeys } }));
    const layouts = { ...writable({ items: [{ id: "a", name: HOSTILE, isModel: false }, { id: "b", name: "b", isModel: true }], current: "a" }), select: async () => {} };
    expectShown(await render({ name: "DrawingRail", props: { layouts } }));
    const selection = writable({ name: HOSTILE, category: HOSTILE, storey: HOSTILE });
    expectShown(await render({ name: "DrawingRail", props: { selection } }));
  });
});
