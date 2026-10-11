import { act } from "react";
import { createRoot } from "react-dom/client";
import { afterEach, describe, expect, it, vi } from "vitest";

import { writable } from "../core/store.js";
import type { FormatPlugin, Status } from "../core/types.js";
import { createViewer } from "../core/viewer.js";
import { ViewerProvider } from "./context.js";
import { ViewerBody } from "./ViewerBody.js";

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
// jsdom has none.
globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
};

const plugin: FormatPlugin = {
  id: "fake",
  match: { extensions: [".fake"] },
  capabilities: [],
  options: {},
  load: async () => ({
    mount(host, c) {
      host.textContent = c.file.id;
      c.status({ phase: "ready" });
      return { controllers: {}, destroy: () => {} };
    },
  }),
};

const file = (id: string) => ({ id, name: `${id}.fake`, source: { bytes: new Uint8Array([1]) } });

afterEach(() => vi.restoreAllMocks());

// An arrow with an expression body returns what it computes; returned from an
// effect, React took it for the cleanup and threw when the next status came.
it("a status callback that returns a value is only called", async () => {
  const log: [string, Status["phase"]][] = [];
  const errors: unknown[] = [];
  vi.spyOn(console, "error").mockImplementation((...a) => void errors.push(a));
  const host = document.createElement("div");
  document.body.append(host);
  const root = createRoot(host, { onUncaughtError: (e) => void errors.push(e) });
  const render = (id: string) =>
    root.render(
      <ViewerProvider plugins={[plugin]}>
        <ViewerBody file={file(id)} onStatus={(s) => log.push([id, s.phase])} onPages={() => 42} />
      </ViewerProvider>,
    );
  await act(async () => render("a"));
  await act(async () => render("b"));
  await act(async () => root.unmount());
  expect(errors).toEqual([]);
  expect(log).toContainEqual(["a", "ready"]);
  expect(log).toContainEqual(["b", "ready"]);
  host.remove();
});

it("onPages follows the member of an archive that is open, and goes back to none when it closes", async () => {
  const pages = writable({ unit: "page" as const, current: 4, total: 9 });
  const member = { controllers: writable({ pages }), status: writable({ phase: "ready" as const }), format: "pdf" };
  const archive = writable({ members: [], opening: null, refused: null, opened: null as unknown });
  const zip: FormatPlugin = {
    ...plugin,
    load: async () => ({
      mount(host, c) {
        c.status({ phase: "ready" });
        return { controllers: { archive: { ...archive, open: async () => {}, back() {} } as never }, destroy: () => {} };
      },
    }),
  };
  const seen: (number | null)[] = [];
  const host = document.createElement("div");
  document.body.append(host);
  const root = createRoot(host);
  await act(async () =>
    root.render(
      <ViewerProvider plugins={[zip]}>
        <ViewerBody file={file("z")} chrome="none" onPages={(p) => void seen.push(p ? p.total : null)} />
      </ViewerProvider>,
    ),
  );
  expect(seen.at(-1)).toBeNull();
  await act(async () => archive.set({ ...archive.get(), opened: { member: { name: "a.pdf" }, file: file("m"), session: member } }));
  expect(seen.at(-1)).toBe(9);
  await act(async () => archive.set({ ...archive.get(), opened: null }));
  expect(seen.at(-1)).toBeNull();
  await act(async () => root.unmount());
  host.remove();
});

it("a plugin's own label and error message replace the stock ones", async () => {
  const saying = (id: string, ...statuses: Status[]): FormatPlugin => ({
    ...plugin,
    load: async () => ({
      mount(host, c) {
        for (const s of statuses.slice(0, -1)) c.status(s);
        c.status(statuses.at(-1)!);
        return { controllers: {}, destroy: () => {} };
      },
    }),
  });
  const host = document.createElement("div");
  document.body.append(host);
  const root = createRoot(host);
  const said = async (p: FormatPlugin, id: string) => {
    await act(async () =>
      root.render(
        <ViewerProvider plugins={[p]}>
          <ViewerBody file={file(id)} />
        </ViewerProvider>,
      ),
    );
    return host.querySelector(".exv-status p")?.textContent;
  };
  expect(await said(saying("c", { phase: "converting", label: "Decoding the photo" }), "c")).toBe("Decoding the photo");
  expect(await said(saying("l", { phase: "loading", label: "Reading the HEIC" }), "l")).toBe("Reading the HEIC");
  expect(await said(saying("e", { phase: "error", error: { code: "file", message: "Not a HEIC file" } }), "e")).toBe("Not a HEIC file");
  // Without them, the stock messages.
  expect(await said(saying("s", { phase: "converting" }), "s")).toMatch(/\d+ ?%/);
  expect(await said(saying("f", { phase: "error", error: { code: "file" } }), "f")).not.toBe("Not a HEIC file");
  // A host's own code its table does not word shows the generic message, not the key.
  expect(await said(saying("h", { phase: "error", error: { code: "heic" } }), "h")).toBe("This file could not be shown.");
  await act(async () => root.unmount());
  host.remove();
});

describe("the same file id with another source", () => {
  const events: string[] = [];
  const counting = (canReplace: boolean): FormatPlugin => ({
    ...plugin,
    load: async () => ({
      mount(host, c) {
        events.push("mount");
        host.textContent = c.file.id;
        c.status({ phase: "ready" });
        return {
          controllers: {},
          ...(canReplace && {
            replace: async (next) => void events.push(`replace ${(next.file.source as { url: string }).url}`),
          }),
          destroy: () => void events.push("destroy"),
        };
      },
    }),
  });
  const withSource = (url: string) => ({ id: "same", name: "same.fake", source: { url } });

  async function render(p: FormatPlugin, ...urls: string[]) {
    events.length = 0;
    const host = document.createElement("div");
    document.body.append(host);
    const root = createRoot(host);
    for (const url of urls) {
      await act(async () =>
        root.render(
          <ViewerProvider plugins={[p]}>
            <ViewerBody file={withSource(url)} />
          </ViewerProvider>,
        ),
      );
      await act(async () => {});
    }
    await act(async () => root.unmount());
    host.remove();
    return [...events];
  }

  it("replaces the document in place when the engine can", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response(new Uint8Array([1]))));
    expect(await render(counting(true), "https://example.test/a", "https://example.test/b")).toEqual(["mount", "replace https://example.test/b", "destroy"]);
  });

  it("starts the session over when it cannot", async () => {
    expect(await render(counting(false), "https://example.test/a", "https://example.test/b")).toEqual(["mount", "destroy", "mount", "destroy"]);
  });

  it("does nothing for an address that is the same, though a new object each render", async () => {
    expect(await render(counting(true), "https://example.test/a", "https://example.test/a", "https://example.test/a")).toEqual(["mount", "destroy"]);
  });
});

describe("the zoom buttons and the drag toggle", () => {
  function controls() {
    const zoom = { ...writable({ scale: 2, min: 1, max: 4 }), setScale: vi.fn(), fit: vi.fn() };
    const state = writable({ mode: "pan" as "pan" | "select", available: true });
    const drag = { ...state, choose: vi.fn((mode: "pan" | "select") => state.set({ mode, available: state.get().available })) };
    const withControls: FormatPlugin = {
      ...plugin,
      load: async () => ({
        mount(host, c) {
          c.controllers({ zoom, drag });
          c.status({ phase: "ready" });
          return { controllers: { zoom, drag }, destroy: () => {} };
        },
      }),
    };
    return { zoom, state, drag, withControls };
  }
  async function show(p: FormatPlugin, components = {}) {
    const host = document.createElement("div");
    document.body.append(host);
    const root = createRoot(host);
    await act(async () =>
      root.render(
        <ViewerProvider plugins={[p]} components={components}>
          <ViewerBody file={file("t")} />
        </ViewerProvider>,
      ),
    );
    const button = (label: string) => host.querySelector<HTMLButtonElement>(`.exv-tools button[aria-label="${label}"]`);
    return { host, button, done: async () => (await act(async () => root.unmount()), host.remove()) };
  }

  it("zoom in and out by a step of a quarter, and fit; out at the least zoom and in at the most are disabled", async () => {
    const { zoom, withControls } = controls();
    const ui = await show(withControls);
    await act(async () => ui.button("Zoom in")!.click());
    expect(zoom.setScale).toHaveBeenLastCalledWith(2.5);
    await act(async () => ui.button("Zoom out")!.click());
    expect(zoom.setScale).toHaveBeenLastCalledWith(1.6);
    await act(async () => ui.button("Fit to the window")!.click());
    expect(zoom.fit).toHaveBeenCalledTimes(1);
    expect(ui.button("Zoom out")!.disabled).toBe(false);
    await act(async () => zoom.set({ scale: 1, min: 1, max: 4 }));
    expect(ui.button("Zoom out")!.disabled).toBe(true);
    await act(async () => zoom.set({ scale: 4, min: 1, max: 4 }));
    expect(ui.button("Zoom in")!.disabled).toBe(true);
    await ui.done();
  });

  it("the toggle shows the mode, switches it, and is not there when there is no choice", async () => {
    const { state, drag, withControls } = controls();
    const ui = await show(withControls);
    expect(ui.button("Move the page")!.getAttribute("aria-pressed")).toBe("true");
    expect(ui.button("Select text")!.getAttribute("aria-pressed")).toBe("false");
    await act(async () => ui.button("Select text")!.click());
    expect(drag.choose).toHaveBeenLastCalledWith("select");
    expect(ui.button("Select text")!.getAttribute("aria-pressed")).toBe("true");
    await act(async () => state.set({ mode: "select", available: false }));
    expect(ui.button("Move the page")).toBeNull();
    expect(ui.button("Zoom in")).not.toBeNull();
    await ui.done();
  });

  it("each piece can be replaced, or dropped, by the host", async () => {
    const { withControls } = controls();
    const ui = await show(withControls, { ZoomControls: () => null, DragToggle: () => <b id="mine">mine</b> });
    expect(ui.button("Zoom in")).toBeNull();
    expect(ui.host.querySelector(".exv-tools #mine")).not.toBeNull();
    await ui.done();
  });
});

it("a provider given a viewer uses it as it is, whatever plugins it is also given", async () => {
  const mine = createViewer({ plugins: [plugin] });
  const mount = vi.spyOn(mine, "mount");
  const host = document.createElement("div");
  document.body.append(host);
  const root = createRoot(host);
  await act(async () =>
    root.render(
      <ViewerProvider viewer={mine} plugins={[]}>
        <ViewerBody file={file("v")} />
      </ViewerProvider>,
    ),
  );
  expect(mount).toHaveBeenCalledTimes(1);
  expect(host.querySelector(".exv-body")?.getAttribute("data-phase")).toBe("ready");
  await act(async () => root.unmount());
  host.remove();
});

it("the warnings can be dismissed, and come back when they change", async () => {
  const warnings = writable([{ key: "proxy_without_graphics", count: 3 }]);
  const plugin2: FormatPlugin = {
    ...plugin,
    load: async () => ({
      mount(host, c) {
        c.controllers({ warnings });
        c.status({ phase: "ready" });
        return { controllers: { warnings }, destroy: () => {} };
      },
    }),
  };
  const host = document.createElement("div");
  document.body.append(host);
  const root = createRoot(host);
  await act(async () =>
    root.render(
      <ViewerProvider plugins={[plugin2]}>
        <ViewerBody file={file("w")} />
      </ViewerProvider>,
    ),
  );
  const box = () => host.querySelector(".exv-warnings");
  expect(box()?.textContent).toMatch(/3/);
  await act(async () => host.querySelector<HTMLButtonElement>(".exv-warnings button")!.click());
  expect(box()).toBeNull();
  await act(async () => warnings.set([{ key: "proxy_without_graphics", count: 4 }]));
  expect(box()?.textContent).toMatch(/4/);
  await act(async () => root.unmount());
  host.remove();
});

it("the outline rail shows from two entries, not for one", async () => {
  const entry = (title: string) => ({ title, page: 1, depth: 0, offset: null });
  const outlined = (entries: ReturnType<typeof entry>[]): FormatPlugin => ({
    ...plugin,
    load: async () => ({
      mount(host, c) {
        const outline = { ...writable(entries), goTo() {} };
        c.controllers({ outline });
        c.status({ phase: "ready" });
        return { controllers: { outline }, destroy: () => {} };
      },
    }),
  });
  const host = document.createElement("div");
  document.body.append(host);
  const root = createRoot(host);
  const shown = async (entries: ReturnType<typeof entry>[]) => {
    await act(async () =>
      root.render(
        <ViewerProvider plugins={[outlined(entries)]}>
          <ViewerBody file={file(`o${entries.length}`)} />
        </ViewerProvider>,
      ),
    );
    return host.querySelectorAll(".exv-outline-entry").length;
  };
  expect(await shown([entry("Only")])).toBe(0);
  expect(await shown([entry("One"), entry("Two")])).toBe(2);
  await act(async () => root.unmount());
  host.remove();
});

// A host's own buttons need the session's controllers (zoom, say), which
// `onStatus` and `onPages` do not give.
it("children are drawn in the stage, and a function of them gets the session's state", async () => {
  const pages = writable({ unit: "page" as const, current: 1, total: 3 });
  const withPages: FormatPlugin = {
    ...plugin,
    load: async () => ({
      mount(host, c) {
        host.textContent = c.file.id;
        c.controllers({ pages });
        c.status({ phase: "ready" });
        return { controllers: { pages }, destroy: () => {} };
      },
    }),
  };
  const seen: { phase: string; total: number | undefined; session: boolean }[] = [];
  const host = document.createElement("div");
  document.body.append(host);
  const root = createRoot(host);
  await act(async () =>
    root.render(
      <ViewerProvider plugins={[withPages]}>
        <ViewerBody file={file("a")}>
          {({ session, status, controllers }) => {
            seen.push({ phase: status.phase, total: controllers.pages?.get()?.total, session: !!session });
            return <button id="mine">mine</button>;
          }}
        </ViewerBody>
        <ViewerBody file={file("b")}>
          <i id="plain">plain</i>
        </ViewerBody>
      </ViewerProvider>,
    ),
  );
  expect(host.querySelector(".exv-stage #mine")).not.toBeNull();
  expect(host.querySelector(".exv-stage #plain")).not.toBeNull();
  expect(seen.at(-1)).toEqual({ phase: "ready", total: 3, session: true });
  await act(async () => root.unmount());
  host.remove();
});
