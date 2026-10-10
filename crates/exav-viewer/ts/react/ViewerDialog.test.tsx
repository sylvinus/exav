import { act, useState } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, expect, it } from "vitest";

import type { FormatPlugin } from "../core/types.js";
import { ViewerProvider } from "./context.js";
import { ViewerDialog, type ViewerDialogItem } from "./ViewerDialog.js";

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
// jsdom has neither.
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

const items: ViewerDialogItem[] = ["a", "b", "c"].map((id) => ({
  id,
  name: `${id}.fake`,
  title: id.toUpperCase(),
  hint: "FAKE",
  source: { bytes: new Uint8Array([1]) },
}));

let host: HTMLDivElement;
let root: Root;
let changes: (number | null)[];
beforeEach(() => {
  host = document.createElement("div");
  document.body.append(host);
  root = createRoot(host);
  changes = [];
});
afterEach(async () => {
  await act(async () => root.unmount());
  host.remove();
});

function Stack({ locale }: { locale: string }) {
  const [index, setIndex] = useState<number | null>(0);
  return (
    <ViewerProvider plugins={[plugin]} locale={locale}>
      <ViewerDialog
        items={items}
        index={index}
        onIndexChange={(i) => {
          changes.push(i);
          setIndex(i);
        }}
      />
    </ViewerProvider>
  );
}

const title = () => document.querySelector(".exv-dialog-title")?.textContent;
const counter = () => document.querySelector(".exv-counter")?.textContent;
const key = (k: string) => act(async () => void window.dispatchEvent(new KeyboardEvent("keydown", { key: k })));

it("walks the stack with the arrow keys, round from the first to the last", async () => {
  await act(async () => root.render(<Stack locale="en" />));
  expect(document.querySelector<HTMLDialogElement>("dialog.exv-dialog")?.open).toBe(true);
  expect([title(), counter()]).toEqual(["AFAKE", "1 / 3"]);
  await key("ArrowRight");
  expect([title(), counter()]).toEqual(["BFAKE", "2 / 3"]);
  await key("ArrowLeft");
  await key("ArrowLeft");
  expect([title(), counter()]).toEqual(["CFAKE", "3 / 3"]);
  expect(changes).toEqual([1, 0, 2]);
});

it("closes on Escape, which the browser sends to the dialog as cancel", async () => {
  await act(async () => root.render(<Stack locale="en" />));
  const dialog = document.querySelector("dialog.exv-dialog")!;
  await act(async () => void dialog.dispatchEvent(new Event("cancel", { cancelable: true })));
  expect(changes).toEqual([null]);
  expect(document.querySelector("dialog.exv-dialog")).toBeNull();
});

it("speaks the provider's language", async () => {
  await act(async () => root.render(<Stack locale="fr" />));
  const close = document.querySelector<HTMLButtonElement>('button[aria-label="Fermer"]');
  expect(close).not.toBeNull();
  await act(async () => close!.click());
  expect(changes).toEqual([null]);
});
