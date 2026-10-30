/**
 * A host that draws its own UI: each file in the sandboxed frame, and every
 * control on this page, made from the session's controllers. The frame
 * draws the document alone (the player's controls too are this page's:
 * `media.controls: "none"`), takes this page's colours (`theme`, read from
 * its CSS custom properties) and hands back the keys the document does not
 * use. `window.headless` is for the browser tests.
 */
import "./headless.css";

import { builtinTranslate, printPictures, type Controllers, type MessageKey, type Session, type Status, type Store } from "@exav/viewer";
import { createSandboxedViewer } from "@exav/viewer/frame";

declare const __DEMO_ORIGIN__: string;

const BASE = import.meta.env.BASE_URL;
const t = builtinTranslate(new URLSearchParams(location.search).get("lang") ?? navigator.language);

const viewer = createSandboxedViewer({
  url: `${BASE}frame/index.html`,
  origins: { media: [__DEMO_ORIGIN__], connect: [__DEMO_ORIGIN__] },
  options: { media: { controls: "none" } },
});

const $ = (id: string) => document.getElementById(id)!;
const stage = $("stage");
const controls = $("controls");
const sheetTabs = $("sheets");
const thumbs = $("thumbs");
const statusLine = $("status");

function el<K extends keyof HTMLElementTagNameMap>(tag: K, props: Partial<HTMLElementTagNameMap[K]> = {}, ...children: (Node | string)[]): HTMLElementTagNameMap[K] {
  const e = Object.assign(document.createElement(tag), props);
  e.append(...children);
  return e;
}

const button = (label: string, onclick: () => void, title = label) => el("button", { type: "button", textContent: label, title, onclick });

/** Calls `draw` with the store's value now and on each change; returns the unsubscribe. */
function follow<T>(store: Store<T> | undefined, draw: (value: T) => void): () => void {
  if (!store) return () => {};
  draw(store.get());
  return store.subscribe(draw);
}

function statusText(s: Status): string {
  switch (s.phase) {
    case "loading":
    case "converting":
      return t("loading");
    case "error":
      return t(s.error.code === "pdf" ? "error" : (`error_${s.error.code}` as MessageKey));
    case "empty":
      return t("empty_model");
    default:
      return "";
  }
}

const seconds = (s: number) => (Number.isFinite(s) ? `${Math.floor(s / 60)}:${String(Math.floor(s % 60)).padStart(2, "0")}` : "∞");

let session: Session | null = null;
/** What follows the file on screen, dropped on each redraw. */
let widgets: (() => void)[] = [];
let thumbsAbort: AbortController | null = null;

const clearWidgets = () => {
  for (const stop of widgets) stop();
  widgets = [];
  thumbsAbort?.abort();
  controls.replaceChildren();
  sheetTabs.replaceChildren();
  thumbs.replaceChildren();
};

/**
 * The controls of the session shown: an archive's open member, down as many
 * levels as are open, drawn again when anything on the way changes.
 */
function render(root: Session) {
  clearWidgets();
  let scheduled = false;
  const redraw = () => {
    if (scheduled) return;
    scheduled = true;
    queueMicrotask(() => session === root && render(root));
  };
  let shown = root;
  let back: Controllers["archive"] | null = null;
  for (;;) {
    const c = shown.controllers.get();
    widgets.push(shown.controllers.subscribe(redraw));
    const opened = c.archive?.get().opened;
    if (c.archive) {
      // Redrawn when a member opens or closes, not on each extraction step.
      const was = opened;
      widgets.push(c.archive.subscribe((a) => a.opened !== was && redraw()));
    }
    if (!opened) break;
    back = c.archive!;
    shown = opened.session;
  }
  widgets.push(follow(shown.status, (status) => (statusLine.textContent = statusText(status))));
  draw(shown.controllers.get(), back);
}

function draw(c: Controllers, archiveOf: Controllers["archive"] | null) {
  const bar = (...children: (Node | string)[]) => controls.append(el("div", { className: "group" }, ...children));
  if (archiveOf) bar(button(t("archive_back"), () => archiveOf.back()));
  if (c.archive) {
    const list = el("ul", { className: "members" });
    widgets.push(
      follow(c.archive, (a) =>
        list.replaceChildren(
          ...a.members.map((m) => el("li", {}, button(m.name, () => void c.archive!.open(m.index)))),
          ...(a.refused ? [el("li", { textContent: t(a.refused.key) })] : []),
        ),
      ),
    );
    bar(list);
  }
  if (c.pages) {
    const pages = c.pages;
    const field = el("input", { type: "number", min: "1", ariaLabel: t("page_short", { page: "" }).trim() });
    const total = el("span");
    field.onchange = () => pages.goTo?.(Number(field.value));
    widgets.push(
      follow(pages, (p) => {
        if (document.activeElement !== field) field.value = String(p?.current ?? "");
        total.textContent = `/ ${p?.total ?? "…"}`;
      }),
    );
    bar(...(pages.prev ? [button("‹", () => void pages.prev!(), t("prev"))] : []), field, total, ...(pages.next ? [button("›", () => void pages.next!(), t("next"))] : []));
  }
  if (c.zoom) {
    const zoom = c.zoom;
    const label = el("span", { className: "zoom" });
    widgets.push(follow(zoom, (z) => (label.textContent = `${Math.round(z.scale * 100)} %`)));
    bar(button("−", () => zoom.setScale(zoom.get().scale / 1.25), t("zoom_out")), label, button("+", () => zoom.setScale(zoom.get().scale * 1.25), t("zoom_in")), button("⤢", () => zoom.fit(), t("zoom_fit")));
  }
  if (c.media) {
    const media = c.media;
    const play = button("▶", () => void (media.get().paused ? media.play() : media.pause()));
    play.dataset.testid = "play";
    const time = el("input", { type: "range", min: "0", step: "0.1", ariaLabel: "Time" });
    const clock = el("span", { className: "clock" });
    const mute = button("🔊", () => media.setMuted(!media.get().muted));
    time.oninput = () => media.seek(Number(time.value));
    widgets.push(
      follow(media, (m) => {
        play.textContent = m.paused ? "▶" : "⏸";
        time.max = String(Number.isFinite(m.duration) ? m.duration : 0);
        time.value = String(m.currentTime);
        clock.textContent = `${seconds(m.currentTime)} / ${seconds(m.duration)}`;
        mute.textContent = m.muted ? "🔇" : "🔊";
      }),
    );
    // Fullscreen is the page's: the frame may not, the element holding it may.
    bar(play, time, clock, mute, button("⛶", () => void $("viewer").requestFullscreen()));
  }
  if (c.sheets) {
    const sheets = c.sheets;
    widgets.push(
      follow(sheets, (s) =>
        sheetTabs.replaceChildren(
          ...s.items.map((sheet) => {
            const tab = button(sheet.name, () => void sheets.select(sheet.index));
            tab.role = "tab";
            tab.ariaSelected = String(sheet.index === s.current);
            return tab;
          }),
        ),
      ),
    );
  }
  if (c.pictures) {
    const pictures = c.pictures;
    bar(button("⎙", () => void printPictures(pictures), "Print"));
    drawThumbs(pictures, c.pages);
  }
}

/** A picture of each page (the first 50), drawn one after the other, a click going to it. */
function drawThumbs(pictures: NonNullable<Controllers["pictures"]>, pages: Controllers["pages"]) {
  const abort = new AbortController();
  thumbsAbort = abort;
  const count = Math.min(pictures.get().count, 50);
  if (count < 2) return;
  void (async () => {
    for (let page = 1; page <= count && !abort.signal.aborted; page++) {
      const bitmap = await pictures.render(page, 160 * Math.min(devicePixelRatio || 1, 2));
      if (!bitmap) continue;
      if (abort.signal.aborted) {
        bitmap.close();
        return;
      }
      const canvas = el("canvas", { width: bitmap.width, height: bitmap.height });
      canvas.getContext("bitmaprenderer")?.transferFromImageBitmap(bitmap);
      thumbs.append(el("button", { type: "button", title: t("page_short", { page }), onclick: () => pages?.goTo?.(page) }, canvas));
    }
  })();
}

function showFile(file: File) {
  session?.destroy();
  clearWidgets();
  session = viewer.mount(stage, { id: `${file.name}:${file.size}:${file.lastModified}`, name: file.name, type: file.type, source: { blob: file } });
  render(session);
}

$("scheme").onclick = () => {
  const dark = document.documentElement.classList.toggle("dark");
  $("scheme").textContent = dark ? "Light" : "Dark";
  viewer.restyle();
};

(document.querySelector('[data-testid="file-input"]') as HTMLInputElement).onchange = (e) => {
  const file = (e.target as HTMLInputElement).files?.[0];
  if (file) showFile(file);
};

// The keys the frame hands back reach this page's listeners as the page's own.
document.addEventListener("keydown", (e) => {
  $("keys").append(el("li", { textContent: `${e.key}${e.isTrusted ? "" : " (from the frame)"}` }));
  if (e.key === "Escape" && session) {
    session.destroy();
    session = null;
    clearWidgets();
    statusLine.textContent = "";
  }
});

Object.assign(window, { headless: { viewer, session: () => session } });
