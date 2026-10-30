/**
 * The frame app: one file, in a sandboxed iframe, driven by the host page
 * over a MessagePort (`../protocol.ts`). Built into `dist/frame/app/` by
 * `scripts/build-frame.mjs`, with every worker as a classic script and every
 * engine's files beside it, so that nothing is fetched from another origin.
 */
import { archive } from "../../archive/index.js";
// The plugins alone: `cad/index.ts` also re-exports the engine.
import { dwg, dxf } from "../../cad/plugin.js";
import { BUILTIN_ORDER, CONVERTED_FORMATS } from "../../core/formats.js";
import type { BuiltinFormat, Controllers, FormatPlugin, Session, Status } from "../../core/types.js";
import { createViewer } from "../../core/viewer.js";
import { ifc } from "../../ifc/index.js";
import { image } from "../../image/index.js";
import { audio, video } from "../../media/index.js";
import { gltf, obj, ply, stl } from "../../model/index.js";
import {
  coreldraw,
  csv,
  doc,
  docx,
  freehand,
  keynote,
  numbers,
  odg,
  odp,
  ods,
  odt,
  pagemaker,
  ppt,
  pptx,
  publisher,
  quarkxpress,
  rtf,
  visio,
  wpg,
  xls,
  xlsx,
  zonerdraw,
} from "../../office/index.js";
import { pdf } from "../../pdf/index.js";
import { text } from "../../text/index.js";
import type { FileSource } from "../../core/types.js";
import { readPolicy } from "../policy.js";
import type { FrameTheme } from "../../core/theme.js";
import { asRasterError, RasterError } from "../../core/pictures.js";
import {
  checkBytes,
  checkCommand,
  checkOpen,
  checkRaster,
  checkReplace,
  checkThemeMessage,
  checkUnraster,
  checkWatch,
  CONTROLLER_KEYS,
  HELLO,
  NAV_KEYS,
  PROTOCOL,
  refusedRasterId,
  WATCHED_KEYS,
  type ArchiveSnapshot,
  type CommandMessage,
  type ControllerKey,
  type WatchedKey,
  type WatchMessage,
  type RasterMessage,
  type RasterResult,
  type ReplaceMessage,
  type ErrorCode,
  type FrameMessage,
  type FrameOptions,
  type NavKey,
  type OpenSource,
  type Snapshots,
  type Statics,
  type StatusSnapshot,
} from "../protocol.js";
import { portRanges, type PortRanges } from "./ranges.js";
import { portTree, type PortTree } from "./tree.js";
import { installWorkers } from "./workers.js";

const base = new URL("./", import.meta.url);
installWorkers(base);

let port: MessagePort | null = null;
const post = (m: FrameMessage) => port?.postMessage(m);

// Engines open links with `window.open`, which the sandbox refuses: the host
// is asked instead, and decides.
window.open = (url?: string | URL) => {
  if (url !== undefined) post({ type: "link", url: String(url) });
  return null;
};

// Engines copy with `navigator.clipboard.writeText`, which Chromium refuses
// under the frame's policy (the spreadsheet's selected cells on Ctrl+C): the
// text goes through the copy the user's key press starts instead, as a
// selection's would.
if (navigator.clipboard) {
  Object.defineProperty(navigator.clipboard, "writeText", {
    value: (text: string) =>
      new Promise<void>((resolve, reject) => {
        const onCopy = (e: ClipboardEvent) => {
          e.clipboardData?.setData("text/plain", text);
          e.preventDefault();
        };
        document.addEventListener("copy", onCopy);
        let copied = false;
        try {
          copied = document.execCommand("copy");
        } finally {
          document.removeEventListener("copy", onCopy);
        }
        if (copied) resolve();
        else reject(new DOMException("the browser refused the copy", "NotAllowedError"));
      }),
  });
}

function plugins(formats: readonly BuiltinFormat[], o: FrameOptions, source: OpenSource): FormatPlugin<any>[] {
  // The Office engines paint in a worker: their inline module workers cannot start here.
  const office = { mode: "worker" as const };
  const make: Record<BuiltinFormat, () => FormatPlugin<any>> = {
    pdf: () => pdf(o.pdf),
    // An image given by URL is shown without CORS: its pixels stay unreadable here.
    image: () => image({ ...o.image, wasmDecoders: true,...(source.kind === "url" && { crossOrigin: null }) }),
    dwg: () => dwg({ ...o.cad, fontsUrl: new URL("./fonts/", base).href }),
    dxf: () => dxf({ ...o.cad, fontsUrl: new URL("./fonts/", base).href }),
    video: () => video(o.media),
    audio: () => audio(o.media),
    ifc: () => ifc(o.ifc),
    stl: () => stl(o.model),
    obj: () => obj(o.model),
    ply: () => ply(o.model),
    gltf: () => gltf(o.model),
    docx: () => docx(office),
    xlsx: () => xlsx(office),
    pptx: () => pptx(office),
    csv: () => csv(office),
    rtf: () => rtf(o.conversion),
    doc: () => doc(o.conversion),
    odt: () => odt(o.conversion),
    ppt: () => ppt(o.conversion),
    odp: () => odp(o.conversion),
    keynote: () => keynote(o.conversion),
    xls: () => xls(o.conversion),
    ods: () => ods(o.conversion),
    numbers: () => numbers(o.conversion),
    odg: () => odg(o.conversion),
    visio: () => visio(o.conversion),
    coreldraw: () => coreldraw(o.conversion),
    publisher: () => publisher(o.conversion),
    pagemaker: () => pagemaker(o.conversion),
    freehand: () => freehand(o.conversion),
    quarkxpress: () => quarkxpress(o.conversion),
    zonerdraw: () => zonerdraw(o.conversion),
    wpg: () => wpg(o.conversion),
    text,
    archive: () => archive(o.archive),
  };
  // A converted file is shown as a PDF or an XLSX: their plugins too.
  const shown: BuiltinFormat[] = formats.some((f) => CONVERTED_FORMATS.includes(f)) ? ["pdf", "xlsx"] : [];
  return [...formats, ...shown.filter((f) => !formats.includes(f))].map((f) => make[f]());
}

function statusOf(s: Status): StatusSnapshot {
  // The frame's plugins are the package's own: their codes are the built-in ones.
  // A plugin's `label` and an error's `message` stay here, as text from the frame is not shown by the host.
  switch (s.phase) {
    case "error":
      return { phase: "error", code: s.error.code as ErrorCode };
    case "loading":
    case "converting":
      return { phase: s.phase, ...(s.progress !== undefined && { progress: s.progress }), ...(s.step !== undefined && { step: s.step }) };
    default:
      return s;
  }
}

// ── Sessions: the file's, and each archive member's ──────────────────────────

interface Relay {
  id: number;
  session: Session;
  stop: () => void;
}

const sessions = new Map<number, Session>();
/** The member each archive session shows, by the archive session's number. */
const members = new Map<number, Relay>();
let nextSession = 1;

/** Stops following a member, and the members it showed in turn. */
function drop(relay: Relay) {
  relay.stop();
  sessions.delete(relay.id);
  const inner = members.get(relay.id);
  members.delete(relay.id);
  if (inner) drop(inner);
}

/** Plain data only: whatever else a store holds stays here. */
function snapshot<K extends ControllerKey>(key: K, value: unknown, from: number): Snapshots[K] {
  if (key !== "archive") return value as Snapshots[K];
  const a = value as ReturnType<NonNullable<Controllers["archive"]>["get"]>;
  let relay = members.get(from);
  if (relay && relay.session !== a.opened?.session) {
    drop(relay);
    relay = undefined;
  }
  let opened: ArchiveSnapshot["opened"] = null;
  if (a.opened) {
    if (!relay) {
      const r: Relay = { id: nextSession++, session: a.opened.session, stop: () => {} };
      members.set(from, r);
      // Once this snapshot is posted: the host learns the number from it.
      queueMicrotask(() => members.get(from) === r && start(r));
      relay = r;
    }
    const m = a.opened.member;
    opened = {
      member: { index: m.index, name: m.name, uncompressedSize: m.uncompressedSize, encrypted: m.encrypted },
      name: a.opened.file.name,
      format: a.opened.session.format,
      session: relay.id,
    };
  }
  const out: ArchiveSnapshot = {
    members: a.members.map((m) => ({ index: m.index, name: m.name, uncompressedSize: m.uncompressedSize, encrypted: m.encrypted })),
    opening: a.opening,
    opened,
    refused: a.refused,
  };
  return out as Snapshots[K];
}

/** Follows or stops following a store the host asked for, by session (`WatchMessage`). */
const watchers = new Map<number, (type: WatchMessage["type"], key: WatchedKey) => void>();

function start(relay: Relay) {
  const { id, session } = relay;
  sessions.set(id, session);
  let stores: (() => void)[] = [];
  let controllers: Controllers = {};
  /** The stores the host watches, with the stop of the subscription to each (null while the session has none). */
  const watched = new Map<WatchedKey, (() => void) | null>();
  const follow = (key: WatchedKey) => {
    const store = controllers[key];
    if (!store) return;
    watched.set(
      key,
      store.subscribe((v) => post({ type: "state", session: id, key, value: snapshot(key, v, id) })),
    );
    // After the subscription, which is what starts the work: this is the value the host reads first.
    post({ type: "state", session: id, key, value: snapshot(key, store.get(), id) });
  };
  const wire = (c: Controllers) => {
    for (const stop of stores) stop();
    stores = [];
    for (const key of watched.keys()) {
      watched.get(key)?.();
      watched.set(key, null);
    }
    controllers = c;
    const values: Partial<Snapshots> = {};
    for (const key of CONTROLLER_KEYS) {
      const store = c[key];
      if (!store) continue;
      // A watched store is not read until the host asks: its value is null until then.
      if ((WATCHED_KEYS as readonly ControllerKey[]).includes(key)) {
        (values as Record<string, unknown>)[key] = null;
        continue;
      }
      (values as Record<string, unknown>)[key] = snapshot(key, store.get(), id);
      stores.push(store.subscribe((v) => post({ type: "state", session: id, key, value: snapshot(key, v, id) })));
    }
    const statics: Statics = {
      ...(c.pages && { pages: { goTo: !!c.pages.goTo, step: !!c.pages.next && !!c.pages.prev } }),
      ...(c.ground && { ground: { ...c.ground.colors } }),
    };
    post({ type: "controllers", session: id, values, statics });
    // The new stores of what the host still watches.
    for (const key of [...watched.keys()]) follow(key);
  };
  watchers.set(id, (type, key) => {
    if (type === "unwatch") {
      watched.get(key)?.();
      watched.delete(key);
    } else if (!watched.has(key)) {
      watched.set(key, null);
      follow(key);
    }
  });
  const stopStatus = session.status.subscribe((s) => post({ type: "status", session: id, status: statusOf(s) }));
  const stopControllers = session.controllers.subscribe(wire);
  post({ type: "status", session: id, status: statusOf(session.status.get()) });
  wire(session.controllers.get());
  relay.stop = () => {
    stopStatus();
    stopControllers();
    for (const stop of stores) stop();
    for (const stop of watched.values()) stop?.();
    watched.clear();
    watchers.delete(id);
  };
}

// ── Commands from the host ───────────────────────────────────────────────────

const isInt = (v: unknown): v is number => Number.isSafeInteger(v);
const isNum = (v: unknown): v is number => typeof v === "number" && Number.isFinite(v);

async function run(m: CommandMessage): Promise<void> {
  const c = sessions.get(m.session)?.controllers.get();
  if (!c) return;
  const [a, b] = m.args;
  switch (`${m.target}.${m.action}`) {
    case "pages.goTo":
      if (isInt(a)) c.pages?.goTo?.(a);
      return;
    case "pages.next":
      return c.pages?.next?.();
    case "pages.prev":
      return c.pages?.prev?.();
    case "zoom.setScale": {
      const anchor = b as { x?: unknown; y?: unknown } | undefined;
      if (!isNum(a) || a <= 0) return;
      if (anchor === undefined) c.zoom?.setScale(a);
      else if (isNum(anchor?.x) && isNum(anchor?.y)) c.zoom?.setScale(a, { x: anchor.x, y: anchor.y });
      return;
    }
    case "zoom.fit":
      return c.zoom?.fit();
    case "drag.choose":
      if (a === "pan" || a === "select") c.drag?.choose(a);
      return;
    case "outline.goTo": {
      const entry = isInt(a) ? c.outline?.get()[a] : undefined;
      if (entry) c.outline?.goTo(entry);
      return;
    }
    case "layers.setVisible":
      if (typeof a === "string" && typeof b === "boolean") c.layers?.setVisible(a, b);
      return;
    case "layers.setAll":
      if (typeof a === "boolean") c.layers?.setAll(a);
      return;
    case "storeys.setVisible":
      if (typeof a === "string" && typeof b === "boolean") c.storeys?.setVisible(a, b);
      return;
    case "storeys.setAll":
      if (typeof a === "boolean") c.storeys?.setAll(a);
      return;
    case "layouts.select":
      if (typeof a === "string") await c.layouts?.select(a);
      return;
    case "ground.set":
      if (a === "light" || a === "dark") c.ground?.set(a);
      return;
    case "archive.open":
      if (isInt(a)) await c.archive?.open(a);
      return;
    case "archive.back":
      return c.archive?.back();
    case "media.play":
      return c.media?.play();
    case "media.pause":
      return c.media?.pause();
    case "media.seek":
      if (isNum(a)) c.media?.seek(a);
      return;
    case "media.setVolume":
      if (isNum(a)) c.media?.setVolume(a);
      return;
    case "media.setMuted":
      if (typeof a === "boolean") c.media?.setMuted(a);
      return;
    case "media.setRate":
      if (isNum(a)) c.media?.setRate(a);
      return;
    case "sheets.select":
      if (isInt(a)) await c.sheets?.select(a);
      return;
  }
}

/** The pictures being drawn, by the host's number for each: a request to stop aborts its signal. */
const rasters = new Map<number, AbortController>();

/** A page drawn as a picture, sent to the host, or why not. */
async function raster(m: RasterMessage) {
  const abort = new AbortController();
  rasters.set(m.id, abort);
  const pictures = sessions.get(m.session)?.controllers.get().pictures;
  let result: RasterResult;
  try {
    if (!pictures) throw new RasterError("unsupported", "nothing here is drawn as a picture");
    const r = await pictures.raster(m.page, { ...m.options, signal: abort.signal });
    const { bitmap, ...rest } = r;
    result = { ok: true, bitmap, ...rest };
  } catch (error) {
    const e = asRasterError(error, abort.signal);
    if (e.code === "failed") console.warn("frame: a picture failed", error);
    result = { ok: false, code: e.code };
  }
  rasters.delete(m.id);
  const bitmap = result.ok ? result.bitmap : null;
  if (bitmap && !port) bitmap.close();
  else port?.postMessage({ type: "rastered", id: m.id, result } satisfies FrameMessage, bitmap ? [bitmap] : []);
}

// ── The next document ────────────────────────────────────────────────────────

/** The file's session: the one `replace` acts on. */
let root: Session | null = null;

async function replace(m: ReplaceMessage): Promise<boolean> {
  const live = root;
  if (!live) return false;
  const s = m.source;
  let source: FileSource;
  let fresh: PortRanges | null = null;
  if (s.kind === "ranges") {
    fresh = portRanges(post, s.size, new Uint8Array(s.head), m.generation);
    ranges.add(fresh);
    source = { ranges: fresh };
  } else source = s.kind === "url" ? { url: s.url } : { blob: s.blob };
  const { name, type, path, format } = m.file;
  let ok = false;
  try {
    ok = await live.replace({ id: "file", name, type, path, ...(format && { format }), source, ...(around && { tree: around.tree }) });
  } catch (error) {
    console.warn("frame: a replacement failed", error);
  }
  // The reads of the document that is gone were cancelled with it; the host forgets its bytes on this answer.
  if (ok) {
    ranges.clear();
    if (fresh) ranges.add(fresh);
  } else if (fresh) ranges.delete(fresh);
  return ok;
}

// ── Theme ────────────────────────────────────────────────────────────────────

let themed: readonly string[] = [];

/** The host's values in place of the stylesheet's defaults, on the element they are declared on. */
function applyTheme(theme: FrameTheme) {
  const root = document.getElementById("root")!;
  for (const name of themed) root.style.removeProperty(name);
  themed = Object.keys(theme.tokens);
  for (const [name, value] of Object.entries(theme.tokens)) root.style.setProperty(name, value);
  // As the host's: browsers paint a frame whose scheme differs from its element's on an opaque ground.
  document.documentElement.style.colorScheme = theme.scheme ?? "";
}

// ── Keys the document does not use, handed to the host ───────────────────────

const VERTICAL: Partial<Record<NavKey, -1 | 1>> = { ArrowUp: -1, PageUp: -1, Home: -1, ArrowDown: 1, PageDown: 1, End: 1 };
const HORIZONTAL: Partial<Record<NavKey, -1 | 1>> = { ArrowLeft: -1, ArrowRight: 1 };

/** Where the user last pressed: the browser scrolls what is under it when nothing has the focus. */
let lastPressed: Element | null = null;
addEventListener("pointerdown", (e) => (lastPressed = e.target instanceof Element ? e.target : null), true);

/** Whether `key` would scroll something from `start` up: then the document uses it. */
function scrolls(start: Element | null, key: NavKey): boolean {
  const v = VERTICAL[key];
  const h = HORIZONTAL[key];
  for (let el = start; el; el = el.parentElement) {
    const style = getComputedStyle(el);
    if (v && /(auto|scroll)/.test(style.overflowY) && (v < 0 ? el.scrollTop > 0 : el.scrollTop + el.clientHeight < el.scrollHeight - 1)) return true;
    if (h && /(auto|scroll)/.test(style.overflowX) && (h < 0 ? el.scrollLeft > 0 : el.scrollLeft + el.clientWidth < el.scrollWidth - 1)) return true;
  }
  return false;
}

addEventListener("keydown", (e) => {
  if (e.defaultPrevented || e.ctrlKey || e.altKey || e.metaKey || !(NAV_KEYS as readonly string[]).includes(e.key)) return;
  const key = e.key as NavKey;
  const target = e.target instanceof Element && e.target !== document.body ? e.target : lastPressed;
  if (key !== "Escape") {
    // A player's own controls take the arrows.
    if (target instanceof HTMLMediaElement || target?.closest("input, textarea, select, [contenteditable]")) return;
    if (scrolls(target, key)) return;
  }
  post({ type: "key", key, shift: e.shiftKey, repeat: e.repeat });
});

// ── The host ─────────────────────────────────────────────────────────────────

let opened = false;
/** The files read by ranges that are alive: the document shown, and one replacing it. */
const ranges = new Set<PortRanges>();
/** The files around the one shown, when the host listed them. */
let around: PortTree | null = null;

function receive(data: unknown) {
  if (!opened) {
    const open = checkOpen(data, BUILTIN_ORDER);
    if (!open) return;
    opened = true;
    applyTheme(open.theme);
    const viewer = createViewer({ plugins: plugins(open.formats, open.options, open.source), assetBase: new URL("./exav-viewer/", base).href });
    const host = document.getElementById("root")!;
    const { name, type, path, format } = open.file;
    const s = open.source;
    let source: FileSource;
    if (s.kind === "ranges") {
      const first = portRanges(post, s.size, new Uint8Array(s.head));
      ranges.add(first);
      source = { ranges: first };
    } else source = s.kind === "url" ? { url: s.url } : { blob: s.blob };
    if (open.tree) around = portTree(post, open.tree);
    const session = viewer.mount(host, { id: "file", name, type, path, ...(format && { format }), source, ...(around && { tree: around.tree }) });
    root = session;
    start({ id: 0, session, stop: () => {} });
    addEventListener("resize", () => session.resize());
    return;
  }
  const bytes = checkBytes(data);
  // Each file ignores the ids it did not ask for.
  if (bytes) {
    for (const r of ranges) r.receive(bytes);
    around?.receive(bytes);
    return;
  }
  const theme = checkThemeMessage(data);
  if (theme) return applyTheme(theme.theme);
  const drawing = checkRaster(data);
  if (drawing) return void raster(drawing);
  // A request that is none is still answered: the host waits for it.
  const refused = refusedRasterId(data);
  if (refused !== null) return post({ type: "rastered", id: refused, result: { ok: false, code: "invalid" } });
  const undrawing = checkUnraster(data);
  if (undrawing) return void rasters.get(undrawing.id)?.abort();
  const watching = checkWatch(data);
  if (watching) return watchers.get(watching.session)?.(watching.type, watching.key);
  const replacing = checkReplace(data, BUILTIN_ORDER);
  if (replacing) {
    void replace(replacing).then((ok) => post({ type: "replaced", call: replacing.call, ok }));
    return;
  }
  const command = checkCommand(data);
  if (!command) return;
  void run(command)
    .then(
      () => true,
      (error) => (console.warn("frame: a command failed", error), false),
    )
    .then((ok) => post({ type: "done", call: command.call, ok }));
}

// The port arrives once, from the page that embeds this frame. Any later
// window message is ignored.
addEventListener("message", function hello(e: MessageEvent) {
  const p = e.ports[0];
  if (e.source !== parent || parent === window || (e.data as { type?: unknown } | null)?.type !== HELLO || !p) return;
  removeEventListener("message", hello);
  port = p;
  port.onmessage = (m) => receive(m.data);
  // The policy in this page, for the host to check against its own origins.
  // One served as a header alone is not readable here.
  const csp = document.querySelector('meta[http-equiv="Content-Security-Policy" i]')?.getAttribute("content");
  post({ type: "ready", protocol: PROTOCOL, policy: csp ? readPolicy(csp) : null });
});
