/**
 * `@exav/viewer/frame`: the viewer in a sandboxed frame. Each file opens in
 * an `<iframe sandbox="allow-scripts">` of its own, served from the frame
 * app this package ships (`dist/frame/app/`), so the parsers run in an opaque
 * origin: no cookies, no storage, no access to this page, and nothing
 * fetched from anywhere else than the origins its Content-Security-Policy
 * names (none but its own, unless deployed with some: see `delivery.ts`).
 *
 * `createSandboxedViewer` returns a `Viewer` like `createViewer`'s, whose
 * sessions follow the frame: the default React UI and any headless one work
 * unchanged. Every message from the frame is checked before it reaches a
 * store, since the frame runs the code a hostile file would attack.
 */
import { createDetector } from "../core/detect.js";
import { BUILTIN_ORDER, CONVERTED_FORMATS, MATCHERS, WASM_IMAGES } from "../core/formats.js";
import { asRasterError, isPage, MAX_PICTURE_EDGE, MAX_PICTURE_PIXELS, RasterError } from "../core/pictures.js";
import { picturesOver } from "../core/raster.js";
import { createSourceReader } from "../core/source.js";
import { derived, writable, type Store, type WritableStore } from "../core/store.js";
import { checkTheme, themeOf, type FrameTheme } from "../core/theme.js";
import type {
  ArchiveController,
  ArchiveMember,
  BuiltinFormat,
  Controllers,
  FormatId,
  FormatMatcher,
  OutlineEntry,
  Raster,
  RasterOptions,
  Session,
  Status,
  Viewer,
  ViewerError,
  ViewerFile,
} from "../core/types.js";
import { errorCode } from "../core/viewer.js";
import { checkDelivery, prepare, readRefusal, type Delivery, type Prepared } from "./delivery.js";
import { policyMismatch, type FrameOrigins } from "./policy.js";
import {
  checkFrameMessage,
  HELLO,
  linkTarget,
  MAX_DRAWS,
  NAV_KEYS,
  PROTOCOL,
  READS,
  TREE,
  type ArchiveSnapshot,
  type BytesMessage,
  type CommandMessage,
  type CommandTarget,
  type ControllerKey,
  type FrameMessage,
  type FrameOptions,
  type NavKey,
  type OpenMessage,
  type OpenSource,
  type RasterMessage,
  type RasterResult,
  type ReplaceMessage,
  type Snapshots,
  type Statics,
  type StatusSnapshot,
  type ThemeMessage,
  type UnrasterMessage,
  type WatchedKey,
  type WatchMessage,
} from "./protocol.js";

export type { FrameOptions, NavKey } from "./protocol.js";
export { NAV_KEYS } from "./protocol.js";
export type { FrameTheme } from "../core/theme.js";
export type { Delivery } from "./delivery.js";
export { FRAME_CSP, FRAME_PERMISSIONS, frameCsp, frameHeaders, type FrameOrigins } from "./policy.js";

export interface SandboxConfig {
  /**
   * The frame app's page: where the host serves `dist/frame/app/` (its
   * `index.html`), with the headers the documentation lists. Best on a
   * registrable domain of its own that sets no cookies.
   */
  url: string;
  /**
   * The formats the frame opens, in detection order. Default: every built-in
   * one but `CONVERTED_FORMATS`, which are named to be opened (and which
   * need the frame built with an external converter for what the package's
   * own converters do not read, `externalConverter`): `BUILTIN_ORDER` names
   * them all.
   */
  formats?: readonly BuiltinFormat[];
  /** Plugin options, as plain data. */
  options?: FrameOptions;
  /**
   * Asked before a link the user followed in a document is opened in a new
   * tab (`noopener,noreferrer`). Only absolute http(s) links get here.
   * Default: the browser's `confirm`.
   */
  confirmLink?: (url: string, file: ViewerFile) => boolean | Promise<boolean>;
  /** How long the frame may take to start. Default 20_000 ms. */
  startTimeoutMs?: number;
  /**
   * How each kind of file reaches the frame (see the Security page for
   * what each lets the frame do). Defaults: PDF and archives "ranges";
   * video, audio and images "url" when the file's URL is on an
   * `origins.media` origin, else "blob". Every other format: "blob".
   */
  delivery?: Delivery;
  /**
   * The origins the frame's policy names besides its own, as it was
   * deployed with them (`--media-origin`, `--connect-origin`). The frame
   * reports its policy when it starts: one that differs is refused.
   */
  origins?: FrameOrigins;
  /**
   * The keys handed back from the frame when the document does not use them
   * (`NAV_KEYS`, by default all of them), dispatched as a `keydown` on the
   * `<iframe>` that bubbles to this page's listeners. `false`: none. They
   * come from the frame: at most `KEY_RATE` a second, never a key with a
   * modifier but Shift, and `isTrusted` false.
   */
  keys?: readonly NavKey[] | false;
  /**
   * The frame's colours and sizes (`TOKENS`): "inherit" (default) reads the
   * values in force where each file is mounted, so the page's own CSS
   * custom properties reach the frame; a theme sets them; null leaves the
   * frame's defaults. Read again on `restyle()`, and when the device's
   * colour scheme changes.
   */
  theme?: "inherit" | FrameTheme | null;
}

/** A `Viewer` whose files run in sandboxed frames. */
export interface SandboxedViewer extends Viewer {
  /** Sends the theme again to every frame shown: after the page's theme changed. */
  restyle(): void;
}

/** Keys taken from a frame in one second, at most. */
export const KEY_RATE = 30;

const ALL: readonly BuiltinFormat[] = BUILTIN_ORDER;
/** The converted formats only when named: they need the converter. */
const DEFAULT: readonly BuiltinFormat[] = ALL.filter((f) => !CONVERTED_FORMATS.includes(f));

function matcher(id: BuiltinFormat): FormatMatcher {
  if (id !== "image") return MATCHERS[id];
  // The frame decodes what browsers do not draw.
  const all = [MATCHERS.image, WASM_IMAGES];
  return {
    types: all.flatMap((m) => m.types ?? []),
    extensions: all.flatMap((m) => m.extensions ?? []),
    extensionOverrides: all.flatMap((m) => m.extensionOverrides ?? []),
  };
}

function toStatus(s: StatusSnapshot): Status {
  return s.phase === "error" ? { phase: "error", error: { code: s.code } } : s;
}

const defaultConfirm = (url: string) => window.confirm(`Open this link in a new tab?\n\n${url}`);

/**
 * Why a picture from the frame is not the one asked for, or null. The size
 * it was asked at is a promise the frame must keep: the host does not take
 * a bitmap of another size for it.
 */
export function rasterMismatch(asked: Omit<RasterOptions, "signal">, got: Extract<RasterResult, { ok: true }>, space: string): string | null {
  if (got.space !== space) return `a picture in the space ${got.space}, not ${space}`;
  if (got.width > MAX_PICTURE_EDGE || got.height > MAX_PICTURE_EDGE || got.width * got.height > MAX_PICTURE_PIXELS) return "a picture past the limits";
  const whole = (n: number) => Math.max(1, Math.round(n));
  if (asked.width !== undefined && got.width !== whole(asked.width)) return `a picture ${got.width} px wide, not ${whole(asked.width)}`;
  if (asked.height !== undefined && got.height !== whole(asked.height)) return `a picture ${got.height} px high, not ${whole(asked.height)}`;
  if (asked.longEdge !== undefined && Math.max(got.width, got.height) > whole(asked.longEdge)) return `a picture longer than the ${whole(asked.longEdge)} px asked`;
  return null;
}

/** The viewer's `plugins` are empty: they live in the frame. */
export function createSandboxedViewer(config: SandboxConfig): SandboxedViewer {
  checkDelivery(config.delivery, config.origins);
  const formats = (config.formats ?? DEFAULT).filter((f) => ALL.includes(f));
  const detector = createDetector(formats.map((id) => ({ id, match: matcher(id) })));
  /** Each frame shown, by what sends it its theme again. */
  const shown = new Set<() => void>();
  const mount = (host: HTMLElement, file: ViewerFile): Session => mountFrame(config, formats, detector.detect, host, file, shown);
  return {
    ...detector,
    plugins: [],
    assetBase: "",
    mount,
    // The frame fetches its engines itself, from its own origin.
    prefetch: async () => {},
    restyle: () => {
      for (const restyle of shown) restyle();
    },
  };
}

/** The theme for a frame in `host`, as `config.theme` says. */
function themeFor(config: SandboxConfig, host: HTMLElement): FrameTheme {
  const theme = config.theme === undefined ? "inherit" : config.theme;
  if (theme === null) return { tokens: {}, scheme: null };
  return theme === "inherit" ? themeOf(host) : checkTheme(theme);
}

interface Proxy {
  session: Session;
  status: WritableStore<Status>;
  controllers: WritableStore<Controllers>;
  stores: Partial<{ [K in ControllerKey]: WritableStore<Snapshots[K]> }>;
  /** Listeners on the stores the frame follows only on request, over all the controllers the session has had. */
  watchers: Record<WatchedKey, number>;
}

function mountFrame(
  config: SandboxConfig,
  formats: readonly BuiltinFormat[],
  detect: (file: ViewerFile) => FormatId | null,
  host: HTMLElement,
  file: ViewerFile,
  shown: Set<() => void>,
): Session {
  const format = file.format ?? detect(file);
  const known = formats.find((f) => f === format) ?? null;
  const abort = new AbortController();
  let ended = false;
  /** The file as the frame will get it, read from the start. */
  let prepared: Promise<Prepared> | null = null;
  /** The file on screen: the one `replace` last took. */
  let current = file;
  /** The bytes of each file read by ranges that is alive, by the number the frame names it with (0 is the first). */
  const documents = new Map<number, Extract<Prepared, { kind: "ranges" }>["ranges"]>();
  /** How the first file was delivered: what the frame's engines were made for. */
  let firstKind: Prepared["kind"] | null = null;
  /** The frame's reads not answered yet. */
  const reads = new Map<number, { length: number; abort: AbortController }>();
  let outstanding = 0;
  let refusedOnce = false;
  let port: MessagePort | null = null;
  let iframe: HTMLIFrameElement | null = null;
  let timer: ReturnType<typeof setTimeout> | undefined;
  let confirming = false;
  let nextCall = 1;
  const pending = new Map<number, () => void>();
  const sessions = new Map<number, Proxy>();
  /** Pictures asked of the frame, not drawn yet, with what each was asked for. */
  const draws = new Map<number, { options: RasterOptions; space: string | null; done: (result: RasterResult) => void }>();
  let nextDraw = 1;
  /** Documents sent to replace the one shown, not answered yet (`replace`). */
  const replacements = new Map<number, (ok: boolean) => void>();
  /** Whether the frame has been given the file: only then can it take another. */
  let started = false;
  /** The newest `replace` call, and the one before it still to be answered. */
  let latest = 0;
  let superseding: AbortController | null = null;
  let answered: Promise<unknown> = Promise.resolve();
  let lastDocument = 0;
  const keys = new Set<string>(config.keys === false ? [] : (config.keys ?? NAV_KEYS));
  /** When the keys of the last second came. */
  let keyTimes: number[] = [];
  const restyle = () => port?.postMessage({ type: "theme", theme: themeFor(config, host) } satisfies ThemeMessage);
  const scheme = typeof matchMedia === "function" ? matchMedia("(prefers-color-scheme: dark)") : null;

  const proxy = (id: number, info: { file: ViewerFile; format: FormatId | null }): Proxy => {
    const status = writable<Status>({ phase: "loading" });
    const controllers = writable<Controllers>({});
    const p: Proxy = {
      status,
      controllers,
      stores: {},
      watchers: { viewport: 0 },
      session: {
        get file() {
          return id === 0 ? current : info.file;
        },
        format: info.format,
        status,
        controllers,
        // A member shown by an archive is replaced by opening another.
        replace: id === 0 ? (next) => replace(next) : async () => false,
        resize: () => {},
        // A member is closed through its archive's `back`.
        destroy: id === 0 ? () => end() : () => {},
      },
    };
    sessions.set(id, p);
    return p;
  };
  const root = proxy(0, { file, format });

  const fail = (code: ViewerError["code"], cause: unknown) => {
    if (ended) return;
    console.warn(`${format ?? "viewer"}: the sandboxed frame failed`, cause);
    root.status.set({ phase: "error", error: { code, cause } });
    teardown();
    // Whatever it shows now is not the file's.
    iframe?.remove();
    iframe = null;
  };

  const teardown = () => {
    clearTimeout(timer);
    // Stops the download, and every read the frame asked for.
    abort.abort();
    reads.clear();
    outstanding = 0;
    port?.close();
    port = null;
    for (const resolve of pending.values()) resolve();
    pending.clear();
    for (const { done } of draws.values()) done({ ok: false, code: "aborted" });
    draws.clear();
    for (const resolve of replacements.values()) resolve(false);
    replacements.clear();
    superseding?.abort();
    documents.clear();
    shown.delete(restyle);
    scheme?.removeEventListener("change", restyle);
  };

  const end = () => {
    if (ended) return;
    teardown();
    ended = true;
    iframe?.remove();
    iframe = null;
  };

  const reply = (m: BytesMessage) => port?.postMessage(m, "data" in m ? [m.data] : []);

  /** A read the frame asked for: checked, then answered with the bytes or a refusal. */
  const read = (id: number, generation: number, offset: number, length: number) => {
    // An id already in use is the frame's confusion: its first read stands.
    if (reads.has(id)) return;
    const ranges = documents.get(generation);
    const why = ranges ? readRefusal({ offset, length }, ranges.size, { count: reads.size, bytes: outstanding }) : "the file is not read by ranges";
    if (why) {
      // Said once: a frame could ask a thousand times.
      if (!refusedOnce) console.warn(`${format ?? "viewer"}: a read from the sandboxed frame refused: ${why}`);
      refusedOnce = true;
      return reply({ type: "bytes", id, error: "refused" });
    }
    const own = new AbortController();
    reads.set(id, { length, abort: own });
    outstanding += length;
    ranges!
      .read(offset, length, AbortSignal.any([abort.signal, own.signal]))
      .then(
        (bytes): BytesMessage => {
          // Its own buffer, exactly the bytes, to transfer.
          const data = bytes.byteOffset === 0 && bytes.byteLength === bytes.buffer.byteLength ? bytes : bytes.slice();
          return { type: "bytes", id, data: data.buffer as ArrayBuffer };
        },
        (error): BytesMessage => {
          if (!abort.signal.aborted && !own.signal.aborted) console.warn(`${format ?? "viewer"}: a read for the sandboxed frame failed`, error);
          return { type: "bytes", id, error: "failed" };
        },
      )
      .then((m) => {
        if (reads.get(id)?.abort !== own) return;
        reads.delete(id);
        outstanding -= length;
        reply(m);
      });
  };

  /**
   * A whole file of the tree the frame was told of, answered with its bytes.
   * Only a path the host listed is read: the frame names no other file.
   */
  const fetchFile = (id: number, path: string) => {
    if (reads.has(id)) return;
    const tree = current.tree;
    const refuse = (why: string) => {
      if (!refusedOnce) console.warn(`${format ?? "viewer"}: a file asked for by the sandboxed frame refused: ${why}`);
      refusedOnce = true;
      reply({ type: "bytes", id, error: "refused" });
    };
    if (!tree || !tree.paths.slice(0, TREE.maxPaths).includes(path)) return refuse("it is not in the tree");
    if (reads.size >= READS.maxReads) return refuse("too many reads at once");
    const own = new AbortController();
    reads.set(id, { length: 0, abort: own });
    const signal = AbortSignal.any([abort.signal, own.signal]);
    let opened: ReturnType<typeof createSourceReader> | undefined;
    void (async (): Promise<BytesMessage> => {
      opened = createSourceReader(await tree.open(path, signal), signal);
      const bytes = await opened.bytes();
      if (bytes.byteLength > TREE.maxFileBytes) return { type: "bytes", id, error: "refused" };
      // Its own buffer, to transfer: the source may keep the one it read.
      return { type: "bytes", id, data: bytes.slice().buffer as ArrayBuffer };
    })()
      .catch((error): BytesMessage => {
        if (!abort.signal.aborted && !own.signal.aborted) console.warn(`${format ?? "viewer"}: a file for the sandboxed frame could not be read`, error);
        return { type: "bytes", id, error: "failed" };
      })
      .then((m) => {
        opened?.dispose();
        if (reads.get(id)?.abort !== own) return;
        reads.delete(id);
        reply(m);
      });
  };

  const command = (session: number, target: CommandTarget, action: string, args: unknown[] = []) =>
    new Promise<void>((resolve) => {
      if (!port) return resolve();
      const call = nextCall++;
      pending.set(call, resolve);
      const message: CommandMessage = { type: "command", call, session, target, action, args };
      port.postMessage(message);
    });

  /**
   * A picture of a page, from the frame. Rejects with a `RasterError`: the
   * frame's own, or "failed" when too many are being drawn, the frame ends
   * first, or what it sent is not what was asked for.
   */
  const draw = (session: number, page: number, options: RasterOptions, space: string): Promise<Raster> =>
    new Promise<Raster>((resolve, reject) => {
      const { signal, ...plain } = options;
      if (!port || signal?.aborted) return reject(new RasterError("aborted", "aborted"));
      if (draws.size >= MAX_DRAWS) return reject(new RasterError("failed", `more than ${MAX_DRAWS} pictures at once`));
      const id = nextDraw++;
      let settled = false;
      const onAbort = () => {
        if (settled) return;
        settled = true;
        reject(new RasterError("aborted", "aborted"));
        // The slot stays taken until the frame answers: a frame that never does cannot be asked for more.
        port?.postMessage({ type: "unraster", id } satisfies UnrasterMessage);
      };
      const done = (result: RasterResult) => {
        signal?.removeEventListener("abort", onAbort);
        const bitmap = result.ok ? result.bitmap : null;
        if (settled) return bitmap?.close();
        settled = true;
        if (!result.ok) return reject(new RasterError(result.code));
        const wrong = rasterMismatch(plain, result, space);
        if (wrong) {
          result.bitmap.close();
          return reject(new RasterError("failed", wrong));
        }
        const { ok: _ok, ...raster } = result;
        resolve(raster);
      };
      signal?.addEventListener("abort", onAbort, { once: true });
      draws.set(id, { options: plain, space, done });
      port.postMessage({ type: "raster", id, session, page, options: plain } satisfies RasterMessage);
    });

  /** The member session each archive session shows. */
  const children = new Map<number, number>();
  const forget = (id: number) => {
    sessions.delete(id);
    const child = children.get(id);
    children.delete(id);
    if (child !== undefined) forget(child);
  };

  /** The archive store the UI reads: members as sent, the open member as a session proxy. */
  const archiveState = (id: number, s: ArchiveSnapshot) => {
    let opened: ReturnType<ArchiveController["get"]>["opened"] = null;
    const previous = children.get(id);
    if (previous !== undefined && previous !== s.opened?.session) forget(previous);
    if (s.opened) {
      const { member, name, format: f, session } = s.opened;
      // A session number is the frame's to give, once: one already in use elsewhere is refused.
      const nested =
        children.get(id) === session
          ? sessions.get(session)
          : sessions.has(session)
            ? undefined
            : proxy(session, { file: { id: `${file.id}:${member.index}`, name, path: name, format: f ?? undefined, source: null }, format: f });
      if (nested) {
        children.set(id, session);
        opened = { member: member as ArchiveMember, file: nested.session.file, session: nested.session };
      }
    }
    return { members: s.members, opening: s.opening, opened, refused: s.refused };
  };

  /** What the host itself has to say about the file, after the frame's warnings. */
  let hostWarnings: Snapshots["warnings"] = [];
  /** The frame's own warnings for the file shown, as the frame sent them. */
  let frameWarnings: Store<Snapshots["warnings"]> | null = null;
  const withHostWarnings = (id: number, frame: Store<Snapshots["warnings"]> | null): Store<Snapshots["warnings"]> | null => {
    if (id === 0) frameWarnings = frame;
    if (id !== 0 || hostWarnings.length === 0) return frame;
    const own = hostWarnings;
    return frame ? derived(frame, (w) => [...w, ...own]) : writable(own);
  };
  const setHostWarnings = (next: Snapshots["warnings"]) => {
    hostWarnings = next;
    root.controllers.update(({ warnings: _, ...rest }) => {
      const w = withHostWarnings(0, frameWarnings);
      return w ? { ...rest, warnings: w } : rest;
    });
  };

  const watch = (session: number, type: WatchMessage["type"], key: WatchedKey) => port?.postMessage({ type, session, key } satisfies WatchMessage);

  /**
   * A store the frame follows only while someone listens (`WatchMessage`): it
   * is watched from the first listener to the last, over all the controllers
   * the session has. A read with no listener asks the frame to report it once
   * and returns the last value it reported: the answer is for the next read.
   */
  const watchedStore = <K extends WatchedKey>(id: number, key: K, store: WritableStore<Snapshots[K]>): Store<Snapshots[K]> => ({
    get() {
      const p = sessions.get(id);
      if (p && p.watchers[key] === 0) {
        watch(id, "watch", key);
        watch(id, "unwatch", key);
      }
      return store.get();
    },
    subscribe(listener) {
      const p = sessions.get(id);
      if (p && p.watchers[key]++ === 0) watch(id, "watch", key);
      const unsubscribe = store.subscribe(listener);
      let left = false;
      return () => {
        if (left) return;
        left = true;
        unsubscribe();
        if (p && --p.watchers[key] === 0) watch(id, "unwatch", key);
      };
    },
  });

  const buildControllers = (id: number, values: Partial<Snapshots>, statics: Statics): Controllers => {
    const p = sessions.get(id)!;
    p.stores = {};
    const c: Controllers = {};
    const store = <K extends ControllerKey>(key: K): WritableStore<Snapshots[K]> | null => {
      if (!(key in values)) return null;
      const s = writable(values[key] as Snapshots[K]);
      (p.stores as Record<string, unknown>)[key] = s;
      return s;
    };
    const pages = store("pages");
    if (pages)
      c.pages = {
        ...pages,
        ...(statics.pages?.goTo && { goTo: (page: number) => void command(id, "pages", "goTo", [page]) }),
        ...(statics.pages?.step && { next: () => command(id, "pages", "next"), prev: () => command(id, "pages", "prev") }),
      };
    const zoom = store("zoom");
    if (zoom)
      c.zoom = {
        ...zoom,
        setScale: (scale, anchor) => void command(id, "zoom", "setScale", anchor ? [scale, { x: anchor.x, y: anchor.y }] : [scale]),
        fit: () => void command(id, "zoom", "fit"),
      };
    const drag = store("drag");
    if (drag)
      c.drag = {
        ...drag,
        choose: (mode) => {
          // Shown at once, as the other toggles; the frame's own state follows and wins.
          drag.update((s) => ({ ...s, mode: s.available ? mode : s.mode }));
          void command(id, "drag", "choose", [mode]);
        },
      };
    const outline = store("outline");
    if (outline)
      c.outline = {
        ...outline,
        goTo: (entry: OutlineEntry) => {
          const index = outline.get().indexOf(entry);
          if (index >= 0) void command(id, "outline", "goTo", [index]);
        },
      };
    // Toggles show at once, as in the page; the frame's own state follows and wins.
    const layers = store("layers");
    if (layers)
      c.layers = {
        ...layers,
        setVisible: (layer, visible) => {
          layers.update((s) => ({ ...s, items: s.items.map((i) => (i.id === layer ? { ...i, visible } : i)) }));
          void command(id, "layers", "setVisible", [layer, visible]);
        },
        setAll: (visible) => {
          layers.update((s) => ({ ...s, items: s.items.map((i) => ({ ...i, visible })) }));
          void command(id, "layers", "setAll", [visible]);
        },
      };
    const storeys = store("storeys");
    if (storeys)
      c.storeys = {
        ...storeys,
        setVisible: (storey, visible) => {
          storeys.update((s) => ({ ...s, items: s.items.map((i) => (i.id === storey ? { ...i, visible } : i)) }));
          void command(id, "storeys", "setVisible", [storey, visible]);
        },
        setAll: (visible) => {
          storeys.update((s) => ({ ...s, items: s.items.map((i) => ({ ...i, visible })) }));
          void command(id, "storeys", "setAll", [visible]);
        },
      };
    const layouts = store("layouts");
    if (layouts) c.layouts = { ...layouts, select: (layout) => command(id, "layouts", "select", [layout]) };
    const ground = store("ground");
    if (ground)
      c.ground = {
        ...ground,
        colors: statics.ground ?? { light: "#ffffff", dark: "#212830" },
        set: (g) => {
          ground.set(g);
          void command(id, "ground", "set", [g]);
        },
      };
    const selection = store("selection");
    if (selection) c.selection = selection;
    const info = store("info");
    if (info) c.info = info;
    const warnings = withHostWarnings(id, store("warnings"));
    if (warnings) c.warnings = warnings;
    const media = store("media");
    if (media)
      c.media = {
        ...media,
        play: () => command(id, "media", "play"),
        pause: () => void command(id, "media", "pause"),
        seek: (seconds) => void command(id, "media", "seek", [seconds]),
        setVolume: (volume) => void command(id, "media", "setVolume", [volume]),
        setMuted: (muted) => void command(id, "media", "setMuted", [muted]),
        setRate: (rate) => void command(id, "media", "setRate", [rate]),
      };
    const sheets = store("sheets");
    if (sheets) c.sheets = { ...sheets, select: (index) => command(id, "sheets", "select", [index]) };
    const pictures = store("pictures");
    if (pictures) c.pictures = picturesOver(pictures, (page, options) => draw(id, page, options, pictures.get().space));
    const viewport = store("viewport");
    if (viewport) c.viewport = watchedStore(id, "viewport", viewport);
    const archive = store("archive");
    if (archive) {
      const state = writable(archiveState(id, archive.get()));
      archive.subscribe((s) => state.set(archiveState(id, s)));
      c.archive = {
        ...(state as Store<ReturnType<ArchiveController["get"]>>),
        open: (index) => command(id, "archive", "open", [index]),
        back: () => void command(id, "archive", "back"),
      };
    }
    return c;
  };

  const receive = (message: FrameMessage) => {
    switch (message.type) {
      case "ready": {
        clearTimeout(timer);
        if (message.protocol !== PROTOCOL) return fail(errorCode(format), new Error(`the frame speaks protocol ${message.protocol}, not ${PROTOCOL}`));
        // Its policy is fixed where it is deployed: one that does not allow
        // what this viewer will give it, or allows more, is a deployment
        // error, said here rather than left to the policy to block.
        const mismatch = policyMismatch(message.policy, config.origins ?? {});
        if (mismatch) return fail(errorCode(format), new Error(mismatch));
        void send();
        return;
      }
      case "read":
        return read(message.id, message.generation, message.offset, message.length);
      case "fetch":
        return fetchFile(message.id, message.path);
      case "cancel":
        reads.get(message.id)?.abort.abort();
        return;
      case "status": {
        const p = sessions.get(message.session);
        p?.status.set(toStatus(message.status));
        return;
      }
      case "controllers": {
        const p = sessions.get(message.session);
        p?.controllers.set(buildControllers(message.session, message.values, message.statics));
        return;
      }
      case "state": {
        const s = sessions.get(message.session)?.stores[message.key] as WritableStore<unknown> | undefined;
        s?.set(message.value);
        return;
      }
      case "done": {
        const resolve = pending.get(message.call);
        pending.delete(message.call);
        resolve?.();
        return;
      }
      case "rastered": {
        const asked = draws.get(message.id);
        draws.delete(message.id);
        // A picture not asked for is not kept.
        if (asked) asked.done(message.result);
        else if (message.result.ok) message.result.bitmap.close();
        return;
      }
      case "replaced": {
        // An answer to no call is ignored.
        const resolve = replacements.get(message.call);
        replacements.delete(message.call);
        resolve?.(message.ok);
        return;
      }
      case "key": {
        if (!keys.has(message.key) || !iframe) return;
        const now = performance.now();
        keyTimes = keyTimes.filter((t) => now - t < 1000);
        if (keyTimes.length >= KEY_RATE) return;
        keyTimes.push(now);
        iframe.dispatchEvent(new KeyboardEvent("keydown", { key: message.key, code: message.key, shiftKey: message.shift, repeat: message.repeat, bubbles: true, cancelable: true, composed: true }));
        return;
      }
      case "link": {
        const url = linkTarget(message.url);
        // One question at a time: a frame cannot queue a hundred.
        if (!url || confirming) return;
        confirming = true;
        void Promise.resolve()
          .then(() => (config.confirmLink ?? defaultConfirm)(url, file))
          .then((yes) => {
            if (yes && !ended) window.open(url, "_blank", "noopener,noreferrer");
          })
          .catch(() => undefined)
          .finally(() => (confirming = false));
        return;
      }
    }
  };

  /** What the frame is given of a prepared file; a file read by ranges is kept as document `generation`. */
  const sourceOf = (p: Prepared, generation: number, transfer: Transferable[]): OpenSource => {
    if (p.kind === "ranges") {
      documents.set(generation, p.ranges);
      const head = p.ranges.head.slice().buffer as ArrayBuffer;
      transfer.push(head);
      return { kind: "ranges", size: p.ranges.size, head };
    }
    return p.kind === "url" ? { kind: "url", url: p.url } : { kind: "blob", blob: p.blob };
  };

  const readWhole = (p: Prepared): Snapshots["warnings"] => (p.kind === "blob" && p.readWhole ? [{ key: "source_read_whole", count: 1 }] : []);

  const send = async () => {
    try {
      const p = await prepared!;
      if (ended || !port) return;
      firstKind = p.kind;
      if (readWhole(p).length) setHostWarnings(readWhole(p));
      const transfer: Transferable[] = [];
      const message: OpenMessage = {
        type: "open",
        formats,
        file: { name: file.name, type: file.type ?? "", path: file.path ?? file.name, format: known },
        source: sourceOf(p, 0, transfer),
        ...(file.tree ? { tree: { path: file.tree.path, paths: file.tree.paths.slice(0, TREE.maxPaths) } } : {}),
        options: config.options ?? {},
        theme: themeFor(config, host),
      };
      port.postMessage(message, transfer);
      started = true;
      shown.add(restyle);
      if (config.theme === undefined || config.theme === "inherit") scheme?.addEventListener("change", restyle);
    } catch (error) {
      if (!abort.signal.aborted) fail(errorCode(format), error);
    }
  };

  /**
   * `Session.replace` for the file's session. The frame takes one document
   * at a time: a newer call while an older one is being read supersedes it
   * (that one resolves true, as in the page), and while one is with the frame
   * the next waits for its answer.
   */
  const replace = async (next: ViewerFile): Promise<boolean> => {
    if (ended || !started || !port || !known || !next.source) return false;
    if ((next.format ?? detect(next)) !== known) return false;
    const mine = ++latest;
    superseding?.abort();
    const own = new AbortController();
    superseding = own;
    const signal = AbortSignal.any([abort.signal, own.signal]);
    let p: Prepared;
    try {
      p = await prepare(next.source, known, next, { delivery: config.delivery, origins: config.origins, signal });
    } catch (error) {
      // Superseded, or the session ended: not a failure. Otherwise the old document stays, under the error.
      if (signal.aborted) return true;
      console.warn(`${format ?? "viewer"}: the next document could not be read`, error);
      root.status.set({ phase: "error", error: { code: errorCode(format), cause: error } });
      return true;
    }
    // The frame's engines were made for the way the first file came: an image shown from a URL is drawn without CORS.
    if ((p.kind === "url") !== (firstKind === "url")) return false;
    await answered;
    if (mine !== latest || ended || !port) return true;
    const generation = ++lastDocument;
    const transfer: Transferable[] = [];
    const message: ReplaceMessage = {
      type: "replace",
      call: nextCall++,
      generation,
      file: { name: next.name, type: next.type ?? "", path: next.path ?? next.name, format: known },
      source: sourceOf(p, generation, transfer),
    };
    const reply = new Promise<boolean>((resolve) => replacements.set(message.call, resolve));
    answered = reply;
    port.postMessage(message, transfer);
    const ok = await reply;
    if (!ok) {
      documents.delete(generation);
      return false;
    }
    // The reads of the documents before this one are over with them.
    for (const g of [...documents.keys()]) if (g !== generation) documents.delete(g);
    current = next;
    setHostWarnings(readWhole(p));
    return true;
  };

  if (!file.source) {
    // Nothing to show yet: the UI shows the placeholder.
  } else if (!known) {
    root.status.set({ phase: "error", error: { code: errorCode(format) } });
  } else {
    // The host reads the file, or gives the frame an address its policy
    // allows: the frame reaches nothing else.
    prepared = prepare(file.source, known, file, {
      delivery: config.delivery,
      origins: config.origins,
      signal: abort.signal,
      progress: (share) => root.status.get().phase === "loading" && root.status.set({ phase: "loading", step: "file", progress: share }),
    });
    // Refused or failed: said at once, without waiting for the frame.
    prepared.catch((error) => !abort.signal.aborted && fail(errorCode(format), error));
    const frame = document.createElement("iframe");
    // Scripts only: an opaque origin, no popups, no navigation of this page,
    // no downloads, no forms, no modal dialogs. Of the powerful features,
    // autoplay: a player started by this page's controls (`media.play`).
    frame.setAttribute("sandbox", "allow-scripts");
    frame.setAttribute("allow", "autoplay");
    frame.setAttribute("referrerpolicy", "no-referrer");
    frame.className = "exav-viewer-sandbox";
    frame.title = file.name;
    // Filling the host element without the stylesheet too, for a host drawing its own UI.
    Object.assign(frame.style, { display: "block", width: "100%", height: "100%", border: "0" });
    let loads = 0;
    frame.addEventListener("load", () => {
      loads += 1;
      // A second load is the frame navigating itself away: it is not ours anymore.
      if (loads > 1) return fail(errorCode(format), new Error("the frame navigated"));
      const channel = new MessageChannel();
      port = channel.port1;
      port.onmessage = (e: MessageEvent) => {
        if (ended) return;
        const message = checkFrameMessage(e.data);
        if (message) receive(message);
      };
      // An opaque origin cannot be named as the target: "*" carries the port
      // and nothing else. Everything after it goes over the port.
      frame.contentWindow?.postMessage({ type: HELLO, protocol: PROTOCOL }, "*", [channel.port2]);
    });
    timer = setTimeout(() => fail(errorCode(format), new Error("the frame did not start")), config.startTimeoutMs ?? 20_000);
    frame.src = config.url;
    iframe = frame;
    host.append(frame);
  }

  return {
    get file() {
      return current;
    },
    format: root.session.format,
    status: root.session.status,
    controllers: root.session.controllers,
    replace,
    resize: root.session.resize,
    destroy: end,
  };
}
