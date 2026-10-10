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
import { BUILTIN_ORDER, MATCHERS, WASM_IMAGES } from "../core/formats.js";
import { derived, writable, type Store, type WritableStore } from "../core/store.js";
import type {
  ArchiveController,
  ArchiveMember,
  BuiltinFormat,
  Controllers,
  FormatId,
  FormatMatcher,
  OutlineEntry,
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
  PROTOCOL,
  type ArchiveSnapshot,
  type BytesMessage,
  type CommandMessage,
  type CommandTarget,
  type ControllerKey,
  type FrameMessage,
  type FrameOptions,
  type OpenMessage,
  type OpenSource,
  type Snapshots,
  type Statics,
  type StatusSnapshot,
} from "./protocol.js";

export type { FrameOptions } from "./protocol.js";
export type { Delivery } from "./delivery.js";
export { FRAME_CSP, FRAME_PERMISSIONS, frameCsp, frameHeaders, type FrameOrigins } from "./policy.js";

export interface SandboxConfig {
  /**
   * The frame app's page: where the host serves `dist/frame/app/` (its
   * `index.html`), with the headers the documentation lists. Best on a
   * registrable domain of its own that sets no cookies.
   */
  url: string;
  /** The formats the frame opens, in detection order. Default: every built-in one. */
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
}

const ALL: readonly BuiltinFormat[] = BUILTIN_ORDER;

function matcher(id: BuiltinFormat): FormatMatcher {
  if (id !== "image") return MATCHERS[id];
  // The frame decodes what browsers do not draw.
  const a = MATCHERS.image;
  return { types: [...(a.types ?? []), ...(WASM_IMAGES.types ?? [])], extensions: [...(a.extensions ?? []), ...(WASM_IMAGES.extensions ?? [])] };
}

function toStatus(s: StatusSnapshot): Status {
  return s.phase === "error" ? { phase: "error", error: { code: s.code } } : s;
}

const defaultConfirm = (url: string) => window.confirm(`Open this link in a new tab?\n\n${url}`);

/** The viewer's `plugins` are empty: they live in the frame. */
export function createSandboxedViewer(config: SandboxConfig): Viewer {
  checkDelivery(config.delivery, config.origins);
  const formats = (config.formats ?? ALL).filter((f) => ALL.includes(f));
  const detector = createDetector(formats.map((id) => ({ id, match: matcher(id) })));
  const mount = (host: HTMLElement, file: ViewerFile): Session => mountFrame(config, formats, detector.detect(file), host, file);
  return {
    ...detector,
    plugins: [],
    assetBase: "",
    mount,
    // The frame fetches its engines itself, from its own origin.
    prefetch: async () => {},
  };
}

interface Proxy {
  session: Session;
  status: WritableStore<Status>;
  controllers: WritableStore<Controllers>;
  stores: Partial<{ [K in ControllerKey]: WritableStore<Snapshots[K]> }>;
}

function mountFrame(config: SandboxConfig, formats: readonly BuiltinFormat[], detected: FormatId | null, host: HTMLElement, file: ViewerFile): Session {
  const format = file.format ?? detected;
  const known = formats.find((f) => f === format) ?? null;
  const abort = new AbortController();
  let ended = false;
  /** The file as the frame will get it, read from the start. */
  let prepared: Promise<Prepared> | null = null;
  let ranges: Extract<Prepared, { kind: "ranges" }>["ranges"] | null = null;
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

  const proxy = (id: number, info: { file: ViewerFile; format: FormatId | null }): Proxy => {
    const status = writable<Status>({ phase: "loading" });
    const controllers = writable<Controllers>({});
    const p: Proxy = {
      status,
      controllers,
      stores: {},
      session: {
        file: info.file,
        format: info.format,
        status,
        controllers,
        // A frame holds one file: the next document gets a new frame.
        replace: async () => false,
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
  const read = (id: number, offset: number, length: number) => {
    // An id already in use is the frame's confusion: its first read stands.
    if (reads.has(id)) return;
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

  const command = (session: number, target: CommandTarget, action: string, args: unknown[] = []) =>
    new Promise<void>((resolve) => {
      if (!port) return resolve();
      const call = nextCall++;
      pending.set(call, resolve);
      const message: CommandMessage = { type: "command", call, session, target, action, args };
      port.postMessage(message);
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
  let hostWarnings: readonly { key: string; count: number }[] = [];
  const withHostWarnings = (id: number, frame: Store<Snapshots["warnings"]> | null): Store<Snapshots["warnings"]> | null => {
    if (id !== 0 || hostWarnings.length === 0) return frame;
    const own = hostWarnings;
    return frame ? derived(frame, (w) => [...w, ...own]) : writable(own);
  };

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
        return read(message.id, message.offset, message.length);
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

  const send = async () => {
    try {
      const p = await prepared!;
      if (ended || !port) return;
      if (p.kind === "blob" && p.readWhole) {
        hostWarnings = [{ key: "source_read_whole", count: 1 }];
        root.controllers.update((c) => ({ ...c, warnings: withHostWarnings(0, c.warnings ?? null)! }));
      }
      let source: OpenSource;
      const transfer: Transferable[] = [];
      if (p.kind === "ranges") {
        ranges = p.ranges;
        const head = p.ranges.head.slice().buffer as ArrayBuffer;
        transfer.push(head);
        source = { kind: "ranges", size: p.ranges.size, head };
      } else source = p.kind === "url" ? { kind: "url", url: p.url } : { kind: "blob", blob: p.blob };
      const message: OpenMessage = {
        type: "open",
        formats,
        file: { name: file.name, type: file.type ?? "", path: file.path ?? file.name, format: known },
        source,
        options: config.options ?? {},
      };
      port.postMessage(message, transfer);
    } catch (error) {
      if (!abort.signal.aborted) fail(errorCode(format), error);
    }
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
      progress: (share) => root.status.get().phase === "loading" && root.status.set({ phase: "loading", progress: share }),
    });
    // Refused or failed: said at once, without waiting for the frame.
    prepared.catch((error) => !abort.signal.aborted && fail(errorCode(format), error));
    const frame = document.createElement("iframe");
    // Scripts only: an opaque origin, no popups, no navigation of this page,
    // no downloads, no forms, no modal dialogs.
    frame.setAttribute("sandbox", "allow-scripts");
    frame.setAttribute("allow", "");
    frame.setAttribute("referrerpolicy", "no-referrer");
    frame.className = "exv-sandbox";
    frame.title = file.name;
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

  return { ...root.session, destroy: end };
}
