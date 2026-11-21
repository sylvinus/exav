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
import { checkPackageLimits, checkSniffBytes, checkSniffTimeout, createDetector, readsHead } from "../core/detect.js";
import { BUILTIN_ORDER, CONVERTED_FORMATS } from "../core/formats.js";
import { highlightId, MAX_HIGHLIGHTS } from "../core/highlights.js";
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
  Detector,
  FileSource,
  FormatId,
  Highlight,
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
import { addressGiven, checkDelivery, prepare, readRefusal, refusesAddress, type Delivery, type Prepared } from "./delivery.js";
import { policyMismatch, type FrameOrigins } from "./policy.js";
import {
  checkFrameMessage,
  checkOptions,
  frameMatcher,
  HELLO,
  followTarget,
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
  type FrameHighlight,
  type FrameMessage,
  type FrameOptions,
  type NavKey,
  type OpenMessage,
  type OpenSource,
  type PingMessage,
  type RasterMessage,
  type RasterResult,
  type ReplaceMessage,
  type SniffMessage,
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
   * tab (`noopener,noreferrer`), or a `mailto:` one in the mail program.
   * Only absolute http(s) links and `mailto:` ones get here.
   * Default: the browser's `confirm`.
   */
  confirmLink?: (url: string, file: ViewerFile) => boolean | Promise<boolean>;
  /**
   * After the question about a link is answered, how long the frame's links
   * are dropped, in milliseconds, so that a frame cannot ask again at once.
   * Default 2000; 0: no pause.
   */
  linkQuietMs?: number;
  /** How long the frame may take to start. Default 20_000 ms. */
  startTimeoutMs?: number;
  /**
   * How long the frame may go without answering this page, in milliseconds,
   * once it has started: this page pings it, a third of this value apart, and
   * the session fails when a ping stays unanswered this long (the frame
   * crashed, navigated away, or its main thread hangs). Default 30,000;
   * 0: no ping.
   */
  frameTimeoutMs?: number;
  /**
   * How long the detection of a file's first bytes may take, in milliseconds,
   * before the file's name and type decide. The detection runs in the frame,
   * which this page sends the bytes and which answers what the file is; the
   * frame uses the same value for the files inside an archive.
   * Default 30,000; 0: no timeout.
   */
  sniffTimeoutMs?: number;
  /**
   * How many bytes from the start of a file are read to tell what it is (the
   * files inside an archive too). Default 65,536. A file this page reads (a
   * Blob, bytes, ranges, or an address it fetches for the frame) is read by
   * this page, with a range request for an address, which it makes for the
   * file anyway; a file the frame is given the address of is read by the
   * frame where its policy lets it fetch the address (a PDF), else told by its
   * name and type. 0: files are told by their name and type alone.
   */
  sniffBytes?: number;
  /**
   * The limits on a ZIP's directory, checked in the frame before it opens an
   * Office file or an archive, as the options of the same names of
   * `createViewer`: `maxExtractedBytes` (default 512 MiB), `maxMembers`
   * (20,000) and `maxCompressionRatio` (1000); 0: no limit.
   */
  maxExtractedBytes?: number;
  maxMembers?: number;
  maxCompressionRatio?: number;
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

/** Why a file is not delivered: no format the frame opens is what its bytes or its name say. */
const NOT_OPENED = Symbol("not opened");

const ALL: readonly BuiltinFormat[] = BUILTIN_ORDER;
/** The converted formats only when named: they need the converter. */
const DEFAULT: readonly BuiltinFormat[] = ALL.filter((f) => !CONVERTED_FORMATS.includes(f));

function toStatus(s: StatusSnapshot): Status {
  return s.phase === "error" ? { phase: "error", error: { code: s.code } } : s;
}

const defaultConfirm = (url: string) => window.confirm(`${url.startsWith("mailto:") ? "Write this email in your mail program?" : "Open this link in a new tab?"}\n\n${url}`);

/** The default of `linkQuietMs`. */
export const LINK_QUIET_MS = 2000;

function checkLinkQuietMs(n: number | undefined): number {
  if (n === undefined) return LINK_QUIET_MS;
  if (!Number.isSafeInteger(n) || n < 0) throw new RangeError(`linkQuietMs: a whole number of milliseconds, 0 for none, not ${String(n)}`);
  return n;
}

/** The directives a page's policy refuses a frame's address with: the `effectiveDirective` of the violation. */
const FRAME_DIRECTIVES = ["frame-src", "child-src", "default-src"];

/** The origin of an address (relative to `base` when given), or null where it is none (`inline`, `eval`, an empty string). */
function originOf(address: string, base?: string): string | null {
  try {
    const { origin } = new URL(address, base);
    return origin === "null" ? null : origin;
  } catch {
    return null;
  }
}

/** The default of `frameTimeoutMs`. */
export const FRAME_TIMEOUT_MS = 30_000;

function checkFrameTimeoutMs(ms: number | undefined): number {
  if (ms === undefined) return FRAME_TIMEOUT_MS;
  if (!Number.isFinite(ms) || ms < 0) throw new RangeError(`frameTimeoutMs: a number of milliseconds, 0 for no ping, not ${String(ms)}`);
  return ms;
}

/**
 * Whether the user has just clicked or pressed a key in this page, or in a
 * frame of it, which activates the page too. True where the browser cannot say.
 */
function activated(): boolean {
  return "userActivation" in navigator ? navigator.userActivation.isActive : true;
}

/**
 * A controller of its own that `parent` aborts too, where `AbortSignal.any`
 * would need Safari 17.4. `release` once the work is over: the session's
 * signal outlives every read.
 */
function follows(parent: AbortSignal): { own: AbortController; release: () => void } {
  const own = new AbortController();
  const stop = () => own.abort();
  if (parent.aborted) own.abort();
  else parent.addEventListener("abort", stop, { once: true });
  return { own, release: () => parent.removeEventListener("abort", stop) };
}

/** The size a file of the tree states before it is read, or null (a URL, a source resolved on demand). */
function sizeOf(source: FileSource): number | null {
  if ("bytes" in source) return source.bytes.byteLength;
  if ("blob" in source) return source.blob.size;
  if ("ranges" in source) return source.ranges.size;
  return null;
}

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
  const limits = checkPackageLimits(config);
  const linkQuietMs = checkLinkQuietMs(config.linkQuietMs);
  const frameTimeoutMs = checkFrameTimeoutMs(config.frameTimeoutMs);
  checkSniffTimeout(config.sniffTimeoutMs);
  const formats = (config.formats ?? DEFAULT).filter((f) => ALL.includes(f));
  // By name and type only: the bytes are told in the frame (`sniff`).
  const detector = createDetector(
    formats.map((id) => ({ id, match: frameMatcher(id) })),
    undefined,
    undefined,
    checkSniffBytes(config.sniffBytes),
    limits,
  );
  /** Each frame shown, by what sends it its theme again. */
  const shown = new Set<() => void>();
  const mount = (host: HTMLElement, file: ViewerFile): Session => mountFrame({ ...config, linkQuietMs, frameTimeoutMs }, formats, detector, host, file, shown);
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
  detector: Detector,
  host: HTMLElement,
  file: ViewerFile,
  shown: Set<() => void>,
): Session {
  const detect = detector.detect;
  // What the name and the type say, until the first bytes of a file at hand
  // are read (`decide`).
  let format = file.format ?? detect(file);
  let known = formats.find((f) => f === format) ?? null;
  const abort = new AbortController();
  let ended = false;
  /** The file as the frame will get it, read from the start. */
  let prepared: Promise<Prepared> | null = null;
  /** What the file is shown as and the source to deliver, once known; null where no format the frame opens. */
  let decision: Promise<{ as: BuiltinFormat; source: FileSource } | null> | null = null;
  /** The file on screen: the one `replace` last took. */
  let current = file;
  /** The bytes of each file read by ranges that is alive, by the number the frame names it with (0 is the first). */
  const documents = new Map<number, Extract<Prepared, { kind: "ranges" }>["ranges"]>();
  /** How the first file was delivered: what the frame's engines were made for. */
  let firstKind: Prepared["kind"] | null = null;
  /** The frame's reads not answered yet. */
  const reads = new Map<number, { length: number; abort: AbortController }>();
  let outstanding = 0;
  /** Bytes of the tree's files being read for the frame, all fetches together: at most `TREE.maxFileBytes`. */
  let fetching = 0;
  let refusedOnce = false;
  let port: MessagePort | null = null;
  let iframe: HTMLIFrameElement | null = null;
  let timer: ReturnType<typeof setTimeout> | undefined;
  /** Pings the frame once it is ready (`frameTimeoutMs`). */
  let pinger: ReturnType<typeof setInterval> | undefined;
  /** When the ping the frame has not answered was sent, or null. */
  let pingSince: number | null = null;
  /** Stops listening for the page's policy refusing the frame. */
  let unwatchPolicy: () => void = () => {};
  let confirming = false;
  /** Until when the frame's links are dropped: a moment after each answer, so that a frame cannot ask again at once. */
  let quietUntil = 0;
  /** The formats the frame was published for, null for all of them, once it is ready. */
  let published: readonly BuiltinFormat[] | null = null;
  /** Whether the frame said `ready`: a second one is ignored. */
  let greeted = false;
  let isReady: () => void = () => {};
  const ready = new Promise<void>((resolve) => (isReady = resolve));
  /** The `sniff` calls not answered yet: undefined is no answer. */
  const sniffs = new Map<number, (format: BuiltinFormat | null | undefined) => void>();
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
  /** The calls of `replace` so far: the one that reads its bytes to tell its format yields to a newer one. */
  let asked = 0;
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
        get format() {
          return id === 0 ? format : info.format;
        },
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

  /**
   * The highlights given to each session, by session and highlight id: their
   * labels, colours and quotes are read from here, never from the frame.
   */
  const given = new Map<number, Map<string, FrameHighlight>>();
  const giveHighlights = (session: number, list: readonly Highlight[]): FrameHighlight[] => {
    const withIds = list.slice(0, MAX_HIGHLIGHTS).map((h, i) => ({ ...h, id: highlightId(h, i) }) as FrameHighlight);
    given.set(session, new Map(withIds.map((h) => [h.id, h])));
    return withIds;
  };

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
    clearInterval(pinger);
    unwatchPolicy();
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
    const { own, release } = follows(abort.signal);
    reads.set(id, { length, abort: own });
    outstanding += length;
    ranges!
      .read(offset, length, own.signal)
      .then(
        (bytes): BytesMessage => {
          // A copy to transfer: the buffer may be one the host keeps.
          return { type: "bytes", id, data: bytes.slice().buffer as ArrayBuffer };
        },
        (error): BytesMessage => {
          if (!own.signal.aborted) console.warn(`${format ?? "viewer"}: a read for the sandboxed frame failed`, error);
          return { type: "bytes", id, error: "failed" };
        },
      )
      .then((m) => {
        release();
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
    const { own, release } = follows(abort.signal);
    reads.set(id, { length: 0, abort: own });
    const signal = own.signal;
    let opened: ReturnType<typeof createSourceReader> | undefined;
    /** What this fetch adds to `fetching`. */
    let counted = 0;
    /** The fetches together went past the limit while this one was read. */
    let over = false;
    let stopCounting = () => {};
    void (async (): Promise<BytesMessage> => {
      const source = await tree.open(path, signal);
      // A source that states its size is judged before it is read.
      const size = sizeOf(source);
      if (size !== null) {
        if (size > TREE.maxFileBytes || fetching + size > TREE.maxFileBytes) return { type: "bytes", id, error: "refused" };
        counted = size;
        fetching += size;
      }
      opened = createSourceReader(source, signal, TREE.maxFileBytes);
      // One that does not is counted as it arrives.
      if (size === null)
        stopCounting = opened.progress.subscribe((p) => {
          const more = (p?.loaded ?? counted) - counted;
          counted += more;
          fetching += more;
          if (fetching > TREE.maxFileBytes) {
            // This one is refused, and gives its share back at once: the others go on.
            over = true;
            fetching -= counted;
            counted = 0;
            stopCounting();
            own.abort();
          }
        });
      const bytes = await opened.bytes();
      if (over || bytes.byteLength > TREE.maxFileBytes) return { type: "bytes", id, error: "refused" };
      // Its own buffer, to transfer: the source may keep the one it read.
      return { type: "bytes", id, data: bytes.slice().buffer as ArrayBuffer };
    })()
      .catch((error): BytesMessage => {
        if (over || error instanceof RangeError) return { type: "bytes", id, error: "refused" };
        if (!own.signal.aborted) console.warn(`${format ?? "viewer"}: a file for the sandboxed frame could not be read`, error);
        return { type: "bytes", id, error: "failed" };
      })
      .then((m) => {
        stopCounting();
        release();
        opened?.dispose();
        fetching -= counted;
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
    const highlights = store("highlights");
    if (highlights)
      c.highlights = {
        ...derived(highlights, (s) => ({
          items: s.items.map((i) => {
            const h = given.get(id)?.get(i.id);
            return {
              ...i,
              ...(h?.color !== undefined && { color: h.color }),
              ...(h?.label !== undefined && { label: h.label }),
              ...(h && "text" in h && { text: h.text }),
            };
          }),
          current: s.current,
        })),
        set: (list) => void command(id, "highlights", "set", [giveHighlights(id, list)]),
        goTo: (h) => void command(id, "highlights", "goTo", [h]),
      };
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

  /**
   * Pings the frame every third of `frameTimeoutMs` while no ping is
   * unanswered, and fails the session when one stays so for the whole of it.
   * A tick more than twice its interval after the one before (the tab was
   * frozen or throttled, so neither this page nor the frame ran) does not
   * count that gap: the ping is sent again and the wait starts over.
   */
  const startPings = () => {
    const timeout = config.frameTimeoutMs ?? FRAME_TIMEOUT_MS;
    if (timeout === 0) return;
    let lastTick = performance.now();
    pinger = setInterval(() => {
      if (!port) return;
      const now = performance.now();
      const late = now - lastTick > (2 * timeout) / 3;
      lastTick = now;
      if (pingSince === null || late) {
        pingSince = now;
        port.postMessage({ type: "ping" } satisfies PingMessage);
      } else if (now - pingSince >= timeout) fail(errorCode(format), new Error(`the frame did not answer in ${timeout} ms`));
    }, timeout / 3);
  };

  const receive = (message: FrameMessage) => {
    switch (message.type) {
      case "ready": {
        // Once: another would have the file sent again, and its reads answered again.
        if (greeted) return;
        greeted = true;
        clearTimeout(timer);
        if (message.protocol !== PROTOCOL) return fail(errorCode(format), new Error(`the frame speaks protocol ${message.protocol}, not ${PROTOCOL}`));
        // Its policy is fixed where it is deployed: one that does not allow
        // what this viewer will give it, or allows more, is a deployment
        // error, said here rather than left to the policy to block.
        const mismatch = policyMismatch(message.policy, config.origins ?? {});
        if (mismatch) return fail(errorCode(format), new Error(mismatch));
        published = message.formats;
        isReady();
        startPings();
        // Likewise a frame published without this file's format: said here, with its cause.
        // The format is the bytes' where they are read, so after they are.
        void (decision ?? Promise.resolve(null)).then(
          () => {
            if (ended) return;
            if (known && message.formats && !message.formats.includes(known)) return fail(errorCode(format), new Error(`the frame was published without ${known}: name it in the \`formats\` of the Vite plugin, or with \`--format\``));
            void send();
          },
          () => undefined,
        );
        return;
      }
      case "pong":
        pingSince = null;
        return;
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
      case "sniffed":
        // An answer to no call is ignored too.
        return sniffs.get(message.call)?.(message.format);
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
        const url = followTarget(message.url);
        // One question at a time, none right after an answer, and none the
        // user did not just click or press a key for: a frame can neither
        // queue a hundred, nor ask again as soon as one is answered, nor ask
        // by itself.
        if (!url || confirming || performance.now() < quietUntil || !activated()) return;
        confirming = true;
        void Promise.resolve()
          .then(() => (config.confirmLink ?? defaultConfirm)(url, current))
          .then((yes) => {
            if (yes && !ended) window.open(url, "_blank", "noopener,noreferrer");
          })
          .catch(() => undefined)
          .finally(() => {
            confirming = false;
            quietUntil = performance.now() + (config.linkQuietMs ?? LINK_QUIET_MS);
          });
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

  /**
   * What `f` is: what the frame tells from its first bytes (`askFrame`),
   * which this page reads where it reads the file anyway (an address by a
   * range request), and the frame where it is given the address and may
   * fetch it; else what its name and type say. And the source to deliver,
   * which is `f`'s, with a `resolve` answered once for the detection and the
   * delivery. An address the delivery refuses (`refusesAddress`) is not asked
   * for anything.
   */
  const decide = async (f: ViewerFile, signal: AbortSignal): Promise<{ format: FormatId | null; source: FileSource }> => {
    let source = f.source!;
    const named = f.format ?? detect(f);
    if (!readsHead(f, detector.headBytes)) return { format: named, source };
    let address: { url: string; init?: RequestInit } | null = "url" in source ? source : null;
    if ("resolve" in source) {
      const original = source;
      const answer = original.resolve(signal);
      // The head's read and the delivery's each ask once; a later call (a signed address that expired) is the host's.
      let shared = 2;
      source = { resolve: (s) => (shared-- > 0 ? answer : original.resolve(s)) };
      const r = await answer;
      if (typeof r === "string") address = { url: r };
    }
    const as = formats.find((x) => x === named) ?? null;
    let asked: SniffMessage["source"] | null = null;
    if (address) {
      if (refusesAddress(address, as, f, config)) return { format: named, source };
      // The frame is given the address: this page makes no request for it,
      // and the frame reads the start itself where its policy lets it fetch.
      const given = addressGiven(address, as, f, config);
      if (given && !given.fetchable) return { format: named, source };
      if (given) asked = { kind: "url", url: given.url };
    }
    if (!asked) {
      const reader = createSourceReader(source, signal);
      try {
        const head = await reader.head(detector.headBytes);
        if (!head) return { format: named, source };
        asked = { kind: "head", head: head.bytes.slice().buffer, size: head.size };
      } finally {
        reader.dispose();
      }
    }
    const said = await askFrame(f, asked, signal);
    return { format: said === undefined ? named : said, source };
  };

  /**
   * What the frame says `f` is, told by `source`: a format it was published
   * for and this viewer opens, or null for none. Undefined when it has not
   * answered in `sniffTimeoutMs`, or names another format: the name and the
   * type decide then.
   */
  const askFrame = async (f: ViewerFile, source: SniffMessage["source"], signal: AbortSignal): Promise<BuiltinFormat | null | undefined> => {
    const stopped = new Promise<void>((resolve) => signal.addEventListener("abort", () => resolve(), { once: true }));
    await Promise.race([ready, stopped]);
    if (signal.aborted || ended || !port) return undefined;
    const call = nextCall++;
    const timeoutMs = checkSniffTimeout(config.sniffTimeoutMs);
    let timeout: ReturnType<typeof setTimeout> | undefined;
    const answer = new Promise<BuiltinFormat | null | undefined>((resolve) => {
      sniffs.set(call, resolve);
      if (timeoutMs > 0) timeout = setTimeout(() => resolve(undefined), timeoutMs);
      void stopped.then(() => resolve(undefined));
    });
    const message: SniffMessage = {
      type: "sniff",
      call,
      formats,
      file: { name: f.name, type: f.type ?? "", path: f.path ?? f.name },
      source,
      sniff: { timeoutMs: config.sniffTimeoutMs, bytes: detector.headBytes },
    };
    port.postMessage(message, source.kind === "head" ? [source.head] : []);
    const format = await answer;
    clearTimeout(timeout);
    sniffs.delete(call);
    if (!format) return format;
    return formats.includes(format) && (published === null || published.includes(format)) ? format : undefined;
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
        // Plain data, as the frame will check it: a function or a key like `__proto__` never leaves this page.
        options: checkOptions({ ...config.options, sniff: { timeoutMs: config.sniffTimeoutMs, bytes: config.sniffBytes }, limits: detector.limits }),
        theme: themeFor(config, host),
        ...(file.highlights && { highlights: giveHighlights(0, file.highlights) }),
        ...(file.focusHighlight !== undefined && { focusHighlight: file.focusHighlight }),
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
   *
   * The next document goes to the same frame, in the realm the one before
   * ran in: a host that needs each file isolated from the others mounts a
   * new session for it instead.
   */
  const replace = async (next: ViewerFile): Promise<boolean> => {
    if (ended || !started || !port || !known || !next.source) return false;
    const mineAsked = ++asked;
    let nextFormat = next.format ?? detect(next);
    let nextSource = next.source;
    if (readsHead(next, detector.headBytes)) {
      // As the first document: what its bytes say, when they say anything.
      try {
        ({ format: nextFormat, source: nextSource } = await decide(next, abort.signal));
      } catch (error) {
        if (abort.signal.aborted) return true;
        console.warn(`${format ?? "viewer"}: the next document could not be read`, error);
        root.status.set({ phase: "error", error: { code: errorCode(format), cause: error } });
        return true;
      }
      // Superseded by a newer call, or the session ended: not a failure.
      if (mineAsked !== asked || ended || !port) return true;
    }
    if (nextFormat !== known) return false;
    const mine = ++latest;
    superseding?.abort();
    // Not released: the document's source keeps the signal for its later requests (a signed address asked again).
    const { own } = follows(abort.signal);
    superseding = own;
    const signal = own.signal;
    let p: Prepared;
    try {
      p = await prepare(nextSource, known, next, { delivery: config.delivery, origins: config.origins, signal });
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

  /** Shows the file in a frame of its own. */
  const showFrame = () => {
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
    // The page's own policy refusing the frame: a `frame-src`, or the
    // `child-src` or `default-src` it falls back to, that does not name its
    // origin. Said now, with what to add.
    const origin = originOf(config.url, document.baseURI);
    const onViolation = (e: Event) => {
      const v = e as SecurityPolicyViolationEvent;
      if (!origin || v.disposition !== "enforce" || !FRAME_DIRECTIVES.includes(v.effectiveDirective) || originOf(v.blockedURI) !== origin) return;
      // Browsers report `frame-src` whichever of the three the page has set.
      fail(errorCode(format), new Error(`the page's Content-Security-Policy blocks the frame: add ${origin} to its frame-src (to its child-src or default-src when it has no frame-src)`));
    };
    document.addEventListener("securitypolicyviolation", onViolation);
    unwatchPolicy = () => document.removeEventListener("securitypolicyviolation", onViolation);
    timer = setTimeout(() => fail(errorCode(format), new Error("the frame did not start")), config.startTimeoutMs ?? 20_000);
    frame.src = config.url;
    iframe = frame;
    host.append(frame);
  };

  if (!file.source) {
    // Nothing to show yet: the UI shows the placeholder.
  } else if (!known && !readsHead(file, detector.headBytes)) {
    root.status.set({ phase: "error", error: { code: errorCode(format) } });
  } else {
    const given = file.source;
    // What the file is: the frame tells it by its first bytes where they are
    // at hand, else its name and type decide.
    decision = (readsHead(file, detector.headBytes) ? decide(file, abort.signal) : Promise.resolve({ format, source: given })).then((d) => {
      format = d.format;
      known = formats.find((f) => f === format) ?? null;
      return known ? { as: known, source: d.source } : null;
    });
    // The host reads the file, or gives the frame an address its policy
    // allows: the frame reaches nothing else.
    prepared = decision.then((o) =>
      o
        ? prepare(o.source, o.as, file, {
            delivery: config.delivery,
            origins: config.origins,
            signal: abort.signal,
            progress: (share) => root.status.get().phase === "loading" && root.status.set({ phase: "loading", step: "file", progress: share }),
          })
        : Promise.reject(NOT_OPENED),
    );
    // Refused or failed: said at once, without waiting for the frame.
    prepared.catch((error) => {
      if (abort.signal.aborted) return;
      if (error !== NOT_OPENED) return fail(errorCode(format), error);
      root.status.set({ phase: "error", error: { code: errorCode(format) } });
      teardown();
      iframe?.remove();
      iframe = null;
    });
    // At once: the frame is asked what the bytes are, or opens the format the name gives.
    showFrame();
  }

  return {
    get file() {
      return current;
    },
    get format() {
      return format;
    },
    status: root.session.status,
    controllers: root.session.controllers,
    replace,
    resize: root.session.resize,
    destroy: end,
  };
}
