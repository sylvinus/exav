/**
 * The messages between a host page and the sandboxed frame (`frame/app/`).
 *
 * The host opens a MessageChannel and hands one port to the frame in its only
 * `window.postMessage`; everything else goes over the port. Each side checks
 * what it receives against the shapes below and drops what does not match:
 * the host treats every frame message as untrusted, since the frame runs the
 * parsers.
 */
import { checkRasterOptions, checkRegion, isRasterErrorCode, MAX_PICTURE_EDGE, MAX_PICTURE_PIXELS, regionMatches, type RasterErrorCode } from "../core/pictures.js";
import { checkTheme, isColor, type FrameTheme } from "../core/theme.js";
import type { BuiltinFormat, LayerItem, LoadStep, MediaState, OutlineEntry, RasterOptions, RasterRegion, RegionSpace, Selection, StoreyItem, Viewport, Warning } from "../core/types.js";
import type { FramePolicy } from "./policy.js";

export { isColor };

/** Bumped on any change to the messages; both sides must agree. */
export const PROTOCOL = 5;

/** The `type` of the one `window.postMessage`, which carries the port. */
export const HELLO = "exav-frame/hello";

// ── Limits ───────────────────────────────────────────────────────────────────

/** Longest string taken from the frame: a layer name, an outline title. */
export const MAX_TEXT = 1024;
/** Longest archive member name. */
export const MAX_PATH = 4096;
/** Longest link the frame may ask the host to open. */
export const MAX_URL = 2048;
/** Most items in one list (layers, members, outline entries...). */
export const MAX_ITEMS = 100_000;
/** Pictures the host waits for at once. */
export const MAX_DRAWS = 8;

/**
 * The keys the frame hands back to the host when the document does not use
 * them: moving between files, closing. Never one with Ctrl, Alt or Meta,
 * never one that types: a frame that could send those could press a host's
 * shortcuts.
 */
export const NAV_KEYS = ["Escape", "ArrowLeft", "ArrowRight", "ArrowUp", "ArrowDown", "PageUp", "PageDown", "Home", "End"] as const;
export type NavKey = (typeof NAV_KEYS)[number];

/**
 * A file read by ranges: what the frame may ask of the host at once. The
 * frame keeps to them; the host refuses what goes beyond.
 */
export const READS = {
  /** Bytes in one read. */
  maxLength: 4 * 1024 * 1024,
  /** Reads outstanding. */
  maxReads: 8,
  /** Bytes outstanding, all reads together. */
  maxBytes: 16 * 1024 * 1024,
  /** The first bytes, sent with the file. */
  head: 65_536,
};

// ── Host to frame ────────────────────────────────────────────────────────────

/** Plugin options that are plain data, per plugin. Functions stay on the frame's side. */
export interface FrameOptions {
  pdf?: {
    minZoom?: number;
    maxZoom?: number;
    prerenderMargin?: string;
    pageMaxPixels?: number;
    detailMaxPixels?: number;
    outlineMaxDepth?: number;
    outlineMaxEntries?: number;
  };
  image?: {
    minScale?: number;
    maxScale?: number;
    wheelStep?: number;
    detailDelayMs?: number;
    detailMargin?: number;
    detailMaxPixels?: number;
    maxDecodeBytes?: number;
  };
  cad?: {
    ground?: "light" | "dark";
    colors?: { light: string; dark: string };
    timeoutMs?: number;
    maxPrimitives?: number;
    maxDecompressedBytes?: number;
    lineweights?: "drawing" | "always" | "never";
    monochrome?: boolean;
  };
  ifc?: { ground?: "light" | "dark"; colors?: { light: string; dark: string }; highlight?: string; timeoutMs?: number; maxTriangles?: number };
  model?: { surface?: number; zUp?: boolean; timeoutMs?: number; maxTriangles?: number };
  archive?: { maxExtractedBytes?: number; maxMembers?: number; maxCompressionRatio?: number };
  /** For the converted Office formats (`rtf()`, `doc()`...). */
  conversion?: { timeoutMs?: number; maxMemory?: number; converter?: "exav" | "external"; externalConverter?: string };
  /** "none": no player controls in the frame, for a host drawing its own (`MediaController`). */
  media?: { controls?: "native" | "none" };
}

/**
 * How the file's bytes reach the frame. `blob`: whole. `url`: an address the
 * frame's policy allows, for an element or pdf.js to fetch. `ranges`: its
 * size and first bytes; the rest on request (`read`).
 */
export type OpenSource = { kind: "blob"; blob: Blob } | { kind: "url"; url: string } | { kind: "ranges"; size: number; head: ArrayBuffer };

export interface OpenMessage {
  type: "open";
  /** The formats the frame may use, in detection order. */
  formats: readonly BuiltinFormat[];
  file: { name: string; type: string; path: string; format: BuiltinFormat | null };
  source: OpenSource;
  options: FrameOptions;
  theme: FrameTheme;
}

/** The answer to a `read`: the bytes, exactly as many as asked (fewer only at the end of the file), or why not. */
export type BytesMessage = { type: "bytes"; id: number; data: ArrayBuffer } | { type: "bytes"; id: number; error: "refused" | "failed" };

/** The page's theme changed (`SandboxedViewer.restyle`). */
export interface ThemeMessage {
  type: "theme";
  theme: FrameTheme;
}

/**
 * A page drawn as a picture (`PicturesController.raster`), answered by a
 * `rastered` with the same id. `options` are the request's, without its
 * signal (`unraster` is that).
 */
export interface RasterMessage {
  type: "raster";
  id: number;
  session: number;
  page: number;
  options: Omit<RasterOptions, "signal">;
}

/** A picture no longer wanted. Its `rastered` still comes. */
export interface UnrasterMessage {
  type: "unraster";
  id: number;
}

/**
 * The next document of the session: the file with other bytes, as `open`
 * gave the first. `generation` numbers the documents (0 is the one `open`
 * gave): the frame names it in each `read`, so that the host answers from the
 * bytes of the document asked about while two are alive. Answered by a
 * `replaced` with the same call.
 */
export interface ReplaceMessage {
  type: "replace";
  call: number;
  generation: number;
  file: OpenMessage["file"];
  source: OpenSource;
}

export type CommandTarget = "pages" | "zoom" | "drag" | "outline" | "layers" | "storeys" | "layouts" | "ground" | "archive" | "media" | "sheets";
const COMMAND_TARGETS: readonly CommandTarget[] = ["pages", "zoom", "drag", "outline", "layers", "storeys", "layouts", "ground", "archive", "media", "sheets"];

export interface CommandMessage {
  type: "command";
  /** Answered by a `done` with the same number. */
  call: number;
  session: number;
  target: CommandTarget;
  action: string;
  args: readonly unknown[];
}

/**
 * The controllers whose store the frame follows only on request, because
 * working its value out costs: the frame reports it (`state`) from a `watch`
 * until the matching `unwatch`. Until then its value in `controllers` is null.
 */
export const WATCHED_KEYS = ["viewport"] as const satisfies readonly ControllerKey[];
export type WatchedKey = (typeof WATCHED_KEYS)[number];

/** Someone follows the store of `key` (a first listener, or a read), or no one does any more. */
export interface WatchMessage {
  type: "watch" | "unwatch";
  session: number;
  key: WatchedKey;
}

export type HostMessage = OpenMessage | CommandMessage | BytesMessage | ThemeMessage | RasterMessage | UnrasterMessage | ReplaceMessage | WatchMessage;

// ── Frame to host ────────────────────────────────────────────────────────────

export type StatusSnapshot =
  | { phase: "loading" | "converting"; progress?: number; step?: LoadStep }
  | { phase: "ready"; partial?: boolean }
  | { phase: "empty" }
  | { phase: "error"; code: ErrorCode };

export type ErrorCode = "pdf" | "image" | "image_no_preview" | "drawing" | "drawing_version" | "office" | "needs_converter" | "media" | "model" | "archive" | "text" | "text_binary" | "file";

export interface ArchiveSnapshot {
  members: readonly { index: number; name: string; uncompressedSize: number; encrypted: boolean }[];
  opening: number | null;
  /** The member on screen, shown by the nested session `session`. */
  opened: { member: { index: number; name: string; uncompressedSize: number; encrypted: boolean }; name: string; format: string | null; session: number } | null;
  refused: { key: "archive_no_reader" | "archive_failed_member" | "archive_member_encrypted" | "archive_member_unsupported" } | null;
}

/** The value of each controller's store, as the frame sends it. */
export interface Snapshots {
  pages: { unit: "page" | "slide"; current: number; total: number } | null;
  zoom: { scale: number; min: number; max: number };
  drag: { mode: "pan" | "select"; available: boolean };
  outline: readonly OutlineEntry[];
  layers: { kind: "layers" | "categories"; items: readonly LayerItem[] };
  storeys: { items: readonly StoreyItem[] };
  layouts: { items: readonly { id: string; name: string; isModel: boolean }[]; current: string };
  ground: "light" | "dark";
  selection: Selection | null;
  info: Record<string, number>;
  warnings: readonly Warning[];
  archive: ArchiveSnapshot;
  media: MediaState;
  sheets: { items: readonly { index: number; name: string }[]; current: number };
  pictures: { count: number; space: RegionSpace };
  viewport: Viewport | null;
}

export type ControllerKey = keyof Snapshots;

export const CONTROLLER_KEYS: readonly ControllerKey[] = [
  "pages",
  "zoom",
  "drag",
  "outline",
  "layers",
  "storeys",
  "layouts",
  "ground",
  "selection",
  "info",
  "warnings",
  "archive",
  "media",
  "sheets",
  "pictures",
  "viewport",
];

/** What a controller has besides its store. */
export interface Statics {
  pages?: { goTo: boolean; step: boolean };
  ground?: { light: string; dark: string };
}

export type FrameMessage =
  /** `policy`: the frame page's own Content-Security-Policy, null when it carries none in a meta tag. */
  | { type: "ready"; protocol: number; policy: FramePolicy | null }
  | { type: "status"; session: number; status: StatusSnapshot }
  /** The session's controllers changed: these keys, with their values now. */
  | { type: "controllers"; session: number; values: Partial<Snapshots>; statics: Statics }
  | { type: "state"; session: number; key: ControllerKey; value: unknown }
  | { type: "done"; call: number; ok: boolean }
  /** A link the user followed in the document. The host decides. */
  | { type: "link"; url: string }
  /** Bytes of the document `generation` read by ranges, answered by a `bytes` with the same id (unique over the frame's life). */
  | { type: "read"; id: number; generation: number; offset: number; length: number }
  /** A read no longer wanted. Its `bytes` still comes. */
  | { type: "cancel"; id: number }
  /** A key pressed in the frame that the document did not use. */
  | { type: "key"; key: NavKey; shift: boolean; repeat: boolean }
  /** The answer to a `raster`: the picture and what it shows, or why there is none. */
  | { type: "rastered"; id: number; result: RasterResult }
  /** The answer to a `replace`: whether the document was replaced. False: nothing changed. */
  | { type: "replaced"; call: number; ok: boolean };

/** The picture of a `rastered`, as the frame sends it. */
export type RasterResult =
  | { ok: true; bitmap: ImageBitmap; width: number; height: number; page: number; layout?: string; space: RegionSpace; region?: RasterRegion }
  | { ok: false; code: RasterErrorCode };

// ── Checks ───────────────────────────────────────────────────────────────────

const isObject = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);
const isText = (v: unknown, max = MAX_TEXT): v is string => typeof v === "string" && v.length <= max;
const isInt = (v: unknown, min = 0, max = Number.MAX_SAFE_INTEGER): v is number => Number.isSafeInteger(v) && (v as number) >= min && (v as number) <= max;
/** Finite, or an infinite bound (a zoom with no maximum). */
const isNumber = (v: unknown): v is number => typeof v === "number" && !Number.isNaN(v);
const isFinite = (v: unknown): v is number => typeof v === "number" && Number.isFinite(v);
const isList = (v: unknown, max = MAX_ITEMS): v is unknown[] => Array.isArray(v) && v.length <= max;
const oneOf = <T extends string>(v: unknown, values: readonly T[]): v is T => typeof v === "string" && (values as readonly string[]).includes(v);
/** A key the host may use as an object key or in a message key: a plain word, not one of Object's. */
const isWord = (v: unknown): v is string => typeof v === "string" && /^[a-z_]{1,64}$/.test(v) && !["__proto__", "constructor", "prototype"].includes(v);

/** A bitmap within the picture limits (`MAX_PICTURE_EDGE` a side, `MAX_PICTURE_PIXELS` in all); false where the platform has none. */
function isPicture(v: unknown): v is ImageBitmap {
  return (
    typeof ImageBitmap !== "undefined" &&
    v instanceof ImageBitmap &&
    v.width >= 1 &&
    v.height >= 1 &&
    v.width <= MAX_PICTURE_EDGE &&
    v.height <= MAX_PICTURE_EDGE &&
    v.width * v.height <= MAX_PICTURE_PIXELS
  );
}

const SPACES: readonly RegionSpace[] = ["page", "pixels", "drawing", "camera", "frame"];

const ERROR_CODES: readonly ErrorCode[] = ["pdf", "image", "image_no_preview", "drawing", "drawing_version", "office", "needs_converter", "media", "model", "archive", "text", "text_binary", "file"];
const REFUSALS = ["archive_no_reader", "archive_failed_member", "archive_member_encrypted", "archive_member_unsupported"] as const;

const STEPS: readonly LoadStep[] = ["file", "engine", "start", "read", "convert", "render"];

export function checkStatus(v: unknown): StatusSnapshot | null {
  if (!isObject(v)) return null;
  const progress = v.progress === undefined || (isFinite(v.progress) && v.progress >= 0 && v.progress <= 1);
  const step = v.step === undefined || oneOf(v.step, STEPS);
  switch (v.phase) {
    case "loading":
    case "converting":
      return progress && step
        ? {
            phase: v.phase,
            ...(v.progress !== undefined && { progress: v.progress as number }),
            ...(v.step !== undefined && { step: v.step as LoadStep }),
          }
        : null;
    case "ready":
      return v.partial === undefined || typeof v.partial === "boolean" ? { phase: "ready", ...(v.partial && { partial: true }) } : null;
    case "empty":
      return { phase: "empty" };
    case "error":
      return oneOf(v.code, ERROR_CODES) ? { phase: "error", code: v.code } : null;
    default:
      return null;
  }
}

// A size of -1 is one the archive does not declare (a gzip or xz stream's).
const checkMember = (m: unknown) =>
  isObject(m) && isInt(m.index) && isText(m.name, MAX_PATH) && isFinite(m.uncompressedSize) && m.uncompressedSize >= -1 && typeof m.encrypted === "boolean"
    ? { index: m.index, name: m.name, uncompressedSize: m.uncompressedSize, encrypted: m.encrypted }
    : null;

/** Each check returns a fresh copy of what it accepted, never the object it was given. */
const CHECKS: { [K in ControllerKey]: (v: unknown) => Snapshots[K] | undefined } = {
  pages(v) {
    if (v === null) return null;
    if (!isObject(v) || !oneOf(v.unit, ["page", "slide"] as const) || !isInt(v.current) || !isInt(v.total)) return undefined;
    return { unit: v.unit, current: v.current, total: v.total };
  },
  zoom(v) {
    if (!isObject(v) || !isNumber(v.scale) || !isNumber(v.min) || !isNumber(v.max)) return undefined;
    return { scale: v.scale, min: v.min, max: v.max };
  },
  drag(v) {
    if (!isObject(v) || !oneOf(v.mode, ["pan", "select"] as const) || typeof v.available !== "boolean") return undefined;
    return { mode: v.mode, available: v.available };
  },
  outline(v) {
    if (!isList(v)) return undefined;
    const out: OutlineEntry[] = [];
    for (const e of v) {
      if (!isObject(e) || !isText(e.title) || !isInt(e.page, 1) || !isInt(e.depth, 0, 64)) return undefined;
      if (e.offset !== null && !(isFinite(e.offset) && e.offset >= 0 && e.offset <= 1)) return undefined;
      out.push({ title: e.title, page: e.page, depth: e.depth, offset: e.offset });
    }
    return out;
  },
  layers(v) {
    if (!isObject(v) || !oneOf(v.kind, ["layers", "categories"] as const) || !isList(v.items)) return undefined;
    const items: LayerItem[] = [];
    for (const i of v.items) {
      if (!isObject(i) || !isText(i.id) || !isText(i.name) || !isColor(i.color) || typeof i.visible !== "boolean") return undefined;
      items.push({ id: i.id, name: i.name, color: i.color, visible: i.visible });
    }
    return { kind: v.kind, items };
  },
  storeys(v) {
    if (!isObject(v) || !isList(v.items)) return undefined;
    const items: StoreyItem[] = [];
    for (const i of v.items) {
      if (!isObject(i) || !isText(i.id) || !isText(i.name) || typeof i.visible !== "boolean") return undefined;
      if (i.elevation !== null && !isFinite(i.elevation)) return undefined;
      items.push({ id: i.id, name: i.name, elevation: i.elevation, visible: i.visible });
    }
    return { items };
  },
  layouts(v) {
    if (!isObject(v) || !isList(v.items) || !isText(v.current)) return undefined;
    const items: { id: string; name: string; isModel: boolean }[] = [];
    for (const i of v.items) {
      if (!isObject(i) || !isText(i.id) || !isText(i.name) || typeof i.isModel !== "boolean") return undefined;
      items.push({ id: i.id, name: i.name, isModel: i.isModel });
    }
    return { items, current: v.current };
  },
  ground: (v) => (oneOf(v, ["light", "dark"] as const) ? v : undefined),
  selection(v) {
    if (v === null) return null;
    if (!isObject(v) || !isText(v.name) || !isText(v.category)) return undefined;
    return isText(v.storey) ? { name: v.name, category: v.category, storey: v.storey } : { name: v.name, category: v.category };
  },
  info(v) {
    if (!isObject(v)) return undefined;
    const entries = Object.entries(v);
    if (entries.length > 64) return undefined;
    const out: Record<string, number> = {};
    for (const [k, n] of entries) {
      if (!isWord(k) || !isFinite(n)) return undefined;
      out[k] = n;
    }
    return out;
  },
  warnings(v) {
    if (!isList(v, 64)) return undefined;
    const out: Warning[] = [];
    for (const w of v) {
      if (!isObject(w) || !isWord(w.key) || !isInt(w.count)) return undefined;
      if (w.names === undefined) {
        out.push({ key: w.key, count: w.count });
        continue;
      }
      if (!isList(w.names, 16) || !w.names.every((n) => isText(n, 256))) return undefined;
      out.push({ key: w.key, count: w.count, names: w.names as string[] });
    }
    return out;
  },
  archive(v) {
    if (!isObject(v) || !isList(v.members)) return undefined;
    const members: ArchiveSnapshot["members"][number][] = [];
    for (const m of v.members) {
      const c = checkMember(m);
      if (!c) return undefined;
      members.push(c);
    }
    if (v.opening !== null && !isInt(v.opening)) return undefined;
    let opened: ArchiveSnapshot["opened"] = null;
    if (v.opened !== null) {
      const o = v.opened;
      const member = isObject(o) ? checkMember(o.member) : null;
      if (!isObject(o) || !member || !isText(o.name, MAX_PATH) || !(o.format === null || isText(o.format, 64)) || !isInt(o.session, 1)) return undefined;
      opened = { member, name: o.name, format: o.format, session: o.session };
    }
    let refused: ArchiveSnapshot["refused"] = null;
    if (v.refused !== null) {
      if (!isObject(v.refused) || !oneOf(v.refused.key, REFUSALS)) return undefined;
      refused = { key: v.refused.key };
    }
    return { members, opening: v.opening, opened, refused };
  },
  media(v) {
    if (!isObject(v) || !oneOf(v.kind, ["video", "audio"] as const)) return undefined;
    const flags = ["paused", "ended", "muted", "waiting", "blocked"] as const;
    if (!flags.every((f) => typeof v[f] === "boolean")) return undefined;
    const seconds = (n: unknown) => isFinite(n) && n >= 0;
    if (!seconds(v.currentTime) || !seconds(v.buffered) || !(isNumber(v.duration) && v.duration >= 0)) return undefined;
    if (!isFinite(v.volume) || v.volume < 0 || v.volume > 1 || !isFinite(v.rate) || v.rate <= 0 || v.rate > 16) return undefined;
    return {
      kind: v.kind,
      paused: v.paused as boolean,
      ended: v.ended as boolean,
      currentTime: v.currentTime as number,
      duration: v.duration,
      buffered: v.buffered as number,
      volume: v.volume,
      muted: v.muted as boolean,
      rate: v.rate,
      waiting: v.waiting as boolean,
      blocked: v.blocked as boolean,
    };
  },
  sheets(v) {
    if (!isObject(v) || !isList(v.items) || !isInt(v.current)) return undefined;
    const items: { index: number; name: string }[] = [];
    for (const i of v.items) {
      if (!isObject(i) || !isInt(i.index) || !isText(i.name)) return undefined;
      items.push({ index: i.index, name: i.name });
    }
    return { items, current: v.current };
  },
  pictures: (v) => (isObject(v) && isInt(v.count, 0, MAX_ITEMS) && oneOf(v.space, SPACES) ? { count: v.count, space: v.space } : undefined),
  viewport(v) {
    if (v === null) return null;
    if (!isObject(v) || !oneOf(v.space, SPACES) || !isInt(v.page, 1, MAX_ITEMS) || !(v.layout === undefined || isText(v.layout))) return undefined;
    if (!regionMatches(v.space, v.region)) return undefined;
    const region = v.region === undefined ? undefined : checkRegion(v.region);
    // Only a rectangle or a camera has a region; "frame" has none, and no viewport to follow.
    if (!region) return undefined;
    return { space: v.space, page: v.page, ...(v.layout !== undefined && { layout: v.layout }), region };
  },
};

/** The value of `key` if it has the shape that controller's store has, else undefined. */
export function checkSnapshot<K extends ControllerKey>(key: K, v: unknown): Snapshots[K] | undefined {
  return (CHECKS[key] as (v: unknown) => Snapshots[K] | undefined)(v);
}

export function checkStatics(v: unknown): Statics | null {
  if (!isObject(v)) return null;
  const out: Statics = {};
  if (v.pages !== undefined) {
    const p = v.pages;
    if (!isObject(p) || typeof p.goTo !== "boolean" || typeof p.step !== "boolean") return null;
    out.pages = { goTo: p.goTo, step: p.step };
  }
  if (v.ground !== undefined) {
    const g = v.ground;
    if (!isObject(g) || !isColor(g.light) || !isColor(g.dark)) return null;
    out.ground = { light: g.light, dark: g.dark };
  }
  return out;
}

/**
 * A frame message, checked whole, or null. A `controllers` message keeps only
 * the known keys whose value checks; any other key fails it.
 */
export function checkFrameMessage(v: unknown): FrameMessage | null {
  if (!isObject(v)) return null;
  switch (v.type) {
    case "ready": {
      if (!isInt(v.protocol)) return null;
      if (v.policy === null) return { type: "ready", protocol: v.protocol, policy: null };
      const policy = checkPolicy(v.policy);
      return policy ? { type: "ready", protocol: v.protocol, policy } : null;
    }
    case "status": {
      const status = checkStatus(v.status);
      return isInt(v.session) && status ? { type: "status", session: v.session, status } : null;
    }
    case "controllers": {
      if (!isInt(v.session) || !isObject(v.values)) return null;
      const statics = checkStatics(v.statics);
      if (!statics) return null;
      const values: Partial<Snapshots> = {};
      for (const [key, value] of Object.entries(v.values)) {
        if (!oneOf(key, CONTROLLER_KEYS)) return null;
        const checked = checkSnapshot(key, value);
        if (checked === undefined) return null;
        (values as Record<string, unknown>)[key] = checked;
      }
      return { type: "controllers", session: v.session, values, statics };
    }
    case "state": {
      if (!isInt(v.session) || !oneOf(v.key, CONTROLLER_KEYS)) return null;
      const value = checkSnapshot(v.key, v.value);
      return value === undefined ? null : { type: "state", session: v.session, key: v.key, value };
    }
    case "done":
      return isInt(v.call) && typeof v.ok === "boolean" ? { type: "done", call: v.call, ok: v.ok } : null;
    case "link":
      return isText(v.url, MAX_URL) ? { type: "link", url: v.url } : null;
    // Shapes only: whether a read is within the file and the limits is the host's to judge.
    case "read":
      return isInt(v.id) && isInt(v.generation) && isInt(v.offset) && isInt(v.length)
        ? { type: "read", id: v.id, generation: v.generation, offset: v.offset, length: v.length }
        : null;
    case "cancel":
      return isInt(v.id) ? { type: "cancel", id: v.id } : null;
    case "key":
      return oneOf(v.key, NAV_KEYS) && typeof v.shift === "boolean" && typeof v.repeat === "boolean" ? { type: "key", key: v.key, shift: v.shift, repeat: v.repeat } : null;
    case "replaced":
      return isInt(v.call) && typeof v.ok === "boolean" ? { type: "replaced", call: v.call, ok: v.ok } : null;
    case "rastered":
      return isInt(v.id) ? { type: "rastered", id: v.id, result: checkRasterResult(v.result) } : (closeBitmap(isObject(v.result) ? v.result.bitmap : undefined), null);
    default:
      return null;
  }
}

function closeBitmap(v: unknown): void {
  if (typeof ImageBitmap !== "undefined" && v instanceof ImageBitmap) v.close();
}

/**
 * A picture the frame sent, or the failure it stands for: one that is not
 * well formed (a bitmap that is none, past the limits, of another size than
 * it says) is closed and is a "failed". The page of the host that asked
 * checks the rest: its space, the size it asked for.
 */
function checkRasterResult(v: unknown): RasterResult {
  const fail: RasterResult = { ok: false, code: "failed" };
  if (!isObject(v)) return fail;
  if (v.ok === false) return isRasterErrorCode(v.code) ? { ok: false, code: v.code } : fail;
  const bad = (): RasterResult => (closeBitmap(v.bitmap), fail);
  if (v.ok !== true || !isPicture(v.bitmap)) return bad();
  const { bitmap } = v;
  if (v.width !== bitmap.width || v.height !== bitmap.height || !isInt(v.page, 1, MAX_ITEMS) || !oneOf(v.space, SPACES)) return bad();
  if (!(v.layout === undefined || isText(v.layout))) return bad();
  let region: RasterRegion | undefined;
  if (v.space !== "frame") {
    if (!regionMatches(v.space, v.region)) return bad();
    region = checkRegion(v.region);
    if (!region) return bad();
  } else if (v.region !== undefined) return bad();
  return {
    ok: true,
    bitmap,
    width: bitmap.width,
    height: bitmap.height,
    page: v.page,
    ...(v.layout !== undefined && { layout: v.layout }),
    space: v.space,
    ...(region && { region }),
  };
}

/** Lists of short words without markup: what a policy's sources look like. */
function checkPolicy(v: unknown): FramePolicy | null {
  if (!isObject(v)) return null;
  const out: Partial<FramePolicy> = {};
  for (const key of ["script", "connect", "img", "media"] as const) {
    const list = v[key];
    if (!isList(list, 64) || !list.every((s) => isText(s, 256) && /^[\x21-\x7e]+$/.test(s))) return null;
    out[key] = [...(list as string[])];
  }
  return out as FramePolicy;
}

/**
 * Whether the host may open `url` for the frame: an absolute http(s) URL.
 * Relative URLs are refused, as the frame has no base the host shares.
 */
export function linkTarget(url: string): string | null {
  try {
    const parsed = new URL(url);
    return parsed.protocol === "http:" || parsed.protocol === "https:" ? parsed.href : null;
  } catch {
    return null;
  }
}

// ── The frame's checks of what the host sends ────────────────────────────────

const num = (v: unknown) => (isFinite(v) ? v : undefined);
const colors = (v: unknown) => (isObject(v) && isColor(v.light) && isColor(v.dark) ? { light: v.light, dark: v.dark } : undefined);
const ground = (v: unknown) => (oneOf(v, ["light", "dark"] as const) ? v : undefined);

/** Drops `undefined` values, so that a plugin's defaults apply. */
function defined<T extends Record<string, unknown>>(o: T): T {
  return Object.fromEntries(Object.entries(o).filter(([, v]) => v !== undefined)) as T;
}

/** The options the frame will use: known keys of the right type, the rest dropped. */
export function checkOptions(v: unknown): FrameOptions {
  const out: FrameOptions = {};
  const { pdf, image, cad, ifc, model, archive, conversion, media } = isObject(v) ? v : {};
  if (isObject(pdf))
    out.pdf = defined({
      minZoom: num(pdf.minZoom),
      maxZoom: num(pdf.maxZoom),
      prerenderMargin: typeof pdf.prerenderMargin === "string" && /^\d{1,4}(px|%)$/.test(pdf.prerenderMargin) ? pdf.prerenderMargin : undefined,
      pageMaxPixels: num(pdf.pageMaxPixels),
      detailMaxPixels: num(pdf.detailMaxPixels),
      outlineMaxDepth: num(pdf.outlineMaxDepth),
      outlineMaxEntries: num(pdf.outlineMaxEntries),
    });
  if (isObject(image))
    out.image = defined({
      minScale: num(image.minScale),
      maxScale: num(image.maxScale),
      wheelStep: num(image.wheelStep),
      detailDelayMs: num(image.detailDelayMs),
      detailMargin: num(image.detailMargin),
      detailMaxPixels: num(image.detailMaxPixels),
      maxDecodeBytes: num(image.maxDecodeBytes),
    });
  if (isObject(cad))
    out.cad = defined({
      ground: ground(cad.ground),
      colors: colors(cad.colors),
      timeoutMs: num(cad.timeoutMs),
      maxPrimitives: num(cad.maxPrimitives),
      maxDecompressedBytes: num(cad.maxDecompressedBytes),
      lineweights: oneOf(cad.lineweights, ["drawing", "always", "never"] as const) ? cad.lineweights : undefined,
      monochrome: typeof cad.monochrome === "boolean" ? cad.monochrome : undefined,
    });
  if (isObject(ifc))
    out.ifc = defined({
      ground: ground(ifc.ground),
      colors: colors(ifc.colors),
      highlight: isColor(ifc.highlight) ? ifc.highlight : undefined,
      timeoutMs: num(ifc.timeoutMs),
      maxTriangles: num(ifc.maxTriangles),
    });
  if (isObject(model))
    out.model = defined({
      surface: num(model.surface),
      zUp: typeof model.zUp === "boolean" ? model.zUp : undefined,
      timeoutMs: num(model.timeoutMs),
      maxTriangles: num(model.maxTriangles),
    });
  if (isObject(archive))
    out.archive = defined({
      maxExtractedBytes: num(archive.maxExtractedBytes),
      maxMembers: num(archive.maxMembers),
      maxCompressionRatio: num(archive.maxCompressionRatio),
    });
  if (isObject(conversion)) {
    const converter = oneOf(conversion.converter, ["exav", "external"] as const) ? conversion.converter : undefined;
    // A package name the asset manifest lists, or a path or an http(s) URL.
    const external = conversion.externalConverter;
    const externalConverter =
      typeof external === "string" &&
      (/^(@[a-z0-9._-]{1,64}\/)?[a-z0-9._-]{1,64}$/.test(external) || /^(\.{0,2}\/|https?:\/\/)[^\s\u0000-\u001f\u007f]{1,500}$/.test(external))
        ? external
        : undefined;
    out.conversion = defined({ timeoutMs: num(conversion.timeoutMs), maxMemory: num(conversion.maxMemory), converter, externalConverter });
  }
  if (isObject(media)) out.media = defined({ controls: oneOf(media.controls, ["native", "none"] as const) ? media.controls : undefined });
  return out;
}

/** The first message the frame takes: an `open`, checked, or null. */
export function checkOpen(v: unknown, known: readonly BuiltinFormat[]): OpenMessage | null {
  if (!isObject(v) || v.type !== "open" || !isObject(v.file) || !isList(v.formats, 64)) return null;
  const source = checkSource(v.source);
  if (!source) return null;
  const formats = v.formats.filter((f): f is BuiltinFormat => oneOf(f, known));
  const f = v.file;
  if (!isText(f.name, MAX_PATH) || !isText(f.type, 256) || !isText(f.path, MAX_PATH)) return null;
  const format = f.format === null ? null : oneOf(f.format, known) ? f.format : undefined;
  if (format === undefined) return null;
  return { type: "open", formats, file: { name: f.name, type: f.type, path: f.path, format }, source, options: checkOptions(v.options), theme: checkTheme(v.theme) };
}

function checkSource(v: unknown): OpenSource | null {
  if (!isObject(v)) return null;
  switch (v.kind) {
    case "blob":
      return v.blob instanceof Blob ? { kind: "blob", blob: v.blob } : null;
    case "url": {
      const url = isText(v.url, MAX_URL) ? linkTarget(v.url) : null;
      return url ? { kind: "url", url } : null;
    }
    case "ranges":
      return isInt(v.size, 1) && v.head instanceof ArrayBuffer && v.head.byteLength === Math.min(v.size, READS.head)
        ? { kind: "ranges", size: v.size, head: v.head }
        : null;
    default:
      return null;
  }
}

export function checkBytes(v: unknown): BytesMessage | null {
  if (!isObject(v) || v.type !== "bytes" || !isInt(v.id)) return null;
  if (v.data instanceof ArrayBuffer) return { type: "bytes", id: v.id, data: v.data };
  return oneOf(v.error, ["refused", "failed"] as const) ? { type: "bytes", id: v.id, error: v.error } : null;
}

export function checkCommand(v: unknown): CommandMessage | null {
  if (!isObject(v) || v.type !== "command" || !isInt(v.call) || !isInt(v.session) || !isText(v.action, 32) || !isList(v.args, 4)) return null;
  if (!oneOf(v.target, COMMAND_TARGETS)) return null;
  return { type: "command", call: v.call, session: v.session, target: v.target, action: v.action, args: v.args };
}

export function checkThemeMessage(v: unknown): ThemeMessage | null {
  return isObject(v) && v.type === "theme" ? { type: "theme", theme: checkTheme(v.theme) } : null;
}

/** A `raster`: a page and well-formed options; sizes are checked against the limits where the picture is drawn. */
export function checkRaster(v: unknown): RasterMessage | null {
  if (!isObject(v) || v.type !== "raster" || !isInt(v.id) || !isInt(v.session) || !isInt(v.page, 1)) return null;
  const options = checkRasterOptions(v.options);
  return options ? { type: "raster", id: v.id, session: v.session, page: v.page, options } : null;
}

/**
 * The id of a message that claims to be a `raster` but is not one `checkRaster`
 * takes, or null: the frame still owes it an answer.
 */
export function refusedRasterId(v: unknown): number | null {
  return isObject(v) && v.type === "raster" && isInt(v.id) && !checkRaster(v) ? v.id : null;
}

export function checkUnraster(v: unknown): UnrasterMessage | null {
  return isObject(v) && v.type === "unraster" && isInt(v.id) ? { type: "unraster", id: v.id } : null;
}

export function checkWatch(v: unknown): WatchMessage | null {
  if (!isObject(v) || (v.type !== "watch" && v.type !== "unwatch") || !isInt(v.session) || !oneOf(v.key, WATCHED_KEYS)) return null;
  return { type: v.type, session: v.session, key: v.key };
}

/** A `replace`, its file and source checked as an `open`'s are. */
export function checkReplace(v: unknown, known: readonly BuiltinFormat[]): ReplaceMessage | null {
  if (!isObject(v) || v.type !== "replace" || !isInt(v.call) || !isInt(v.generation, 1) || !isObject(v.file)) return null;
  const source = checkSource(v.source);
  const f = v.file;
  if (!source || !isText(f.name, MAX_PATH) || !isText(f.type, 256) || !isText(f.path, MAX_PATH)) return null;
  const format = f.format === null ? null : oneOf(f.format, known) ? f.format : undefined;
  if (format === undefined) return null;
  return { type: "replace", call: v.call, generation: v.generation, file: { name: f.name, type: f.type, path: f.path, format }, source };
}
