/**
 * The messages between a host page and the sandboxed frame (`frame/app/`).
 *
 * The host opens a MessageChannel and hands one port to the frame in its only
 * `window.postMessage`; everything else goes over the port. Each side checks
 * what it receives against the shapes below and drops what does not match:
 * the host treats every frame message as untrusted, since the frame runs the
 * parsers.
 */
import type { BuiltinFormat, LayerItem, OutlineEntry, Selection } from "../core/types.js";
import type { FramePolicy } from "./policy.js";

/** Bumped on any change to the messages; both sides must agree. */
export const PROTOCOL = 3;

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
  cad?: { ground?: "light" | "dark"; colors?: { light: string; dark: string }; timeoutMs?: number; maxPrimitives?: number; maxDecompressedBytes?: number };
  ifc?: { ground?: "light" | "dark"; colors?: { light: string; dark: string }; highlight?: string; timeoutMs?: number; maxTriangles?: number };
  model?: { surface?: number; zUp?: boolean; timeoutMs?: number; maxTriangles?: number };
  archive?: { maxExtractedBytes?: number; maxMembers?: number; maxCompressionRatio?: number };
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
}

/** The answer to a `read`: the bytes, exactly as many as asked (fewer only at the end of the file), or why not. */
export type BytesMessage = { type: "bytes"; id: number; data: ArrayBuffer } | { type: "bytes"; id: number; error: "refused" | "failed" };

export type CommandTarget = "pages" | "zoom" | "drag" | "outline" | "layers" | "layouts" | "ground" | "archive";

export interface CommandMessage {
  type: "command";
  /** Answered by a `done` with the same number. */
  call: number;
  session: number;
  target: CommandTarget;
  action: string;
  args: readonly unknown[];
}

export type HostMessage = OpenMessage | CommandMessage | BytesMessage;

// ── Frame to host ────────────────────────────────────────────────────────────

export type StatusSnapshot =
  | { phase: "loading" | "converting"; progress?: number }
  | { phase: "ready"; partial?: boolean }
  | { phase: "empty" }
  | { phase: "error"; code: ErrorCode };

export type ErrorCode = "pdf" | "image" | "drawing" | "drawing_version" | "office" | "media" | "model" | "archive" | "file";

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
  layouts: { items: readonly { id: string; name: string; isModel: boolean }[]; current: string };
  ground: "light" | "dark";
  selection: Selection | null;
  info: Record<string, number>;
  warnings: readonly { key: string; count: number }[];
  archive: ArchiveSnapshot;
}

export type ControllerKey = keyof Snapshots;

export const CONTROLLER_KEYS: readonly ControllerKey[] = ["pages", "zoom", "drag", "outline", "layers", "layouts", "ground", "selection", "info", "warnings", "archive"];

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
  /** Bytes of a file read by ranges, answered by a `bytes` with the same id. */
  | { type: "read"; id: number; offset: number; length: number }
  /** A read no longer wanted. Its `bytes` still comes. */
  | { type: "cancel"; id: number };

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

/**
 * A colour the host may put in a style: hex, or rgb()/hsl() of plain
 * numbers. Anything else could be `url(...)`, a request the frame chose.
 */
export function isColor(v: unknown): v is string {
  if (typeof v !== "string" || v.length > 64) return false;
  return /^#[0-9a-f]{3,8}$/i.test(v) || /^(rgb|hsl)a?\(\s*[\d.]+%?(\s*[\s,/]\s*[\d.]+%?){2,3}\s*\)$/i.test(v);
}

const ERROR_CODES: readonly ErrorCode[] = ["pdf", "image", "drawing", "drawing_version", "office", "media", "model", "archive", "file"];
const REFUSALS = ["archive_no_reader", "archive_failed_member", "archive_member_encrypted", "archive_member_unsupported"] as const;

export function checkStatus(v: unknown): StatusSnapshot | null {
  if (!isObject(v)) return null;
  const progress = v.progress === undefined || (isFinite(v.progress) && v.progress >= 0 && v.progress <= 1);
  switch (v.phase) {
    case "loading":
    case "converting":
      return progress ? { phase: v.phase, ...(v.progress !== undefined && { progress: v.progress as number }) } : null;
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
    const out: { key: string; count: number }[] = [];
    for (const w of v) {
      if (!isObject(w) || !isWord(w.key) || !isInt(w.count)) return undefined;
      out.push({ key: w.key, count: w.count });
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
      return isInt(v.id) && isInt(v.offset) && isInt(v.length) ? { type: "read", id: v.id, offset: v.offset, length: v.length } : null;
    case "cancel":
      return isInt(v.id) ? { type: "cancel", id: v.id } : null;
    default:
      return null;
  }
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
  const { pdf, image, cad, ifc, model, archive } = isObject(v) ? v : {};
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
  return { type: "open", formats, file: { name: f.name, type: f.type, path: f.path, format }, source, options: checkOptions(v.options) };
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
  if (!oneOf(v.target, ["pages", "zoom", "drag", "outline", "layers", "layouts", "ground", "archive"] as const)) return null;
  return { type: "command", call: v.call, session: v.session, target: v.target, action: v.action, args: v.args };
}
