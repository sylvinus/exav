import { CONTAINER_TYPES, UNKNOWN_TYPES } from "./formats.js";
import type { FilePart } from "./source.js";
import type { DetectionTable, Detector, FileInfo, FormatId, FormatMatcher, Inspection, PackageLimits, ViewerFile } from "./types.js";
import { END_TAIL, readFromTail } from "./zip-tail.js";

/**
 * Whether the first bytes of `file` are read to tell what it is: no format
 * is given, there is a source, and `headBytes` (`sniffBytes`) is not 0. For
 * an address the head is a range request of its own.
 */
export function readsHead(file: Pick<ViewerFile, "format" | "kind" | "source">, headBytes: number = HEAD_BYTES): boolean {
  return headBytes > 0 && file.format === undefined && file.kind !== "link" && !!file.source;
}

/**
 * Bytes read from the start of a file to tell what it is (`sniffBytes`).
 * Enough for every signature exav's detection reads but a virtual disk's
 * (VHDX, which needs 192 KiB), and for an ISO 9660 image's, 32 KiB in.
 */
export const HEAD_BYTES = 64 * 1024;

/** `n` if it is a whole number of bytes (0: no file is told by its bytes), else throws. */
export function checkSniffBytes(n: number | undefined): number {
  if (n === undefined) return HEAD_BYTES;
  if (!Number.isSafeInteger(n) || n < 0) throw new RangeError(`sniffBytes: a whole number of bytes, 0 for none, not ${String(n)}`);
  return n;
}

/**
 * How long a detection may take before it is not waited for
 * (`sniffTimeoutMs`). It takes moments.
 */
export const DEFAULT_SNIFF_TIMEOUT_MS = 30_000;

/** `ms` if it is a number of milliseconds (0: no timeout), else throws. */
export function checkSniffTimeout(ms: number | undefined): number {
  if (ms === undefined) return DEFAULT_SNIFF_TIMEOUT_MS;
  if (!Number.isFinite(ms) || ms < 0) throw new RangeError(`sniffTimeoutMs: a number of milliseconds, 0 for no timeout, not ${String(ms)}`);
  return ms;
}

/**
 * The limits on a ZIP's directory when the host gives none. The members are
 * the Office plugins' own default (`maxArchiveEntries`), the bytes the
 * `archive()` plugin's, and the ratio the scanner's (`--max-compression-ratio`).
 */
export const DEFAULT_PACKAGE_LIMITS: PackageLimits = { maxExtractedBytes: 512 * 1024 * 1024, maxMembers: 20_000, maxCompressionRatio: 1000 };

/** The limits of `config` over the defaults; each a whole number, 0 for none, else throws. */
export function checkPackageLimits(config: Partial<PackageLimits>): PackageLimits {
  const out = { ...DEFAULT_PACKAGE_LIMITS };
  for (const key of Object.keys(out) as (keyof PackageLimits)[]) {
    const n = config[key];
    if (n === undefined) continue;
    if (!Number.isSafeInteger(n) || n < 0) throw new RangeError(`${key}: a whole number, 0 for no limit, not ${String(n)}`);
    out[key] = n;
  }
  return out;
}

/**
 * The formats whose files are a ZIP exav-unpack's reader opens, which
 * `Detector.exceeds` looks at: the ones `src/sniff/inspect.rs` checks as ZIP
 * packages (`packageKinds` of the sniff module, which a test compares). Kept
 * here because `checksDirectory` is synchronous and decides whether the
 * module is asked at all: each request loads it in a worker of its own.
 */
export const PACKAGE_FORMATS: ReadonlySet<FormatId> = new Set(["docx", "xlsx", "pptx", "odt", "ods", "odp", "odg", "visio", "keynote", "numbers", "archive"]);

/** Whether `Detector.exceeds` looks at files of format `kind` under `limits`: a ZIP-based format, and some limit set. */
export function checksDirectory(kind: FormatId, limits: PackageLimits): boolean {
  return PACKAGE_FORMATS.has(kind) && (limits.maxExtractedBytes !== 0 || limits.maxMembers !== 0 || limits.maxCompressionRatio !== 0);
}

/**
 * What exav's detection says of the start of a file of `size` bytes: a
 * content type, or "" when the bytes prove none the viewer opens.
 */
export type Sniffer = (head: Uint8Array, size: number, signal?: AbortSignal) => Promise<string>;

/** What exav's readers found (`inspect` of exav_viewer_sniff.wasm). */
export interface Finding {
  /** An `Inspection`, "needs-tail" when the format keeps its directory at the end, or a limit passed. */
  verdict: Inspection | "needs-tail" | "too-large" | "too-compressed" | "too-many-entries";
  /** With "needs-tail": the offset from which the reader needs the bytes, else -1. */
  needs: number;
  /** With a limit: exav-unpack's reason for it. */
  reason: string;
}

/**
 * What exav's readers find of a file named as format `kind`, from its first
 * bytes, and from its last where `tail` is not empty. `limits` are those of a
 * ZIP's directory.
 */
export type Inspector = (kind: FormatId, head: Uint8Array, tail: Uint8Array, size: number, limits: PackageLimits, signal?: AbortSignal) => Promise<Finding>;

/** What exav's reader made of a ZIP's last bytes (`zipOfficeKinds` of exav_viewer_sniff.wasm). */
export interface OfficeFinding {
  /** The offset from which the reader needs the file's bytes, else -1. */
  needs: number;
  /** The Office formats the members of the directory say the ZIP may be (`officeKinds`); none while the reader needs bytes. */
  kinds: readonly string[];
}

/** What the members of a ZIP say it may be, from its first bytes and its last (empty until asked for). */
export type Officer = (head: Uint8Array, tail: Uint8Array, size: number, signal?: AbortSignal) => Promise<OfficeFinding>;

/**
 * The plugin a ZIP is opened with for each format `officeKinds` can name,
 * when only its members tell. iWork is left out: its members are told apart
 * by names that a ZIP of another kind has as well (`index.xml`).
 */
const OFFICE_PLUGINS: Readonly<Record<string, FormatId>> = { docx: "docx", xlsx: "xlsx", pptx: "pptx", odt: "odt", ods: "ods", odp: "odp", odg: "odg", vsdx: "visio" };

/** The content type exav's detection gives a ZIP. */
const ZIP_TYPE = "application/zip";

/** No engine: the bytes say nothing. */
const none: Sniffer = async () => "";
const NOT_INSPECTED: Finding = { verdict: "not-inspected", needs: -1, reason: "" };
const noInspector: Inspector = async () => NOT_INSPECTED;
const noOfficer: Officer = async () => ({ needs: -1, kinds: [] });
const NO_LIMITS: PackageLimits = { maxExtractedBytes: 0, maxMembers: 0, maxCompressionRatio: 0 };
const NO_BYTES = new Uint8Array();

interface Entry {
  id: FormatId;
  match: FormatMatcher;
}

/**
 * Detection over these plugins' matchers, in their order. The steps are on
 * `FormatMatcher`. `sniffer` reads the start of a file and `inspector`
 * looks for what is wrong with one that failed to open (`createViewer` gives
 * the ones that run exav's detection in a worker); without them, only a name
 * and a type say what a file is, and no file is inspected. `headBytes` is
 * `sniffBytes`; `limits` are those of a ZIP's directory (`exceeds`).
 * `officer` reads what the members of a ZIP say it is (`detectFile`); without
 * one, a ZIP is what its name and type say.
 */
export function createDetector(
  entries: readonly Entry[],
  sniffer: Sniffer = none,
  inspector: Inspector = noInspector,
  headBytes: number = HEAD_BYTES,
  limits: PackageLimits = DEFAULT_PACKAGE_LIMITS,
  officer: Officer = noOfficer,
): Detector {
  const unknown = new Set(UNKNOWN_TYPES);
  const containers = new Set([...CONTAINER_TYPES, ...entries.flatMap((e) => e.match.containerTypes ?? [])]);
  const matchers = new Map(entries.map((e) => [e.id, e.match] as const));

  const detect = (info: Pick<FileInfo, "type" | "path" | "name" | "kind">): FormatId | null => {
    if (info.kind === "link") return null;
    const type = (info.type ?? "").toLowerCase().split(";")[0]!.trim();
    const path = (info.path ?? info.name ?? "").toLowerCase();

    for (const e of entries) if (e.match.types?.includes(type)) return e.id;

    for (const e of entries) {
      const overrides = e.match.extensionOverrides ?? [];
      const allowed =
        unknown.has(type) ||
        (containers.has(type) && overrides.includes("container")) ||
        overrides.includes(type);
      if (allowed && e.match.extensions?.some((ext) => path.endsWith(ext))) return e.id;
    }

    for (const e of entries) if (e.match.containerTypes?.includes(type)) return e.id;
    return null;
  };

  /** Whether a file of format `id` can be what the bytes say `type` is: a .docx is a zip. */
  const canBe = (id: FormatId, type: string): boolean => {
    const m = matchers.get(id);
    if (!m) return false;
    return !!(m.types?.includes(type) || m.containerTypes?.includes(type) || (containers.has(type) && m.extensionOverrides?.includes("container")));
  };

  const sniff: Detector["sniff"] = async (head, size = head.length, signal) => (headBytes > 0 ? sniffer(head.subarray(0, headBytes), size, signal) : "");

  /** What the readers find of the file, asking for the end of it as they need it, under `bound`. */
  const examine = async (kind: FormatId, head: Uint8Array, size: number, tail: (length: number) => Promise<FilePart | null>, bound: PackageLimits, signal?: AbortSignal): Promise<Finding> => {
    try {
      // A file that fits in `head` has its end there.
      const whole = head.length >= size;
      const first = await inspector(kind, head, whole ? head : NO_BYTES, size, bound, signal);
      if (first.verdict !== "needs-tail" || whole) return first.verdict === "needs-tail" ? NOT_INSPECTED : first;
      const found = await readFromTail<Finding>(END_TAIL, tail, async (end) => {
        const next = await inspector(kind, head, end.bytes, end.size, bound, signal);
        if (next.verdict !== "needs-tail") return { done: true, value: next };
        return next.needs >= 0 ? { done: false, needs: next.needs } : { done: true, value: NOT_INSPECTED };
      });
      return found ?? NOT_INSPECTED;
    } catch (error) {
      if (signal?.aborted) throw error;
      console.warn("detect: the file could not be inspected", error);
      return NOT_INSPECTED;
    }
  };

  // No limit applies to a file that failed to open: it was not refused for one.
  const inspect: Detector["inspect"] = async (kind, head, size, tail, signal) => {
    const found = await examine(kind, head, size, tail, NO_LIMITS, signal);
    return found.verdict as Inspection;
  };

  const exceeds: Detector["exceeds"] = async (kind, head, size, tail, signal) => {
    if (!checksDirectory(kind, limits)) return null;
    const { verdict, reason } = await examine(kind, head, size, tail, limits, signal);
    const code = verdict === "too-large" ? "too_large" : verdict === "too-compressed" ? "too_compressed" : verdict === "too-many-entries" ? "too_many_entries" : null;
    return code && { code, reason };
  };

  /** The one plugin the members of the ZIP say it is, else null. */
  const packaged = async (head: Uint8Array, size: number, tail: (length: number) => Promise<FilePart | null>, signal?: AbortSignal): Promise<FormatId | null> => {
    try {
      // A file that fits in `head` has its end there.
      const fetch = head.length >= size ? async () => ({ bytes: head, size }) : tail;
      const kinds = await readFromTail<readonly string[]>(END_TAIL, fetch, async (end) => {
        const found = await officer(head, end.bytes, end.size, signal);
        return found.needs < 0 ? { done: true, value: found.kinds } : { done: false, needs: found.needs };
      });
      const plugins = new Set<FormatId>();
      for (const kind of kinds ?? []) {
        const id = OFFICE_PLUGINS[kind];
        if (id !== undefined) plugins.add(id);
      }
      const [only] = plugins;
      return plugins.size === 1 && only !== undefined && matchers.has(only) ? only : null;
    } catch (error) {
      if (signal?.aborted) throw error;
      console.warn("detect: the members of the ZIP could not be read, it is an archive", error);
      return null;
    }
  };

  const detectFile: Detector["detectFile"] = async (info, head, size, signal, tail) => {
    if (info.kind === "link") return null;
    const named = detect(info);
    let type = "";
    try {
      type = await sniff(head, size, signal);
    } catch (error) {
      if (signal?.aborted) throw error;
      console.warn("detect: the first bytes could not be read, the name and the type decide", error);
    }
    // The bytes say nothing the viewer opens: the name and the type do.
    if (!type) return named;
    // As if the host had sent the type the bytes give.
    const byBytes = detect({ ...info, type });
    const found = byBytes === named || (named !== null && canBe(named, type)) ? named : byBytes;
    // A ZIP no name claims for another format is what its members say.
    if (found !== "archive" || type !== ZIP_TYPE || !tail || (named !== null && named !== "archive")) return found;
    return (await packaged(head, size ?? head.length, tail, signal)) ?? found;
  };

  return {
    detect,
    sniff,
    headBytes,
    inspect,
    limits,
    exceeds,
    detectFile,
    detectBytes: (name, head, size, signal) => detectFile({ name, path: name, type: "" }, head, size, signal),
    table(): DetectionTable {
      return {
        formats: entries.map((e) => ({ id: e.id, matcher: e.match })),
        unknownTypes: UNKNOWN_TYPES,
        containerTypes: CONTAINER_TYPES,
      };
    },
  };
}
