/** Bounds on what an archive may cost to open and extract. */
export interface Limits {
  /** Total decompressed bytes across the whole archive. */
  maxExtractedBytes?: number;
  /** The most bytes any single buffered object may hold at once. */
  maxBufferBytes?: number;
  /** Number of members. */
  maxMembers?: number;
  /** How deep an archive inside an archive may nest. */
  maxRecursion?: number;
  /** Largest decompressed:compressed ratio tolerated. */
  maxCompressionRatio?: number;
  /**
   * Formats that may be opened, named as `detectFormat` reports them. Anything
   * absent is refused rather than extracted. An unknown name is ignored, so a
   * page pinned to an older build does not fail for naming a format it lacks.
   */
  allowedFormats?: string[];
}

/** One member's metadata, without its contents. */
export interface MemberInfo {
  name: string;
  index: number;
  compressedSize: number;
  uncompressedSize: number;
  encrypted: boolean;
}

/** One extracted member. */
export interface Entry {
  name: string;
  /** The member's contents. */
  bytes: Uint8Array;
  /** The same contents as a stream. A fresh stream on every access. */
  readonly data: ReadableStream<Uint8Array>;
  encrypted: boolean;
  /**
   * Empty when the member decoded. Otherwise why it did not — unsupported
   * compression, a missing password, a limit reached. The member is still
   * reported: a container whose contents could not be read is not an empty
   * container.
   */
  unsupported: string;
}

/**
 * A caller-supplied source over bytes the caller owns, read in-process with no
 * Worker. `read` is SYNCHRONOUS — it returns bytes, not a Promise of them —
 * because the archive readers beneath it are `Read + Seek`.
 */
export interface SyncReader {
  read(offset: number, length: number): Uint8Array;
  size: number;
}

export interface OpenOptions {
  /**
   * A Worker to use instead of one created here, for bundlers that cannot
   * resolve `new URL("./worker.js", import.meta.url)`.
   */
  worker?: Worker;
}

/**
 * An open archive.
 *
 * A `File` is read a piece at a time inside a Worker and never held whole; a
 * `Uint8Array` is read in-process, since it is already in memory.
 */
export class Archive {
  static open(
    source: Blob | File | Uint8Array | ArrayBuffer | SyncReader,
    limits?: Limits,
    options?: OpenOptions,
  ): Promise<Archive>;
  /** The detected format's name. Known since `open`. */
  format(): string;
  /**
   * Every member's metadata. Where the archive carries an index this extracts
   * nothing; an index-less single stream (gzip, xz) is walked once — taking
   * `passwords`, costing what `extractAll` costs — and the walk is kept.
   */
  list(passwords?: string[]): Promise<MemberInfo[]>;
  /** Extract one member by index. */
  extract(index: number, passwords?: string[]): Promise<Entry>;
  /**
   * Extract every member, under one budget for the whole archive. Where a limit
   * stops the walk, the last entry says so rather than the list simply ending.
   */
  extractAll(passwords?: string[]): Promise<Entry[]>;
  /** Release the archive and the reader behind it. Safe to call twice. */
  close(): Promise<void>;
}

/** Extract every member from bytes already in memory. */
export function unpack(
  data: Uint8Array | ArrayBuffer,
  passwords?: string[],
  limits?: Limits,
): Promise<Entry[]>;

/** The archive/container format these magic bytes name, if any. */
export function detectFormat(data: Uint8Array): string | undefined;

/** Rejoin the multi-volume archives among a group of files. */
export function joinVolumes(
  files: { name: string; data: Uint8Array }[],
): { name: string; data: Uint8Array; parts: string[]; incomplete: string | null }[];

/** Whether a filename marks one part of a byte-split archive (`big.7z.001`). */
export function isVolumePart(name: string): boolean;

/** Instantiate the wasm module. Memoised; awaited internally by every call. */
export default function init(module_or_path?: unknown): Promise<unknown>;
