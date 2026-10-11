import type { Store } from "./store.js";

/** A rectangle in fractions of a page (0..1). */
export interface Region {
  x: number;
  y: number;
  width: number;
  height: number;
}

// ── Files ────────────────────────────────────────────────────────────────────

export type BuiltinFormat =
  | "pdf"
  | "image"
  | "docx"
  | "xlsx"
  | "pptx"
  | "csv"
  | "dwg"
  | "dxf"
  | "ifc"
  | "stl"
  | "video"
  | "audio"
  | "archive";

/** Format ids are the plugin ids. A host's own plugins may add more. */
export type FormatId = BuiltinFormat | (string & {});

/**
 * Where the bytes come from. Engines that stream (pdf.js, `<video>`) take a
 * URL as it is; the others read the whole file through the `SourceReader`.
 */
export type FileSource =
  | { url: string; init?: RequestInit }
  | { blob: Blob }
  | { bytes: Uint8Array }
  /** Read a piece at a time: PDF and ZIP open from what they need, the others read it all. */
  | { ranges: ByteRanges }
  /** Resolved when the file is opened, for a URL that is signed on demand. */
  | { resolve: (signal: AbortSignal) => Promise<string | Blob | Uint8Array> };

/** A file read by offset, on demand. */
export interface ByteRanges {
  /** In bytes. */
  readonly size: number;
  /** `length` bytes at `offset`, fewer only past the end of the file. */
  read(offset: number, length: number, signal: AbortSignal): Promise<Uint8Array>;
}

/** What the host knows before any byte is read. */
export interface FileInfo {
  /** Stable per file. A new id is a new session: a fresh engine, the old one freed. */
  id: string;
  /** Display name. The extension is read from it only when `path` is absent. */
  name: string;
  /**
   * The content type the host trusts. "", "application/octet-stream" and
   * "binary/octet-stream" mean unknown, and the extension decides.
   */
  type?: string;
  /**
   * Where the extension is read from when the type does not settle it: a
   * storage key, say, which a user cannot rename. Defaults to `name`.
   */
  path?: string;
  /** A link has no bytes: detection answers null. */
  kind?: "file" | "link";
  size?: number;
}

export interface ViewerFile<Meta = unknown> extends FileInfo {
  /** `null` while the host has nothing to show yet; see `placeholder`. */
  source: FileSource | null;
  /**
   * Shown instead of a surface while `source` is null. "pending": the bytes
   * will arrive. "unavailable": they will not on this device. `label`
   * replaces the default message.
   */
  placeholder?: { state: "pending" | "unavailable"; label?: string };
  /** A format to use instead of detecting one. */
  format?: FormatId;
  /** Free data for plugin options resolved per file (markers, detail source...). */
  meta?: Meta;
}

/** Reads the source once per session; cancelled and revoked when the session ends. */
export interface SourceReader {
  /** A URL an engine can fetch. For blob and byte sources, an object URL the session owns. */
  url(): Promise<string>;
  blob(): Promise<Blob>;
  /** The whole file. Office documents need it: `blob:` URLs answer no range requests. */
  bytes(): Promise<Uint8Array>;
  /** Fetch progress, `total` when the size is known. */
  progress: Store<{ loaded: number; total: number | null } | null>;
}

// ── Detection ────────────────────────────────────────────────────────────────

/** One magic-byte signature. */
export interface Signature {
  /** The content type these bytes prove. */
  type: string;
  prefix: readonly number[];
  offset?: number;
  also?: readonly number[];
  alsoOffset?: number;
}

/**
 * How a plugin claims files. Detection is data, so the table can be exported
 * for a server-side copy (`Detector.table`).
 *
 *   0. `kind === "link"`: none.
 *   1. the type, exactly, against every plugin's `types`;
 *   2. the extension, against `extensions`, when the type is unknown, or is
 *      some plugin's container type and this plugin lists "container" in
 *      `extensionOverrides` (every .docx is a zip), or is one of the types
 *      this plugin lists there (a .csv typed `text/plain`);
 *   3. the type, exactly, against `containerTypes` (a zip is an archive);
 *   4. none.
 *
 * Plugins are tried in registration order within each step.
 */
export interface FormatMatcher {
  types?: readonly string[];
  /** Types this plugin claims only after the extension step. */
  containerTypes?: readonly string[];
  /** Lower case, with the dot: ".pdf". Matched with `endsWith`. */
  extensions?: readonly string[];
  /** Known types the extension may still answer over: "container", or types. */
  extensionOverrides?: readonly ("container" | (string & {}))[];
  /** Magic bytes, for files with no trusted type (archive members). */
  signatures?: readonly Signature[];
  /**
   * Rejects a sniffed type the bytes do not really back: a STEP file is an
   * IFC model only when its schema says so or its name ends in .ifc.
   */
  confirmSniff?(head: Uint8Array, name: string): boolean;
}

export interface Detector {
  /** From the host's metadata alone. Synchronous, to decide "viewer or new tab". */
  detect(info: Pick<FileInfo, "type" | "path" | "name" | "kind">): FormatId | null;
  /** From a name and the first bytes (`HEAD_BYTES` are enough). For archive members. */
  detectBytes(name: string, head: Uint8Array): FormatId | null;
  /** The content type the first bytes prove, or "". */
  sniff(head: Uint8Array): string;
  /** The whole table as JSON, for a server-side copy and its parity test. */
  table(): DetectionTable;
}

export interface DetectionTable {
  formats: { id: FormatId; matcher: Omit<FormatMatcher, "confirmSniff"> }[];
  /** The signatures `sniff` reads, in order, first match wins. */
  signatures: readonly Signature[];
  unknownTypes: readonly string[];
}

// ── Plugins ──────────────────────────────────────────────────────────────────

export type Capability =
  | "pages"
  | "zoom"
  | "drag"
  | "outline"
  | "layers"
  | "layouts"
  | "ground"
  | "selection"
  | "info"
  | "image-surface"
  | "nested";

export interface FormatPlugin<Options = unknown> {
  id: FormatId;
  match: FormatMatcher;
  capabilities: readonly Capability[];
  /** Options given to the factory, `pdf({ ... })`. */
  options: Options;
  /** Always a dynamic import: nothing heavy may be reachable before it. */
  load(): Promise<Renderer<Options>>;
  /**
   * What `Viewer.prefetch` fetches besides the engine's code, so the format
   * opens offline later: URLs relative to `assetBase`.
   */
  prefetch?(assetBase: string): Promise<readonly string[]>;
}

export interface Renderer<Options = unknown> {
  mount(host: HTMLElement, ctx: RenderContext<Options>): RendererHandle | Promise<RendererHandle>;
}

export interface RenderContext<Options = unknown> {
  file: ViewerFile;
  options: Options;
  source: SourceReader;
  /** Aborted when the file changes or the viewer closes. */
  signal: AbortSignal;
  /** Where the host publishes the assets copied by `@exav/viewer/vite`. */
  assetBase: string;
  status(next: Status): void;
  /** Publish controllers before mount resolves (the UI follows them at once). */
  controllers(next: Controllers): void;
  detector: Detector;
  /**
   * A session showing `file` in `host`, with the same plugins: what an
   * archive does for a member, and a plugin does that decodes a format and
   * shows the result as another one (HEIC drawn as an image).
   *
   * `forward`: this session's status and controllers become the nested
   * session's, as they change, so that the UI follows the nested file as if
   * it were this one. A plugin that wraps a file in another does not wire
   * them by hand.
   */
  mountNested(host: HTMLElement, file: ViewerFile, options?: { forward?: boolean }): Session;
}

/** What `RendererHandle.replace` is given: the next document of the session. */
export interface ReplaceContext {
  file: ViewerFile;
  source: SourceReader;
  /** Aborted when the session ends or another `replace` supersedes this one. */
  signal: AbortSignal;
}

export interface RendererHandle {
  /** The container changed size (a rail folded, a tablet rotated). */
  resize?(): void;
  /**
   * Show another document of the same format in place of this one, keeping
   * what the user set (zoom, scroll position): a report's preview redrawn
   * after an option changed. Absent when the engine cannot; the session then
   * starts over with a new one (`Session.replace` says so). It resolves once
   * the new document is shown, and rejects, leaving the old one, if it
   * cannot be.
   */
  replace?(next: ReplaceContext): Promise<void>;
  /** Free everything: workers, WebGL contexts, bitmaps, object URLs. */
  destroy(): void;
  controllers: Controllers;
}

// ── Status ───────────────────────────────────────────────────────────────────

export type Status =
  /**
   * `label`: what the plugin is doing, worded for the user in the host's
   * language, shown instead of the stock message (a host's plugin decoding
   * a photo is not "preparing the model").
   */
  | { phase: "loading"; progress?: number; label?: string }
  /** A step after the fetch that takes seconds and reports its progress. */
  | { phase: "converting"; progress?: number; label?: string }
  /**
   * `partial`: something reached the screen and the engine then failed (an
   * Office file that lays out seven pages and throws on an embedded object).
   * The surface stays; the error is logged, not shown.
   */
  | { phase: "ready"; partial?: boolean }
  /** Parsed, nothing to draw: an IFC of property sets, an STL with no triangles. */
  | { phase: "empty" }
  | { phase: "error"; error: ViewerError };

/** The codes the built-in plugins report; a plugin of the host may use its own. */
export type BuiltinErrorCode = "pdf" | "image" | "drawing" | "drawing_version" | "office" | "media" | "model" | "archive" | "file";

export interface ViewerError {
  /**
   * The message key is "error" for pdf, `error_<code>` otherwise, looked up
   * in the host's `translate` like any other: a host's own code, `heic`, is
   * worded by its table's `error_heic` (or by `message`, below).
   * `drawing_version`: a DWG of a release the engine does not read (R12
   * and older).
   */
  code: BuiltinErrorCode | (string & {});
  /** Worded for the user in the host's language, shown instead of the stock message for `code`. */
  message?: string;
  cause?: unknown;
}

// ── Controllers ──────────────────────────────────────────────────────────────

export interface Controllers {
  pages?: PagesController;
  zoom?: ZoomController;
  drag?: DragController;
  outline?: OutlineController;
  layers?: LayersController;
  layouts?: LayoutsController;
  ground?: GroundController;
  selection?: Store<Selection | null>;
  info?: Store<Record<string, number>>;
  image?: ImageSurface;
  archive?: ArchiveController;
  /**
   * What the user should know about what is shown, as message keys
   * (`warning_<key>`) and counts: what is left out of the picture (a
   * drawing's external references, part of a model too large), or, in the
   * sandboxed frame, that a file to be read by ranges was downloaded whole
   * (`source_read_whole`).
   */
  warnings?: Store<readonly { key: string; count: number }[]>;
}

/** PDF and DOCX report pages; PPTX reports slides and is stepped by buttons. */
export interface PagesController
  extends Store<{
    unit: "page" | "slide";
    /** 1-based. */
    current: number;
    total: number;
  } | null> {
  goTo?(page: number): void;
  next?(): Promise<void>;
  prev?(): Promise<void>;
}

export interface ZoomController extends Store<{ scale: number; min: number; max: number }> {
  /** `anchor` in container pixels; the centre by default. */
  setScale(scale: number, anchor?: { x: number; y: number }): void;
  fit(): void;
}

/**
 * What a mouse drag does on a document that scrolls (a PDF). `mode` is what
 * it does now: "pan" moves the page, as a hand does, "select" selects text.
 * `available` is whether there is a choice to make: a page larger than the
 * viewer, which is when dragging to pan is wanted. Below that, `mode` is
 * "select" whatever was chosen, and a toolbar has nothing to show.
 */
export interface DragController extends Store<{ mode: "pan" | "select"; available: boolean }> {
  /** The user's choice; it applies while `available`. */
  choose(mode: "pan" | "select"): void;
}

export interface OutlineEntry {
  title: string;
  /** 1-based. */
  page: number;
  /** 0 at the top level. */
  depth: number;
  /** Fraction of the page's height, or null for a destination with no position. */
  offset: number | null;
}

export interface OutlineController extends Store<readonly OutlineEntry[]> {
  /** Scrolls the heading under the eye, 12px below the top; the page top when `offset` is null. */
  goTo(entry: OutlineEntry): void;
}

export interface LayerItem {
  /** What `setVisible` takes: the layer name for CAD, the category for IFC. */
  id: string;
  name: string;
  /** CSS colour. */
  color: string;
  visible: boolean;
}

export interface LayersController
  extends Store<{
    /** Decides the labels: layers of a drawing, or categories of a model. */
    kind: "layers" | "categories";
    items: readonly LayerItem[];
  }> {
  setVisible(id: string, visible: boolean): void;
  setAll(visible: boolean): void;
}

export interface LayoutsController
  extends Store<{
    items: readonly { id: string; name: string; isModel: boolean }[];
    current: string;
  }> {
  /** The status is "loading" until the new layout is drawn. */
  select(id: string): Promise<void>;
}

export interface GroundController extends Store<"light" | "dark"> {
  /** Never fetches the file again, and keeps the layers hidden. */
  set(ground: "light" | "dark"): void;
  readonly colors: { light: string; dark: string };
}

/** IFC: the element last tapped. */
export interface Selection {
  name: string;
  category: string;
  /** The storey (or other spatial element) that contains it. */
  storey?: string;
}

export interface ArchiveMember {
  index: number;
  /** Verbatim from the archive. Sanitise before using it as a file name. */
  name: string;
  /** As the archive declares it; -1 where it declares none (a gzip or xz stream). */
  uncompressedSize: number;
  encrypted: boolean;
}

export interface ArchiveController
  extends Store<{
    /** Directories left out: the tree is in the names. */
    members: readonly ArchiveMember[];
    /** The index being extracted. */
    opening: number | null;
    /**
     * The member on screen: the file built for it, and the session showing
     * it, whose status and controllers the UI follows as for any file.
     */
    opened: { member: ArchiveMember; file: ViewerFile; session: Session } | null;
    /** Why the last member did not open, as a message key. */
    refused: { key: "archive_no_reader" | "archive_failed_member" | "archive_member_encrypted" | "archive_member_unsupported" } | null;
  }> {
  open(index: number): Promise<void>;
  /** Back to the list; frees the member. */
  back(): void;
}

// ── Image surface ────────────────────────────────────────────────────────────

/**
 * The image stage's transform. Screen = page * scale + (x, y), in container
 * CSS pixels; `page` is the image fitted to the container at scale 1.
 */
export interface ViewState {
  page: { width: number; height: number };
  container: { width: number; height: number };
  scale: number;
  x: number;
  y: number;
}

export interface ImageSurface extends Store<ViewState> {
  /** Fractions of the page under a client point, or null outside it. */
  toPage(clientX: number, clientY: number): { x: number; y: number } | null;
  /** Container pixels of a page fraction. */
  toScreen(fx: number, fy: number): { x: number; y: number };
  /**
   * The marker nearest to the container point `at` (a tap's `context.screen`)
   * within `radius` px (default 22), or null. Markers are placed by page
   * fractions, as `toScreen` takes them.
   */
  pick<T extends { x: number; y: number }>(markers: Iterable<T>, at: { x: number; y: number }, radius?: number): T | null;
  /**
   * Laid out in page pixels and transformed with the image: an overlay drawn
   * here pans and zooms with it. `--exv-scale` keeps a marker's screen size.
   */
  pageLayer: HTMLElement;
  /** Untransformed, above everything: HTML controls placed with `toScreen`. */
  screenLayer: HTMLElement;
}

/** Draws into an image surface's layers; `destroy` removes it. */
export interface OverlayHost {
  mount(surface: ImageSurface): { destroy(): void };
}

/**
 * Redraws part of the page sharp past the raster's resolution. `pageWidth`:
 * the whole page width in device pixels at the current zoom. A newer request
 * with the same `slot` supersedes an older one, which then resolves null. A
 * returned ImageBitmap is closed by the viewer.
 */
export type DetailSource = (request: {
  pageWidth: number;
  region: Region;
  slot: string;
  signal: AbortSignal;
}) => Promise<ImageBitmap | HTMLCanvasElement | null>;

// ── Viewer and sessions ──────────────────────────────────────────────────────

export interface ViewerConfig {
  plugins: readonly FormatPlugin<any>[];
  /** Where `@exav/viewer/vite` published the copied assets. Default "/exav-viewer/". */
  assetBase?: string;
}

export interface Viewer extends Detector {
  readonly plugins: readonly FormatPlugin<any>[];
  readonly assetBase: string;
  /** Renders `file` into `host`: one session per file id. */
  mount(host: HTMLElement, file: ViewerFile): Session;
  /** Fetches these formats' engines and assets without opening anything, for offline use. */
  prefetch(formats: readonly FormatId[]): Promise<void>;
}

export interface Session {
  /** The file on screen: the last one `replace` took. */
  readonly file: ViewerFile;
  readonly format: FormatId | null;
  readonly status: Store<Status>;
  readonly controllers: Store<Controllers>;
  /**
   * Shows `file`, the same document under the same id with other bytes, in
   * place of the current one, keeping the zoom and scroll position where the
   * format can (PDF, images). Resolves `true` when it did. `false`: this
   * session cannot (another format, a plugin without `replace`, a document
   * in a sandboxed frame), and nothing was changed: mount a new session, as
   * for a new file. A new document that cannot be read ends in an error
   * status.
   */
  replace(file: ViewerFile): Promise<boolean>;
  resize(): void;
  destroy(): void;
}
