---
title: Core API
description: "@exav/viewer without React: the viewer, files and sources, sessions, statuses and controllers, detection, and the plugin contract."
---

`@exav/viewer` is the framework-free core. It mounts a file into an element
and reports on it through stores; it draws no chrome. `@exav/viewer/react`
is one UI on top of it, and a host can write another from the same stores.
`@exav/viewer/styles.css` is needed either way: it lays out what the engines
draw into (the drawing's canvas, the PDF's pages, the image stage) as well as
the default UI. The element given to `mount` must have a size.

## The viewer

```ts
import "@exav/viewer/styles.css";
import { createViewer } from "@exav/viewer";
import { pdf } from "@exav/viewer/pdf";
import { dwg } from "@exav/viewer/cad";

const viewer = createViewer({
  plugins: [pdf(), dwg()],
  assetBase: "/exav-viewer/", // the default
});
```

`@exav/viewer/cad` also exports the drawing renderer's helpers
(`isCadSupported`, `layerColor`, `GROUNDS`). A bundle that only lists
plugins imports `dwg` and `dxf` from `@exav/viewer/cad/plugin` instead,
which leaves the renderer out until a drawing is opened.

| Member | |
|---|---|
| `mount(host, file)` | Shows `file` in the element `host` and returns its `Session`. |
| `detect(info)` | The format of a file from its `type`, `path` and `name`, or `null`: synchronous, for deciding between the viewer and a download before anything is fetched. |
| `detectBytes(name, head)` | The same from a name and the first bytes (`HEAD_BYTES`, 512, are enough), for files with no trusted type. |
| `sniff(head)` | The content type the first bytes prove, or `""`. |
| `table()` | The whole detection table as JSON, for a server-side copy. |
| `prefetch(formats)` | Loads these formats' code and fetches the assets their plugins list, for offline use ([Integration](/viewer/integration/#offline)). |
| `plugins`, `assetBase` | As given. |

Plugins are matched in the order given. The order of `allPlugins()` is
`BUILTIN_ORDER`.

## The viewer in a sandboxed frame

```ts
import { createSandboxedViewer } from "@exav/viewer/frame";

const viewer = createSandboxedViewer({
  url: "https://viewer-frame.example-files.com/exav-frame/index.html",
  formats: ["pdf", "image", "dwg", "dxf"], // default: every built-in format
  options: { cad: { ground: "dark" }, image: { maxDecodeBytes: 128 * 2 ** 20 } },
  confirmLink: (url) => window.confirm(`Open ${url}?`), // the default asks the same
});
```

The same `Viewer`, whose `mount` puts each file in a frame of its own
([Security](/viewer/security/)): sessions, statuses and
controllers behave as above, every value checked as it comes from the
frame. The differences:

- `options` are the plugins' options that are plain data (`FrameOptions`):
  no `overlay`, `detail` or `onTap`, and so no `image` controller.
- `plugins` is empty and `assetBase` is `""`: the engines are the frame's.
  `prefetch` does nothing.
- `confirmLink(url, file)` decides on a link the user followed in a
  document: absolute `http:` and `https:` URLs only reach it, and it is
  opened with `noopener,noreferrer` when it resolves `true`.
- `startTimeoutMs` (default 20,000): a frame that has not answered by then
  is reported as an error.
- `delivery` (`Delivery`): how each kind of file reaches the frame,
  `{ media?: "url" | "blob", images?: "url" | "blob", pdf?: "ranges" | "blob" | "url", archive?: "ranges" | "blob" }`.
  Defaults: PDF and archives `"ranges"`, video, audio and images `"url"`
  when the file's URL is on an `origins.media` origin, `"blob"` otherwise
  and for every other format
  ([what each lets the frame do](/viewer/security/#how-a-file-reaches-the-frame)).
- `origins` (`FrameOrigins`): `{ media?: string[], connect?: string[] }`,
  the origins the frame's policy names, as it was deployed
  ([Integration](/viewer/integration/#how-the-bytes-reach-the-frame)).
  A frame reporting other ones is an error.

`createSandboxedViewer` throws on a delivery it does not know, an origin
that is not `scheme://host[:port]`, or `"url"` without an origin to allow
it.

`frameHeaders(frameAncestors, origin?, origins?)`, `frameCsp(origin?,
origins?)` and `FRAME_CSP` give the frame's policy and the headers to serve
it with.

## Files

```ts
interface ViewerFile<Meta = unknown> {
  id: string;            // a new id is a new session
  name: string;          // shown, and where the extension is read when `path` is absent
  type?: string;         // the content type the host trusts
  path?: string;         // where the extension is read from: a storage key
  kind?: "file" | "link";
  size?: number;
  source: FileSource | null;
  placeholder?: { state: "pending" | "unavailable"; label?: string };
  format?: FormatId;     // skips detection
  meta?: Meta;           // the host's own data, for options resolved per file
}

type FileSource =
  | { url: string; init?: RequestInit }
  | { blob: Blob }
  | { bytes: Uint8Array }
  | { ranges: ByteRanges }
  | { resolve: (signal: AbortSignal) => Promise<string | Blob | Uint8Array> };

interface ByteRanges {
  readonly size: number;
  // `length` bytes at `offset`, fewer only past the end of the file
  read(offset: number, length: number, signal: AbortSignal): Promise<Uint8Array>;
}
```

A `ranges` source is read as pdf.js and the ZIP reader ask for it (a PDF's
pages on screen, an archive's directory and the members opened), and whole,
4 MiB at a time, by the other engines. The sandboxed frame reads files this
way, over its port.

A type of `""`, `application/octet-stream` or `binary/octet-stream` is
unknown, and the extension decides. A container type yields to the
extension for the formats that are containers (a `.docx` sent as
`application/zip` is Word, not an archive). A `link` has no bytes and
detects as `null`.

`source: null` shows `placeholder` instead of a surface: `"pending"` while
the bytes are on their way, `"unavailable"` when they will not come (offline,
not downloaded).

## Sessions

```ts
const session = viewer.mount(element, file);
const stop = session.status.subscribe((s) => {
  if (s.phase === "error") showDownloadInstead(s.error.code);
});
// the element changed size without the window doing so:
session.resize();
// another file, or the viewer closes: frees workers, WebGL contexts, bitmaps, object URLs
session.destroy();
```

| Member | |
|---|---|
| `file`, `format` | The file, and the format detected for it (`null`: no plugin claims it; the status is then an error). |
| `status` | `Store<Status>`. |
| `controllers` | `Store<Controllers>`: what the engine lets a UI do, published as soon as it can. |
| `replace(file)` | Another document under the same id (see below). |
| `resize()` | Tell the engine its container changed size. The React UI does it with a `ResizeObserver`. |
| `destroy()` | End the session: the fetch is aborted, and the engine frees what it holds, an archive's open member included. |

A store has `get()` and `subscribe(listener)`, which calls `listener` on
each change (not with the current value) and returns the function that
unsubscribes.

### Replacing the document

A host that draws the same document again after something changed (a report's
preview, a plan with a new mark) does not want to lose the zoom and the place
the reader was at. `session.replace(file)` shows `file`, the same id with
other bytes, in place of the current document, and resolves `true` when it
did. PDFs and images keep their zoom and position (an image of another shape
is fitted); the old document stays on screen until the new one is shown, and
if the new one cannot be read the old one stays, under an error status.
`false` means this session cannot (another format, a plugin of the host
without `replace`, a file in a sandboxed frame) and changed nothing: mount a
new session, as for a new file.

The React UI does it for you: give `ViewerBody` the same `file.id` with a
different `source` and the document is replaced in place, or the session
started over where it cannot be. Compare sources, not objects: an address
(`{ url }`) the same as before is not a new source, whatever object holds it,
but `{ bytes }` and `{ blob }` are compared by identity, so keep one object
for the same bytes.

### Status

```ts
type Status =
  | { phase: "loading"; progress?: number; label?: string }
  | { phase: "converting"; progress?: number; label?: string }   // a step after the fetch that reports its progress
  | { phase: "ready"; partial?: boolean }        // partial: something drew, then the engine failed
  | { phase: "empty" }                           // parsed, nothing to draw
  | { phase: "error"; error: { code: "pdf" | "image" | "drawing" | "drawing_version" | "office" | "media" | "model" | "archive" | "file" | (string & {}); message?: string; cause?: unknown } };
```

`label` and `message` are for a plugin of the host: text worded for the user
in the host's language, shown by the default status overlay instead of the
stock message of the phase or of `code`. A photo being decoded is then not
"preparing the model". A plugin of the host may also use a code of its own
(`heic`): the message is looked up as `error_heic` in the host's `translate`
like the built-in ones, and the generic `error_file` shows where the table has
none. The sandboxed frame does not carry labels, messages or codes of its own
(its plugins are the package's own).

`drawing_version`: a DWG of a release the engine does not read (R12 and
older), said as such rather than as a drawing that would not parse.

`errorCode(format)` gives the code a format's errors carry.

### Controllers

Each is present when the format has it. All are stores.

| Controller | Formats | What it holds, what it does |
|---|---|---|
| `pages` | PDF, Word (pages), PowerPoint (slides) | `{ unit, current, total }`; `goTo(page)`, and `next()`, `prev()` for slides |
| `zoom` | PDF, images, drawings | `{ scale, min, max }`; `setScale(scale, anchor?)`, `fit()` |
| `drag` | PDF | what a mouse drag does: `{ mode: "pan" \| "select", available }`; `choose(mode)`. `available` is true once the page is larger than the viewer, which is when the choice matters; below that a drag always selects text. Hand ("pan") is the default |
| `outline` | PDF | the document's own outline, flattened: `{ title, page, depth, offset }`; `goTo(entry)` |
| `layers` | DWG, DXF (layers), IFC (categories) | `{ kind, items: { id, name, color, visible }[] }`; `setVisible(id, visible)`, `setAll(visible)` |
| `layouts` | DWG, DXF | model space and each paper layout; `select(id)`, `""` being model space |
| `ground` | DWG, DXF, IFC | `"light"` or `"dark"`; `set(ground)`, which never fetches the file again and keeps hidden layers hidden |
| `selection` | IFC | the element last tapped: `{ name, category, storey? }` |
| `info` | STL | `{ triangles }` |
| `image` | images | the image surface: transforms, and layers to draw on |
| `archive` | archives | the members; `open(index)`, `back()`, and `opened`: the member's own session |
| `warnings` | DWG, DXF, IFC, STL | what the picture lacks, as message keys and counts: for a drawing, its external references, which are not drawn (`external_references`), the entities left out past `maxPrimitives` (`scene_truncated`) and custom objects saved without their graphics (`proxy_without_graphics`); for a model, the elements left out past `maxTriangles` (`model_truncated`, STL: `model_partial`), geometry of a kind not drawn (`model_unsupported`), a damaged file (`model_damaged`); in the sandboxed frame, any format: a file to be read by ranges that the server sent whole (`source_read_whole`) |

An archive's member is a session like any other, in `archive.opened.session`:
its status and controllers are followed the same way, an archive inside it
included.

## Plugin options

| Plugin | Options |
|---|---|
| `pdf()` | `minZoom`, `maxZoom` (multiples of the page fitted to the width, default 1 and 6), `drag` (what a mouse drag does on a page larger than the viewer: `"pan"`, the default, or `"select"`; the user can switch, see the `drag` controller), `prerenderMargin`, `pageMaxPixels`, `detailMaxPixels`, `outlineMaxDepth`, `outlineMaxEntries` |
| `image()` | `wasmDecoders` (default false: the plugin then claims only the four formats every browser draws, PNG, JPEG, WebP and GIF; true adds what exav-render decodes in WebAssembly, TIFF, BMP, ICO, PNM, QOI, DDS, Farbfeld, Radiance HDR, JPEG 2000 and JBIG2, in a file of its own and as the members an archive opens), `maxDecodeBytes` (default 256 MiB), `overlay(file)` and `detail(file)` (below), `onTap(file, point, context)`, `minScale`, `maxScale`, `wheelStep`, `wheel` (what a plain wheel or two-finger scroll does: `"zoom"` about the pointer, the default, or `"pan"` the sheet, as a document reader scrolls; Ctrl or ⌘ with the wheel, a trackpad pinch, zooms in both, a mouse notch by a step of about 35%), `tapSlop`, `crossOrigin` (the `<img>`'s, default `"anonymous"` so that pixels can be read back; `null` shows an image from a server without CORS, unreadable) |
| `dwg()`, `dxf()` | `ground`, `colors` (`{ light, dark }`), `fontsUrl` (a directory serving the bundled fonts, for a host that publishes them itself), `timeoutMs` (default 120,000: past it the engine is stopped and the file reported unreadable), `maxPrimitives` (default 8,000,000 strokes and fill vertices per layout, about 220 MB of buffers: past it the rest of the drawing is left out, with a warning), `maxDecompressedBytes` (default 512 MiB: what the compressed sections of a 2004 or later DWG may expand to; past it the file is reported unreadable). While a drawing parses, the thumbnail it was saved with (PNG or BMP), if any, stands in for it |
| `docx()`, `xlsx()`, `pptx()`, `csv()` | `useGoogleFonts` (default false), `mode` (`"main"`, the default: parse in a worker made from an inline module and paint on the page; `"worker"`: both in a worker started from a file, what the sandboxed frame uses) |
| `ifc()` | `ground`, `colors`, `highlight`, `timeoutMs` (default 120,000), `maxTriangles` (default 6,000,000, about 330 MB of buffers: past it the remaining elements are left out, with a warning) |
| `stl()` | `surface` (a colour), `zUp` (default true), `timeoutMs` (default 120,000), `maxTriangles` (default 6,000,000) |
| `archive()` | `maxExtractedBytes` (512 MiB), `maxMembers` (5000), `maxCompressionRatio` (200) |

### Drawing over an image

`image({ overlay })` gives, per file, something drawn on the image surface:
annotations, markers, a crop frame. The surface has a `pageLayer` laid out in
the image's own pixels, which pans and zooms with it, and an untransformed
`screenLayer` for controls, with `toPage(clientX, clientY)` and
`toScreen(fx, fy)` to convert between them in fractions of the page.
`reactOverlay` from `@exav/viewer/react` writes one in React. It renders
again on every change of the view, so on every frame of a pan: memoise what
is costly to build (the SVG of a few hundred marks, say) on what it depends
on, which is the document and the page size, not the view.

The surface captures the pointer on `pointerdown`, so a button in the
`screenLayer` never gets its `click`. A tap is reported to `onTap` instead,
in fractions of the page (`point`) and in container pixels
(`context.screen`). To find the marker under it, give the markers (anything
with `x` and `y` in page fractions) to `surface.pick(markers, context.screen,
radius?)`, which returns the nearest one within `radius` pixels (default 22),
or `null`.

`image({ detail })` redraws the visible part sharper than the raster: a
plan whose vector original the host can render, say. It is called with the
region and the device width of the whole page, and returns a bitmap.

### Opening PDFs beside the viewer

A host that opens PDFs with pdf.js itself (sheets kept for offline use,
thumbnails) wants the same options as the viewer: `documentOptions(assetBase,
pdfjsVersion)` from `@exav/viewer/pdf` gives them (no `eval`, the bundled
fonts, the CMaps, ICC profiles and image decoders served from `assetBase`),
and `pdfjsAssetDir(assetBase, version)` and `pdfjsWasmDir(assetBase,
version)` say where those are published.

### PDF pages off the main thread

`createPdfRasterizer()` from `@exav/viewer/pdf` renders pages in a worker,
for a host keeping rasters of its own (thumbnails, sheets for offline use):
`open(id, data)`, `draw(id, page, longEdge)` to a PNG `Blob`,
`region(...)` to an `ImageBitmap`, `forget(id)`, `destroy()`. Where
`OffscreenCanvas` is missing it runs on the main thread.

## Writing a plugin

A plugin is data and a dynamic import:

```ts
import type { FormatPlugin } from "@exav/viewer";

export function gltf(): FormatPlugin<Record<string, never>> {
  return {
    id: "gltf",
    match: { types: ["model/gltf-binary"], extensions: [".glb"] },
    capabilities: ["zoom"],
    options: {},
    // Nothing heavy may be reachable before this import.
    load: () => import("./gltf-renderer.js").then((m) => m.renderer),
  };
}
```

```ts
// gltf-renderer.ts
import type { Renderer } from "@exav/viewer";

export const renderer: Renderer = {
  async mount(host, ctx) {
    ctx.status({ phase: "loading" });
    const bytes = await ctx.source.bytes();       // or url(), blob()
    if (ctx.signal.aborted) throw new DOMException("aborted", "AbortError");
    const view = draw(host, bytes);               // the plugin's own
    ctx.status({ phase: "ready" });
    return {
      controllers: { zoom: view.zoom },
      resize: () => view.resize(),
      destroy: () => view.free(),                 // everything: workers, contexts, URLs
    };
  },
};
```

The context also carries the plugin's `options`, the `file`, the viewer's
`assetBase` and `detector`, `controllers(next)` to publish controllers before
`mount` resolves, and `mountNested(host, file, options?)`, which archives use to
show a member with the same plugins. A plugin that decodes a format the
browser does not draw and shows the result as another one (HEIC drawn as an
image) passes `{ forward: true }`: its own status and controllers then follow
the nested session's as they change, and the UI behaves as if it were showing
the nested file itself:

```ts
async mount(host, ctx) {
  ctx.status({ phase: "converting", label: "Decoding the photo" });
  const png = await decodeHeic(await ctx.source.bytes());
  const nested = ctx.mountNested(host, { ...ctx.file, id: `${ctx.file.id}:png`, source: { blob: png }, format: "image" }, { forward: true });
  return { controllers: {}, destroy: () => nested.destroy() };
}
```

A handle may also have `replace(next)`, which shows another document of the
same format in place of this one (see [Replacing the document](#replacing-the-document));
without it `session.replace` answers `false`. A `mount` that throws ends in an error
status with the format's code; one aborted by `signal` ends quietly.

`match` is data: `types`, `extensions`, `containerTypes`,
`extensionOverrides`, magic-byte `signatures`, and `confirmSniff(head, name)`
to reject a sniffed type the bytes do not back. Being data, the detection
table can be exported (`viewer.table()`) and checked against a server's
copy.
