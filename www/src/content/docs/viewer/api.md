---
title: Core API
description: "@exav/viewer without React: the viewer, files and sources, sessions, statuses and controllers, detection, and the plugin contract."
---

`@exav/viewer` is the framework-free core. It mounts a file into an element
and reports on it through stores; it draws no chrome. `@exav/viewer/react`
is one UI on top of it, and a host can write another from the same stores.
With the engines in the page, `@exav/viewer/styles.css` is needed either
way: it lays out what the engines draw into (the drawing's canvas, the PDF's
pages, the image stage) as well as the default UI. In a sandboxed frame the
page needs none: the frame fills the element, and its own page has the
stylesheet. The element given to `mount` must have a size.

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
  formats: ["pdf", "image", "dwg", "dxf"], // default: every built-in format but the converted Office ones (BUILTIN_ORDER names all)
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
- `keys` (default `NAV_KEYS`: Escape, the arrows, Page Up and Down, Home,
  End): the keys handed back from the frame when the document does not use
  them, dispatched as a `keydown` on the `<iframe>` that bubbles to the
  page's own listeners, so that arrows move between files and Escape closes
  the viewer while the focus is in the document. An arrow the document
  scrolls with stays in the frame. Never a key with Ctrl, Alt or Meta,
  never one that types, at most 30 a second, with `isTrusted` false; `false`
  takes none.
- `theme` (default `"inherit"`): the frame's colours and sizes. The frame's
  page does not inherit the host's styles, so with `"inherit"` the `TOKENS`
  in force where each file is mounted are read, resolved to plain values
  (`themeOf(element)`) and sent to it: the page's CSS custom properties
  restyle the document's own surfaces (a text file, Markdown, an archive
  member) as they restyle the default UI, and the frame takes the page's
  colour scheme. A `FrameTheme` sets them instead; `null` keeps the frame's
  defaults. `viewer.restyle()` sends them again to every frame shown, after
  the page's theme changed; with `"inherit"`, a change of the device's
  colour scheme does so by itself.

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
is fitted), in the page and in the sandboxed frame alike; the old document
stays on screen until the new one is shown, and if the new one cannot be read
the old one stays, under an error status. `false` means this session cannot
(another format, a plugin of the host without `replace`, a frame that has not
started yet, a file delivered another way than the first, say an image given
by URL after one given as bytes) and changed nothing: mount a new session, as
for a new file. In a frame, one replacement is with the frame at a time:
call it again before it resolves and the earlier call resolves `true` without
having been shown.

The React UI does it for you: give `ViewerBody` the same `file.id` with a
different `source` and the document is replaced in place, or the session
started over where it cannot be. Compare sources, not objects: an address
(`{ url }`) the same as before is not a new source, whatever object holds it,
but `{ bytes }` and `{ blob }` are compared by identity, so keep one object
for the same bytes.

### Status

```ts
type Status =
  | { phase: "loading"; progress?: number; label?: string; step?: LoadStep }
  | { phase: "converting"; progress?: number; label?: string; step?: LoadStep }   // a step after the fetch that reports its progress
  | { phase: "ready"; partial?: boolean }        // partial: something drew, then the engine failed
  | { phase: "empty" }                           // parsed, nothing to draw
  | { phase: "error"; error: { code: "pdf" | "image" | "image_no_preview" | "drawing" | "drawing_version" | "office" | "needs_converter" | "media" | "model" | "archive" | "text" | "text_binary" | "file" | (string & {}); message?: string; cause?: unknown } };
```

`step` says what a load is doing, for a progress display, and `progress`
(0 to 1) how much of that step is done, where it is counted:

| Step | What | Counted |
|---|---|---|
| `file` | the file's bytes arrive (every format, while its plugin says nothing more precise) | bytes, when the size is known |
| `engine` | an [external converter](/viewer/integration/#the-external-converter)'s code and data arrive, the first time (its `download` stage) | bytes, when the converter knows the total |
| `start` | the external converter starts (its `start` stage) | no |
| `read` | the document is read: by the PDF or model reader, or by the external converter (its `load` stage) | what the converter reports, `done` of `total` |
| `convert` | it is converted to what is shown: by the package's converters (no count) or by the external converter (its `export` stage) | what the external converter reports, `done` of `total` |
| `render` | what is shown is drawn: a converted file's PDF, XLSX, PPTX or DOCX, a model's scene | no |

A plugin goes through the steps it has, in this order: a PDF or a drawing
reads, a model reads then renders, a file the package converts (an XLS, a
PPT, a DOC...) converts then renders, and a file an external converter takes
goes through all of them (`engine` only the first time). The default status overlay words each step and
draws a bar when `progress` is given; a host that draws its own reads
`status.step` and `status.progress`, through the sandboxed frame too.

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
`image_no_preview`: a camera RAW file that embeds no preview, whose sensor
data is not decoded.
`office`: a converted Office file that could not be converted or shown. Its
`cause` says why: a `SheetConversionError`, `SlideConversionError` or
`DocConversionError` (`format`, and `kind`: `"not-format"`, `"encrypted"`,
`"unsupported"`, `"too-large"`, `"malformed"`, `"timeout"` or `"crashed"`) from
the package's converters, or an `ExternalConversionError` (`kind` `"failed"` or
`"timeout"`) from an external one.
`needs_converter`: a format only an external converter reads, and none is set;
the `cause` is a `NeedsConverterError` (`kind` `"needs-converter"`, `format` the
viewer's name for the file).

`errorCode(format)` gives the code a format's errors carry.

### Controllers

Each is present when the format has it. All are stores.

| Controller | Formats | What it holds, what it does |
|---|---|---|
| `pages` | PDF, Word (pages), PowerPoint (slides) | `{ unit, current, total }`; `goTo(page)`, and `next()`, `prev()` for slides |
| `zoom` | PDF, images, drawings, Word, Excel, CSV | `{ scale, min, max }`, where `scale` is 1 at the fitted view (a page to the width, a sheet at 100 %, an image or drawing whole) and more or less when zoomed in or out, so a button back to it is wanted when it is not 1; `setScale(scale, anchor?)`, `fit()` |
| `sheets` | Excel | `{ items: { index, name }[], current }`; `select(index)`. The engine draws no tabs: the UI does (the default UI below the sheet) |
| `pictures` | every format that draws something (not text or archives) | `{ count, space }`; `raster(page, options)`, `toBlob(page, options)` and `render(page, longEdge)`: a page drawn again at the size and region asked for, as an `ImageBitmap` or an image file ([Pictures of pages](#pictures-of-pages), below). In the sandboxed frame, the picture is pixels sent out of it, checked for their size |
| `viewport` | the same | what the session shows now, as a region of one page, in the coordinates of `pictures.space`: `{ space, page, layout?, region }`, or `null` while nothing is drawn. Read-only, and worked out only while it is followed or read ([below](#pictures-of-pages)) |
| `media` | video, audio | `{ kind, paused, ended, currentTime, duration, buffered, volume, muted, rate, waiting, blocked }`; `play()`, `pause()`, `seek(seconds)`, `setVolume(v)`, `setMuted(m)`, `setRate(r)`, for a host drawing its own player (`video({ controls: "none" })`). `blocked`: the browser refused to start without a click on the player itself |
| `drag` | PDF | what a mouse drag does: `{ mode: "pan" \| "select", available }`; `choose(mode)`. `available` is true once the page is larger than the viewer, which is when the choice matters; below that a drag always selects text. Hand ("pan") is the default |
| `outline` | PDF | the document's own outline, flattened: `{ title, page, depth, offset }`; `goTo(entry)` |
| `layers` | DWG, DXF (layers), IFC (categories) | `{ kind, items: { id, name, color, visible }[] }`; `setVisible(id, visible)`, `setAll(visible)` |
| `storeys` | IFC (a model with two or more building storeys that hold something) | `{ items: { id, name, elevation, visible }[] }`, highest first (`elevation` in metres, or `null`); `setVisible(id, visible)`, `setAll(visible)`. A hidden storey's elements, outlines included, are not drawn, not picked, and not in pictures; the default UI lists them above the categories |
| `layouts` | DWG, DXF | model space and each paper layout; `select(id)`, `""` being model space |
| `ground` | DWG, DXF, IFC | `"light"` or `"dark"`; `set(ground)`, which never fetches the file again and keeps hidden layers hidden |
| `selection` | IFC | the element last tapped: `{ name, category, storey? }` |
| `info` | STL | `{ triangles }` |
| `image` | images | the image surface: transforms, and layers to draw on |
| `archive` | archives | the members; `open(index)`, `back()`, and `opened`: the member's own session |
| `warnings` | DWG, DXF, IFC, STL | what the picture lacks, as message keys and counts, with `names` when there is something to name: for a drawing, its external references, which are not drawn (`external_references`, the files they name), entities of a kind not drawn (`unknown_entities`, their types), its thumbnail shown because nothing in it is drawn (`preview_shown`), the entities left out past `maxPrimitives` (`scene_truncated`) and custom objects saved without their graphics (`proxy_without_graphics`); for a model, the elements left out past `maxTriangles` (`model_truncated`, STL: `model_partial`), geometry of a kind not drawn (`model_unsupported`), a damaged file (`model_damaged`); in the sandboxed frame, any format: a file to be read by ranges that the server sent whole (`source_read_whole`) |

An archive's member is a session like any other, in `archive.opened.session`:
its status and controllers are followed the same way, an archive inside it
included.

## Plugin options

| Plugin | Options |
|---|---|
| `pdf()` | `minZoom`, `maxZoom` (multiples of the page fitted to the width, default 0.25, which shows a whole page on any screen, and 6), `drag` (what a mouse drag does on a page larger than the viewer: `"pan"`, the default, or `"select"`; the user can switch, see the `drag` controller), `prerenderMargin`, `pageMaxPixels`, `detailMaxPixels`, `outlineMaxDepth`, `outlineMaxEntries` |
| `image()` | `wasmDecoders` (default false: the plugin then claims only the formats every browser draws, PNG, JPEG, WebP, GIF and SVG; true adds what exav-render decodes in WebAssembly, TIFF, BMP, ICO, PNM, QOI, DDS, Farbfeld, Radiance HDR, JPEG 2000, JBIG2 and JPEG XL, and camera RAW files, shown by the largest preview they embed that fits `maxDecodeBytes`, in a file of its own and as the members an archive opens), `maxDecodeBytes` (default 256 MiB), `overlay(file)` and `detail(file)` (below), `onTap(file, point, context)`, `minScale`, `maxScale`, `wheelStep`, `wheel` (what a plain wheel or two-finger scroll does: `"zoom"` about the pointer, the default, or `"pan"` the sheet, as a document reader scrolls; Ctrl or ⌘ with the wheel, a trackpad pinch, zooms in both, a mouse notch by a step of about 35%), `tapSlop`, `crossOrigin` (the `<img>`'s, default `"anonymous"` so that pixels can be read back; `null` shows an image from a server without CORS, unreadable) |
| `dwg()`, `dxf()` | `ground`, `colors` (`{ light, dark }`), `lineweights` (`"drawing"`, the default, as the drawing's `$LWDISPLAY` says; `"always"`; `"never"`, every line a pixel), `monochrome` (everything in ink, as monochrome.ctb plots; default false), `fontsUrl` (a directory serving the bundled fonts, for a host that publishes them itself), `timeoutMs` (default 120,000: past it the engine is stopped and the file reported unreadable), `maxPrimitives` (default 8,000,000 strokes and fill vertices per layout, up to 256 MB of buffers: past it the rest of the drawing is left out, with a warning), `maxDecompressedBytes` (default 512 MiB: what the compressed sections of a 2004 or later DWG may expand to; past it the file is reported unreadable). While a drawing parses, the thumbnail it was saved with (PNG or BMP), if any, stands in for it |
| `docx()`, `xlsx()`, `pptx()`, `csv()` | `useGoogleFonts` (default false), `mode` (`"main"`, the default: parse in a worker made from an inline module and paint on the page; `"worker"`: both in a worker started from a file, what the sandboxed frame uses), `maxArchiveEntries` (the most entries a document's ZIP may list, default 20000) |
| `rtf()`, `doc()`, `odt()`, `ppt()`, `odp()`, `keynote()`, `xls()`, `ods()`, `numbers()`, `odg()`, `visio()`, `coreldraw()`, `publisher()`, `pagemaker()`, `freehand()`, `quarkxpress()`, `zonerdraw()`, `wpg()` | `converter` (`"exav"`, the default: the package's converters, then the external one for what they do not read, and for text documents the external one first when there is one; `"external"`: the external converter alone, for every format), `externalConverter` (a package name that `@exav/viewer/vite` or `exav-viewer-assets` copied, or the URL of an ES module; default none, see [Integration](/viewer/integration/#the-external-converter)), `timeoutMs` (default 120,000: past it the conversion's worker, or the wait for the external converter, is stopped and the file reported unreadable), `maxMemory` (bytes a conversion may take. The package's converters count their own: 1 GiB by default, at most 1.5 GiB; past it the file is reported unreadable rather than shown with pictures missing. The external converter gets the number as set, and none when it is not). What the bytes are decides within each kind: an RTF saved as .doc is read as RTF, an XLSX named .xls is shown as it is |
| `video()`, `audio()` | `controls` (`"native"`, the default: the browser's player; `"none"`: no controls in the surface, for a host drawing its own from the `media` controller; a click on a video plays or pauses it). FLAC is claimed with the rest of what browsers play |
| `text()` | none: it reads at most 2 MiB and 50,000 lines of a file, and cuts a line at 10,000 characters |
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

### Printing

The sandboxed frame cannot open the print dialog, and a browser cannot print
a TIFF or a JPEG 2000 from its URL. `printPictures(pictures, options?)` from
`@exav/viewer` draws the pages through a session's `pictures` controller,
then prints them from a hidden frame of the page, built element by element:

```ts
const pictures = session.controllers.get().pictures;
if (pictures) await printPictures(pictures, { longEdge: 2480, onProgress: (done, total) => {} });
```

`pages` picks some pages, `signal` stops it. It resolves `false` when
nothing was printed. The page's policy must allow `blob:` images.

### Pictures of pages

Every format that draws something can be exported as a picture through
`controllers.pictures` (text and archive views have none). A picture is drawn
again from the document's own data (vectors, geometry, text) at the size
asked for, never read off the screen, so it is sharp at any zoom.

```ts
const pictures = session.controllers.get().pictures;
if (pictures) {
  // A page, as an ImageBitmap the caller owns and closes:
  const { bitmap, region, width, height } = await pictures.raster(1, { longEdge: 2000 });
  // What the user sees now, as an image file the host can save:
  const { blob } = await pictures.toBlob(1, { width: 1200, height: 800, region: "current", type: "jpeg", quality: 0.9 });
}
```

`pictures.get()` is `{ count, space }`: the number of pages and the
coordinates a `region` is written in. A page is 1-based: a PDF or Word page, a
PowerPoint slide, a spreadsheet's sheet, 1 for an image or a model, a CAD
layout in the order of the `layouts` controller (model space first), 1 for a
video (the frame being shown).

| `RasterOptions` | |
|---|---|
| `longEdge`, or `width` and/or `height` | The size, in pixels. `longEdge` is held to the limits; a `width` and a `height` past them are refused (`"too-large"`). One of `width` and `height` alone takes the other from the region's shape. The limits are `MAX_PICTURE_EDGE` (16,384 a side) and `MAX_PICTURE_PIXELS` (64 Mi pixels in all), the same for a host in the page and in the sandboxed frame |
| `region` | What to draw, in the coordinates of `space` (below), or `"current"`: what `controllers.viewport` holds. Default: the whole page, the drawing's extents, the model framed as the viewer first frames it |
| `layout` | CAD: the layout (its `layouts` id) the region is in |
| `fit` | When the picture's shape is not the region's: `"contain"` (default) widens the region to the picture's shape so that all of it is drawn; `"cover"` narrows it so that the picture is filled. The picture is never stretched |
| `lineweight` | CAD: `"screen"` (default) draws lines as many pixels wide as the viewer does at its own zoom; `"scaled"` scales them with the picture, as if the viewer's zoom were raised to the picture's size |
| `background` | A CSS colour (hex or a colour function) or `"transparent"`. Default: white for a document, transparent for an image, the viewer's ground for a drawing or a model. A format that cannot draw on transparency rejects it (`"unsupported"`) |
| `signal` | An `AbortSignal`: the promise rejects with `"aborted"`, and the work and its memory are released |

`raster` resolves to the bitmap, its `width` and `height`, the `page`, the
`layout` for CAD, the `space` and the **`region` actually drawn**, after
`fit`, in the same coordinates as the one asked for, so that a caller can map
pixels back to the document. `toBlob` takes the same options and `type`
(`"png"`, the default, `"jpeg"` or `"webp"`) and `quality` (0 to 1), and resolves
to the same fields with a `blob` instead of the bitmap. The encoding is done
by the page that owns the session, from pixels: in the sandboxed frame the
document's code never writes the file, nor touches the host's canvases.
JPEG has no transparency: it is drawn on `background`, or white. A browser
without an encoder for a type (Safari has none for WebP) rejects with
`"unsupported"` instead of handing back a PNG. `render(page, longEdge)`,
which `printPictures` uses, is `raster` with a longest side, null where `raster`
would reject.

| `space` | Formats | A `region` is |
|---|---|---|
| `"page"` | PDF, Word, PowerPoint, spreadsheets, the converted office formats | `{ x, y, width, height }`, fractions of the page (0 to 1), origin at the top left. It may reach past the page: the background shows there |
| `"pixels"` | images | `{ x, y, width, height }`, pixels of the source image, origin at the top left |
| `"drawing"` | DWG, DXF | `{ x, y, width, height }` in drawing units, y up, of the layout named by `layout` (model space, or a paper layout in paper units) |
| `"camera"` | IFC, STL, OBJ, PLY, glTF | `{ position, target, up?, projection, aspect }`: a perspective (vertical `fov`, in degrees) or orthographic (`height`) camera, in the model's world coordinates; `aspect` is the width over the height it was framed for, which `fit` keeps |
| `"frame"` | video | none: the frame being shown |

A failed picture rejects with a `RasterError` (exported by `@exav/viewer`),
whose `code` is `"unsupported"` (the format cannot draw it), `"too-large"`
(past the limits, or more than the device can hold), `"aborted"`, `"invalid"`
(a size, region or page that is none) or `"failed"`.

`controllers.viewport` is the part of the document in view, in the same
coordinates: `{ space, page, layout?, region }`, updated as the user pans,
zooms or orbits, and `null` while nothing is drawn. It is read-only. Read it,
change the region, and give it back as `region` to draw something near what
the user sees; `region: "current"` draws exactly that.

A session that never uses the viewport pays nothing for it. For the formats
where working it out costs (Word, PowerPoint, Excel, CSV, PDF: boxes to
measure, and for a sheet a second copy of the workbook), it is worked out
while the store has a listener, and once for each `get()` without one. A
spreadsheet's is measured asynchronously: its `get()` returns the last
measure and starts the next, so subscribe to follow it. For images,
drawings and models it is read off the view's own state, a few arithmetic
operations, and kept up to date. `region: "current"` does not need the
viewport to be followed.

In the sandboxed frame the options cross the port as plain data, checked on
both sides, and a picture is an `ImageBitmap` of at most the limits above,
which the host checks against the size it asked for: a bitmap of another size
is a failure. At most 8 pictures are asked for at once. A request the frame
finds malformed is answered with a `RasterError` `"invalid"`. The frame
follows the viewport only from the host's first listener to its last, and a
`get()` without one returns the last value the frame reported and asks it for
a fresh one: subscribe to follow the viewport there.

### Strings

`builtinTranslate(locale)` and `MESSAGES` from `@exav/viewer` are the
built-in strings (English, French, German, Spanish, Dutch: the language of
the locale, English otherwise), for a host drawing its own UI that wants
exav's wording of its statuses and warnings (`error_<code>`,
`warning_<key>`, `archive_members`...).

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
