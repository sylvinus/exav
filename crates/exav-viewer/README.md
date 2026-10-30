# @exav/viewer

A file viewer for the browser: <!-- formats:viewer-summary -->PDF, images, DWG and DXF drawings, Word, Excel, PowerPoint and CSV, text (Markdown, JSON, XML, source code), IFC, STL, OBJ, PLY and glTF models, video, audio, and what is inside an archive<!-- /formats:viewer-summary -->; and, converted in the browser, RTF, the 1997 Office
formats and OpenDocument. One package; each format's engine is
loaded only when a file of that format is opened, and only the engines a
host lists are ever bundled.

**[Live demo](https://exav.org/viewer/demo/)** · **[Documentation](https://exav.org/viewer/)**

- A hostile file reaches nothing of the host: in the sandboxed mode each
  file opens in an `<iframe sandbox="allow-scripts">` of its own, in an
  opaque origin, under a policy that lets nothing in or out, and the host
  checks every message the frame sends. See
  [Security](https://exav.org/viewer/security/).
- Formats browsers do not draw (TIFF, BMP variants, ICO, PNM, QOI, DDS,
  farbfeld, HDR, JPEG 2000, JBIG2, JPEG XL, camera RAW files, shown by the
  preview they embed), DWG/DXF drawings and IFC, STL, OBJ, PLY and glTF
  models are decoded by exav's own Rust decoders, compiled to WebAssembly and run in workers. So are the
  JPEG 2000, JBIG2 and fax images of PDFs: pdf.js is given them in place of
  its OpenJPEG and PDFium decoders (C and C++), which are not copied. The
  modules import nothing but wasm-bindgen's plumbing: no network, no global
  object, no clock.
- Nothing is fetched from another origin. Every asset (workers, wasm, fonts,
  pdf.js's CMaps) is served by the host, so the viewer runs under a strict
  Content-Security-Policy and offline.
- Archives open in place, an archive inside an archive included, with the
  same plugins.
- Whatever draws something can be exported as a picture: a page, a region of
  it in the format's own coordinates (a fraction of a page, pixels of an
  image, drawing units, a 3D camera), or what the user sees now
  (`controllers.viewport`), drawn again from the document's data at the size
  asked for, as an `ImageBitmap` or an image file (`pictures.raster`,
  `pictures.toBlob`), in the sandboxed frame too. See
  [Pictures of pages](https://exav.org/viewer/api/#pictures-of-pages).
- A session keeps its zoom and place when the same document comes again with
  other bytes (`session.replace`), in the sandboxed frame too.
- A framework-free core with a plugin contract, and a default React UI on
  top of it whose every piece can be restyled or replaced.

## Install

```bash
npm install @exav/viewer
```

then the engines of the formats you open (all optional peer dependencies):

| Format | Plugin | Install beside it |
|---|---|---|
| PDF | `pdf()` from `@exav/viewer/pdf` | `pdfjs-dist` (5 or 6) |
| Images, SVG, camera RAW (DNG, CR2, CR3, NEF, ARW, ORF, RW2, RAF, PEF, SRW, 3FR, IIQ, X3F and more: the largest embedded preview) | `image({ wasmDecoders: true })` from `@exav/viewer/image` | nothing |
| DWG, DXF | `dwg()`, `dxf()` from `@exav/viewer/cad` | nothing |
| Word, Excel, PowerPoint, CSV | `docx()`, `xlsx()`, `pptx()`, `csv()` from `@exav/viewer/office` | `@silurus/ooxml` |
| RTF, DOC, ODT | `rtf()`, `doc()`, `odt()` from `@exav/viewer/office`, beside `docx()` | `@silurus/ooxml` (read by exav-render's `docs`, a prototype; an external converter and `pdf()` do better) |
| XLS, ODS, Numbers | `xls()`, `ods()`, `numbers()` from `@exav/viewer/office`, beside `xlsx()` | `@silurus/ooxml` (an external converter for the files exav-render's `sheets` does not recognise) |
| PPT, ODP, Keynote, ODG, Visio (VSDX) | `ppt()`, `odp()`, `keynote()`, `odg()`, `visio()` from `@exav/viewer/office`, beside `pptx()` | `@silurus/ooxml` (an external converter and `pdf()` for the files exav-render's `slides` does not recognise, such as the binary .vsd) |
| Binary Visio (VSD), CorelDRAW, Publisher, PageMaker, FreeHand, QuarkXPress, Zoner Draw, WPG | `visio()`, `coreldraw()`, `publisher()`, `pagemaker()`, `freehand()`, `quarkxpress()`, `zonerdraw()`, `wpg()` from `@exav/viewer/office`, beside `pdf()` | an external converter (see below) |
| Text, Markdown, JSON, XML, source code | `text()` from `@exav/viewer/text` | nothing (Markdown is read by a small wasm module, loaded when one is opened) |
| IFC | `ifc()` from `@exav/viewer/ifc` | `three` |
| STL, OBJ, PLY, glTF | `stl()`, `obj()`, `ply()`, `gltf()` from `@exav/viewer/model` | `three` |
| Video, audio | `video()`, `audio()` from `@exav/viewer/media` | nothing |
| Archives | `archive()` from `@exav/viewer/archive` | `@exav/unpack-wasm` |
| Default UI | `@exav/viewer/react` | `react`, `react-dom` (19) |

IFC models (IFC2X3, IFC4, IFC4X3) are read and meshed by exav's own engine
(exav-render), and three.js draws them. Categories and building storeys
(`controllers.storeys`, for a model with two or more) can be hidden.

XLS, ODS and Numbers are converted to XLSX, shown by `xlsx()` as a
workbook; PPT, ODP, Keynote, ODG and VSDX (a page to a slide) to PPTX, shown
by `pptx()`; RTF, DOC and ODT to DOCX, shown by `docx()`. All by exav-render,
which the package ships as WebAssembly modules
(`wasm/exav_viewer_sheets_bg.wasm`, `..._slides_...`, `..._docs_...`): no
install is needed, and nothing is fetched besides the module. What no
converter of the package reads (binary Visio, CorelDRAW, Publisher,
PageMaker, FreeHand, QuarkXPress, Zoner Draw and WordPerfect Graphics
files, a CSV or a DIF saved as .xls) goes to an external converter if the
host set one, and ends in the "needs_converter" error, with the format's
name, if not. Each plugin also takes its templates (.dot, .pps, .pot, .xlt,
.ott, .otp, .ots, .otg, Visio's), the flat XML OpenDocument files (.fodt,
.fodp, .fods, .fodg), and Word 6.0/95 and Excel 2.1 to 95 files. What the
bytes are decides, within each kind: an RTF saved as .doc is read as RTF,
an XLSX named .xls is shown unconverted. The sandboxed viewer opens these
formats only when named in `formats` (`BUILTIN_ORDER` names every one).

A file a converter of the package recognises and cannot convert (encrypted
with a password, too large, damaged, of a version it does not read) ends in
the Office error, whose cause is a `SheetConversionError`,
`SlideConversionError` or `DocConversionError` naming the reason in its
`kind`; it is never handed to the external converter, which gets only what
the package's converters do not recognise. exav-render reads PowerPoint 95
and 97 to 2003 (2 to 4 are recognised and reported as unsupported), Excel 2
to 2003, the text formats Excel opens from a .xls file (XML Spreadsheet
2003, HTML tables, SYLK), OpenDocument drawings (a page to a slide, in the
largest page's size) and Keynote and Numbers of every version. Text
documents (DOC, ODT, RTF) are read by `docs`, a prototype, where no external
converter is set; with one, text documents go to it.

### The external converter

`rtf({ externalConverter })` and the other plugins take `converter` and
`externalConverter` (a plugin's options, or `conversion` in the sandboxed
viewer's):

- `converter: "exav"` (the default): the converters of the package, then the
  external one for what they do not read. For text documents, the external
  converter first when there is one.
- `converter: "external"`: the external converter alone, for every format.
- `externalConverter`: where the converter is. A URL (absolute, rooted, or
  relative to the page) of an ES module, or the name of a package copied
  beside the viewer's assets, which `exavViewer({ externalConverter:
  "<package>" })` of `@exav/viewer/vite` (or `exav-viewer-assets
  --external-converter <package>`) copies: its published files go under
  `assetBase`, and `manifest.json` names its entry. Default: none.

The module exports `convert`, and may export `prefetch`:

```ts
export function convert(bytes: Uint8Array, options: {
  hint: string;          // what the viewer took the file for: "rtf", "doc", "odt", "ppt",
                         // "odp", "keynote", "xls", "ods", "numbers", "odg", "visio",
                         // "coreldraw", "publisher", "pagemaker", "freehand", "quarkxpress",
                         // "zonerdraw" or "wpg": a hint, the bytes decide
  maxMemory?: number;    // bytes, when the host set the `maxMemory` option
  signal?: AbortSignal;  // aborted when the file is closed or `timeoutMs` passes: reject
  onProgress?: (p: ConvertProgress) => void;
}): Promise<{ format: "pdf" | "xlsx"; bytes: Uint8Array }>;

export function prefetch?(hint: string): string[] | Promise<string[]>;  // URLs, relative to the module
```

`ConvertProgress` is `{ stage: "download"; loaded; total }` (the module's
code and data arriving, `total` 0 when not known), `{ stage: "start" }`, and
`{ stage: "load" | "export"; done; total }`; the viewer shows them as its
loading and converting steps. A PDF is shown by `pdf()`, an XLSX by
`xlsx()`: register them. A rejection ends in the Office error, its cause an
`ExternalConversionError` (`kind` "failed", with the module's error as its
cause, or "timeout": the viewer stops waiting after `timeoutMs` whether or
not the module looks at its signal). `e2e/fixtures/fake-converter.js` is a
minimal module that implements it.

## Use

With Vite, add the plugin, which copies the engines' runtime files into the
build and serves them in development:

```ts
// vite.config.ts
import { exavViewer } from "@exav/viewer/vite";

export default { plugins: [exavViewer()] };
```

```tsx
import "@exav/viewer/styles.css";
import { dwg, dxf } from "@exav/viewer/cad";
import { pdf } from "@exav/viewer/pdf";
import { image } from "@exav/viewer/image";
import { ViewerBody, ViewerProvider } from "@exav/viewer/react";

const plugins = [pdf(), image({ wasmDecoders: true }), dwg(), dxf()];

export function Preview({ file }: { file: File }) {
  return (
    <ViewerProvider plugins={plugins} locale="en">
      <ViewerBody file={{ id: file.name, name: file.name, type: file.type, source: { blob: file } }} />
    </ViewerProvider>
  );
}
```

`ViewerDialog` shows a list of files in a modal with previous and next,
download and "open in a new tab".

The sandboxed mode: publish the frame app the package ships, and give
`sandbox` instead of `plugins`. The engines are the frame's own, so no peer
dependency is needed. Serve the frame with the headers the
[Security](https://exav.org/viewer/security/#serving-the-frame)
page lists, ideally from a domain of its own.

```ts
// vite.config.ts
export default { plugins: [exavViewer({ frameDir: "exav-frame", frameOrigin: "https://app.example.com" })] };
```

```tsx
import { SandboxedViewerProvider } from "@exav/viewer/react/sandbox";

<SandboxedViewerProvider sandbox={{ url: "/exav-frame/index.html" }} locale="en">
  <ViewerBody file={file} />
</SandboxedViewerProvider>
```

The converted formats in the frame: name them, `sandbox={{ url, formats:
BUILTIN_ORDER }}`. For an external converter, install it where the frame
is built and give `exavViewer({ frameDir, externalConverter: "<package>" })`
its name (it is copied beside the frame app, and the frame's
`conversion.externalConverter` names it).

The host reads each file for the frame: a PDF or a ZIP by HTTP range
requests, as the frame asks for parts, the rest whole. Video, audio and
images can go to the frame by URL instead, from origins written into its
policy when it is deployed (`mediaOrigins`, `--media-origin`) and given to
the viewer as `sandbox.origins` (see `delivery` in the
[Integration](https://exav.org/viewer/integration/#how-the-bytes-reach-the-frame)
page).

Without React:

```ts
// It lays out the engines' surfaces as well as the default UI: import it with or without React.
import "@exav/viewer/styles.css";
import { createViewer } from "@exav/viewer";
import { pdf } from "@exav/viewer/pdf";

const viewer = createViewer({ plugins: [pdf()] });
const session = viewer.mount(element, { id: "1", name: "report.pdf", source: { url: "/files/report.pdf" } });
// While loading: what it is doing (`step`: "file", "engine", "convert"...) and how far (`progress`, 0 to 1)
session.status.subscribe((s) => console.log(s.phase, "step" in s && s.step, "progress" in s && s.progress));
// later
session.destroy();
```

`createSandboxedViewer` from `@exav/viewer/frame` gives the same sessions
for files in the frame. A host can draw every control itself from their
controllers (pages, zoom, sheets, a player's controls, thumbnails,
printing) with no React and no stylesheet in its page; the frame takes the
page's colours and hands back the arrow keys and Escape. See
[Integration](https://exav.org/viewer/integration/#a-host-that-draws-its-own-ui)
and `demo/headless.html`.

Other bundlers: copy the assets with the command the package installs, and
serve the directory as the viewer's `assetBase` (default `/exav-viewer/`):

```bash
npx exav-viewer-assets public/exav-viewer
# and the sandboxed frame app (--media-origin, --connect-origin: repeatable)
npx exav-viewer-assets public/exav-viewer --frame public/exav-frame --frame-origin https://app.example.com
```

The files are under versioned directories, so `assetBase` can be served
`Cache-Control: immutable`. With an `externalConverter` they include that
package's published files under `converters/<name>/<version>/`. The
package's own wasm, workers and fonts are
referenced with `new URL("...", import.meta.url)`, which Vite, webpack 5 and
Parcel follow and emit; Rollup and esbuild need a plugin for it.

Content-Security-Policy, for every format in the page (in the sandboxed
mode the page needs only `frame-src` for the frame, which has its own):

```
default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline';
img-src 'self' blob: data:; font-src 'self' blob: data:; media-src 'self' blob:;
worker-src 'self' blob:; connect-src 'self' blob: data:; object-src 'none'
```

`worker-src blob:` and `style-src 'unsafe-inline'` are needed by the Office
engine only. The demo is served with this policy, its frame with the
frame's, and its browser tests fail on any violation.

## Licence

MIT. The DWG module contains the NewStroke font (CC0-1.0) and encoding_rs,
whose WHATWG data is BSD-3-Clause; the bundled fonts are under the SIL Open
Font License. See NOTICE and LICENSES/. The engines installed beside the
package keep their own licences: pdf.js is Apache-2.0 (and its ICC engine,
qcms, MIT), the others MIT; an external converter you install keeps its
own.
The sandboxed frame app
(`dist/frame/app/`) bundles them, with their licence files in its
`licenses/`.
