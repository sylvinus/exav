# @exav/viewer

A file viewer for the browser: PDF, images, DWG and DXF drawings, Word,
Excel, PowerPoint and CSV, IFC and STL models, video, audio, and what is
inside an archive. One package; each format's engine is loaded only when a
file of that format is opened, and only the engines a host lists are ever
bundled.

**[Live demo](https://exav.org/viewer/demo/)** · **[Documentation](https://exav.org/viewer/)**

- A hostile file reaches nothing of the host: in the sandboxed mode each
  file opens in an `<iframe sandbox="allow-scripts">` of its own, in an
  opaque origin, under a policy that lets nothing in or out, and the host
  checks every message the frame sends. See
  [Security](https://exav.org/viewer/security/).
- Formats browsers do not draw (TIFF, BMP variants, ICO, PNM, QOI, DDS,
  farbfeld, HDR, JPEG 2000, JBIG2), DWG/DXF and IFC/STL models are decoded
  by exav's own Rust decoders, compiled to WebAssembly and run in workers. So are the
  JPEG 2000, JBIG2 and fax images of PDFs: pdf.js is given them in place of
  its OpenJPEG and PDFium decoders (C and C++), which are not copied. The
  modules import nothing but wasm-bindgen's plumbing: no network, no global
  object, no clock.
- Nothing is fetched from another origin. Every asset (workers, wasm, fonts,
  pdf.js's CMaps) is served by the host, so the viewer runs under a strict
  Content-Security-Policy and offline.
- Archives open in place, an archive inside an archive included, with the
  same plugins.
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
| Images | `image({ wasmDecoders: true })` from `@exav/viewer/image` | nothing |
| DWG, DXF | `dwg()`, `dxf()` from `@exav/viewer/cad` | nothing |
| Word, Excel, PowerPoint, CSV | `docx()`, `xlsx()`, `pptx()`, `csv()` from `@exav/viewer/office` | `@silurus/ooxml` |
| IFC | `ifc()` from `@exav/viewer/ifc` | `three` |
| STL | `stl()` from `@exav/viewer/model` | `three` |
| Video, audio | `video()`, `audio()` from `@exav/viewer/media` | nothing |
| Archives | `archive()` from `@exav/viewer/archive` | `@exav/unpack-wasm` |
| Default UI | `@exav/viewer/react` | `react`, `react-dom` (19) |

IFC models (IFC2X3, IFC4, IFC4X3) are read and meshed by exav's own engine
(exav-render), and three.js draws them.

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
session.status.subscribe((s) => console.log(s.phase));
// later
session.destroy();
```

Other bundlers: copy the assets with the command the package installs, and
serve the directory as the viewer's `assetBase` (default `/exav-viewer/`):

```bash
npx exav-viewer-assets public/exav-viewer
# and the sandboxed frame app (--media-origin, --connect-origin: repeatable)
npx exav-viewer-assets public/exav-viewer --frame public/exav-frame --frame-origin https://app.example.com
```

The files are under versioned directories, so `assetBase` can be served
`Cache-Control: immutable`. The package's own wasm, workers and fonts are
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
qcms, MIT), the others MIT. The sandboxed frame app
(`dist/frame/app/`) bundles them, with their licence files in its
`licenses/`.
