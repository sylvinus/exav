---
title: File viewer
description: "@exav/viewer, a file viewer for the browser: PDF, images, DWG and DXF, Office documents, IFC and STL models, media and archives, each engine loaded on first use, every asset from the host's own origin."
---

**A file viewer for the browser, as one npm package, `@exav/viewer`.** It
shows PDF, images, DWG and DXF drawings, Word, Excel, PowerPoint and CSV, IFC
and STL models, video and audio, and the files inside an archive. Each
format is a plugin; a host lists the ones it opens, and only their engines
are bundled. An engine's code is fetched when the first file of its format
opens, never before.

**[Try the demo](/viewer/demo/)**: its samples are public-domain or
CC0 files ([exav-samples](https://github.com/sylvinus/exav-samples)), and a
file you open in it stays in your browser.

- **A hostile file reaches nothing.** In the sandboxed mode each file opens
  in an `<iframe sandbox="allow-scripts">` of its own, in an opaque origin,
  under a policy that lets nothing out: an engine a file manages to run
  code in finds no cookie, no storage, no page to read and no way to send
  anything. The host checks every message the frame sends.
  [Security](/viewer/security/) gives the guarantees, per
  browser, and the checks that keep them.
- **exav's own decoders in WebAssembly.** The image formats browsers do not
  draw (TIFF in most of them, BMP variants, ICO, PNM, QOI, DDS, farbfeld,
  HDR, JPEG 2000, JBIG2), the JPEG 2000, JBIG2 and fax images inside PDFs,
  DWG and DXF drawings, and IFC and STL models are decoded by
  [exav-render](/subprojects/exav-render/), safe Rust compiled to wasm and
  run in a worker. The modules import nothing but wasm-bindgen's plumbing:
  no network, no global object, no clock. A crafted file can fail to open,
  or be stopped after a time limit or at its module's memory cap; what the
  decoder does stays in its worker.
- **One origin.** Workers, wasm, fonts, pdf.js's CMaps and standard fonts:
  every file an engine fetches is served by the host. The
  viewer runs under a strict [Content-Security-Policy](/viewer/integration/#content-security-policy),
  offline, and sends nothing to a third party.
- **Archives open in place**, with the same plugins: a PDF inside a zip has
  its outline, a zip inside a zip opens too, and the extraction is bounded
  by [exav-unpack](/unpack/wasm/)'s limits.
- **Framework-free core, React UI on top.** The core mounts a file into an
  element and hands back stores to follow (pages, zoom, layers, the
  archive's members...). `@exav/viewer/react` draws the default chrome from
  them; any piece of it can be restyled with CSS custom properties or
  replaced.

## Formats

| Format | Plugin | Engine | Install beside the package |
|---|---|---|---|
| PDF | `pdf()`, `@exav/viewer/pdf` | pdf.js, in a worker | `pdfjs-dist` 5 or 6 |
| PNG, JPEG, GIF, WebP | `image()`, `@exav/viewer/image` | the browser | |
| TIFF, BMP, ICO, PNM, QOI, DDS, farbfeld, HDR, JPEG 2000 (.jp2, .jpf, .j2k), JBIG2 (.jb2) | `image({ wasmDecoders: true })` | exav-render, in a worker | |
| DWG (R13 to 2018), DXF | `dwg()`, `dxf()`, `@exav/viewer/cad` | exav-render, in a worker; WebGL2 | |
| Word, Excel, PowerPoint | `docx()`, `xlsx()`, `pptx()`, `@exav/viewer/office` | @silurus/ooxml | `@silurus/ooxml` |
| CSV, TSV | `csv()` | the separator and encoding read off the bytes | `@silurus/ooxml` |
| IFC (IFC2X3, IFC4, IFC4X3) | `ifc()`, `@exav/viewer/ifc` | exav-render, in a worker; drawn with three.js | `three` |
| STL (binary, ASCII) | `stl()`, `@exav/viewer/model` | exav-render, in a worker; drawn with three.js | `three` |
| Video, audio | `video()`, `audio()`, `@exav/viewer/media` | the browser | |
| zip, 7z, rar, tar, gz, bz2, xz | `archive()`, `@exav/viewer/archive` | [exav-unpack](/unpack/wasm/) in wasm | `@exav/unpack-wasm` |

`@exav/viewer/all` exports `allPlugins()`, every plugin at once, for a host
that installs every engine.

IFC models are read and meshed by exav's own engine, written from
buildingSMART's schemas and documentation: placements, mapped items,
extrusions of every profile type, revolutions, sweeps along a curve,
tessellated face sets, faceted B-reps, advanced B-reps (planar, cylindrical
and B-spline faces), surface models, CSG
primitives, booleans with half-spaces, and openings cut out of their walls.
Elements a file gives no colour take their category's. A model is framed on
its elements, less any standing apart from all the others (an object an
export left a kilometre away, a geo-referencing marker), which are still
drawn; the wheel zooms towards the pointer.

A PDF's pages are drawn by pdf.js, those near the screen only. Over each
lies its text, transparent, to select and copy, and its links: to a place
in the document, which scrolls there, or to an `http:` or `https:` address,
opened in a new tab (in the sandboxed frame, after the host's question).
The browser's find in page sees the text of the pages near the screen
only. Other annotations are drawn as they look, and a document's
JavaScript never runs. A Word document's pages and a presentation's slides
carry their text and hyperlinks the same way, and copy with a line break
between paragraphs. In a spreadsheet, the cells selected (click, drag, or
the row and column headers) copy with Ctrl+C or ⌘C as tab-separated rows,
which paste into another spreadsheet as cells.

pdf.js
ships its JPEG 2000, JBIG2 and fax decoders as OpenJPEG (C) and PDFium's
decoders (C++) compiled to wasm; the viewer does not copy them, and gives
pdf.js exav-render's in their place (hayro-jpeg2000, hayro-jbig2 and
hayro-ccitt, safe Rust). They draw the same pixels, except lossy JPEG 2000,
one level apart on a few samples, and 16-bit JPEG 2000, one level apart at
most. SVG is
not offered: an SVG is a
document that can carry script, not a picture.

## Install

```bash
npm install @exav/viewer
# then the engines of the formats you open, for instance:
npm install pdfjs-dist react react-dom
```

With Vite, add the plugin. It copies the engines' runtime files into the
build, under `exav-viewer/`, and serves them in development:

```ts
// vite.config.ts
import { exavViewer } from "@exav/viewer/vite";

export default { plugins: [exavViewer()] };
```

Other bundlers: [Integration](/viewer/integration/).

## A first viewer

```tsx
import { useState } from "react";
import "@exav/viewer/styles.css";
import { dwg, dxf } from "@exav/viewer/cad";
import { image } from "@exav/viewer/image";
import { pdf } from "@exav/viewer/pdf";
import { ViewerDialog, ViewerProvider, type ViewerDialogItem } from "@exav/viewer/react";

// Created once: a new list starts a new viewer.
const plugins = [pdf(), image({ wasmDecoders: true }), dwg(), dxf()];

const items: ViewerDialogItem[] = [
  { id: "plan", name: "plan.dwg", title: "Floor plan", source: { url: "/files/plan.dwg" } },
  { id: "report", name: "report.pdf", title: "Report", source: { url: "/files/report.pdf" } },
];

export function Files() {
  const [index, setIndex] = useState<number | null>(null);
  return (
    <ViewerProvider plugins={plugins} locale="en">
      {items.map((item, i) => (
        <button key={item.id} onClick={() => setIndex(i)}>{item.title}</button>
      ))}
      <ViewerDialog items={items} index={index} onIndexChange={setIndex} />
    </ViewerProvider>
  );
}
```

`ViewerBody` is the same viewer without the dialog, filling its parent.
[React UI](/viewer/react/) covers both, theming and
translations; [Core API](/viewer/api/) covers the viewer
without React and writing a plugin.

The same, with each file in a sandboxed frame: the host serves the frame app
the package ships ([Integration](/viewer/integration/#the-sandboxed-frame)),
and gives `sandbox` to the provider from `@exav/viewer/react/sandbox`, in place
of `plugins`. The engines are then the frame's: no peer dependency to install,
and a host that runs its engines in the page does not carry the frame's code.

```tsx
import { SandboxedViewerProvider } from "@exav/viewer/react/sandbox";

<SandboxedViewerProvider sandbox={{ url: "/exav-frame/index.html" }} locale="en">
```

## In this section

- [Integration](/viewer/integration/): the assets and
  where they are served from, bundlers other than Vite, caching and
  offline use, the Content-Security-Policy.
- [React UI](/viewer/react/): components, overrides,
  CSS custom properties, messages.
- [Core API](/viewer/api/): files and sources, sessions
  and controllers, detection, plugins.
- [Security](/viewer/security/): the threat model, the
  sandboxed frame and the in-page mode, the headers to serve, the checks,
  what remains.

The Rust decoders behind the wasm modules, and what they do not draw
faithfully yet, are documented under [exav-render](/subprojects/exav-render/).

## Where it lives

`crates/exav-viewer` in the repository: the Rust crate compiled to the five
wasm modules (`src/`), the TypeScript sources of the package (`ts/`, the
sandboxed frame's in `ts/frame/`), the demo (`demo/`) and its browser tests
(`e2e/`). The tests run against the demo built for production, as a host
would bundle the package, each file in the frame and in the page, under
their Content-Security-Policies.

## License

MIT. The DWG module contains the NewStroke stroke font, CC0-1.0, and
encoding_rs, whose WHATWG data is BSD-3-Clause; the bundled fonts (Arimo,
Cousine, Tinos) are under the SIL Open Font License. The
package's `NOTICE` lists the rest. The engines installed beside it keep
their own licenses: pdf.js is Apache-2.0, the others MIT.
The sandboxed frame app bundles those engines, with their license files in
its `licenses/`.
