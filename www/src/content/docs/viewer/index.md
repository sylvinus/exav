---
title: File viewer
description: "@exav/viewer, a file viewer for the browser: PDF, images, DWG and DXF, Office documents, IFC, STL, OBJ, PLY and glTF models, media and archives, each engine loaded on first use, every asset from the host's own origin."
---

**A file viewer for the browser, as one npm package, `@exav/viewer`.** It
shows <!-- formats:viewer-summary -->PDF, images, DWG and DXF drawings, Word, Excel, PowerPoint and CSV, text (Markdown, JSON, XML, source code), IFC, STL, OBJ, PLY and glTF models, video, audio, and what is inside an archive<!-- /formats:viewer-summary -->. It also reads, by
converting them in the browser, the 1997 Office formats, RTF, OpenDocument,
Numbers, Keynote and Visio files. Each format is a plugin; a host lists the
ones it opens, and only their engines are bundled. An engine's code is
fetched when the first file of its format opens, never before.

**[Try the demo](/viewer/demo/)**: its samples are public-domain, CC0,
CC-BY, MIT, BSD or Apache files, most of them made for the demo
([exav-samples](https://github.com/sylvinus/exav-samples) and the
[example files](/viewer/examples/), with each author and licence), and a
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
  HDR, JPEG 2000, JBIG2, JPEG XL, camera RAW files shown by their embedded
  preview), the JPEG 2000, JBIG2 and fax images inside PDFs,
  DWG and DXF drawings, and IFC, STL, OBJ, PLY and glTF models are decoded by
  [exav-render](/subprojects/exav-render/), safe Rust compiled to wasm and
  run in a worker. So are the converters of the formats the Office engines do
  not read: spreadsheets (XLS, ODS, Numbers) to XLSX, presentations and
  drawings (PPT, ODP, Keynote, ODG, Visio) to PPTX, and text documents (DOC,
  ODT, RTF) to DOCX. The modules import nothing but wasm-bindgen's plumbing:
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
| PNG, JPEG, GIF, WebP, SVG | `image()`, `@exav/viewer/image` | the browser | |
| TIFF, BMP, ICO, PNM, QOI, DDS, farbfeld, HDR, JPEG 2000 (.jp2, .jpf, .j2k), JBIG2 (.jb2), JPEG XL (.jxl) | `image({ wasmDecoders: true })` | exav-render, in a worker | |
| Camera RAW: DNG, CR2, CR3, CRW, NEF, NRW, ARW, SR2, SRF, ORF, RW2, RAW, RWL, RAF, PEF, SRW, 3FR, IIQ, X3F, MRW, DCR, KDC, ERF, MEF, MOS | `image({ wasmDecoders: true })` | exav-render, in a worker: the largest JPEG or RGB preview the file embeds, turned by its Exif orientation; the sensor data is not decoded, so a file with no preview shows an error | |
| DWG (R13 to 2018), DXF | `dwg()`, `dxf()`, `@exav/viewer/cad` | exav-render, in a worker; WebGL2 | |
| Word, Excel, PowerPoint | `docx()`, `xlsx()`, `pptx()`, `@exav/viewer/office` | @silurus/ooxml | `@silurus/ooxml` |
| CSV, TSV | `csv()` | the separator and encoding read off the bytes | `@silurus/ooxml` |
| XLS (.xls, .xlt; Excel 2.1 to 2003); ODS (.ods, .ots, .fods); Numbers (.numbers); an XML Spreadsheet 2003, HTML table or SYLK file saved as .xls | `xls()`, `ods()`, `numbers()`, `@exav/viewer/office`, with `xlsx()` | exav-render's `sheets`, in a worker: converted to XLSX, shown by `xlsx()` | `@silurus/ooxml` |
| PPT (.ppt, .pps, .pot; PowerPoint 95 and 97 to 2003); ODP (.odp, .otp, .fodp); Keynote (.key, every version); ODG (.odg, .otg, .fodg); Visio 2013 and later (.vsdx, .vsdm, .vstx, .vstm) | `ppt()`, `odp()`, `keynote()`, `odg()`, `visio()`, `@exav/viewer/office`, with `pptx()` | exav-render's `slides`, in a worker: converted to PPTX, shown by `pptx()`; a page of a drawing is a slide | `@silurus/ooxml` |
| RTF (.rtf); DOC (.doc, .dot; Word 6 to 2003); ODT (.odt, .ott, .fodt) | `rtf()`, `doc()`, `odt()`, `@exav/viewer/office`, with `docx()` | exav-render's `docs` (a prototype), in a worker: converted to DOCX, shown by `docx()` | `@silurus/ooxml` |
| What none of those converters reads: binary Visio (.vsd, .vst), Visio 2003 XML (.vdx, .vtx), CorelDRAW (.cdr, .cmx), Publisher (.pub), PageMaker (6 to 7), FreeHand (3 to 11), QuarkXPress (3.1 to 4.1), Zoner Draw (4, 5), WordPerfect Graphics (.wpg); a CSV or DIF saved as .xls | `visio()`, `coreldraw()`, `publisher()`, `pagemaker()`, `freehand()`, `quarkxpress()`, `zonerdraw()`, `wpg()`, `@exav/viewer/office`, with `pdf()` and `xlsx()` | an [external converter](/viewer/integration/#the-external-converter) the host names; without one the file ends in the `needs_converter` error | the converter's package |
| Text: .txt, .text, .log; Markdown (.md, .markdown); JSON (.json, .geojson); XML (.xml, .xsd, .xsl, .xslt, .rss, .atom, .kml, .gpx, .rdf, .wsdl, .plist); HTML as source (.html, .htm, .xhtml); YAML, TOML, INI and conf files, .jsonl, .srt and .vtt subtitles, diffs (.diff, .patch); source code and scripts (.js, .ts, .py, .sh, .css, .c, .h, .rs, .go, .java and the like) | `text()`, `@exav/viewer/text` | written for the viewer, in TypeScript; no dependency | |
| IFC (IFC2X3, IFC4, IFC4X3) | `ifc()`, `@exav/viewer/ifc` | exav-render, in a worker; drawn with three.js | `three` |
| STL (binary, ASCII) | `stl()`, `@exav/viewer/model` | exav-render, in a worker; drawn with three.js | `three` |
| Wavefront OBJ (.obj), Stanford PLY (.ply, ASCII and binary), glTF 2.0 (.gltf with `data:` buffers, .glb) | `obj()`, `ply()`, `gltf()`, `@exav/viewer/model` | exav-render, in a worker; drawn with three.js. Geometry, groups and nodes, vertex and material colours; no textures, materials files or animations, and no file or URL named by the model is fetched (a glTF whose buffers are other files, and a PLY point cloud, show the error) | `three` |
| Video, audio (MP4, MOV, WebM, Ogg; MP3, M4A, AAC, WAV, Ogg, Opus, FLAC) | `video()`, `audio()`, `@exav/viewer/media` | the browser, with its controls or the host's | |
| Archives: zip, 7z, rar, tar, cab, lzh, arj, ar and deb, cpio, xar and pkg, zoo, arc, alz, egg; compressed files: gz, bz2, xz, zst, lz4, lz, Z; packages that are zips (jar, war, apk, aab, ipa, xpi, whl, nupkg, vsix, kmz); comic books (cbz, cbr, cb7, cbt); disc and disk images: iso, dmg, wim, vhd, vhdx, vmdk, qcow2; chm help files; `winmail.dat` | `archive()`, `@exav/viewer/archive` | [exav-unpack](/unpack/wasm/) in wasm | `@exav/unpack-wasm` |

The peer ranges: `@silurus/ooxml` `>=0.87.0 <1` (the package is built and
tested with 0.89.1), `pdfjs-dist` `>=5.0.0 <7`, `three` `>=0.170.0 <1`,
React 19. All are optional.

`@exav/viewer/all` exports `allPlugins()`, every plugin at once, for a host
that installs every engine.

## Converted formats

The Office engines read Open XML. A file in another Office format is
converted first, in a worker of its own, and the result is shown by the
engine of the Open XML format it became:

- **Spreadsheets** (XLS, ODS, Numbers, and the XML, HTML and SYLK files Excel
  opens from a .xls name) become XLSX, shown as a workbook.
- **Presentations and drawings** (PPT, ODP, Keynote, ODG, Visio 2013 and
  later) become PPTX. A page of a drawing is a slide, in the size of the
  largest page.
- **Text documents** (DOC, ODT, RTF) become DOCX. This converter is a
  prototype: on the project's test files, 32% of the pages of DOC files come
  out close to a reference rendering, against 50% for DOCX files drawn
  natively.

The converters are [exav-render](/subprojects/exav-render/#office-documents)'s
`sheets`, `slides` and `docs`, compiled to three wasm modules that ship inside
the package (`exav_viewer_sheets`, `exav_viewer_slides`,
`exav_viewer_docs`; their [sizes](/viewer/integration/#two-kinds-of-files)
are on the Integration page). A host installs nothing for them, and nothing is
fetched but the module. Values are shown as the file stored them: nothing is
recalculated and no macro runs.

A file a converter recognises and cannot convert (encrypted with a password,
too large, damaged, in a version it does not read) ends in the Office error,
and its cause says why. It is never handed to the external converter.

Binary Visio (.vsd), CorelDRAW, Publisher, PageMaker, FreeHand, QuarkXPress,
Zoner Draw, WordPerfect Graphics, and a CSV or DIF named .xls are read by no
converter of the package. They go to an **external converter**, a module the
host names, and end in the `needs_converter` error when it names none.
[Integration](/viewer/integration/#the-external-converter) gives its contract.
The live demo is built with none.

## Text

The text plugin claims the names and content types in the table and no
other: a file is not opened as text because it happens to be text. `.svg` is
not claimed (it is an image, below), and HTML is shown as
its source, never as a page. It is also what opens the text files inside an
archive, by their names.

- **Nothing is interpreted.** The page is built with `createElement` and
  `textContent`; no markup string from the file is ever parsed, so a
  `<script>`, an `onerror` image or an entity in a file is text on the page.
  JSON and XML are reindented by a tokenizer, not parsed to a tree: JSON
  numbers keep their text (12345678901234567890 and 1.10 stay as written),
  and an XML entity or DTD is neither expanded nor fetched.
- **Markdown** is CommonMark with tables and strikethrough, read in
  WebAssembly (pulldown-cmark, in exav-render) into a tree of data that the
  page draws element by element: headings, emphasis, strong, strike, code spans
  and fences, quotes, nested lists, tables, rules, links, entities, reference
  links and hard breaks. Raw HTML is shown as text, and an image is its alt
  text in brackets: nothing is loaded. A
  link to an absolute `http:`, `https:` or `mailto:` address (without
  credentials) is drawn as its label with the address written beside it, and
  an `http:` or `https:` one opens on a click or Enter as a PDF's links do: in
  the sandboxed frame the host asks first, in the page it opens a new tab
  with no opener. A `mailto:` link is text, and any other target
  (`javascript:`, `data:`, `file:`, a relative path) leaves the label alone.
  A link is not an anchor, so the document itself never navigates.
- **What the bytes say.** A byte-order mark picks UTF-8 or UTF-16;
  otherwise UTF-8 if the bytes are valid in it, else windows-1252. A file
  with a NUL byte in its first 64 KiB, or mostly control characters, is
  not text, and the viewer says so instead of drawing noise. Control
  characters show as their Control Pictures glyph, and bidirectional
  embeddings, overrides and isolates (CVE-2021-42574) and the line and
  paragraph separators show as `<U+202E>` and the like, so a file cannot
  reorder or hide what it says.
- **Limits.** The first 2 MiB and 50,000 lines are read, a line is cut at
  10,000 characters, a Markdown document is cut at 100,000 nodes and
  nests quotes and lists ten deep, JSON nests a hundred deep. A warning
  (`text_truncated`, `text_long_lines`) says when anything was left out.
  Text is drawn in blocks of 200 lines, the rest after the first paint, so
  that a large file does not freeze the tab. A URL source is downloaded
  whole before it is cut.

IFC models are read and meshed by exav's own engine, written from
buildingSMART's schemas and documentation: placements, mapped items,
extrusions of every profile type, revolutions, sweeps along a curve,
tessellated face sets, faceted B-reps, advanced B-reps (planar, cylindrical,
spherical, toroidal and B-spline faces, the last cut by their bounds),
surface models, CSG primitives, booleans with half-spaces, and openings cut
out of their walls. Categories can be hidden, and so can the building
storeys of a model that has two or more (the `storeys` controller, listed
above the categories). Elements a file gives no colour take their category's. A model is framed on
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
most. An SVG is a document that can carry script, so it is drawn as an
`<img>`, where the browser runs none of it and fetches nothing it names,
and drawn again sharp when zoomed.

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
  where they are served from, bundlers other than Vite, the external
  converter, caching and offline use, the Content-Security-Policy.
- [React UI](/viewer/react/): components, overrides,
  CSS custom properties, messages.
- [Core API](/viewer/api/): files and sources, sessions
  and controllers, detection, plugins.
- [Security](/viewer/security/): the threat model, the
  sandboxed frame and the in-page mode, the headers to serve, the checks,
  what remains.
- [Example files](/viewer/examples/): the files of the [demo](/viewer/demo/),
  one or more for each format, with their authors, sources and licences.
- [Format matrix](/project/formats/): every format, with what the scanner,
  the extractor and the viewer do with it.

The Rust decoders behind the wasm modules, and what they do not draw
faithfully yet, are documented under [exav-render](/subprojects/exav-render/).

## Where it lives

`crates/exav-viewer` in the repository: the Rust crate compiled to the seven
wasm modules and the two decoders pdf.js loads (`src/`), the TypeScript sources of the package (`ts/`, the
sandboxed frame's in `ts/frame/`), the demo (`demo/`) and its browser tests
(`e2e/`). The tests run against the demo built for production, as a host
would bundle the package, each file in the frame and in the page, under
their Content-Security-Policies.

## License

MIT. The DWG module contains the NewStroke stroke font, CC0-1.0, and
encoding_rs, whose WHATWG data is BSD-3-Clause; the bundled fonts (Arimo,
Cousine, Tinos) are under the SIL Open Font License. The
package's `NOTICE` lists the rest. The engines installed beside it keep
their own licenses: pdf.js is Apache-2.0, the others MIT. An external
converter a host installs keeps its own.
The sandboxed frame app bundles those engines, with their license files in
its `licenses/`.
