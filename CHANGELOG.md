# Changelog

Notable changes per release. Dates are release dates; the format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) loosely, and versions
follow [semantic versioning](https://semver.org/).

## [Unreleased]

### Added

- **Pictures of pages from the formats that draw something.**
  `controllers.pictures` gives `raster(page, options)`, `toBlob(page, options)`
  and `render(page, longEdge)`. A page is drawn again from the document's own
  data at the size asked for, with a `region` in the format's coordinates (a
  fraction of a page, pixels of an image, drawing units with `layout`, a 3D
  camera) or `"current"`, `fit` ("contain" or "cover"), `lineweight`,
  `background` and an `AbortSignal`. The result reports the region actually
  drawn. `controllers.viewport` is what the session shows now, in the same
  coordinates. Errors are a `RasterError` (`unsupported`, `too-large`,
  `aborted`, `invalid`, `failed`). Pictures are limited to 16,384 px a side and
  64 Mi pixels in all, in the page and in the sandboxed frame, and are encoded
  by the host page. The demo has an "Export image" button beside the file's
  name, which opens a dialog of options.
- **A full screen button** in the viewer's tools (`FullscreenToggle`, a piece a
  host can replace) puts the viewer's box in full screen, from the host page,
  and leaves it. It is not shown where the browser has no full screen. Hosts
  drawing their own controls get `useFullscreen(() => element)` and
  `usePanel(info?)` (the side panel's fold state, shared by the rails and the
  toggle) from `@exav/viewer/react`.
- **`session.replace` works in the sandboxed frame**, so zoom and place are
  kept when a host swaps a document, for PDF and images.
- **A format registry** (`formats/registry.json`, 117 formats) from which the
  format matrix page and the viewer summary are generated, and which
  `make test-formats` and the viewer's and the scanner's tests check against
  the extractor's formats, the scanner's file types and the viewer's matchers.
- **Virtual disks read in place.** VHD (fixed and dynamic), VHDX, QCOW2
  (stored, deflate and zstd clusters) and VMDK (sparse and streamOptimized) are
  read through a `Read + Seek` that reads the container's tables as the walk
  reaches them and keeps only a 32 MiB cache of decoded units, so a disk of any
  declared size costs what it holds. A disk over the buffer limit is walked
  through its partitions and its NTFS and FAT files come out one at a time; a
  smaller one is still one member. What a disk decodes is counted against the
  scan budget. NTFS and FAT are read in place too, and a raw NTFS or FAT image
  or partition over the limit is walked instead of refused or streamed whole.
  ext is still copied into memory, as its volume only.
- **3D model pictures and viewport.** IFC, STL, OBJ, PLY and glTF expose
  `controllers.pictures` (one page) and `controllers.viewport`. A picture is
  redrawn from the geometry by an off-screen renderer at the requested size, in
  tiles beyond GPU limits, with MSAA or supersampling and a transparent or any
  CSS colour background. Regions are cameras in the file's own coordinates.
  `region: "current"` is the live camera, `fit` contain or cover applies, and
  hidden categories stay hidden. The `rasterTile` and `rasterSupersample`
  plugin options are for testing and tuning.
- **DWG and DXF pictures and viewport.** `pictures.raster` draws any layout
  again from the drawing's vectors at the asked pixel size, in a WebGL context
  of its own (tiled and composed past the GPU's limits). It takes a region in
  drawing units (y up, model units or a sheet's paper units), a size, `fit`,
  `lineweight` "screen" or "scaled", any CSS colour or a transparent ground,
  and a `layout` id, and reports the region actually drawn. The `viewport`
  store gives the layout and region in view, and `region: "current"` draws it.
  One picture is drawn at a time per session, abortable. The `rasterTile`
  option tunes the tile size.
- **Pictures and viewport for Word, PowerPoint, Excel and CSV.**
  `controllers.pictures` draws a page, slide or sheet at any size and region
  (fractions of the page; a sheet's page is its used area at 100% without
  headers), and `controllers.viewport` reports the page most in view and the
  visible part. The converted formats (DOC, ODT, RTF, XLS, ODS, Numbers, PPT,
  ODP, Keynote, ODG and the external converter's PDF or XLSX) get them too.
  Pictures are drawn from a second copy of the document and queued one at a
  time. A region whose whole page would pass the engines' 16.7 M pixel limit is
  refused as too large, and `background: "transparent"` is refused.
- **Pictures of a video's current frame.** `controllers.pictures` on video
  (page 1, space "frame"). A video the page cannot read (another origin without
  CORS, or a URL given to the sandboxed frame) is refused as unsupported
  instead of drawn blank.
- **IFC curved faces, trimming, alignments and storeys.** B-rep faces on
  spheres, tori and cylinders (sphere caps and seamless tubes included) are
  meshed in their surface's parameters instead of flat. B-spline faces are cut
  by their bounds, holes included. `StartParam`/`EndParam` of swept disks and
  directrix sweeps are honoured. IFC4X3 curve segments (lines, circles,
  clothoid and polynomial spirals, polynomial curves), gradient curves and
  linear placements without a Cartesian position are evaluated, and
  `IfcGridPlacement` sits at its grid intersection. exav-render reports
  `Element::storey`, `Batch::storey` and `Node::elevation`, and `@exav/viewer`
  has a `storeys` controller with a show/hide list. Conical faces
  (`IfcSurfaceOfRevolution`) are still drawn flat.
- **Camera RAW files open in the viewer and in exav-render**, shown by the
  largest JPEG or RGB preview they embed, turned by their Exif orientation
  (`exav_render::image::raw`, feature `raw`, default; `decode_any` reads a RAW
  file by its preview, `Format::detect` and `decode` still read a TIFF-structured
  one as the TIFF it also is, so exav-imagehash is unchanged). DNG, Canon CR2,
  CR3 and CRW, Nikon NEF and NRW, Sony ARW, SR2 and SRF, Olympus ORF, Panasonic
  RW2, RAW and Leica RWL, Fujifilm RAF, Pentax PEF, Samsung SRW, Hasselblad 3FR,
  Phase One IIQ, Sigma X3F, Kodak, Epson and Leaf files are told by their bytes,
  never their names, and a plain TIFF stays a TIFF. The sensor data is not
  decoded: a file that embeds no preview (most phones' DNG, Minolta MRW, the
  newest CR3 whose preview is HEIF) is `Error::NoPreview`, and the viewer says
  so (`image_no_preview`). Every offset and count in the file is bounds-checked,
  directory chains and loops are capped, and previews count against the decode
  budget as the RGBA a page holds. New `raw_preview` fuzz target.
- **The visible text of legacy and flat office files.** `text-office`
  (`exav-render`, `exav-grep`) and `visible-text-office` (`exav-core`, `exav`),
  opt-in, put the text of DOC, XLS, PPT, RTF, Word 2003 XML, SpreadsheetML 2003,
  SYLK, FODT, FODS, FODP, FODG, Numbers, Pages and Keynote in the text view. A
  match is located by sheet or slide, a link is `label (target)` and
  `--detect phishing` judges it; an encrypted, over-limit or damaged file makes
  the scan PARTIAL, never clean. Compound files are read as office documents by
  their extension only.
- **Demo examples.** 243 freely licensed example files (145 committed, 98
  fetched by `npm run demo:examples` and checked against their SHA-256), with a
  manifest, an attributions page and a NOTICE.
- **Office documents, spreadsheets, presentations and drawings converted in
  safe Rust, inside exav-render.** The features `office-sheets`,
  `office-slides`, `office-docs` and `office` (`exav_render::office`; none is
  a default feature) turn XLS (BIFF2 to BIFF8), ODS, FODS, OTS, Numbers ('08 and
  later), Excel 2003 XML, HTML tables and SYLK into XLSX; PowerPoint 95 to 2003
  (with .pps and .pot), ODP, OTP, FODP and Keynote 1 and later into PPTX;
  DOC and DOT (Word 6 to 2003), ODT, OTT, FODT, RTF, Word 2003 XML and Apple
  Pages (5 and later) into DOCX; and ODG, OTG, FODG and Visio 2013+ (VSDX, VSDM,
  VSTX, VSTM) drawings into PPTX, a page to a slide. @exav/viewer shows the
  result with `xlsx()`, `pptx()` and `docx()`, in a worker per file, from the
  `sheets`, `slides` and `docs` wasm modules (450, 434 and 359 KB brotli). The
  files are read as they are
  stored, nothing recalculated; tables, lists, sections, notes, fields,
  pictures, charts and shapes are kept; tracked changes in DOC are drawn as
  strike-through and underline. Input, cells, paragraphs, memory and
  decompressed parts are bounded (`Limits`); an encrypted file, one over its
  limits or a damaged one is reported with its reason. Fuzz targets
  `sheets_xls`, `sheets_ods`, `sheets_numbers`, `sheets_text`, `slides_ppt`,
  `slides_odp`, `slides_keynote`, `slides_odg`, `slides_vsdx`, `docs_doc`,
  `docs_odt`, `docs_rtf`, `docs_wml` and `docs_pages`.
- **Older presentations.** PowerPoint 95 and Keynote 1 to 5 (XML) are read.
  PowerPoint 2 to 4 (Windows, Macintosh, BinHex) are recognised and reported as
  unsupported. A presentation the converter recognises and cannot convert ends
  in an error with its kind. Also added: picture bullets (ODP, PPT),
  charts stored in PPT files as ODF packages, Keynote tables, charts and movies,
  inline pictures and charts in flat ODP, tile sizes from the picture's
  resolution, text areas of custom shapes, per-path fill and stroke, even-odd
  fills and the default style of unstyled shapes.
- **Large decks and long documents are laid out progressively.** The viewer
  asks @silurus/ooxml for `progressiveLayout` past 32 slides or 64 KB of
  inflated `document.xml`; on a 300-page document the first page shows in about
  2 s instead of about 19 s.
- **`maxArchiveEntries` for Word, Excel, PowerPoint and CSV** (`docx()`,
  `xlsx()`, `pptx()`, `csv()`): the most entries a document's ZIP may list.
  The default is now 20000; @silurus/ooxml's own 4096 refused a deck of about a
  thousand slides with pictures. The size a document may inflate to keeps its
  limit.
- **Volume sets are scanned as the archive they are.** A RAR set
  (`x.part1.rar`, `x.r00`), a ZIP set (`x.z01`, ..., `x.zip`) and a CAB set (the
  cabinets name one another) are rejoined and scanned whole, when their volumes
  sit in one directory (`exav DIR`), when one volume is named and its siblings
  are next to it (regular files only, never a symbolic link), and when they are
  sent together to the daemon. A set with a volume missing is `PARTIAL`, never
  clean. A cabinet read alone now reports the member that continues in another
  one instead of leaving it out.
- **ELF and Mach-O `EP` and section offsets** (`EP`, `Sn`, `SL`, `SEn`) match
  as they do in clamscan, read from the headers. Each was measured against
  clamscan 1.4.3. `EP` on a Mach-O is not resolved there either.
- **The viewer opens more archives:** cab, chm, iso, lzh, arj, ar and deb,
  cpio, xar and pkg, dmg, wim, zst, lz4, lz and Z files, tarballs of each
  compression, zoo, arc, alz, egg, jar and the other packages that are zips
  (apk, ipa, xpi, whl, nupkg, vsix, msix), comic books (cbz, cbr, cb7, cbt),
  virtual disks (vhd, vhdx, vmdk, qcow2) and `winmail.dat`, by name, by the
  type a desktop gives the file, or by the first bytes for a member of an
  archive. A `.tgz` typed `application/x-compressed-tar`, as a Linux desktop
  types it, is claimed now.
- **Text previews in the viewer** (`text()`, `@exav/viewer/text`): plain text,
  logs, Markdown, JSON, XML, YAML, TOML and INI, source code, subtitles and
  diffs, and HTML as source. Nothing in the file is parsed as markup; Markdown
  is read in WebAssembly by pulldown-cmark (CommonMark, tables, strikethrough,
  entities and reference links) through exav-render's new `markdown` feature
  (`forbid(unsafe_code)`, linear on every hostile input tried, a `markdown`
  fuzz target), and drawn element by element. A Markdown link shows its address
  and opens it on a click, as a PDF's links do (the host asks first in the
  frame), images are never loaded, bidirectional and control characters are made
  visible, a file is cut at 2 MiB and 50,000 lines with a warning, and a binary
  file is refused. The new `exav_viewer_text.wasm` module is about 190 KB (82 KB
  gzipped), loaded when a Markdown file is opened; if it fails to load, the
  text is shown as it is with a warning.
- **A visible-text layer, in the scanner and in `exav-grep`.** A document is
  matched through the text a reader sees as well as its bytes: its words without
  the marks, tags, escapes or run boundaries, entities decoded, and each link
  followed by where it goes (`label (target)`, even for a `javascript:` target
  or one with credentials), as a text view that `Target:0` and `Target:7`
  signatures see. That lets a signature match a phrase Word split across runs,
  a PDF kerned into pieces, or a link whose label names one site over a target
  on another. Read: Markdown (pulldown-cmark), HTML (html5gum's tokenizer, no
  tree), the XML parts of Word, PowerPoint, Excel and OpenDocument files by
  their path (quick-xml), AutoCAD drawings (the text, attributes, dimension and
  multileader texts, block and layer names, from exav-render's drawing model), as
  the input or as an archive member; and PDF (hayro) with the `visible-text-pdf`
  feature, which is not a default (see below). With `--alert-phishing`, a link
  whose label names one site and whose target another is now judged in these
  documents as an HTML anchor is, which also catches an HTML link whose target is
  written in entities. It is the new `visible-text` feature of `exav-core` and
  `exav` (default; off under `--clamav-compat`); an object past
  `--max-object-bytes` is not read and the scan is reported incomplete.
  `exav-grep --text` searches the same text, reporting `file.md!text` with the
  text's line numbers. exav-unpack has the `text` and `text-pdf` features and
  `exav_unpack::text`, exav-render `text` and `text-pdf` and
  `exav_render::text::visible_text`, and there is a `visible_text` fuzz target.
  RTF and email headers have none yet (see `docs/BACKLOG.md`).
- **PDF text is opt-in (`visible-text-pdf`, `exav-grep`'s `text-pdf`).**
  hayro-interpret turns on `hayro-syntax`'s `unsafe` feature itself, which
  switches every `flate2` in the build to zlib-rs (a damaged stream then gives
  back other bytes: two of exav-unpack's tests fail with it) and adds SIMD to
  the image decoders. hayro also puts no bound on what a stream decompresses to
  (a 1 MB PDF took 2.1 GB), so exav gives it a PDF only after its own reader has
  taken every stream within the limits. Built without hayro's predefined CJK
  CMaps, which would bring `brotli`.
- **More 3D models in the viewer and exav-render:** Wavefront OBJ, Stanford
  PLY (ASCII and binary) and glTF 2.0 (`.gltf` with embedded buffers, `.glb`),
  read in safe Rust with bounded triangulation, JSON, node trees and
  accessors. Nothing a model names is fetched; a glTF that needs an external
  file is reported, not shown. There is a `mesh` fuzz target for them.
- **JPEG XL in the viewer** (`.jxl`, first frame, 8-bit), decoded in
  WebAssembly by zenjxl-decoder, a fork of the libjxl team's jxl-rs that is
  `forbid(unsafe_code)`, within the viewer's decode budget. The image module
  grows from 1.1 to 1.65 MB. exav-render has it as the `jxl` feature, off by
  default.
- **A host can draw the whole viewer UI itself, the files still sandboxed.**
  The frame draws the document and nothing else; new controllers give the
  rest to the page: `media` (play, pause, seek, volume, rate; `video({
  controls: "none" })` drops the browser's own player controls), `sheets` (an
  Excel workbook's sheets, whose tabs the UI now draws: the engine's are gone),
  `pictures` (a page of a PDF or an image drawn whole as an `ImageBitmap`, for
  thumbnails and printing, at most 4096 px a side), and zoom for Word, Excel
  and CSV, page jumps for Word and slides. `printPictures` prints from those
  pictures, which the frame cannot and which a TIFF or a PDF cannot from its
  URL. The arrows and Escape pressed in the frame, when the document does not
  use them, reach the page's listeners (navigation keys only, at most 30 a
  second; `keys`). The frame takes the page's `--exav-viewer-*` colours and colour
  scheme, read where it is mounted (`theme`, `restyle()`), so a text file or a
  Markdown page in it follows a dark theme. In the frame, the iframe fills its
  element without the stylesheet. `demo/headless.html` is such a host, in
  plain DOM, and has the browser tests of all this.
- **SVG in the viewer**: drawn as an `<img>`, which runs none of its script and fetches nothing it names,
  and drawn again sharp when zoomed. **FLAC** is played with the rest.
- **The viewer speaks German, Spanish and Dutch**, and its strings are exported
  by `@exav/viewer` for hosts without React.
- **The viewer says what a load is doing, and how far it is.** A loading
  status carries a `step` (the file's bytes, the engine's download, its start,
  reading, converting, drawing) and the share of that step done, where it is
  counted; the default UI words each step and draws a bar, and the sandboxed
  frame passes both to the host.
- **DWG and DXF drawings closer to AutoCAD's.** A polyline with width is a
  filled band (its outline under `$FILLMODE` 0). Lineweights are millimetres on
  a layout's sheet, shown when the drawing's `$LWDISPLAY` says so (the cad
  `lineweights` option: `"drawing"`, `"always"`, `"never"`). A text crossing a
  viewport's edge is cut at it rather than kept or dropped whole. A block
  clipped with XCLIP shows only what is inside its boundary, with the frame
  `$XCLIPFRAME` asks for. Transparency holds for an entity in its layer's or
  block's colour; translucent geometry blends over everything behind it in
  draw order, text included, and is no darker where a polyline's segments
  meet. What is not drawn is said: entities by type (a warning's new
  `names`), xrefs counted with the other external references and their path
  drawn where they are inserted, the files they name listed; a drawing with
  nothing drawn here (a 3D model) keeps the thumbnail it was saved with.
  Text follows its block mirrored or stretched, and TEXT's backward and
  upside-down flags; Bottom and Middle alignment sit on the descender as in
  AutoCAD; Aligned keeps its width factor. MTEXT takes its style's width
  factor and slant, and draws `\W`, `\Q`, `\T`, paragraph justification,
  stacked fractions, background masks and frames; multiline attributes and a
  multileader's text are drawn as MTEXT. `%%nnn` and `\X` are read; symbol.ttf,
  the SHX Greek fonts and gdt.shx show the characters they stand for; text the
  stroke font lacks (Chinese in an SHX style) is drawn in an outline face,
  completed from the browser's fonts; an invisible constant attribute is not
  drawn; Greek and Cyrillic wrap at their own widths. A drawing with more
  characters than the glyph atlas affords at a close zoom draws them as
  distance fields, sharp at any zoom. A hatch pattern a unit or less apart
  fades as it crowds below a pixel instead of turning solid; one too dense to
  draw at all fills its region in a half tone instead of leaving it empty.
  3DFACE hides the edges its flags hide; points take `$PDMODE` and
  `$PDSIZE`; polyface and polygon meshes and MESH are drawn as their edges;
  TOLERANCE draws its feature control frame; a leader's arrowhead is its
  style's (`DIMLDRBLK`), and a multileader draws its leader to the landing
  with its arrowhead. Circles, arcs and a polyline's bulges are true arcs
  however close the view, no longer polygons. A dashed polyline restarts its
  pattern at each vertex unless `PLINEGEN` runs it on. AutoCAD's complex
  linetypes (TRACKS, ZIGZAG, FENCELINE1 and 2, BATTING) draw their shapes,
  and a linetype's text sits in its gap rather than a gap's length early,
  over the dash before it. A dimension saved without the block AutoCAD draws
  it from, as some generators write them, is drawn from its definition
  points and its style: linear, aligned, radius, diameter, angular and
  ordinate, its measurement in the style's decimal places, separator and
  zero suppression. Yellow, cyan and the
  lightest colours are darkened on a light ground, the darkest blues lightened
  on a dark one, so a line or a text stays legible (fills keep their colours);
  the cad `monochrome` option draws everything in ink, as monochrome.ctb
  plots. A layout is drawn on its sheet of paper, with the ground around it.
  A line's anti-aliased edge blends over what lies
  behind it, without the halo of paper it used to leave where it crossed
  another line, and a solid fill's edge is anti-aliased too. A stray entity far from the drawing (a line left at the
  origin of a plan in national grid coordinates) no longer shrinks it to a
  speck nor costs it its precision; the zoom stops where precision would run
  out, and the zoom controller says how far it goes. Tessellating takes a
  third less memory at its peak, the page no longer keeps a copy of the
  geometry once it is on the GPU, and a lost GL context comes back with the
  drawing on it.

### Changed

- **Dependencies are at their latest versions**, except the image decoders
  pinned to the versions libclamav 1.5.4 links (`image`, `png`, `gif`,
  `zune-jpeg`, `fax`, `weezl`), which `exav-imagehash` needs for ClamAV's hash.
  Notable: `quick-xml` 0.42, `hfsplus` and `apfs` 0.4, `cfb` 0.15,
  `lzma-rust2` 0.23, `sevenz-rust2` 0.24, `delharc` 0.8 (which also reads
  PMarc LHA archives), `base64` 0.23, `bit-set` 0.11, `yara-x-parser` 1.19;
  and for the viewer and docs, Vite 8, vitest 5, jsdom 30 and Playwright 1.64.
  This clears three RustSec advisories (`ctutils`, `rustls-webpki`,
  `webpki-roots`).
- **The minimum Rust version is 1.95** (it was 1.92), which `delharc` 0.8
  requires. It also leaves a single `lzma-rust2` in the tree.
- **QCOW2** images with an external data file, extended L2 entries or other
  unknown incompatible features are reported instead of misread, and **VMDK**
  grain table entries are read with the header's `numGTEsPerGT`.
- **Salvage keeps more of a damaged cabinet and archive.** A CAB MSZIP block cut
  or damaged part way keeps what it decoded; a cut at the end of the file is
  not reported, damage is. A ZIP member of a codec the `zip` crate lacks that
  fails part way keeps the bytes before the failure and is reported. An
  InstallShield Z member that stops short or fails part way keeps its decoded
  start and is reported, where it used to come out as whole or be dropped.
- The sandboxed frame's protocol is version 5 (it was 4): `draw` and `drawn`
  became `raster` and `rastered`, `replace` and `replaced` are new, and each
  `read` names its document. `MAX_PICTURE_EDGE` is 16,384 (was 4,096) with a
  new `MAX_PICTURE_PIXELS`, and the `pictures` store holds `{ count, space }`.
  The page and the frame must come from the same release.
- **`controllers.viewport` is worked out only while it is used.** A session that
  never reads it no longer measures the layout of Word, PowerPoint and PDF
  pages, and in the sandboxed frame no longer opens a second copy of every
  spreadsheet's workbook, which the frame's own reading of it did. The viewport is kept up to date while the store has a
  listener, and a `get()` without one works it out once (a sheet's is measured
  asynchronously, so its `get()` has the last measure and starts the next). In
  the sandboxed frame, the host sends `watch` when the first listener arrives
  and `unwatch` when the last leaves; the frame reports the viewport only
  between them, and a `get()` without a listener returns the last value the
  frame reported and asks for a fresh one. The demo's "Export image" follows it
  only while "What I see" is chosen.
- The viewer's description names OBJ, PLY and glTF wherever it named IFC and
  STL.
- A batch of an IFC scene now holds one storey's elements, so a scene can hold
  more batches. A face whose edge loop cannot be read counts in
  `warnings.invalid`, and surface evaluation and edge sampling have their own
  per-file budget.
- **External converter for the formats the package does not read.** A binary
  Visio, CorelDRAW, Publisher, WordPerfect or other Document Liberation file
  goes to an external converter: an ES module exporting
  `convert(bytes, { hint, maxMemory, signal, onProgress })` that resolves to
  `{ format: "pdf" | "xlsx", bytes }`, set with the `externalConverter` option,
  `exavViewer({ externalConverter })` in `@exav/viewer/vite` or
  `exav-viewer-assets --external-converter`; the `converter` option is `"exav"`
  or `"external"`. Without one, such a file ends in the new error
  `needs_converter`.
- `@silurus/ooxml` 0.89.1.
- The PPTX writer names slides (`<p:cSld name>`) and writes another Application
  string in `app.xml`.

- **The sandboxed frame may autoplay** (`allow="autoplay"`, `autoplay=*` in its
  `Permissions-Policy`): a player started by the page's controls would
  otherwise refuse to play. Update a frame served with its own headers. The
  frame's protocol is version 4: the frame and the page must come from the
  same release.
- Escape handed back by the frame closes `ViewerDialog`.
- **The viewer's CSS prefix is `exav-viewer-`**, in place of `exv-`: its custom
  properties (`--exav-viewer-accent`...) and its class names. Rename them in a
  theme or a stylesheet written for 0.0.2.

- A JBIG2 stream in a PDF has the same bound on the pixels of its regions as a
  JBIG2 file (512 MiB), whatever memory the caller allows.
- The `extreme` sweep reports a decoder that does not end (10 s) as well as one
  that panics.
- **Fewer dependencies, less `unsafe`.** DMG's LZFSE and LZVN runs are decoded
  by a port of Apple's reference decoder in exav-unpack, checked against it on
  damaged streams too (differential tests, run on request), in place of
  `lzfse_rust`. InstallShield Z archives are
  read in-tree, in place of `unshield` and `explode` (and `arraydeque`). The
  vendored TIFF decoder holds 16-bit float samples as their bits, which drops
  `half` and `zerocopy`; zstd is built without its checksum (`twox-hash`), which
  exav never checked; and `goblin` without the parsers exav does not use. A
  default build has 8 crates fewer, and 1,155 fewer `unsafe` uses in the code it
  links (plus 807 in `zerocopy`'s derive macro).

### Fixed

- **A malformed `raster` message to the sandboxed frame is answered.** The frame
  dropped one whose options failed the checks, so the host's promise stayed
  pending until aborted; the frame now answers `rastered` with the error
  `invalid`, which rejects with a `RasterError`.
- **QCOW2:** an L2 entry with flags and no offset read the file's own header as
  disk data. **VMDK:** a grain table entry of 1, a zeroed grain, read sector 1
  of the file.
- **LZFSE, LZVN and DCL on damaged streams.** An LZVN payload whose end opcode
  was read but whose declared size exceeded the input was reported as cut
  instead of damaged. An LZVN instruction past the block's declared size was
  called damage before the output limit was applied, dropping the part that
  fits. A DCL stream with a bad first header byte and no second was reported
  cut. Found by comparing the decoders with Apple's lzfse and zlib's blast on
  damaged streams.
- IFC: a cylindrical B-rep face bounded by two circles was drawn flat, a
  B-spline face was drawn over its whole surface, and a grid-placed element sat
  at its parent's origin.
- **PDF strings:** `\b` and `\f` were read as the letters, which gave a wrong
  owner key, so an encrypted PDF that opens with an empty password was reported
  password-protected. A short octal escape such as `\0` also swallowed the byte
  after it, closing parenthesis included. Found by a differential run against
  ClamAV (`docs/DIFFTEST_TRIAGE.md`).
- **An object is scanned once per scan when its bytes were already scanned
  clean** in the same place: same container type, same types above it, same
  name extension, at the same depth or shallower. A document that holds copies
  of itself used to be scanned once per copy (a 5 MB file that unpacks to 660
  MB, 152 members of which 50 differ, took 30 s and now takes 3 s). Only a
  member of 64 KiB to 512 MiB that came out clean and complete is remembered,
  by a SHA-256 of its bytes and place; a copy that is not clean, or that sits
  deeper, is scanned as before.
- **Carving** counts a ZIP stapled into an object once. Each local header after
  the first used to be an archive candidate of its own: a zip of a few dozen
  entries filled the cap of 32 and the object was reported over a limit, and the
  rest of the object was rescanned once per entry. A header at the offset the
  previous one says the next entry begins (no data descriptor, encryption or
  ZIP64 size) is no longer a candidate; the first one's walk reads it.

- **A zstd stream of a few kilobytes can no longer take gigabytes of memory**
  (RUSTSEC-2026-0344): ruzstd 0.9.1 bounds what one block decodes to. Also
  rustls 0.23.46 (RUSTSEC-2026-0346 to 0349), in the `http` builds.
- **Two InstallShield Z members with the same path are both scanned.** The
  reader kept only one of them.
- **Each dynamic block in an AutoCAD 2007 or later DWG is drawn as itself.**
  AutoCAD's files can name several anonymous blocks plain `*U`, and every
  insert of one drew the first; they are numbered as AutoCAD numbers them.

Found by an 8-hour fuzzing run:

- **An InstallShield Z archive can no longer ask for billions of members.** A
  few hundred bytes of directory records made the reader build an entry for each
  declared member before anything was checked (1.5 GB). A table declaring more
  than 20,000 is reported as unexamined.
- **A YARA rule with an error deep inside parentheses is refused at once.** The
  parser took about 2^d steps for an error inside d open parentheses (5.6 s for
  3.5 KB of rule text). Nesting past 12 is a compile error.
- **RAR key derivation is bounded for the whole scan.** The bound was per
  archive, so archives inside archives each paid it, and one header asking for
  2^24 PBKDF2 iterations cost 2.6 s. It is now 2^22 iterations (about 0.7 s) for
  RAR5 and 256 derivations for RAR3, counted across the scan. An archive asking
  for a larger count is reported as encrypted, like one no password opens.

Found by fuzzing the virtual disk walker and the Office readers:

- **A FAT directory or file at cluster 1 no longer ends the walk of the whole
  volume.** The `fatfs` crate subtracts 2 from a cluster number it takes from
  the volume without looking at it, so a directory entry or a chain naming
  cluster 1 made it panic, and the panic was caught at the walk's boundary as
  an undecodable volume, losing every other file. It now ends only that
  directory or file, which is reported.
- **A PowerPoint 95 bullet size of 4,294,968 percent or more no longer panics.**
  The size is dropped when it is not from 25 to 400, but the product was taken
  first, and overflowed: a panic in a build that checks overflow.
- **Pinch and ctrl-wheel zoom on a DWG or DXF drawing no longer lags.** A frame
  was drawn for every zoom event, and on a drawing that takes the GPU longer
  than a frame they queued, so the view followed the fingers seconds late.
  While the zoom goes on the canvas is now scaled where it is (a CSS
  transform, at most once per animation frame) and the drawing is drawn sharp
  when the zoom pauses. The zoom and viewport stores are published once per
  frame instead of once per event, which is one message less per event to a
  host of the sandboxed frame. The glyph page the closer view needs, made of
  distance fields when the text is too large for the atlas budget, was made in
  one piece, which held the page's thread for hundreds of milliseconds, when
  the zoom stopped; it is now made in slices of 8 ms while the old page stays up.
- **A trackpad pinch on a DWG or DXF drawing zooms in Safari.** Safari reports
  the pinch as gesture events, which the drawing only cancelled; they now zoom
  by their scale about the fingers, as on an image. The ctrl+wheel events Safari
  may send for the same pinch are ignored while the gesture goes on, so the
  zoom is not applied twice.
- **A PDF zooms out past the page fitted to the width**, down to a quarter of
  it (`pdf({ minZoom })`, default 0.25 instead of 1), so a whole page is in
  view on any screen. The button back to the width shows once zoomed either way.
- **The side panel's toggle is among the tools**, bottom right beside the zoom
  buttons (a `PanelToggle` piece), instead of in the panel's header and a
  square at the top right when it is folded. It stays on a touch screen: what
  is for a mouse (the zoom and drag groups, full screen) has the attribute
  `data-pointer-only`, which a host's own piece can carry too.
- **The fit button of the zoom controls is shown only once the view is not the
  fitted one**, and has a "back to the start" icon instead of the full screen
  one. A Word document's zoom controller now reports its scale relative to the
  page fitted to the width, as the others do relative to their fit.

## [0.0.2] - 2026-10-11

The scanner, rebuilt around one streaming scan; three new projects (a browser
file viewer, image decoders, a perceptual image hash); and a long run of
fuzzing that fixed more than a hundred bounds and decoding bugs.

### Highlights

- **One scan for every input, at any size.** A file, stdin, a FIFO, `INSTREAM`,
  ICAP and HTTP all go through the same pipeline. A file over
  `--max-object-bytes` (256 MiB by default) now gets the full scan (wildcard and
  logical signatures, PCRE, YARA, bytecode, carving, heuristics), read through
  an 8 MiB block cache; it used to get a literal-and-hash pass only. What needs
  the whole object in memory (PE structure, Authenticode, packers, YARA's `pe`,
  `elf` and `dotnet` modules, containers read whole) makes such a file
  `LIMITS-EXCEEDED`, unless something is found. `--all-matches` and
  `ALLMATCHSCAN` list every detection at any size.
- **Faster.** One index of signature literals replaces the automatons; a
  signature with a narrow offset window is checked where it can start; whole-file
  digests are computed once and only when a signature can use them; objects read
  through the block cache are read far fewer times. A prebuilt database is
  smaller and loads faster.
- **DWG and DXF drawings are scanned** (R13 to 2018, ASCII and binary): the
  files an OLE2FRAME embeds are extracted and scanned.
- **`@exav/viewer`**, a new npm package: a file viewer for the browser (PDF,
  images, DWG and DXF, Word, Excel, PowerPoint, CSV, IFC and STL models, video,
  audio, archives), each engine loaded on first use, with a sandboxed mode that
  opens each file in its own `<iframe sandbox>`. Demo at exav.org/viewer/demo/.
- **`exav-render`**, memory-safe decoders for what to draw: TIFF, BMP and other
  raster images, JPEG 2000, JBIG2, fax, DWG, DXF, IFC, STL. **`exav-imagehash`**,
  a crate and a command: perceptual image hashes, with presets equal to
  `sigtool --fuzzy-img` and Python `imagehash.phash`; the scanner's `fuzzy_img#`
  now goes through it.
- **A Helm chart** (`deploy/helm/exav-chart`) and a Kubernetes guide, by
  Bastien Ogier.
- **`exav-unpack` has `unzip`'s command line**: `-l`, `-t`, `-p`, `-d`, `-x`,
  `-o`, `-n`, `-P` and the rest mean what they mean to Info-ZIP `unzip` 6.00,
  with its exit statuses. It extracts every format the library reads, restores
  times, modes and symlinks, never writes through a link, and reads a split ZIP
  (`.z01`) or a RAR volume set from any part.
- Releases carry `exav-unpack`, `exav-grep`, `exav-pe-emu` and `exav-imagehash`
  beside `exav`. exav.org is organised by product.

### Breaking changes

- Removed: `--max-extracted-bytes` (it stops the run with a message naming the
  change: a scan holds 1 GiB, 400M under `--clamav-compat`, and
  `--max-process-bytes` lowers it); `--build-shard-bytes`; exav-core's
  `scan_stream` (use `scan_seekable`); `exav`'s `checksums` feature; the
  `exav-unpack list` and `extract` subcommands (`-l`, `-d DIR`).
- Renamed: environment variables without a flag are `EXAV_DEBUG_*`
  (`EXAV_BC_TRACE` is `EXAV_DEBUG_BC_TRACE`, and so on); the systemd unit is
  `exav.service` (it was `exav-clamd.service`).
- The daemon's signals match clamd's: `SIGUSR2` reloads the signatures and
  `SIGHUP` reopens the `--log` file. `SIGUSR2` used to kill the process.
- A stream that ends before its terminator is answered `ERROR` on `INSTREAM`
  and `EXINSTREAM`. A signature path that loads nothing is an error.
- YARA detections are named `YARA.<rule>` outside `--clamav-compat`. A YARA
  pattern keeps at most a million matches, as yara-x does.
- `--max-process-bytes` also lowers `--max-object-bytes` to a quarter of the
  memory a scan gets: a file past it is `LIMITS-EXCEEDED`, not `out of memory`.
- A scan that fails behind the ICAP listener is a block.
- The published image uses Docker mediatypes, so podman honours its
  `HEALTHCHECK` (by Nastaliss). This drops the buildx provenance attestation.
  The 0.0.1 tags are OCI.

### Added

- `--max-pcre-bytes`, `--min-scan-bytes` (default 6) and
  `--max-pe-emulation-steps`; `--partial-as password-protected=found` reports
  any encrypted member as `Heuristics.Encrypted.*`, as ClamAV's
  `--alert-encrypted` does; the `image-hash` and `phishing` features, on by
  default; `.msu` databases under `--detect pua`.
- Decoding: encrypted RAR with the caller's passwords (headers encrypted
  included), RAR 7 headers, ZIP Shrink, Reduce, Implode and PPMd members, NSIS
  with bzip2, ZIP members found by their local header, ZIP64 included.
- A guide to sizing a server, with the flags for a 4 GB host; a health check in
  the Compose and Kubernetes examples; `make miri`.
- exav-unpack: `Prescan` and `detect_prescanned`, and a modification time on
  `MemberMeta` and `Entry`.

### Changed

- Matching no longer copies an object whole, and PCRE no longer scans a copy of
  it. Bytecode follows ClamAV 1.4.3 in four more places, and its triggers are
  evaluated with the object's container.
- A signature reload lets scans in progress finish. A DMG is walked without
  decompressing its whole disk.
- A compressed stream damaged part way keeps what was decoded before the damage
  and is reported as damaged, not lost or complete. `exav-unpack-wasm`'s
  `list()` decodes nothing it can avoid.
- Dependencies: `bincode` (RUSTSEC-2025-0141) and `serde` are gone from
  `exav-unpack`; the RustCrypto crates move to their current generation
  (`digest` 0.11, `cipher` 0.5); `ureq` 3 for the `http` features, which now
  follows the `HTTP_PROXY`, `HTTPS_PROXY` and `NO_PROXY` environment;
  `tlsh2` 1.x, `ext4-view` 1.0 and `lzma-rust2` 0.21 with their upstream
  fixes; the bzip2 decoder is vendored from `bzip2-rs` with a fix.

### Fixed

Found by fuzzing, an arithmetic audit and the ClamAV comparison. The bugs that
could change a verdict:

- **A decompression or parsing bomb now stops at a budget.** About a hundred
  header numbers added or multiplied unchecked are refused: the disk-image
  readers (VMDK, QCOW2, VHDX, NTFS, WIM, ext, FAT, partitions), CHM, DWG
  polylines and hatches, 7z folders, carving, signature files and databases
  past `u32`. ARC, ZOO and `.Z` decoders no longer allocate without limit.
- **A damaged or cut-short member is never `OK`.** Truncated bzip2, Zstandard,
  xz, UPX, NSIS, 7z PPMd, DMG and EGG data, a RAR member failing its CRC, and a
  member cut off by the end of the file are reported as damaged or
  `UNSCANNABLE`.
- **PCRE subsignatures match as ClamAV's PCRE2 does**: bytes above 0x7F,
  offsets, the `g` flag, `\b` and `\B` beside a high byte, and a repeat that can
  match nothing.
- **RAR**: encrypted headers and stored members, the window of each member in
  an archive, the x86, Itanium and ARM filters, empty members in a solid group,
  a volume set missing a volume, a volume numbered 65,535 or 2^64 - 1.
- **ZIP**: members found only by their local header, with other bytes before
  the archive, in ZIP64 form, compressed with an unknown method, with LZMA or
  Zstandard and cut short. `--all-matches` with `--alert-exceeds-max` dropped
  the alert on a decompression bomb and reported a clean scan.
- **Performance and portability**: a YARA `xor(1-255)` pattern cost 255
  comparisons per position; a scan time limit above 100,000,000 seconds was
  refused by macOS and left no limit.
- **Daemon**: the watch of its signature source missed changes, so new
  signatures were not loaded; a worker stopped mid-job answers with `ERROR`
  instead of closing the connection; scanning a URL took a server that answered
  a range request with the whole object (`200`, not `206`) as the range, and is
  an error now.
- **Emulator and decoders**: a panic on a packed file with a bad import
  directory; the x86 decoder sized `UMONITOR`'s register by the operand size;
  a PE whose parse failed over one malformed directory lost the rest.
- **Documents**: PDF encryption (revision 4, 40-bit RC4), encrypted DMG and
  workbooks, VBA projects, lenient compound files, `Ole10Native` objects, GIF
  extension blocks, HTML and text signatures, JPEG checks under
  `--detect broken-media`, and `fuzzy_img#` hashes now computed as ClamAV 1.4.6
  does.
- An object whose first read failed made the safetensors sniff panic.

## [0.0.1] - 2026-09-16

First public release. Everything below is new, so this section describes what
the project *is* rather than what changed in it.

### The scanner

- **ClamAV-compatible.** Reads CVD/CLD containers and the `.ndb`/`.ldb`/`.hdb`/
  `.mdb`/`.cdb`/`.hsb`/`.pdb`/`.cbc` signature families, speaks the clamd
  protocol, and matches `clamscan`'s output and exit codes, except the
  documented fourth exit code: where ClamAV answers `OK` for a file it gave up
  on, exav answers `PARTIAL` (exit 3).
- **Never a silent clean.** A file that could not be fully examined is reported
  `LIMITS-EXCEEDED`, `UNSCANNABLE` or `PASSWORD-PROTECTED`, never `OK`. This is
  the invariant the rest of the design serves; where ClamAV returns `OK` for a
  file it gave up on, exav does not.
- **Dozens of container formats**, nested arbitrarily deep, all extracted in memory
  under decompression-bomb budgets: archives, disk images, filesystems,
  OLE/OOXML documents, PDF, email, and installer formats. Each is its own Cargo
  feature, so a ZIP-only build is a real build.
- **A native YARA engine** with no `libyara` and no runtime code generation,
  checked against `yara-x` by compiling the same rules with both and comparing
  the matching-rule sets.
- **A sandboxed x86-32 emulator** that unpacks runtime-packed executables by
  running the packer's own stub and capturing the image it rebuilds, so the
  original program is scanned whatever it was packed with.

### Memory safety

`#![forbid(unsafe_code)]` on every crate except `exav`, whose only
exception is the prefork daemon's process management (`fork`, `waitpid`,
`setrlimit`, descriptor passing). No scanned byte reaches any of it.

The x86 decoder, the one component a scanned file drives directly, supplying
control flow rather than data, is `exav-x86`: dependency-free, safe, and
checked instruction by instruction against an independent decoder over
94,245,255 decode sites from real packed malware, agreeing on every one.

### Not included

- No bundled signature URLs. Update sources are supplied by the operator.
- No digital-signature verification of downloaded databases, and no rsync.
- The x86 decoder covers 32-bit protected mode in full, including VEX, EVEX
  and XOP, but only 32-bit mode: no REX, no RIP-relative addressing, no 64-bit
  forms. The emulator runs 32-bit packer stubs.
