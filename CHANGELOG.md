# Changelog

Notable changes per release. Dates are release dates; the format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) loosely, and versions
follow [semantic versioning](https://semver.org/).

## [Unreleased]

### Added

- **`--listen-health ADDR`: a listener that answers while the workers are busy.**
  Under the pool a `PING` waits for a free worker, so a health check timed out
  on a daemon that was only busy and had it restarted. The health listener
  speaks the protocol of its scheme and does nothing else: `clamd://` answers
  `PING`, `VERSION` and `STATS`, `icap://` answers `OPTIONS` (`REQMOD` and
  `RESPMOD` get 405). A child process of its own serves it under the pool,
  threads otherwise; `exav --ping` probes it when the configuration names one.
- **`STATS` is the pool's.** The counters were statics in each process, so under
  the pool `STATS` reported the one worker that happened to answer, and ICAP's
  child counted apart. They are in memory shared by the processes of the pool
  now, `STATS` from any of them (the health listener included) is the pool's
  totals, and a worker killed mid-scan does not leave the in-flight gauge too
  high.
- **`--max-extracted-bytes` is back, and `--max-bytecode-memory-bytes` is new.** The
  total of the members that a scan decodes whole (1G, 400M under
  `--clamav-compat`) had no setting since 0.0.2 took the flag away, and
  `--max-process-bytes` could only lower it. Members that are streamed (ZIP,
  7z, TAR, CAB, the stream codecs) are not in it: 1.5 GB archives of these scan
  past it. `off` or `0` removes either limit; `--max-process-bytes` still
  lowers both to what fits the memory a scan gets.
- **`--object-cache-bytes`, `--object-cache-block-bytes` and `--http-request-bytes`.**
  The block cache an object past `--max-object-bytes` is read through, and the
  requests of an `http(s)://` source, had sizes fixed in the code (64 KiB blocks,
  8 MiB held, requests of 64 KiB growing to 8 MiB). They are settings now, and
  the block is 1 MiB by default: against a 300 MB object with a server that
  waits 100 ms for each request, 1M blocks took 22 s where 64K took 56 s, and
  4M took no less. A scan with `--max-process-bytes`
  lowers the cache and the request to an eighth of its memory each. The
  [block cache](https://exav.org/scanner/concepts/streaming-memory/#the-block-cache)
  page has the model and the measurements.
- **Sweeps for oversized and deeply nested input.** Each is deterministic and
  reproduces by a name and a position:
  - `saturate` (`exav-unpack`, `exav-render`): every length and count of every
    fixture set in turn to `0xFFFFFFFF` and `0x7FFFFFFF`, and the file read; none
    may hold more than a few times the file (resident memory, so a request never
    touched costs nothing), take seconds or panic. `EXAV_DEBUG_SATURATE=full`
    takes more positions and values, `deep` the first 64 KB of the fixtures up to
    256 KB, where the tables of the file systems are.
  - `nesting` (`exav-unpack`, `exav-core`, `exav-render`): MIME parts, RTF
    groups, PDF objects, XDP elements, HTML and XML parts, every signature
    database kind, YARA sources, script and markup, ODF, Word 2003 XML,
    SpreadsheetML, Visio, glTF, IFC and DXF, nested as deep as 200 KB of input
    makes them, on a stack of 256 to 512 KB.
  - `office_memory` (`exav-render`): what each converter allocates, against
    what its memory limit says, for each kind of unit.
- **`exav-grep` searches in bounded memory.** A file is no longer read whole
  past 16 MiB: a container is walked through a block cache, and anything else
  is searched a megabyte at a time. A 3.4 GB log was searched with an 18 MB
  peak, and a 1.5 GB stored member of a ZIP with 280 MB. A file over
  `--max-object-bytes` used to be reported unreadable, and a member over it
  ended the walk. A member over it is now searched as it is read; a container
  inside one, and a line longer than the limit, are reported unreadable.
- **A speed benchmark against `clamscan`** (`scripts/bench-speed.sh`): one
  process each over the same files and signatures, with a warm cache.
- **A file can be shown with the files around it.** `ViewerFile.tree` (a
  `FileTree`: the file's path, the paths of the others, and `open(path)`) is
  what a host gives a file that was opened with others: the demo does it for
  files picked or dropped together and for a folder (a new "Open a folder"
  button, and folders dropped), and an archive does it for each member. In the
  sandboxed frame the host lists the paths in `open` and answers a new `fetch`
  for a path it listed. `resolveInTree` finds the file a reference written for
  another machine (`.\Plans\x.dwg`, `C:\Projects\x.dwg`, a bare name) names,
  by its path from the file, then by the end of it, case and accents aside.
  Three formats use it so far:
  - **DWG and DXF external references are drawn** when their files are in the
    tree: the drawing is bound into the reference, its layers, styles, linetypes
    and blocks named `XREF|NAME` as AutoCAD names them in the host, and the
    references it makes are bound in turn (64 files, eight deep). One not found
    is still its path where it is inserted, counted in the warnings.
    `exav-render`: `Document::xref_paths` and `Document::attach_xref`.
  - **A glTF's buffer files are read from the tree**: a `.gltf` is nearly always
    a document and files beside it, and was an error without them.
    `exav-render`: `gltf::external_buffers` and `gltf::read_with`.
  - **Split archives open from the files beside them**: `big.7z.001` with its
    other parts, `x.part1.rar` or `x.rar` with `x.r00`, `x.z01` with `x.zip`.
    `@exav/unpack-wasm` gains `volumeSet` (the parts of a set, from names) and
    `joinSet` (the set as one archive: the RAR and ZIP volumes through their
    decoders, which `joinVolumes` leaves alone). `.7z.001`, `.zip.001`,
    `.rar.001`, `.tar.001` and `.z01` are archives by name.

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
- **A format registry** (`formats/registry.json`, 126 formats) from which the
  format matrix page and the viewer summary are generated, and which
  `make test-formats` and the viewer's and the scanner's tests check against
  the extractor's formats, the scanner's file types and the viewer's matchers.
- **Virtual disks read in place.** VHD (fixed and dynamic), VHDX, QCOW2
  (stored, deflate and zstd clusters) and VMDK (sparse and streamOptimized) are
  read through a `Read + Seek` that reads the container's tables as the walk
  reaches them and keeps only a 32 MiB cache of decoded units, so a disk of any
  declared size costs what it holds. A disk over the buffer limit is walked
  through its partitions and the files of its filesystems come out one at a
  time; a smaller one is still one member. What a disk decodes is counted
  against the scan budget. The filesystems are read in place too, and a raw
  image or a partition of one over the limit is walked instead of refused or
  streamed whole.
- **Six more filesystems are walked: exFAT, SquashFS, cramfs, romfs, EROFS**
  (and the ext2/3/4 and FAT readers are rewritten, below). Each is a format of
  its own (a file of one is typed and opened) and a filesystem in a disk or a
  partition. SquashFS has both byte orders and all six compressions (gzip,
  LZMA, LZO, XZ, LZ4, Zstandard) and reads sparse blocks and fragments; cramfs
  has both byte orders, the padding for boot code, holes and extended block
  pointers; exFAT follows the chain of a fragmented file and reads zeros past
  the valid length of a file as the system that mounts it does; EROFS reads
  files stored plain, with their tail after the inode, and in chunks with holes
  (a compressed file is reported). A symbolic link and a device node, which
  hold no file's bytes, are not members. The `squashfs`, `cramfs`, `romfs`,
  `erofs` and `exfat` features are in `all-formats`.
- **HFS+ and APFS volumes in a disk or a partition are walked** like the other
  filesystems, where they were only read inside a DMG.
- **A file past `--max-object-bytes` comes out of a disk image or a filesystem**
  instead of being reported `UNSCANNABLE` and skipped. Every reader (FAT, exFAT,
  NTFS, ext, SquashFS, cramfs, romfs, EROFS, HFS+, APFS, and so a disk, a
  partition and a DMG) hands such a file over as a stream read from where the
  volume has it, and the scan puts it in a spill file as it does a ZIP member
  (a 20 GB VM disk with a 1 GB file in it is scanned in full, not partial). A
  stretch the volume does not give ends the stream with an error after the
  bytes before it. A file stored compressed by the filesystem (decmpfs, LZNT1)
  is still decoded whole, and reported past the limit, as an EROFS compressed
  file is at any size. A HFS+ or APFS file over the limit no longer ends the
  walk with a limit; it is read like the rest.
- **7z, WIM and xar are read from where they lie on a seekable source**, not
  held: a 7z archive, a WIM image or a xar package over `--max-object-bytes`
  (a Windows install image, a macOS installer, a large 7z) was
  `LIMITS-EXCEEDED` with its members not reached, and is now opened and
  scanned member by member. A 7z reads its header from the end and each
  folder's packed bytes as its members are read; a WIM decodes a resource a
  chunk at a time; a xar inflates a member from its place in the heap. A 7z
  member far into a solid folder, past the buffer limit, is read where it
  was reported unreachable, the members before it counted against the scan
  budget as they are decoded and dropped. A WIM resource that fails its SHA-1
  with checksums verified now ends its stream with an error, not a report in
  place of the file. A xar whose table of contents is cut short is
  `UNSCANNABLE`, where it was a limit. A container found damaged where its
  source failed to give it is reported with the source's error.
- **Two fuzz targets.** `fsimage` walks hostile ext, exFAT, SquashFS, cramfs,
  romfs, EROFS, 7z, WIM and xar images and partitioned disks holding them, from
  memory and through a block cache, which must agree; `lzo` drives the LZO
  decoder.
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
- **More archives and images are read, from what a sweep of public repositories
  could not open**:
  - **RPM packages are opened** (`Format::Rpm`, feature `rpm`, no dependency):
    each install script (`scripts/prein`, `postin`, `preun`, `postun`, the
    transaction and trigger scripts) is a member, as text, and the payload is a
    member named for its format and compressor (`payload.cpio.xz`), which the
    scanner opens in turn. The headers' counts are checked against the file.
    155 of 2,246 packages from distributions' repositories were refused before;
    all open now. A package of the old kind (a signature that is not a header)
    is reported, never read as if it had one.
  - **LZMA-alone files (`.lzma`) are opened** (`Format::Lzma`, feature `lzma`):
    no magic number, so a file is told by its header's own rules (properties,
    a dictionary of 2^n or 2^n + 2^(n-1), a size that is unknown or below
    256 GiB, the zero byte a range coder starts with), as the xz utilities tell
    it. The dictionary the header asks for is bounded at 128 MiB.
  - **A ZIP behind other bytes is a ZIP**: a zipapp's script line, padding, a
    spanned archive's marker, offsets counted from the file's start. It is told
    by its end record, which must close the file (padding may follow), whose
    directory must end where it starts, and whose first entry's local header must
    be where its offset puts it. The walker already read such archives. Self-
    extractors (an executable in front) were handled before.
  - **xz with SHA-256, or a reserved check type, is decoded**, as liblzma does
    (it warns that the check is not verified): the stream is rewritten as it is
    read, with no check fields, a smaller index and flags that say "no check";
    the data are not touched. No new dependency: `xz4rust`'s `sha256` feature
    (sha2 0.10 beside our 0.11 and six more crates) is not taken.
  - **Targa (TGA) images are shown.** No magic number, so a file is taken for one
    when its header is sane and its pixels fill the rest of the file (or it ends
    with the `TRUEVISION-XFILE.` footer): colour-mapped, true-colour and grey,
    raw or run-length coded, 8 to 32 bits, any origin. A 32-bit file's alpha is
    shown unless nothing set it (all zero) or its extension area says it holds
    nothing. The viewer takes `.tga` and `.icb`. The hash path is not touched.
  - **More TIFFs are shown** (the viewer's reader only: what is hashed is
    unchanged, as ClamAV's is): LZMA strips (libtiff's compression 34925, what
    GDAL writes), ThunderScan, old-style JPEG (compression 6, in the three
    layouts files have it in: a whole JPEG as the strip, a scan with its tables
    in tags 519 to 521, a JPEG stream the file points to), grey of 12 bits (9 to
    15, packed), BitsPerSample with more entries than samples, and a file with
    no PhotometricInterpretation (grey, or RGB with three samples). Checked
    against Pillow on the files of GDAL, libtiff, Pillow and image-tiff that were
    refused (the 12-bit ones by their ordering: libtiff cannot show them).
    `lzma-rust2` is
    now also an `image` dependency of exav-render (already in the tree).
  - **Word's "Save as Web Page" is read** (`docs::Format::Html`, `"html"` in the
    viewer): the HTML a `.doc` holds when Word saved it as a web page, alone or
    in its MIME message ("Single File Web Page", with its pictures). Text,
    headings, lists, tables (spans, borders, widths, shading), links, pictures
    in `data:` addresses or in the message, the page of an `@page` rule and the
    character and paragraph formatting of the style sheet and of `style`
    attributes. A link is kept only when it goes to a web, mail, phone or FTP
    address or to a place in the page: a script, a data address and a path on
    the author's computer are text. It reads with `exav_unpack::html` and the
    style sheets the spreadsheet converter shares (`common::css`).
    About 6% of the files that were refused as "not a document" in a sweep of
    17,000 `.doc` files were this.
- **`maxEntities`, an option of the DWG and DXF viewer** (default 1,000,000,
  about 512 MiB of the module's memory): past it the rest of the drawing is
  left out and the "too large to show whole" warning is shown. Before,
  `maxDecompressedBytes` bound a DWG's sections and the entities were bound at
  8,000,000 (4 GB), which a small hostile file can declare. Entities dropped at
  a reader's limit were not reported by the viewer at all; they count as
  `scene_truncated` now. `parseDrawing` and `attachXref` of the module take
  the option as an argument.

### Changed

- **Rust edition 2024** in every crate (the workspace, the viewer and
  unpack-wasm modules, the fuzz crates and the table generators), resolver 3,
  rustfmt's 2024 style. The code uses what the 1.95 floor has: let chains
  (nested `if` and `if let` collapsed by clippy), `if let` in match guards,
  `array_windows` and `Vec::push_mut`. The minimum Rust version is unchanged.
- **One reader per format, shared by the scanner and the converters** (see
  `docs/ARCHITECTURE.md`). The scanner and `exav-render` each parsed the
  formats they both read, so that what one saw, the other could see otherwise.
  Three readers are now public modules of `exav-unpack`, and `exav-render`'s
  converters read with them:
  - **`exav_unpack::cfb`, the OLE2 compound file reader.** There were three:
    the `cfb` crate (strict, then a fallback of the scanner's when it
    refused a file), the scanner's lenient one, and the converters' own.
    One lenient reader, bounded by the file and by a cap per stream, now
    serves the scanner and every converter (DOC, XLS, PPT, VSDX, text
    views). The `cfb` crate is only a dev-dependency, the writer and strict
    reader the tests check the new one against. A stream past the cap is
    reported the way it was for a clean file. Members of a compound file
    come in the order of its directory.
  - **`exav_unpack::offcrypto`, the decryption of Excel workbooks with a
    password** (RC4, RC4 CryptoAPI, XOR obfuscation), written twice (the
    scanner's and the XLS converter's). The scanner's passwords and the
    converter's default one are tried by the one implementation, which
    decrypts in place instead of holding three copies of the stream, and
    which the real-file reference vectors of both pass. A key size past 128
    bits is refused as a method not had, where the scanner cut it.
    `exav-render` no longer depends on `md-5` and `sha1`.
  - **`exav_unpack::rtf`, the RTF tokenizer.** The scanner found embedded
    objects with a scan of its own for backslashes; it reads with the
    converter's lexer now, so a control word, a group or a hex digit is the
    same thing to both. An `\objdata` ends at its own closing brace whatever
    groups open inside it.
  - **`exav_unpack::biff`, the records, workbook tables and formulas of
    Excel 2 to 2003.** The scanner (to name the `EXEC` and `CALL` of an Excel
    4.0 macro sheet) and the XLS converter each had a table of the function
    ids, 765 and 373 entries that agreed on the 368 they shared, and each
    read the formula tokens: the scanner's walker wrote them in postfix
    order and stopped at the first token it did not know, the converter's
    wrote Excel's formula text. There is one reader now: the record stream
    (CONTINUE joined, read as it is asked for), the sheets, names and
    external references formulas refer to, and the tokens, with the argument
    counts. The converter writes a macro command by its name (`ALERT`,
    `OPEN`), where it wrote `CMD` and the number. The `xlm_macro` member of a
    scan holds the formulas as Excel shows them (`=ALERT("x")`, `=HALT()`)
    where it held `"x" ALERT HALT`, the macro-sheet names, the defined names
    with what they refer to (`_xlnm.Auto_Open=Macro1!$A$1`) and the text
    cells; a formula with a token the reader cannot read still gives the
    calls and strings before it. A formula is written once per operand, not
    once per operator above it, so a chain of thousands of operators costs
    its text.
  - **`exav_unpack::html`, HTML as tokens, and a page's bytes as text.** The
    scanner's text view read HTML with html5gum, and the spreadsheet and text
    document converters with a tokenizer of their own (and a table of HTML
    4's character references). Both read the tokens of html5gum now, so an
    entity, a `<script>` or a `<style>` is the same thing to each, and a
    token is charged to the converter's budget as it is made. A page names
    its encoding with a `<meta>` for the text view too, which it ignored. The
    text document converter no longer reaches into the spreadsheet one:
    style sheets are `common::css`.
  - **`exav_unpack::charset`, text in a Windows code page number** (BIFF, fonts),
    with its tables, which were exav-render's.
  `exav-render`'s office features now depend on `exav-unpack` (features `ole`,
  `html`, `offcrypto`, `rtf`); `exav-unpack`'s `ole` feature no longer pulls the
  `cfb` crate and does pull `encoding_rs`. `exav_unpack::bytes::Cur`, the
  bounds-checked little-endian cursor, is public. The viewer's document module
  now includes html5gum.
- **Dependencies are at their latest versions**, except the image decoders
  pinned to the versions libclamav 1.5.4 links (`image`, `png`, `gif`,
  `zune-jpeg`, `fax`, `weezl`), which `exav-imagehash` needs for ClamAV's hash.
  Notable: `quick-xml` 0.42, `hfsplus` and `apfs` 0.4, `cfb` 0.15,
  `lzma-rust2` 0.23, `sevenz-rust2` 0.24, `delharc` 0.8 (which also reads
  PMarc LHA archives), `base64` 0.23, `bit-set` 0.11, `yara-x-parser` 1.19;
  and for the viewer and docs, Vite 8, vitest 5, jsdom 30 and Playwright 1.61 (the viewer) and 1.64 (exav-unpack-wasm).
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
- The sandboxed frame's protocol is version 5 (it was 3): `draw` and `drawn`
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
- **HFS+ and APFS are read in-tree**, as NTFS is, in place of `hfsplus`, `apfs`
  and `cmpfs` (and `lzvn-core` with them): the catalog is read once for the
  paths, and each file for its bytes. A file macOS compressed (decmpfs) is
  unpacked from its attribute or its resource fork on both; on HFS+ one
  compressed into its resource fork was only reported. Every volume of an APFS
  container is walked, under its name when there are several, and an encrypted
  one is reported. A file with a resource fork has its data fork read as well as
  the fork reported. A file the volume holds only part of comes out with what
  there is, reported; a hole reads as zeros. The catalog of a volume with more
  entries than `max_members` is walked to that limit.
- **ext2/3/4 and FAT are read in-tree** in place of `ext4-view` and `fatfs`
  (and `bitflags` 1.x, `crc` and `crc-catalog` with them), and are read where
  they lie, as NTFS is: the whole volume is no longer copied into memory to
  walk an ext one (a volume over the buffer limit was reported unread). ext
  follows extents and block maps through the third level, inline data, meta
  block groups, 64-bit descriptors and bigalloc; a preallocated extent reads as
  zeros. FAT reads long names only when their checksum is their short name's,
  with the case flags and CP437 of short names. A file in an encrypted ext
  directory is reported as encrypted. Names no longer begin with `/`. A file
  over the per-member budget is reported and the walk goes on, as before; a
  damaged volume ends with an error after the files before the damage, where
  it was one reported member. A volume with more entries than `max_members` is
  walked to that limit.
- **Checksums of APFS are checked only when asked,** as every format's are: a
  wrong one no longer ends the walk of a tree, and the newest superblock whose
  checksum holds is the one used.

### Fixed

- **A large file over HTTP made a request for each executable candidate.**
  Carving looks at the header an `MZ` points to, wherever it is, and in an
  object read in place each lookup was a block of its own: a 1 GB text file
  took 7,700 requests and 11 GB over HTTP, and 12,000 requests with 64K blocks.
  The headers are checked in order of offset now, once enough wait (the size of
  `--object-cache-bytes`) and at the end, so the same file takes 594 requests
  and 4.8 GB, about the passes it needs.
- **A message attached to an email was never scanned.** The email reader took
  the text and binary parts of the top message and skipped the parts that are
  messages themselves (`message/rfc822`, a forwarded mail), so an attachment of
  a forwarded message read as clean. The parts of attached messages are members
  now (`email-part-3-0` is part 0 of the message that is part 3), to 64 levels,
  and a chain deeper is reported unreadable. The parsed message is also taken
  apart without recursion: 40,000 messages in one another (a 1.4 MB file)
  overflowed the stack when the parser's result was dropped.
- **An HFS+ volume whose catalog loops walked to the end of the catalog's
  declared size.** The leaves of the catalog are a chain, and a chain that
  returns to a leaf it has been through was ended only by the number of nodes
  the catalog fork says it holds: on a 19 KB disk image in a DMG that is 1 s,
  and 21 s under the fuzzer's sanitizer (the `timeout` of an 8-hour run), and a
  fork declaring 2^62 bytes would not end. A leaf met again is damage now
  (Brent's cycle check: no memory, and a loop is found within a few steps of
  where it starts).
- **Converting an ODT of many footnotes took time quadratic in their number.**
  Each note looked for its own place among all the notes before it, from the
  first: 160,000 footnotes took 5 s and 300,000 took 18 s, against 1 s and 2 s
  now. Some 90 other kinds of unit in the flat and text formats of the document,
  sheet and slide converters (runs, rows, cells, shapes, styles, comments,
  links, images, fields, tracked changes) were measured at 5,000 and 20,000 and
  scale linearly; the `scaling` test of `exav-render` holds footnotes to that.
- **The phishing check missed an anchor with a tab, a line break or a form feed
  after `<a`.** It looked for `<a` and a space, so `<a\thref=…>`, which every
  browser renders as the same link, was clean to the scan of the raw bytes, and
  under `--clamav-compat`, which has no second pass over the document's links,
  clean outright. Space, tab, line feed, form feed and carriage return are the
  white space of HTML5 after a tag name, and all five find the anchor.
- **A brand under a two-label suffix was every other brand under it.** The
  registered domain was the last two labels, so `barclays.co.uk` and
  `secure-barclays-login.co.uk` were both `co.uk`: no `.co.uk`, `.com.au`,
  `.co.jp` or `.com.br` page could spoof another, and the brands of the
  `.pdb` list under such a suffix (`smile.co.uk`) were stored as the suffix and
  never consulted. A country code preceded by one of `co`, `com`, `org`, `net`,
  `gov`, `ac`, `ne`, `or` and the like now takes three labels. It is not the
  whole public suffix list (thousands of entries such as `city.kawasaki.jp`).
- **A YARA rule with a long chain of operators aborted the process.** `not not
  not ...`, `1 << 1 << 1 ...`, `a contains b contains c ...`, a chain of `==`,
  `|`, `-` and `+` mixed, or `pe.sections[pe.sections[...` recursed once per
  operator in the parser and in what is built from it: 20,000 of them (40 KB of
  rule) overflowed a 2 MiB stack. A condition may chain 256 operators between
  `and`, `or`, commas and parentheses (a parenthesis counts as one operand of the
  chain it is in), and nest 12 deep; a rule past that is refused before it is
  parsed.
- **A Visio formula of signs aborted the process.** `-----...1` recursed once
  per sign, and the steps counter it is bounded by was not counted for them;
  200,000 signs overflowed a 256 KB stack. The signs are read in a loop.
- **The slide readers took 28 to 40 KB of stack for each level of nested
  shapes.** A text body held the nine outline levels inline (6 KB), so the
  functions that build a shape (ODP and ODG groups, Visio sub-shapes, PPT and
  Keynote groups) had frames of 28 to 40 KB, and 32 nested groups needed
  1 MB. The levels were never filled by any reader, and are a list that is
  empty until one is: a frame is under 8 KB, and the whole nesting the parser
  admits fits 256 KB. A shape is 0.7 KB in the model and in the memory limit's
  count, where it was 7 KB, so the same limit admits ten times the shapes. Nested `text:section`s of an ODT, bounded by
  nothing but the parser's 256 levels (3 KB each), stop at 24 as lists do.
- **A ZIP or an XZ file inside itself took 750 KB and 550 KB of stack for 15
  levels.** The walk of a ZIP held a `ZipFile` (its decoders are inline, 40 KB)
  for as long as a member was scanned, and an XZ reader its decoder tables
  (30 KB). Both are out of the frame now, and 200 levels (`--max-unpack-depth
  255`) scan on a 2 MiB stack, where 120 aborted on 8 MiB.
  `make stack-frames` reads the frames of the functions that recurse into
  nested input from release builds and fails on one over 16 KiB.
- **A PPMd header could take its whole memory size at once.** The model of
  7z, RAR and ZIP PPMd streams zero-filled its arena as it was made, so a
  header declaring 4 GiB made the process touch 4 GiB before the first byte
  was decoded. The arena is made of zeroed pages that are touched as they are
  used.
- **The document, sheet and slide converters keep to the memory limit they are
  given.** The limit is an estimate of what the converter's model takes, and
  for text it was off: a paragraph's runs, the XML parts held before they are
  compressed and the charts of a sheet were not counted, so an RTF of one long
  paragraph of runs or a workbook of charts took several times the limit. Each
  is counted at the point it is made, the output is bounded by what is left of
  the limit, and `crates/exav-render/tests/office_memory.rs` measures what a
  converter allocates against what its limit says, for each kind of unit
  (paragraph, cell, shape, chart series, table cell).
- **A bytecode program could take the host's memory three ways, and its CPU a
  fourth.** The frames of the calls in progress (each up to 16 MiB, 64 deep, so
  a gigabyte), the allocations of `malloc` (each under 128 MiB, none freed) and
  the globals (a zero initializer is two bytes of signature for up to 16.7
  million components, each made as 9 bytes at the start of every run: 1,000
  of them were a 5 KB signature and an OOM kill) were bounded one by one or not
  at all. One budget now holds the three, `--max-bytecode-memory-bytes` (256M by
  default; `Limits::max_bytecode_memory_bytes`): globals are made when the program
  first reads them, and a run that reaches the budget stops as incomplete.
  `get_environment` and the other calls that fill memory stored it a byte at a
  time and counted one step for the call, so 100 calls of 16 MB took 0.8 s and
  a loop of them took years inside the step limit; they copy in one piece now
  and cost a step for each 16 bytes (the 268-byte signature of the report ends
  in 0.7 s).
- **A JPEG XL file could take far more than the budget.** Its pixel count was
  limited but not its extra channels, each a float a pixel: the pixels allowed
  are now what the budget divides by the bytes a pixel takes with the channels
  allowed (two). The decoder still sizes the buffers of a frame's sections from
  the lengths of its table of contents before reading them (a file declaring
  one section of a gigabyte takes it); it is listed in `docs/BACKLOG.md`.
- **`exav-grep` printed a match inside the trailing context of another as
  context.** With `-A`, a matching line within the lines after a match came out
  as a context line (`-`) and not as a match (`:`).
- **The memory of an XML tree is counted by what the tree takes.** The
  converters of Word 2003 XML, ODT, FODT, ODP, FODP, FODG, Visio, Keynote,
  ODS, FODS, SpreadsheetML 2003 and Numbers '08/'09 counted the tree of a
  document as at most four times its bytes (not at all for Word 2003 XML and
  ODT), but a tree takes at least 170 bytes an element whatever the element's
  size, so four bytes of `<a/>` cost forty times that. A file of 1,000,000 paragraphs
  (36 MB) used 1.5 GB and one of 1,000,000 cells (2 MB, `.numbers`) used 800 MB
  before any limit applied. The parser now tells the budget the memory of
  each element and text as it builds them, and the two XML trees of the
  converters (`common/xml.rs` and `sheets/ods/dom.rs`) are one.
- **A drawing in the scanner's text view is read within the caller's memory
  limit.** The text of a DXF or DWG was read with the module's defaults (a
  million entities, 1 GiB of decompressed sections), whatever `max_buffer_bytes`
  the scan had: a 16 MB DXF took 555 MB, and a DWG of 66 KB whose sections
  repeat one page took 485 MB. The limits come from `max_buffer_bytes` now
  (`cad::limits_within`, 512 bytes an entity), a drawing past them says its
  text was cut (the scan is marked incomplete), and one whose sections expand
  past them is reported unreadable instead of silently empty.
- **Six findings of an adversarial review of the disk-image, unpacker and
  office changes**, each reproduced first and fixed with a test:
  - **The memory bound of the document and presentation converters counts what
    the model takes.** A table cell was counted as 192 bytes and a paragraph
    as 256, a shape as 512, and they take about 5 kB, 2.7 kB and 13 kB of memory
    in all: an RTF of 1,000,000 cells (24 MB) or an ODP of 300,000 text boxes
    (76 KB) was inside every limit and used 5 GB and 2.4 GB (killed, or a tab
    crashed in the viewer) instead of being refused with `TooLarge("memory")`. The counts
    follow the size of the model's types now, so a document is refused at about
    1 GiB of what it takes (the cell sample stops at 1 GB of memory). The
    workbook converters count 96 bytes for the 48 a cell takes and were left.
  - **Checking the formatting of styled empty ODS cells is bounded.** Each row
    of a sheet whose empty cells are repeated across its width checks every
    column (16,384) for what it shows, uncharged: 16 sheets of 1,023 such rows
    took 7.2 s, and the 4,096 sheets allowed would take 30 minutes. The columns
    checked add up to 2^26 in a workbook (about 2 s); past that the formatting of
    the area is left out, with the warning that already says so.
  - **The runs of an NTFS file are bounded over all its extents.** Each record
    of an attribute list could add thousands of runs and a list names tens of
    thousands of records, so a 64 MiB image could make a file of 20 million
    runs (about 500 MB). A file past a million runs is reported as not read
    whole.
  - **Web pages read as spreadsheets or documents no longer cost the product of
    their style rules and elements.** Each element looked through every rule
    (up to 65,536), and a rule with an `mso-style-parent` looked through them
    all again: a 3 MB page of 200,000 rules and 20,000 elements took 186 s. The
    rules are found by selector, and the declarations a page's elements are
    given add up to 2^24 at most (about 1 s). Each `<script>`, `<style>` or
    `<iframe>` also copied the rest of the page in lower case to find its end
    tag: 200,000 of them took 15 s.
  - **An NTFS file's attribute list no longer costs a record read per entry.**
    `data_extents` read a full MFT record (up to 1 MiB) and applied its fix-ups
    for every entry of the list, and `name_from_extensions` did the same for
    every `$FILE_NAME` entry, so a 39 MB volume held 8 s of CPU (and a 256 MiB
    list 13 minutes). A record is now read once however many entries name it,
    an extent's VCN is followed once, and the list is read once for the name and
    the data. A list naming more than 65,536 extents is not followed, and the
    file is reported as not read whole (it was passed off as its first extent).
    7.7 s and 2.0 s became 0.05 s on the review's samples.
  - **A disk image's PBKDF2 iteration count is bounded.** An encrypted DMG
    (`encrcdsa`) names the count in a `u32`: 264 bytes with `u32::MAX` cost
    9 minutes (21 in a test build) for each password. The iterations of all the
    derivations of a scan (RAR5's and the disk images') now add up to 2^22 at
    most, about 0.7 s, and the member is reported encrypted past that.
  - **7z key derivations are counted and kept.** 7-Zip runs 2^`numCyclesPower`
    SHA-256 rounds (up to 2^24) for each password over each folder, and a hostile
    archive of 2,000 folders took 20 s, 30 folders at 2^24 took 9 s, and the
    defaults allowed days. The key of a password, salt and count is derived
    once in a scan (7-Zip gives the folders of an archive one key), and a scan
    may spend 2^26 rounds (about 1.3 s) on them; a member past that is reported
    encrypted. The two samples now take 0.02 s and 0.3 s.
  - **7z archives with an encrypted header over LZMA (`-mhe=on`, 7-Zip's and
    sevenz-rust2's) are listed with the right password.** The header's coders were
    all given the sum of their output sizes, so the LZMA stage behind the AES one
    expected more than there was and ended "truncated"; the archive was reported
    as an `encrypted.7z` member whatever the password. Each coder decodes to its
    own size now, as the members' do. (The one fixture with a header that had no
    compressed layer worked.)
- **A 7z header with many properties over many files took quadratic time.**
  The entries with no stream were counted again for every property: a 400 KB
  header of 200,000 files and 200,000 properties took 24 s. They are counted
  once, when the property that sets them is read.
- **An RPM whose entries share their scripts no longer builds a member for
  each.** 65,535 entries pointing at one array of 4,096 strings made 268
  million members before the member bound was looked at, and a 1 MB file
  aborted the process for lack of memory. The scripts listed are bounded at
  4,096, and the rest is reported.
- **An ELF header with a table offset at the top of the 64-bit range no longer
  panics.** `e_phoff` or `e_shoff` near `u64::MAX` overflowed an addition in the
  layout read for `Target:6` signatures, so a 120-byte file made the scan an
  error where the signatures should have been applied.
- **`exav` builds again without `all-formats`** (`--no-default-features
  --features yara,zip`, the slim build the documentation describes):
  `analyze_split_sets` is there, and joins nothing, when no archive format is.
  The docs site builds with Starlight's current configuration (`description`,
  for the `tagline` it no longer accepts).
- **`exav-render` builds with `--features image` alone again** (`within` was
  compiled only with `jp2` or `jbig2`), and an uncompressed Targa that starts
  `00 00 02 00` (no ID, no colour map) is no longer taken for a cursor file with
  no images.
- **An XML Spreadsheet's print titles without a sheet no longer make the XLSX
  unreadable.** Some writers give a print area or titles as `=R1`, with no sheet;
  the workbook was written with `$1:$1`, which openpyxl refuses ("could not
  assign names") and Excel repairs. The sheet the name belongs to is put in
  front, as Excel writes it.
- **A JBIG2 symbol dictionary that declares far more symbols than its bytes can
  hold is refused before it is decoded.** hayro-jbig2 goes on decoding symbols
  from what is left of the stream: a sample's dictionary with its symbol count
  changed in two bytes (243 bytes in all) took two minutes and 7 GB, and others
  of the kind half a minute. The declared count is now checked against the
  segment's length (eight symbols a byte at most), in the pre-check that already
  charges region sizes, for JBIG2 files and for PDF streams alike. Found by
  mutating images (`fuzzlite`); to report to hayro-jbig2.
- **A Zstandard file that opens with a skippable frame is read as Zstandard.**
  Skippable frames (`0x184D2A50` to `5F`) are shared by LZ4 and Zstandard, and
  the LZ4 test came first, so a `.zst` with a padding frame ahead of its data
  failed as an LZ4 file with no block (ClamAV's `skip_prefix.txt.zst`). What
  follows the skippable frames now decides.
- **A missing xref's path on a sheet is no longer drawn as giant letters.** The
  label was `$TEXTSIZE` times the insert's scale, so a title block inserted
  at scale 10 in a drawing with `$TEXTSIZE` 40 put 400-unit characters on
  every sheet, covering it in black. On a layout the label is now at most a
  hundredth of the paper.
- **The frame of a DWG image that is not loaded follows its crop.** It was the
  whole picture, so a photo cropped on a sheet drew lines far outside the
  paper, past its edge. A polygonal crop is followed too; an inverted crop
  keeps the whole frame.
- **A DWG wipeout is no longer mirrored vertically.** Its boundary counts from
  the top left with y down, as an image's crop does; it was read y up, so a
  mask landed away from what it hides, and a far one stretched the view until
  the drawing was a dot.
- **Large DWG files (R2004 to R2018) with a section map past 32 KiB are read.**
  Their compression is LZO1X's, where bit 3 of an opcode from 0x10 to 0x1F
  is a distance past 32 KiB and the length is its low three bits; the
  reader took them as 0x10 to 0x17, which only a section map that long (a
  drawing of thousands of 3D solids, here 38 and 74 MB files) can show: it
  failed as "damaged".
- **IFC files whose header the reader could not scan are read.** A quote that
  `\S\` shifts (Vectorworks writes one in a Japanese path) ended the header's
  string early, and a stray `;` in `FILE_SCHEMA(('IFC4'););` stopped the whole
  read, both as "no instances in the file". The schema is taken from what the
  header names before the `;`, and the instances are read.
- **An IFC solid written with some faces the wrong way round is cut right by
  its openings.** A faceted B-rep's faces are made to agree on which way they
  face before the boolean, as exporters do not always write them so; a wall
  lost the part of itself below its window.
- **glTF with quantized positions is drawn.** `KHR_mesh_quantization` stores
  positions and normals as 8 or 16-bit integers that the node's scale puts
  back (gltfpack writes it); the reader took anything but floats as an invalid
  mesh, so such a model (a 25 MB map, 5.8 million triangles) showed nothing.
- **IFC openings written as face sets are cut.** A polygonal or triangulated
  face set that leaves its optional `Closed` out (Bonsai and BlenderBIM do) was
  taken as open, so every wall and slab it should have cut was drawn whole; its
  edges now say whether it is closed. In the tutorial models of the sweep, the
  triangles of a floor of walls went from 2,558 to 4,258.
- **TIFF files of floats, signed values, palettes, planar colour, YCbCr (JPEG
  or not), grey of 2 or 4 bits and BigTIFF are drawn.** The decoder that is kept equal to ClamAV's refuses them (an
  elevation model, a scientific raster, a palette scan: 83 of 96 such files of
  a GitHub sweep showed nothing). The viewer's `decode_any` now reads them
  with the same `tiff` decoder, stretching samples that are not 8 bits from
  the 0.5th to the 99.5th percentile of the values, nodata left out. `decode`
  and the image hash are unchanged.
- **TIFF fax (Group 3, 1 and 2 dimensional, and Huffman RLE) is drawn, and
  Group 4 with a fill order of 2 is read right.** The decoder behind the hash
  reads Group 4 only. The viewer's `decode_any` decodes the strips with
  hayro-ccitt, as libtiff does a white run (a 0 bit, white or black by the
  photometric interpretation); the 11 fax files of the conformance sweep that
  showed nothing now equal Pillow's pixels.
- **A TIFF of 1 to 7 bit samples with a fill order of 2 is drawn in order.** The
  decoder ignores the tag, so a 1-bit scan came out scrambled in groups of 8
  pixels. The viewer's `decode_any` reverses the bits of each byte first, as
  libtiff does; `decode` and the hash are unchanged.
- **A DWG whose BLOCK control cannot be read is not blank.** The block records
  are looked up through that control; one writer's bit size for it is the whole
  record, so its handles were never found and the drawing came out empty
  (LibreCAD's `ordinary_enc_AC1015.dwg`, three lines). The records are now the
  objects of their type when the control lists none, and the drawing says so.
  Its R2004 and R2013 siblings still have unreadable entities (the same bit size
  fault in each object).
- **An RTF with a `}` too many is read to its end.** The reader stopped at the
  first close of the outermost group; html2rtf writes files whose braces do not
  balance, and 2 paragraphs of 1,559 words came out. What follows an early close
  is now read, in a group of its own, as unrtf does.
- **A palette TIFF with an alpha sample is drawn.** Indices with an extra sample
  beside each (SamplesPerPixel 2; ImageMagick's `input_256_matte.tiff`, GDAL
  and QGIS test rasters) were refused. The viewer's `decode_any` draws them
  as RGBA; `decode` and the hash still refuse them, as ClamAV's decoder does.
- **A CMYK TIFF with spot or alpha channels is drawn.** Photoshop writes
  SamplesPerPixel 6 after its four inks (chunky or planar), which the decoder
  refused. The viewer's `decode_any` draws the inks and leaves the rest out;
  `decode` and the hash are unchanged.
- **An old-style LZW TIFF is drawn, and so is an RLE BMP that ends with a delta
  past the last row.** TIFF 5.0 files (least significant bit first, a code late
  like GIF, starting 0x00 and an odd byte) failed on a code that is not in the
  table (libtiff's `quad-lzw-compat.tiff`); `image` calls an RLE stream that
  moves past the picture corrupt, where Windows and Pillow draw what came
  before (Mozilla's `rle4-delta-320x240.bmp`). `decode_any` only.
- **A YCbCr TIFF with subsampled chroma and no JPEG is drawn.** LZW, Deflate,
  PackBits or uncompressed YCbCr stores its chroma once for each 2 by 2 (or
  2 by 1, 4 by 1...) block of luma values, in units of the luma then Cb and Cr;
  the decoder read it as pixels of three samples and failed (libtiff's
  `ycbcr-cat.tif`). The viewer's reader spreads each unit over its pixels, as
  libtiff does. The hashing decoder is unchanged.
- **A Deflate TIFF with a wrong Adler-32 is drawn.** The checksum at the end of
  a strip is not checked by the viewer's reader, as libtiff does not (OpenCV's
  `multipage.tif`, written by a faulty encoder, showed nothing). The hashing
  decoder is unchanged.
- **A TIFF whose directory links to itself is drawn.** The viewer's reader takes
  a link back to a directory already read as the end of the chain, as libtiff
  does (`test_ifd_loop_to_self.tif`); the hashing decoder keeps calling it a
  cycle.
- **A TIFF strip with no StripByteCounts is drawn.** A file with a StripOffsets
  and no byte counts (an office suite's `tdf115863.tif`, a one-strip scan) was
  refused; libtiff and Pillow read the strip to the end of the file, and so does
  `decode_any` now. `decode` and the hash are unchanged.
- **A CIELab TIFF of 8 bits is drawn.** L*a*b* (photometric 8, ImageSharp's
  `CieLab.tiff`) was refused; `decode_any` converts it to sRGB with a D50
  white, within a few levels of libtiff's own conversion. `decode` and the
  hash are unchanged.
- **A tiled TIFF that names its tiles with the strip tags is drawn, and so is a
  JPEG-in-TIFF of RGB components.** libtiff keeps the offsets of tiles and of
  strips in one field, so a file with TileWidth and StripOffsets reads there
  and Pillow draws it (ImageSharp's `quad-tile.tiff`). zune-jpeg 0.4 takes a
  three-component JPEG with an Adobe marker and the ids R, G, B for CMYK
  and fails (`rgb_jpegcompressed_nojpegtable.tiff`); the file's own sample
  count wins. Both for `decode_any` only; `decode` and the hash are unchanged.
- **A TIFF of 3 to 6 bands with no colour meaning shows its first band.**
  Satellite scenes and other multi-band rasters (photometric MinIsBlack with
  several samples) were refused; the viewer's `decode_any` draws band 1 as
  grey, stretched when it has 16 bits.
- **A footnote or endnote in a list nested four deep keeps its text.** An ODT's
  note was read only when the nesting depth so far was under four, a limit
  meant for notes in notes, so a bibliography's endnote in a nested bullet
  list came out empty. Notes inside notes are now counted on their own (three
  levels are read).
- **An MTEXT is placed by its world insertion point, not an OCS one.** The
  insertion point and text direction of an MTEXT are world coordinates and its
  extrusion is the normal of the plane it lies in (ezdxf reads it so; the DXF
  reference marks only the direction as WCS). It was put through the
  extrusion's OCS frame like a TEXT: with an extrusion of -Z the text landed
  mirrored across the origin (at x = -100 for an insertion at 100), and in a
  tilted plane it was moved by the plane's frame. A text in a plain plane is
  drawn as before.
- **An ellipse is drawn in the plane of its extrusion.** The ELLIPSE's centre and
  major axis are in world coordinates, its extrusion gives the plane and the
  way the parameter runs; the tessellator took the plane for the drawing's, so
  an elliptical arc with an extrusion of -Z (a mirrored one) was the other half
  of the ellipse, and one in a tilted plane was not squashed as seen from above
  (dxf-viewer's `ocs-curves.dxf`).
- **A TIFF with an extra sample of no stated use is drawn opaque.** A fourth band
  that ExtraSamples calls unspecified (0) was taken for an alpha: a 16-bit
  texture from the glTF sample models, and test files of image-tiff and
  OpenImageIO, came out nearly or partly invisible. The viewer's `decode_any`
  draws them opaque, as libtiff's reader and Pillow do; an extra sample
  declared an alpha (1 or 2) is still one. `decode` and the hash are unchanged.
- **A TIFF is drawn turned as its Orientation tag says.** A scan stored on its
  side (orientation 6 or 8) or mirrored was shown as stored; the viewer's
  `decode_any` now turns it, as libtiff and a browser do for a JPEG. `decode`
  and the hash are unchanged.
- **A TIFF with premultiplied alpha is drawn with its colours divided by it.**
  Colours stored multiplied by their alpha (ExtraSamples 1, what OpenImageIO
  and Photoshop write) were drawn as plain colours, darker where the image is
  soft; the viewer's `decode_any` now divides them, as Pillow and libtiff do.
  `decode` and the hash are unchanged.
- **TIFF files compressed with Zstandard are drawn.** GeoTIFFs and cloud
  optimised ones use it; the decoder behind the hash has no Zstandard (nor has
  ClamAV's), so all 10 such files of the GDAL test suite showed nothing. The
  viewer's `decode_any` reads them with ruzstd, which exav-unpack already
  links; `decode` and the image hash still refuse them.
- **LZW tiles that `weezl` ends short are drawn whole.** Asked for the 2 bytes of
  a tile row and then its 14 of padding, `weezl` can stop 30 bytes before the end
  of a valid stream, and the tile (and the TIFF) is refused; GDAL's
  `gtiff_rgbsmall_LZW_tiled_separate.tif` is one. The viewer's `decode_any`
  decodes such a stream a block at a time; `decode` and the hash keep what
  ClamAV's decoder gives.
- **LZW tiles that overhang the image no longer panic the TIFF decoder.** When the
  data of a row was asked for at the end of a tile's stream, `weezl` gave its
  last two bytes and said `NoProgress`, and the reader asserted that it had
  given none. A 20x20 image in 16x16 tiles was refused by `decode` and
  `decode_any`, and aborted a WebAssembly build. The reader now returns the
  bytes.
- **BMP files with an OS/2 2.x header, a plane count other than 1 or RLE rows
  stored top-down are drawn.** `image` refuses all three; Pillow and other
  readers open them. The viewer's `decode_any` rewrites the header (the
  64-byte one cut to 40, planes 1, a negative height made positive and the
  rows turned over) and decodes again. `decode` and the hash are unchanged.
- **A plain PNM with a comment after the maximum value or among the samples is
  drawn.** `image` refuses such a file (9 of 5,115 `.ppm` files of a sweep,
  Blender and test-suite renders among them). The viewer's `decode_any` cuts
  the comments out and decodes it again.
- **Cursors, and icons with a wrong length, a wrong size or a cut AND mask, are
  drawn.** `.cur` files were not recognised as images. In the viewer's
  `decode_any`, a cursor is read as the icon it is laid out as, and each icon
  image is tried with the length its entry gives and with all the bytes that
  follow, its entry corrected to the size the image holds and a short mask
  filled with zeros. Of the images of one size in an icon file, the one with
  most colour is shown (the 8-bit one was before, without its soft edges), and
  a 32-bit image is drawn by its alpha, not cut by its AND mask as `image`
  does, which Windows does not do either; a colour profile after the pixels of
  a V5 header is not read as the mask; a count of colours in the header of a
  32-bit image no longer moves its pixels.
  `decode` and the image hash are unchanged.
- **A 7z with archive properties whose ids are more than a byte is read.** 7-Zip
  reads a property id as a number and skips the property by its size; the
  reader took the id for a byte, lost its place and refused the archive as
  ending early (Apache Commons Compress's `COMPRESS-681.7z`).
- **An ASCII PLY whose lines carry more values than the header declares is
  read.** A face line of the VCG library's `fuze_ascii.ply` ends in nine values
  the header does not name; read as a stream, the second face started inside
  the first line's leftovers, and 1 face of 1,000 was drawn. A file that reads
  as damaged is now read again with a line to a record, and that is kept when
  it is the better reading.
- **A GLB whose JSON chunk is not padded to four bytes is read.** Older
  trimesh exports (`cube.glb`, `pins.glb`) put the next chunk right after a
  JSON chunk of 962 bytes; the reader skipped to the next multiple of four and
  refused the file for a chunk length. It now takes the next chunk where one
  starts, with or without the padding.
- **A bare JPEG 2000 codestream with subsampled chroma is read as YCbCr.** With no
  colour box to say so, its samples were drawn as RGB (a green and magenta
  picture); OpenJPEG's tools read three components whose second is
  subsampled as sYCC, and so does exav now.
- **A JPEG 2000 of four bands under a greyscale colour box shows its first
  band.** GDAL writes a multi-band raster (Sentinel-2 patches, SPOT scenes)
  that way, and the decoder takes any four components for CMYK, so it was
  drawn as a pale wash.
- **A DXT1 texture keeps its transparent texels.** `image` draws the "no
  colour" index of a BC1 block opaque and black, so a tree or fence texture cut
  out of its picture showed a black box; `decode_any` reads such a file with
  bcdec_rs. `decode` and the hash are unchanged.
- **DDS textures of BC4, BC5, BC6H and BC7, of sizes that are not multiples of 4,
  and uncompressed, 8-bit palette or float layouts are drawn.** `image` reads DXT1, DXT3 and
  DXT5 of multiples of 4 only: 160 of 2,580 `.dds` files of a GitHub sweep
  (game textures, normal maps, cube maps) showed nothing. The viewer's
  `decode_any` reads them with bcdec_rs (MIT, safe, no dependencies), the
  first surface of the file; `decode` and the hash are unchanged.
- **A fast-saved Word 6 or 95 document opens, and its text is in its own code
  page.** The length of the piece table was read as two bytes and is four, so
  the pieces came out as CPs of billions and the file was refused as damaged;
  and the 8-bit text was always Windows 1252, so a Russian, Greek, Polish or
  Turkish document was mojibake. The language in the header now gives the
  code page (Windows 1250, 1251, 1253 to 1258, 874, or Mac Roman for a
  Macintosh file); double-byte languages are not read yet.
- **Shared strings of an XLS after a header that ends its record are read as
  they are written.** The CONTINUE that holds the characters starts with the
  width flag, which was skipped when the header ended exactly at the record's
  end: 16-bit strings came out as `C_x0000_L_x0000_A` and the cells after
  them were wrong (3,400 of 11,000 cells of one workbook, 190,000 of 244,000
  of another).
- **A DXF whose entities name an ordinary block as their owner is drawn.**
  LibreDWG's R14 output gives the ENTITIES section the owner of its first
  BLOCK (`*U`), so the model space came out empty and the drawing was blank.
  The section is the layouts' whatever the owner says; the owner only picks
  which layout.
- **An ICO whose PNG is not 32-bit, or with one image that does not decode among
  several, is drawn.** `image` refuses the whole file; each image is now tried
  alone, the largest first, in the viewer's `decode_any`.
- **A tar from before `ustar` (V7) is recognised.** It has no magic, so it was
  taken for an unknown file and not unpacked; its first header is now accepted
  when the name, the octal mode and size and the checksum are all right.
- **7z archives with empty files or directories among more than eight entries
  are read.** The header's `EmptyFile` and `Anti` bit vectors have one bit per
  entry without a stream, and were read with one per entry, so the property
  after them started at the wrong byte: the names were lost (`entry_1`,
  `entry_2`), or the header was refused with "unexpected NID". Which entries
  were directories was also taken from the wrong bit. Found on 6 of the first
  517 `.7z` files of a GitHub sweep, all of which 7-Zip tests as sound.
- **A 7z of nothing, or of empty files and directories only, is read.** It has
  no streams: an archive that is the signature header alone ("unexpected end of
  data"), or a header with the file list and no stream list ("FILES_INFO
  before MAIN_STREAMS_INFO"), which is what 7-Zip writes for a folder of
  empty files.
- **Office packages are no longer read whole from a source that fetches ranges.**
  The `zip` crate looks for a package's directory from the start of the file
  unless told the archive starts there, so opening an ODP or a Keynote file
  read all of it, pictures included. The directory is taken where the end
  record says first, and the crate's search is the fallback for a package
  something precedes.
- **IFC products with a null `GlobalId` are drawn.** The schema requires one,
  web-ifc writes `$`, and the reader took every such product for no product:
  a floor plan of 176 elements showed 26.
- **IFC bars swept along a polyline or a composite curve are whole.** Allplan
  writes `StartParam` 0 and `EndParam` 1 for a polyline of any length, which
  cut a bent bar to its first segment; and Revit counts a polyline of a
  composite curve once, where the reader counted its segments, which cut a
  spiral bar to a few turns. Both are read as the end of the curve when the
  number fits that count and not the other.
- **The text of shapes in a group is kept in an ODT converted to DOCX.** A
  `draw:g` was dropped whole, with the text boxes and shapes in it.
- **An IFC that holds only alignments says so.** An alignment is a curve, which
  is not drawn, and a model of nothing else showed an empty view with no
  warning; it now counts `IFCALIGNMENT` as not drawn.
- **glTF with a node rotation of all zeros is drawn.** Exporters write it for
  no rotation (FF7 model dumps do); it failed the whole file as an invalid node
  transform.
- **An ASCII STL after a byte-order mark or lines of comment is read as text.**
  The file was taken for a binary one, and drawn as garbage or not at all.
- **PLY headers some writers make are read.** The remarks in braces of the
  format's own example, a line of text with no keyword (Blender 2.4 wrote
  one) or a `comment` with no space after it, an empty `face` element before
  the vertices, and vertices with no `z` (a flat drawing).
- **Volumes of two archives are no longer one set.** `a.7z.001` with
  `a.zip.002` were joined, as the base extension was not compared. The scanner
  rejoined volumes the same way.
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
