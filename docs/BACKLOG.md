# Backlog

Work decided or proposed and deliberately postponed. Gaps exav already
reports (never a silent `Clean`) are in [GAPS.md](GAPS.md); the public roadmap
is on exav.org.

## Search and text

- **exav-grep `--text`**: search the text a viewer would show rather than raw
  bytes. Done: Markdown, HTML, the XML parts of OOXML and ODF files, DWG and DXF
  (TEXT, MTEXT without format codes, attributes, layer and block names, from
  exav-render's drawing model), PDF text (opt-in `text-pdf`) and, with
  `text-office`, the legacy and flat office formats (DOC, XLS, PPT, RTF, Word
  2003 XML, SpreadsheetML 2003, SYLK, FODT, FODS, FODP, FODG, Numbers, Pages,
  Keynote), located by sheet or slide (`book.xls!text/sheet "Budget"`). To do:
  IFC names and property values, decoded email, matches located by page and by
  entity (`plans.zip!a1.dwg!layout "A1"/MTEXT 2F3`).
- **exav-grep `--ocr`**: images (all exav-render formats, fax TIFF and JBIG2
  included) and scanned PDF pages rasterised by hayro, through a pure-Rust OCR
  (`ocrs`, MIT/Apache, on a pure-Rust runtime; model about 10 MB, behind a
  build feature; licence of the weights and quality to check first; Latin
  script first). Page and time budgets; a page that could not be read gives
  exit code 3. Tesseract is C++ and excluded.
- **QR codes for the scanner**: decode QR codes in images and PDFs (pure-Rust
  `rqrr`, MIT/Apache) so signatures can match their URLs ("quishing").
- **Visible-text layer for the scanner**: let signatures match a document's
  extracted text (the `--text` extractors), not only its bytes. Done for
  Markdown, HTML, the XML parts of Office and OpenDocument files, drawings,
  (opt-in) PDF and (opt-in, `visible-text-office`) the legacy and flat office
  formats: `visible-text` in exav-core, `exav-grep --text`, through
  `exav_render::text::visible_text`, matched as a text view; a link's label and
  target are in that text, and `--alert-phishing` judges them. An office
  document whose text cannot be taken out (encrypted, past a limit, damaged)
  marks the scan incomplete. To do: an email's headers (its bodies are members,
  HTML and text, and are read); the hyperlinks of OOXML files, which live in
  the `.rels` parts, apart from their labels; PDF link annotations (hayro is
  run without annotations); IFC names and property values; speaker notes and
  animations text of presentations (the converters leave them out); PDF text
  without hayro's `unsafe` feature (a vendored patch of hayro-interpret, as the
  viewer does for zenjxl-decoder) so that it can be a default; making
  `visible-text-office` a default (the readers are the largest of the scan).
  Markdown is known by its extension, and a Markdown file with another name is
  not read; a compound file is read as an office document by its extension
  (`.doc`, `.xls`, `.ppt` and their templates), so as not to read an installer
  whole to find out.

## Formats

- **Decoder oracle tests**: the LZFSE/LZVN and DCL differential tests against
  Apple's lzfse and zlib's blast (`#[ignore]`d, built by
  `crates/exav-unpack/tests/oracle/build.sh`) run on request only; a `make`
  target and a place in the nightly campaign are not done.
- **MHTML** (`.mht`, `.mhtml`): look into what exav does beyond typing it
  (`CL_TYPE_MHTML` in `crates/exav-core/src/filetype.rs`): extraction of
  parts, encodings, scripts, viewer support. To scope first.
- **DWG before R13** (AC1009 and older): reported as an unsupported version
  today; the ODA specification does not document these releases.
- **Disks read in place, what is left** (docs/STREAMING_FORMATS.md): ext is
  copied into memory as a volume because `ext4-view` takes a `'static` reader
  (reading it in place needs a copy of the crate with a lifetime on its
  types); HFS+ and APFS inside a VHD, VHDX, QCOW2 or VMDK are streamed or
  reported, not walked in place (the DMG code does it for a DMG); a partition
  table inside a partition is not followed in place; a file larger than the
  buffer limit is refused rather than streamed out of the filesystem; DMG's
  reader does not count what it decodes against the scan budget as the other
  disks do; a truncated or damaged streamOptimized VMDK is indexed by its
  markers, which is not how VMware finds a grain (its tables).
- **IFC geometry**, what is left (listed on the exav-render docs page):
  cones, which no IFC schema has as a surface (`IfcConicalSurface` does not
  exist; a cone is an `IfcSurfaceOfRevolution`, with its sibling
  `IfcSurfaceOfLinearExtrusion` still drawn flat); faces whose loops wind
  round a closed surface in ways other than a sphere's cap or a band of two
  loops (a torus cut at one circle, a tube of three); the pcurves of
  `IfcSurfaceCurve`, which Bentley's samples write wrong; in IFC4X3,
  `IfcSegmentedReferenceCurve` (cant), `IfcOffsetCurveByDistances`, the sine
  and cosine spirals (the published formula uses a length it does not
  define), `IfcSectionedSolidHorizontal` (its profile axes are described
  with `Axis` as the profile's y), and the alignment's business-logic
  segments (`IfcAlignmentSegment` design parameters: the `Axis` curve is
  read instead); the grid's own axes are curves and are not drawn. A parameter
  on an `IfcIndexedPolyCurve` with arcs has no published meaning: its sweep
  takes the whole curve, counted.
- **CAB LZX and Quantum** lose the frame being decoded when a cut or damage
  stops it (at most 32 KiB of output). MSZIP and stored blocks keep the part
  of the block decoded before the stop. LZX is decoded by `lzxd`, whose window
  is private and which hands a frame over whole or not at all; the cheapest
  sound route is a vendored copy of it (MIT OR Apache-2.0, about 1,800 lines,
  as the CAB reader itself is) with a call that returns the decoded part of a
  frame. Quantum's decoder reads zeros past its input, so a part of a frame
  would need its own end-of-input check first.
- **Inno Setup extraction**: `formats/inno.rs` recognises an installer and
  reports it; no file is extracted. Licences checked: innoextract (Daniel
  Scharrer, the reference for the layout) is under the zlib licence, so its
  source may be read, with a crate NOTICE entry; Inno Setup's own source is
  under a custom licence (permissive, with notice and "marked as modified"
  terms) that is not one of the licences exav reads sources under, so it is not
  read. What remains: the offset table and the version-tagged setup headers
  (the structures differ by version, which innoextract carries as a table),
  the setup-0 header block (zlib or LZMA1, CRC-32 per sub-block), the file
  entries and locations, the setup-1 chunks (stored, zlib, bzip2, LZMA1, LZMA2,
  the x86 call and jump filter, CRC-32, Adler-32, MD5, SHA-1 or SHA-256 per
  file) read within the output, entry, chunk and dictionary budgets, names
  sanitised as other formats do, and an encrypted installer (header encryption
  or Inno 6.5's ChaCha20 chunks) reported, never clean; a sample installer
  built by the compiler under wine or a free installer small enough to commit;
  a fuzz target and seeds; and routing of an installer in a PE overlay to it.
- **Cuts inside a codec header** (a UPX file cut inside its first block, an EGG
  LZMA block cut inside its codec header) stay `Unscannable` on purpose: no
  byte of the stream is there to decode, and a packed file with none of its
  content examined is not reported as examined.
- **xz checksum after a full block** counts as damage, because the decoder
  cannot tell whether more blocks follow.
- **JBIG2 symbol dictionaries** are bounded only by hayro-jbig2's own
  65,535 × 65,535 symbol limit: the symbol sizes sit inside the compressed
  data, so they cannot be counted against the memory budget before decoding,
  and the crate has no budget setting. Regions are counted (fuzz finding,
  docs/FUZZING.md). Needs a budget hook upstream or a pre-pass that bounds
  the dictionaries.
- **Image decode time**, measured on a build with optimisations: JBIG2
  regions decode at about 230 Mpx a second when the data is empty (a few times
  slower on real data), JPEG 2000 at about 50 Mpx a second, and the grey
  conversion and Lanczos resize of a large JPEG (an 805-byte file that decodes
  to a few million pixels) take 0.4 s. A decode is bounded by the
  memory budget (at most `DECODE_MAX`, 512 MiB, for a JBIG2 file's regions and
  for every image through `exav_render::image::decode`, and the same for the
  PDF decoders' regions), so a native decode is seconds; the decoders have no
  work budget of their own, which a JBIG2 symbol dictionary also escapes (see
  above). In the viewer the worker's 60 s timeout stops what is slower.
- **PowerPoint 2, 3 and 4**: exav-render's `slides` recognises them (Windows, Mac,
  BinHex, `PP40` stream) and reports `unsupported`. Text-only decoding would
  have to come from seven sample files alone; no
  specification exists to check against.
- **PowerPoint 95 pictures, freeforms and arcs**: the reader (`ppt95.rs`) was
  written from one sample and leaves these out; more samples are needed.
- **Office converters, open decisions** (exav-render's `sheets`, `slides` and `docs`):
  - docs converter: fall back to the external converter when it says `unsupported`
    (Pages '09, Word 1/2); make it the default for text documents even where
    an external converter is set (it goes first only without one today: 32% of
    DOC pages close, against 50% for native DOCX); keep
    tracked changes in DOC as strike-through and underline in one colour, or
    leave deleted text out; Word 2003 XML sniffing claims any `.xml` that
    mentions `w:wordDocument`; commit a small Word 6 fixture for the fuzz seeds
    and e2e; Pages tables, pictures and headers.
  - `@silurus/ooxml-legacy-office` (0.89, DOC, experimental) as a first try for
    DOC with ours as fallback: about 5 points more close pages on the 137
    documents both draw, draws 139 of 348 against our 271, 387 KB brotli more.
  - slides: draw the first slide while the rest converts (needs ranged
    delivery); propose a random-access archive source to @silurus/ooxml; Keynote
    table borders follow the style (hidden means none); about 20 ODP chart documents differ because of the sheets chart
    writer (axes, legends).
  - Three OfficeArt readers (`common/escher.rs`, `slides/ppt/escher.rs`,
    `sheets/xls/escher.rs`), two ODF XML trees (`common/xml.rs` and
    `sheets/ods/dom.rs`, which counts against the sheets budget and error
    type), and two ZIP readers (`common/package.rs` and `slides/package.rs`,
    which handles an encrypted member in its own way) are still apart. The byte
    cursor, compound file, code pages, iWork archive, base64 and the ODF colour,
    percentage and text helpers are shared.
- **Demo examples**: DWG, IFC, PLY, STL and some PDFs from Zenodo and figshare
  state their licence for the record, not per file (a furniture block or logo
  inside could come from a third party; the hospital and HVAC drawings are the
  most exposed): keep or drop; `demo:build` downloads 87 MB (`--offline` copies
  the committed files only; CI and the e2e rig may want it); the CAD files, the
  ISO and the encrypted archives are not byte-reproducible; the sidebar is long
  and wants collapsible sections; viewer gaps the examples showed: `.pages` has
  no matcher in `ts/core/formats.ts`, G3 fax TIFF is not decoded (G4 only),
  Minolta MRW has no preview. No clean sample exists for Pentax PEF, Sigma X3F,
  Phase One IIQ, Hasselblad 3FR, Samsung SRW, Kodak DCR, IWA Pages or a real OBJ.
- **Camera RAW**: the detection rule that makes a TIFF a RAW on a maker's name
  plus a SubIFD or thumbnail (opens old Sony SRF and Nikon scanner NEF); a
  default cap on the preview size in the viewer (today up to about 67 Mpx);
  check the Adobe, CIPA and ISO licence wording in NOTICE 1p; CR3 previews
  stored as HEIF, Minolta MRW and Kodak DCR thumbnails.
- **CAD**: level of detail for large drawings (the potsdam fit frame spends 760
  of 864 ms in strokes), annotative objects (annotation scales per owner and
  viewport), an external file resolver (xrefs, images); 46 DWG oracle
  differences left unexplained (36 MULTILEADER context scales in sample
  0e74f0aa, DWG-only material dictionaries in edf22e18); 3D is out of scope.
- **PE emulator**: TELock (11 samples, needs a trace on real Windows, see the
  Windows VM item), Yoda's Protector, and the `PROGRESS_WINDOW` tuning.

## Viewer

- **DWG picture export, what it leaves open**: a single viewport of a paper
  layout cannot be addressed (the scene data on the TS side holds no viewport
  transform, clip or frozen-layer list: it needs a viewport table in
  `sheetJson` from the Rust side; model coordinates are reached with
  `layout: ""`); a truncation by `maxPrimitives` is not reported on the
  `Raster`; `rasterTile` cannot be set in the sandboxed frame; DESIGN.md of the
  DWG module has no section on pictures yet.
- **Format registry: generating the detection tables** (`formats/registry.json`)
  is not planned: the scanner's and the extractor's magic tables carry offsets,
  minimum lengths and priorities a flat table does not hold, and the checks in
  `make test-formats` already catch a disagreement. Revisit if the viewer's
  matchers (`ts/core/formats.ts`) are the first thing generated.
- **Picture export, what it leaves open**: `controllers.viewport` is
  read-only (a host reads it, changes it and passes it back as `region`); the
  limits (16,384 px a side, 64 Mpx in all) are fixed, not a host option within
  a cap; iOS Safari's smaller canvas ceiling makes a large export fail with
  `too-large`; the exports have been compared with the screen in headless
  Chromium only, not on a real GPU; a replaced document (`session.replace`)
  keeps its zoom only when the new file is delivered the way the first was.
- **3D model pictures, what they leave open**: the IFC outlines are one-pixel
  lines, so at a large output size they are thin next to the model (fat lines
  would scale them); each picture builds its own light probe, lights and
  shaders, a few seconds on a software GPU (a kept renderer between pictures
  would trade that against holding a context); the default tile is 2048 px
  (not 4096) because a multisampled 4096 px tile is about half a gigabyte;
  `lineweight` and `layout` are ignored for a model.
- **Format registry**: `formats/registry.json` is checked against the code
  (`make test-formats`, the viewer's `registry.test.ts`, the scanner's
  `format_registry.rs`) and generates the format matrix and the viewer summary
  sentence. The detection tables themselves (the extractor's and the scanner's
  magic, the viewer's matchers) are still written by hand: generating them from
  the registry is the next step, file by file.
- **hayro as the viewer's PDF rasterizer**: evaluated in
  `docs/PDF-RENDERER-EVALUATION.md` (1370 PDFs, harness in
  `scripts/pdf-compare/`). On par with pdf.js in wasm with SIMD and closer to
  poppler on shadings and fonts, but it opens no encrypted file, draws some
  pages blank and has outliers, and the text layer, links and outline would
  have to be built. The cheaper path is an optional engine with pdf.js kept for
  the interactive parts and as the fallback.
- **Archives in the viewer, left out on purpose**: email (`.eml`, `.msg`,
  `.mbox`) and OLE containers, which another reader would open as documents;
  OpenDocument and EPUB, which are documents that happen to be zips; the
  packers and installers (`upx`, `sfx`, `nsis`, `inno`, `pepack`); and the
  formats the engine only recognises (`.ace`, `.sit`). A `.crx` is a zip with
  a header before it, and is not claimed.
- **Preferring the browser's own decoder for JPEG XL**: Safari decodes it and
  Chrome ships it from 155; the viewer's image module decodes every format it
  claims itself, so that a file looks the same everywhere. Drawing it with
  `<img>` where the browser can, as for the formats browsers draw, would spare
  those users the 540 KB the module grew by (1.1 to 1.65 MB).
- **Text previews**: line numbers, a collapsible JSON and XML tree, `mailto:`
  links (the host only opens http and https), search in the file, reading only the first
  2 MiB of a URL source (the source reader has no prefix read), per-record
  `.jsonl` formatting, GFM task lists and bare-URL autolinks, and refusing a
  binary file named `x.txt` at detection rather than at open.
- **3D models**: glTF triangle strips and fans, `KHR_mesh_quantization`, Draco
  and meshopt (counted as unsupported today); PLY point clouds drawn as points
  (refused today); OFF and 3MF; smooth normals for OBJ and PLY files without
  them; detecting the up axis of OBJ and PLY (Y up is assumed); a model-specific
  error message in the viewer. The `mesh` fuzz target is in the nightly
  campaign.
- **hayro instead of pdf.js** once it supports encrypted PDFs, blend modes and
  knockout groups: the PDF path would be Rust end to end. Compare pixel output
  against pdf.js on a corpus first.
- **wpd for WebP** (halidecx/wpd, BSD-2-Clause): revisit when it is published
  on crates.io with releases; measure its safe build (no assembly) against
  `image-webp` and `dwebp` on a corpus, and its wasm size.
- **The Office engines refuse a ZIP with bytes after its end record**
  ("ZIP central directory preflight failed"), which `unzip` and most libraries
  read. The viewer trims such a tail itself (`trimZipTail`); the report to
  @silurus/ooxml is still to be made, with a deck that has one stray newline
  after the end record.
- **Pictures of Word pages and slides past 16 million pixels**: the engines
  draw a whole page at most that large (they return a smaller bitmap without
  saying so) and cannot draw a part of one, so a small region of a page is cut
  from a drawing of the whole page and refused as too large past the limit.
  A request to the engines for a sub-rectangle (or a tile size) would lift it.
- **Pictures of an Office document share the viewer's copy**: a second copy of
  the document is parsed for the pictures. `fromDocument`, `fromPresentation`
  and `fromWorkbook` borrow one (a borrowed workbook draws nothing until a sheet
  is gone to), but a delimited text has no workbook to borrow, so the CSV's
  pictures are drawn from a workbook made of its table (`table.ts`). Sharing
  would spare the second parse once the engine documents that start-up and
  reads delimited text into a workbook.
- **A sheet's viewport without a second workbook**: its page is the used
  area, which only the worksheet model says, so the viewport is worked out from
  the second copy once someone reads or subscribes to it. The engine offers no
  extent of the used area on the viewer. For the same reason a sheet's
  `get()` has the last measure and starts the next, and in the sandboxed frame
  every `get()` does (the port is asynchronous): a synchronous read of an
  up-to-date viewport needs the frame's answer to be awaited, which the `Store`
  interface has no place for.
- **The second copy is kept until the session ends**: an idle release would
  spare memory after a one-off picture.
- **`ViewerDialog` for hosts with a form beside the file**: an `aside` and a
  `placeholder` (while a file is chosen), a `title` with no file; the counter,
  arrow keys, download and "open in a tab" are written again by a host that
  keeps its own dialog around `ViewerBody`.
- **Cross-browser e2e**: Firefox runs the frame, delivery, selection,
  converted and office-raster specs, WebKit those and model-raster; the rest
  run on Chromium only (`playwright.config.ts`). The engines' text is made the
  same by `e2e/fonts.conf` (a bare `serif` is DejaVu Serif in Firefox and
  WebKit, Liberation Serif in Chromium). Why the others are left out:
  - Firefox headless here has no WebGL, so every spec that draws with it
    (model, CAD, IFC) cannot run.
  - The CAD specs fail in WebKit on Linux (14 of `cad-raster.spec.ts`, and the
    viewer itself shows a black canvas): a WebGL canvas made with
    `antialias: false` presents black, or nothing with `alpha`, even for a
    bare context cleared to red, in every attribute combination tried; with
    `antialias: true` or `preserveDrawingBuffer: true` it is shown. The CAD
    renderer needs `antialias: false` (its strokes antialias in the shader).
    Seen only in the headless WebKit build Playwright ships for Linux, on
    software rendering; not checked on Safari or a GPU, so whether a user
    sees it is open (`cad.spec.ts`, not run in WebKit, shares the cause).
  - The other specs have not been tried in Firefox and WebKit.

## CI

- **Delete the viewer e2e diagnostics** (`screenshot: "only-on-failure"` in
  `crates/exav-viewer/playwright.config.ts` and the `viewer-e2e-results`
  upload step in `.github/workflows/ci.yml`) once the three PDF tests that
  fail only on the GitHub runner are understood.

## Robustness

- **A read-only FAT reader of our own**: the `fatfs` crate panics on a chain
  through cluster 1 (it subtracts 2 from any cluster number it reads). The
  volume walk now contains the panic per directory or file, and the fuzz
  targets tolerate that call site, so other `fatfs` panics there would not
  show up in fuzzing. A hand-written reader would remove the class, as was
  done for CAB and ARJ.
- **Fuzzing the viewer's TypeScript**: property tests (fast-check, MIT, in
  vitest) for the two places a hostile document's output meets code the viewer
  trusts: the host's validation of the messages a sandboxed frame sends
  (`ts/frame/host.ts`, `protocol.ts`: every message shape, sizes, ports), and
  the CSV reader. The Rust side is fuzzed (docs/FUZZING.md); this half is not.
- **A differential oracle for the YARA engine**: yara-x (or libyara) compiled
  into a fuzz target to compare rule results on fuzzed rules and data. The
  existing difftests cover the rule corpora; the fuzzer would reach
  combinations they do not. yara-x pulls wasmtime, so it needs its own fuzz
  workspace.
- **Observe the PE emulator's `[obs]` fields on real Windows**: the TEB, PEB,
  loader-entry and KUSER_SHARED_DATA fields in `crates/exav-pe-emu/src/win.rs`
  that no clean written source gives (tagged `[obs]`; its NOTICE names, for
  each, the API that reports the same value). A small 32-bit program run
  under WoW64 on a Windows evaluation image (on this ARM host, Windows under
  qemu emulation) would compare each field with its API and confirm the
  emulator's layout. The x86 CONTEXT layout `run.rs` builds for exception
  dispatch is unverified too and could be checked the same way.

The arithmetic audit (`tmp/ARITHMETIC_AUDIT.md`, not committed; its row names
are used below) found about a hundred sites where a header's number is added
to or multiplied by something unchecked. Fixed and tested: the disk-image
formats, the signature engine's gaps, offsets, byte comparisons, PCRE group
references and logic sums, the dotnet, elf and bytecode-PE readers, the
fancy-regex size analysis, the `.Z` and ARC table counters (a `.Z` whose table
filled was lost), LZ4 skippable frames, the ARC, UPX and RAR4 position walks
(32-bit), the delta and audio RAR filters, OLE crypto lengths and spin count,
PDF key sizes, the 7z LZMA2 dictionary, split-ZIP offsets, the TIFF strip,
tile and format counts, DXF group codes, the daemon's scan-time limit and
build-time year, `-A` in exav-grep, exav-imagehash dimensions, the RAR volume
join, the encrypted DMG chunk loop, the 7z coder chain length, the ISO
directory loop, the PE resource node loop, the IFC visit budget, the
`MINSERT` of an empty block, the PDF `find_next_obj` scan, the TIFF tile row
buffer, the PE emulator's `rep` ticks, the bytecode machine's pointer
arithmetic and the 32-bit sums of the ARJ, EGG, UDIF and VBA readers. Fixed
without a test of their own (the input is not practical to build): C14 (HTTP
range end), C15 (`ml.rs` histogram, needs 4 GiB), E1 (x87 infinity store), T5
to T8 (JPEG 2000 palette and size sums), T9 (`strip_count`, which nothing
calls), R13 (zero-column proxy mesh), R7 (IFC trim parameter), `ccitt.rs`
stride, the BCJ2 position (4 GiB of output), the bytecode layout and version
sums, the warning counters (R17, 4 billion of them), the `azo.rs` range-coder
sums and the pin offsets of `engine/pins.rs`. Section 2 of the audit, done
with tests: a truncated CHM listing entry (the CHM came back clean and
silent; the files before it are kept and the damage reported), `.ldb`
expressions nested without limit (a stack overflow), a seek past `u64`, the
`setitimer` seconds, the `.ftm` rule that ended the search, the pillow
resampling weights held for the whole image, the memory amplifications (DWG
object map notes, the InstallShield Z member read through the budget, the
total of RAR5 and RAR4 key derivations, RAR3 PPMd's memory against the buffer
limit, the 7z solid block read once instead of once per member). The rest of
section 2 is done too, with tests: the `as` truncations of the signature
parser (a fixed gap past `u32`, a count past `u32`), the exav-x86 name tables
(a cell that names no mnemonic is no instruction, and every cell of the
generated tables is checked to name one), a stored YARA pattern with a bad
base64 alphabet or no bytes, the `u32` name, anchor and hash tables (a
database of more than 4 GiB of text is refused), the JPEG 2000 palette
planes, the quadratic scans of the DWG linetype, hatch, fill and text code and
of the mesh normals (a window of 256 faces around a vertex) and the IFC
cylinder unrolling, the 7z encrypted block decrypted once per block, and the
PE emulator's open handles, its searches and its module placement.

Open:

- **The sweep's hang limit on wasm32**: the `extreme` suite sets fields to
  fixed large values and to `2^32` or `2^64` minus the field's own position,
  and ARJ's CRCs are made right again after each change. Each walk runs in a
  thread with a 10 s limit, so a sum that wraps to a smaller position and loops
  (the EGG extension walk) is reported as a hang. The wasm32 build has no
  threads: there a walk is timed after it ends, so a real hang stops the run
  instead of failing it.
- **`d.get(off..off + n)` in other spellings**: the 90 sites written as
  `x.get(a..a + b)` now use `crate::bytes::at` (exav-core has its own copy).
  Slices written `d[a..a + b]`, and `get` on a `&str` or a `Vec` of another
  type, were not touched.
- **`clippy::arithmetic_side_effects`**: denied in the disk-image formats
  (vhd, vmdk, qcow2, vhdx, vdisk, volumes, ntfs, wim without its two codecs, ext, fat,
  partition, iso, dmg, udif, udf); the codecs `wim/lzx.rs` and `wim::xpress`
  allow it. The lint is far too noisy for the other decoders (about 2,500
  sites in `exav-unpack`). Extend it file by file as each is cleaned.
- **The wasm32 sweep's samples**: `make test-wasm` runs the `extreme` suite,
  which covers the disk images and one small sample of 28 other containers
  (`extreme.rs`). It finds what a single field set to an extreme reaches in
  those samples; a bug behind a field the sample does not use (a split-volume
  RAR, a spanned ZIP, an encrypted container) needs a sample that uses it.

## Dependencies

- **TLS without C or assembly**: `ring` (via rustls) is the only C/assembly in
  the tree, in the `http` features and the published Docker image. A pure-Rust
  rustls crypto provider would remove it once one is mature and audited.
