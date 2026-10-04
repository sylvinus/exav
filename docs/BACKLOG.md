# Backlog

Work decided or proposed and deliberately postponed. Gaps exav already
reports (never a silent `Clean`) are in [GAPS.md](GAPS.md); the public roadmap
is on exav.org.

## Search and text

- **exav-grep `--text`**: search the text a viewer would show rather than raw
  bytes: DWG/DXF (TEXT, MTEXT without format codes, attributes, tables, layer
  and block names, from exav-render's drawing model), IFC names and property
  values, OOXML paragraph text then legacy `.doc`/`.xls`, PDF text through
  ToUnicode and font encodings, decoded HTML and email. Matches located by
  page, sheet or entity (`plans.zip!a1.dwg!layout "A1"/MTEXT 2F3`).
- **exav-grep `--ocr`**: images (all exav-render formats, fax TIFF and JBIG2
  included) and scanned PDF pages rasterised by hayro, through a pure-Rust OCR
  (`ocrs`, MIT/Apache, on a pure-Rust runtime; model about 10 MB, behind a
  build feature; licence of the weights and quality to check first; Latin
  script first). Page and time budgets; a page that could not be read gives
  exit code 3. Tesseract is C++ and excluded.
- **QR codes for the scanner**: decode QR codes in images and PDFs (pure-Rust
  `rqrr`, MIT/Apache) so signatures can match their URLs ("quishing").
- **Visible-text layer for the scanner**: let signatures match a document's
  extracted text (the `--text` extractors), not only its bytes.

## Signatures

- **`EP` and section offsets on ELF and Mach-O**: ClamAV resolves `EP`,
  `Sn`, `SL` and `SEn` on both; exav builds the layout from a PE only
  (`pe_image` in `crates/exav-core/src/lib.rs`), so such a subsignature never
  matches there. No ELF or Mach-O signature in `daily` 28140 uses one;
  `main` not checked.

## Formats

- **MHTML** (`.mht`, `.mhtml`): look into what exav does beyond typing it
  (`CL_TYPE_MHTML` in `crates/exav-core/src/filetype.rs`): extraction of
  parts, encodings, scripts, viewer support. To scope first.
- **DWG before R13** (AC1009 and older): reported as an unsupported version
  today; the ODA specification does not document these releases.
- **IFC geometry**: conical, spherical and toroidal B-rep faces, B-spline face
  trimming, IFC4X3 alignments, sweep start and end parameters, grid
  placements, a storey filter in the viewer (listed on the exav-render docs
  page).
- **CAB MSZIP and LZX** lose the block or frame being decoded when a cut or
  damage stops it (limit of the decoding library).
- **ZIP's buffered path** (`decode_zip_raw`, reachable only through the
  `extract` API) does not keep a decoded prefix on error.
- **Cuts inside a codec header** (a UPX file cut inside its first block, an EGG
  LZMA block cut inside its codec header) stay `Unscannable`.
- **xz checksum after a full block** counts as damage, because the decoder
  cannot tell whether more blocks follow.
- **JBIG2 symbol dictionaries** are bounded only by hayro-jbig2's own
  65,535 × 65,535 symbol limit: the symbol sizes sit inside the compressed
  data, so they cannot be counted against the memory budget before decoding,
  and the crate has no budget setting. Regions are counted (fuzz finding,
  docs/FUZZING.md). Needs a budget hook upstream or a pre-pass that bounds
  the dictionaries.
- **Image decode time** is limited only through memory: a budget bounds the
  pixels, and so the time only in proportion. Within the viewer's 1 GiB image
  budget a JBIG2 file can still declare about 8 billion pixels of regions,
  minutes of CPU (stopped by the decode worker's 60 s timeout in the viewer,
  not at all in a native caller). A work budget in the decoders, or a
  per-format pixel cap below the memory budget, would bound it.

## Viewer

- **JPEG XL**, after 0.0.2: a fork of the `jxl` crate without SIMD and with
  its other `unsafe` rewritten, in the viewer's image module only. The plan is
  on the roadmap page (www/src/content/docs/project/roadmap.md). The demo
  already has a sample, `eckersberg-colosseum-arches.jxl`, in exav-samples.
- **hayro instead of pdf.js** once it supports encrypted PDFs, blend modes and
  knockout groups: the PDF path would be Rust end to end. Compare pixel output
  against pdf.js on a corpus first.
- **wpd for WebP** (halidecx/wpd, BSD-2-Clause): revisit when it is published
  on crates.io with releases; measure its safe build (no assembly) against
  `image-webp` and `dwebp` on a corpus, and its wasm size.
- **Replacing a document in a sandboxed frame**: `session.replace` answers
  `false` there, as a frame holds one file, so the zoom and position start
  over (in the page they stay). It needs a `replace` message in the frame's
  protocol and a way to hand the frame another source over its port.
- **The Office engines refuse a ZIP with bytes after its end record**
  ("ZIP central directory preflight failed"), which `unzip` and most libraries
  read. The viewer trims such a tail itself (`trimZipTail`); the report to
  @silurus/ooxml is still to be made, with a deck that has one stray newline
  after the end record.
- **`ViewerDialog` for hosts with a form beside the file**: an `aside` and a
  `placeholder` (while a file is chosen), a `title` with no file; the counter,
  arrow keys, download and "open in a tab" are written again by a host that
  keeps its own dialog around `ViewerBody`.

## Dependencies

- **TLS without C or assembly**: `ring` (via rustls) is the only C/assembly in
  the tree, in the `http` features and the published Docker image. A pure-Rust
  rustls crypto provider would remove it once one is mature and audited.
