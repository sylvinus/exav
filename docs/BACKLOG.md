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

## CI

- **Delete the viewer e2e diagnostics** (`screenshot: "only-on-failure"` in
  `crates/exav-viewer/playwright.config.ts` and the `viewer-e2e-results`
  upload step in `.github/workflows/ci.yml`) once the three PDF tests that
  fail only on the GitHub runner are understood.

## Robustness

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

- **A sweep that finds hangs**: the `extreme` suite sets fields to fixed
  large values and to `2^32` or `2^64` minus the field's own position, and
  ARJ's CRCs are made right again after each change. It only sees a panic or
  an abort. A sum that wraps to a smaller position and so loops (the EGG
  extension walk) is not seen; that one has a unit test at the helper level.
  A time limit on each run, which the wasm build cannot have without threads,
  would find the next one.
- **`crate::bytes::at` everywhere**: `d.get(off..off + n)` is spelled about
  150 times in `exav-unpack` and as many in `exav-core`. Only the disk-image
  formats use the checked form. A mechanical replacement, by a script, wants
  the owner's go-ahead.
- **`clippy::arithmetic_side_effects`**: denied in the disk-image formats
  (vhd, vmdk, qcow2, vhdx, ntfs, wim without its two codecs, ext, fat,
  partition, iso, dmg, udif, udf); the codecs `wim/lzx.rs` and `wim::xpress`
  allow it. The lint is far too noisy for the other decoders (about 2,500
  sites in `exav-unpack`). Extend it file by file as each is cleaned.
- **The wasm32 sweep's samples**: `make test-wasm` runs the `extreme` suite,
  which covers the disk images and one small sample of 28 other containers
  (`extreme.rs`). It finds what a single field set to an extreme reaches in
  those samples; a bug behind a field the sample does not use (a split-volume
  RAR, a spanned ZIP, an encrypted container) needs a sample that uses it.
- **The second half of the NTFS attribute-list walk** has no test of its own.

## Dependencies

- **TLS without C or assembly**: `ring` (via rustls) is the only C/assembly in
  the tree, in the `http` features and the published Docker image. A pure-Rust
  rustls crypto provider would remove it once one is mature and audited.
