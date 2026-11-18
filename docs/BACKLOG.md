# Backlog

Work decided or proposed and deliberately postponed. Gaps exav already
reports (never a silent `Clean`) are in [GAPS.md](GAPS.md); the public roadmap
is on exav.org.

## Search and text

- **exav-grep `--text`**: search the text a viewer would show rather than raw
  bytes. Done: Markdown, HTML, the XML parts of OOXML and ODF files, DWG and DXF
  (TEXT, MTEXT without format codes, attributes, layer and block names, DWG
  hyperlinks, from exav-render's drawing model), PDF text (opt-in `text-pdf`) and, with
  `text-office`, the legacy and flat office formats (DOC, XLS, PPT, RTF, Word
  2003 XML, SpreadsheetML 2003, SYLK, FODT, FODS, FODP, FODG, Numbers, Pages,
  Keynote), located by sheet or slide (`book.xls!text/sheet "Budget"`). To do:
  matches located by page and by entity
  (`plans.zip!a1.dwg!layout "A1"/MTEXT 2F3`).
- **exav-grep `--ocr`**: images (all exav-render formats, fax TIFF and JBIG2
  included) and scanned PDF pages rasterised by hayro, through a pure-Rust OCR
  (`ocrs`, MIT/Apache, on a pure-Rust runtime; model about 10 MB, behind a
  build feature; licence of the weights and quality to check first; Latin
  script first). Page and time budgets; a page that could not be read gives
  exit code 3. Tesseract is C++ and excluded.
- **QR codes in PDF images, what is left**: the PDF reader describes every
  image (`Entry::raster`), and the raw, CCITT and JBIG2 ones (with their
  globals) are read. Said, not read (the scan is `PARTIAL`): the Lab,
  Separation, DeviceN and other color spaces, the TIFF predictor, an Indexed
  image over 8 bits, an image whose dictionary lacks `/Width`, `/Height`,
  `/BitsPerComponent` or `/ColorSpace`. Not said: inline images (`BI ... EI`,
  not members), and a CCITT or JBIG2 stream the decoder reads leniently
  (garbage or a missing page information is a white image, a truncated stream
  is the part drawn). `exav-qr` has no `--passwords`. The reader (exav-qr)
  checks the deadline, a memory budget and the caps on finder patterns and
  candidate grids in its own loops, so the `qr` feature builds with
  `panic = "abort"` too. There a panic of the reader on a crafted
  image is no longer contained (`catch_unwind` needs unwinding): the panic
  sites in exav-qr that image content can reach (`assert!`, `unwrap`,
  indexing, arithmetic with overflow checks) are still to be removed.
- **QR codes: more PDF color spaces**: read Lab, Separation and DeviceN (their
  tint transform needs PDF functions, types 0, 2, 3 and 4), and the TIFF
  predictor 2, in `exav_render::image::from_raster`; today these images are
  said and not read.
- **QR codes on the drawn pages of a PDF** (a code drawn as vector paths or
  made of glyphs, not an image), once hayro draws a PDF's pages (see the hayro
  items under Viewer).
- **Visible-text layer for the scanner**: let signatures match a document's
  extracted text (the `--text` extractors), not only its bytes. Done for
  Markdown, HTML, the XML parts of Office and OpenDocument files, drawings,
  (opt-in) PDF and (opt-in, `visible-text-office`) the legacy and flat office
  formats: `visible-text` in exav-core, `exav-grep --text`, through
  `exav_render::text::visible_text`, matched as a text view; a link's label and
  target are in that text, and `--detect phishing` judges them. An office
  document whose text cannot be taken out (encrypted, past a limit, damaged)
  marks the scan incomplete. To do: the labels of PDF links (hayro is run
  without annotations: the page text under each annotation rectangle); the
  speaker notes of PPT and FODP files and the text of animations (the
  converters leave them out); PDF text
  without hayro's `unsafe` feature (a vendored patch of hayro-interpret, as the
  viewer does for zenjxl-decoder) so that it can be a default; making
  `visible-text-office` a default (the readers are the largest of the scan).
  Markdown is known by its extension, and a Markdown file with another name is
  not read; a compound file is read as an office document by its extension
  (`.doc`, `.xls`, `.ppt` and their templates), so as not to read an installer
  whole to find out.
- **A compound file that holds several documents**: the text view reads each
  of them; the viewer opens the one its name asks for. `officeKinds` of the
  sniff module gives all of them, from `exav_unpack::cfb::compound_kinds`, the
  function the text view uses, so a file named `.xls` that holds a Word
  document and no workbook goes to the external converter, not to the
  spreadsheet converter.

## Formats

- **What bounded detection does not look at.** Detection reads the first
  4 MiB, the end, and the 1 MiB after a PE's image (`after_image`); what it
  searched for anywhere before is looked for there. Left: a compiled AutoIt
  script whose resource lies past the first 4 MiB (the `SCRIPT` resource by
  its name), a self-extractor's archive in a resource past them (IExpress
  keeps its cabinet in `CABINET`), an ELF's appended archive past them, and an
  encoded script past a page's first 4 MiB (the page reader could decode it,
  as clamscan's HTML normaliser does). The self-extractor check takes
  `PK\x03\x04` and `Rar!` without a header check.
- **One reader per format**: the compound file, the encrypted workbook, RTF,
  BIFF (records, workbook tables, formulas) and HTML are read once for the
  scanner and the converters ([ARCHITECTURE.md](ARCHITECTURE.md)). Left to
  extract into `exav-unpack`: the PowerPoint records and the Word FIB (the
  scanner reads them to find embedded storages and the encryption flag, the
  converters to build the document), ZIP packages (the converters open them
  with the `zip` crate and limits of their own), the XML trees, and the two
  tables of code pages (AutoCAD's names for drawings, numbers for BIFF; both
  end in `encoding_rs`). Merging the three `limits.rs` of the converters into
  one budget is part of it. The scripts that generated the function table of
  BIFF (`ftab.py`, `ftab.json` in `exav-render/scripts/office/sheets`) write a
  file that no longer exists; the table in `biff/ftab.rs` is edited by hand.
- **Recognised, not opened**: these formats are typed and reported
  `UNSCANNABLE` (`formats/reported.rs`), never clean, and none is extracted.
  By how much each needs:
  - *InstallShield sets* (`data1.hdr` with `dataN.cab`, as members of an MSI
    or as files) are reported, not joined across their files: the files of a
    set whose header is a separate file are not scanned.
  - *StuffIt* (`.sit`): methods 0, 13, 14 and 15 are read by the `stuffit`
    crate (Apache-2.0 or MIT, which names The Unarchiver as its reference: its
    provenance has to be checked against the rule about sources read). StuffIt
    X (`.sitx`) is not covered by it.
  - *ACE*: `acefile` (BSD-2) documents ACE 1.0 and 2.0 from a 1998 format note
    and two reference tools. There is no valid sample to check a decoder
    against, so it stays reported until one is found.
  - *lrzip*: defined only by GPL source that exav does not read; no
    permissive implementation exists. Stays reported.
- **InstallShield, what is left**: the older plain-text file list and the list
  of wide-text names of a setup executable (seen in the Omada Controller setup)
  are not read. The findings `imphash`, `pe-imphash` and `static-score` are
  printed for an executable that is not an installer or packer only.
- **Python bytecode** of a version past 3.21, or from PyPy, is not typed (the
  magic number table in `formats/pyc.rs`).
- **EROFS fragments**: the tail of a file kept in the packed inode is reported,
  not read; it needs a read at an offset of the (compressed) packed inode.
  Other filesystems worth a reader: XFS, Btrfs and F2FS (larger than any
  here), and squashfs before version 4.
- **An Office package inside an archive, in the viewer**: a file is told by
  its ZIP directory (`detectFile`), a member of an archive is not
  (`detectBytes`), so a DOCX member named `x.zip` opens as a nested archive.
- **DXF hyperlinks** (`PE_URL` xdata, groups 1001, 1000, 1002, 1071): the DWG
  reader feeds them to the text view and the phishing check
  (`Dwg::hyperlinks`); the DXF reader does not read them. The parse takes
  `(code, value)` items, so the DXF side only has to give it an entity's xdata
  tags.
- **PDF object streams, what is left**: the bytecode `pdf_*` object table (raw
  ` obj` markers, for parity with the engine it mirrors) does not list the
  objects inside object streams, `pdf_has_encrypt` in the build without
  `decrypt` looks at raw bytes, stream-level crypt filters are not honoured,
  and objects are found by scanning rather than through the cross-reference
  table. The bytecode PDF object table is built for every PDF when bytecode is
  loaded, before a program is known to run; for a streamed PDF that is a read
  of its own.
- **Decoder oracle tests**: the LZFSE/LZVN and DCL differential tests against
  Apple's lzfse and zlib's blast (`#[ignore]`d, built by
  `crates/exav-unpack/tests/oracle/build.sh`) run on request only; a `make`
  target and a place in the nightly campaign are not done.
- **MHTML** (`.mht`, `.mhtml`): look into what exav does beyond typing it
  (`CL_TYPE_MHTML` in `crates/exav-core/src/filetype.rs`): extraction of
  parts, encodings, scripts, viewer support. To scope first.
- **DWG before R13** (AC1009 and older): reported as an unsupported version
  today; the ODA specification does not document these releases.
- **Disks read in place, what is left** (docs/STREAMING_FORMATS.md): a
  partition table inside a partition is not followed in place; DMG's
  reader does not count what it decodes against the scan budget as the other
  disks do; a truncated or damaged streamOptimized VMDK is indexed by its
  markers, which is not how VMware finds a grain (its tables).

## Large files and memory

What a scan holds does not grow with a file's size for most inputs
([Streaming & memory](https://exav.org/scanner/concepts/streaming-memory/)).
What is left, most worth doing first.

**Tabled for 0.0.4: no scan holds a whole object.** The aim is that a file
of any size is scanned in bounded memory, with no check skipped for being large
and no format opened only if it fits. What still holds a whole object, in the
order to take it:

1. Encrypted RAR archives and RAR5 links past the limit (the first item below).
2. The readers that take a packed PE whole (NSIS, AutoIt, UPX, the PE
   packers), which want the image or the overlay as a source (the second
   item).
3. One forward pass over a file past the limit, the members that spill, and
   HTTP sources (the next items).
4. The small formats read whole (ARJ, ZOO, ARC, ALZ, EGG, InstallShield Z,
   BinHex, uuencode) and the WIM name tree, each only when someone meets one past
   the limit.

PDF stays on the block cache: its cross-reference table is at the end, and
holding the file is what recovery needs. The `exav-render` converters hold their
document model, bounded by `max_memory`; they are the viewer's, not the
scanner's, and are not part of this aim.

- **The converters' fixed limits, decided: from `--max-object-bytes`.** The
  scanner runs exav-render's converters for the text of DOC, XLS, PPT, iWork
  and flat XML files, and sets only their memory (the smaller of
  `--max-object-bytes` and 1 GiB). Their other limits are fixed: input
  (512 MiB documents, 256 MiB sheets), cells (2,000,000 and 4,000,000),
  paragraphs (5,000,000), sheets (4,096), one decompressed part (256 MiB). A
  file past one has no text view and its scan is incomplete. They are to
  follow the object limit, with no flags of their own: the input and part
  sizes the limit itself, the counts in proportion to it, and the memory too
  past 1 GiB.
- **The text documents' model per footnote**: a flat ODT of 300,000 one-word
  footnotes takes 2.3 GB of memory (7.6 KB a note) and converts in time that
  grows faster than the notes do, from reading the model rather than from a
  quadratic step: each note's content is its own `Vec<Block>`, and a `Block`
  is 944 bytes. A smaller `Block` (the rare large parts of a paragraph behind
  a pointer) makes such a document, and every large one, cheaper.

- **RAR**: a single archive is read in place, keeping only the window, and a
  multi-volume set past `--max-object-bytes` is read across its volumes.
  Encrypted archives and RAR5 links still take the whole-archive path, so they
  are refused past the limit. RAR5 output could be drained from the window
  instead of staged. A set of many volumes opens them all together and keeps at
  least two blocks of cache for each part: a set of thousands of parts would
  want a pool of open files and a shared cache.
- **PE structure past the limit**: a PE past `--max-object-bytes` is parsed
  from its image (headers and sections up to the end of the last section's
  data, the debug records and the page after each section): layout, section
  hashes, imports, icons, Authenticode (digest streamed), YARA's `pe`, `elf`
  and `dotnet` modules, the bytecode header data. Still `LIMITS-EXCEEDED`: a PE
  whose image is past the limit; ELF and Mach-O (the UPX and packer check reads
  one whole); the readers that take a packed PE whole (NSIS, AutoIt, UPX, PE
  packers), which need a source from the end of the image in exav-unpack, as
  the Inno reader has. A PE that only looks packed, with no packer named, is
  scanned as it is when it is held, and `LIMITS-EXCEEDED` past the limit: two
  421 MB PEs of the corpus (a 300 KB image and a compressed overlay).
- **A carved ZIP is read with the ZIPs after it**: an archive carved out of an
  object runs to the object's end, and a ZIP whose directory is not its own
  is read by its local headers. A PE with 45 ZIPs one after the other (an
  IKVM bundle) gives about 2,400 members for each of the 32 it carves, so the
  scan meets `--max-members` (`file count > 100000`), then the carving cap (45
  ZIPs for 32 carved); clamscan says OK.
- **One forward pass**: carving, the digests, the signature sweep with its
  verification, YARA's patterns and the static model's byte counts are fed
  from one read of an object read through the cache (detection reads only the
  start, the end and the places the structure names). Left: the literals that signatures look for past an unbounded gap are
  searched in one walk after the sweep (0.9x of the object on a database of
  such signatures; those in a signature's forward part could be searched as the
  sweep goes by, a hook per window in `sweep_fed` with the verifier behind a
  `RefCell`; those before an internal anchor cannot); a YARA regexp with no
  longest match whose first atom comes late is followed from byte 0, so many
  of them each re-read what lies before it (they could share one catch-up); a
  PE's image is read once for the engine and once for icons and section hashes
  (keep it in `Facts`); a PE with an icon database takes an engine pass of its
  own. Re-running a decoder for each pass, in place of reading a spill file,
  would settle the compressed members below.
- **The block cache's policy**: a sequential run streams through two blocks of
  its own once the cache is full, and the rest is least recently used, in
  constant time per access. Left: pinning the head of the object (detection,
  headers, a ZIP's directory) if a trace shows it evicted.
- **Members without a spill**: a stored member over `--max-object-bytes` is
  scanned where it lies, through its container's block cache. A compressed
  member over it is still written to a spill file, which bounds the member by
  `--max-spill-bytes` (2 GiB) and needs the disk, and its normalised text
  views need as much again. A compressed member has no range. Either a seekable decoder under the
    block cache, with restart points: a deflate window (32 KiB) every N MiB as
    zlib's `zran` keeps, bzip2 blocks, xz blocks, zstd frames. The index grows
    with the member, so the spacing must grow with it (at 20 GB and 64 MiB
    apart it is about 10 MB), a single-stream xz or single-frame zstd or a solid
    7z/LZMA block has no points but the start, and a scattered read decodes up
    to N MiB, so a hostile file multiplies decode time unless that is charged to
    `--max-matcher-bytes`. Or the forward pass above, re-running the decoder for
    each pass in place of reading a spill file: deflate decodes at several
    hundred MB/s, xz slower. A container inside a compressed member needs seeks
    too and meets the same costs. Spill stays the default; streaming is for no
    disk or a member past the ceiling.
- **HTTP sources** (`HttpRangeReader`): a large object costs two to five times
  its size in transfer, by how many passes the database makes; `--http-spill`
  pays disk for one transfer. Left: a no-range object within
  `--max-object-bytes` is held and then copied by the scan, twice its size
  (stream the body into the scan, or hand the bytes to `analyze`); behind a
  proxy from the environment the private-address filter sees only addresses
  written out; a check of the object by its digest, in place of the
  validators, for a server that gives none.
- **Read whole, rarely large**: ARJ, ZOO, ARC, ALZ, EGG, InstallShield Z,
  BinHex and uuencode. Each needs its own reader to take a source, and none is
  often past the limit.
- **PDF**: not worth it. The file is held (the cross-reference table is at the
  end, and recovery scans the whole of it) and each stream object is decoded one
  at a time under the buffer limit, so streaming would save one object.
- **Compressed files in filesystems past the limit**: a decmpfs file whose
  bytes are in the attribute (inline, at most 64 KiB coded) is one unit, held
  within the buffer limit and reported past it, because the LZVN and LZFSE
  decoders are not resumable; resumable ones would read it as the others are.
  EROFS fragments and the extent-record format are reported, not read. NTFS
  (LZNT1) is read a unit at a time, tested on synthetic volumes only (no
  Windows-made one), as is a `$MFT` in several extents.
- **An encrypted Office package past the buffer limit** is reported as not
  decrypted; decrypting it as it is read would scan it.
- **`--max-hole-bytes` has no exav-grep flag**: the default (64G) applies.
- **WIM**: the directory tree (the names) is held whole under the buffer limit;
  without it the files are scanned under the names `wim-resource-N`. LZMS
  resources are reported, not read.
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
- **Inno Setup, what is left**: data versions past 6.4.0.1 (6.4.3 has data
  entries of 103 bytes, which innoextract does not describe; 6.5 and later),
  files in a separate `setup-N.bin`, and encrypted files opened with the
  installer's password. innoextract (zlib licence) is the reference; Inno
  Setup's own source is under a licence exav does not read sources under.
- **Cuts inside a codec header** (a UPX file cut inside its first block, an EGG
  LZMA block cut inside its codec header) stay `Unscannable` on purpose: no
  byte of the stream is there to decode, and a packed file with none of its
  content examined is not reported as examined.
- **xz checksum after a full block** counts as damage, because the decoder
  cannot tell whether more blocks follow.
- **A tar hard link** is extracted by `exav-unpack` as an empty file; GNU tar
  links it. The reader does not pass a hard link's target on
  (`MemberMeta::link` is for symbolic links).
- **Small gaps found by the wild-sample sweeps**:
  a UPX-packed DOS `.exe` (`upx -t` accepts it; exav's UPX reader covers PE and
  ELF); CHM overlays appended to PE files (PuTTY builds: 7-Zip lists them,
  ClamAV does not scan overlays); an empty spreadsheet template (no table) reads as
  "damaged: no sheets" instead of an empty workbook.
- **JBIG2 symbol dictionaries** are bounded only by hayro-jbig2's own
  65,535 × 65,535 symbol limit: the symbol sizes sit inside the compressed
  data, so they cannot be counted against the memory budget before decoding,
  and the crate has no budget setting. Regions are counted (fuzz finding,
  docs/FUZZING.md), and so is the symbol count of a dictionary (at most eight
  symbols a byte: one with its count changed in two bytes took 100 s and 7 GB),
  but a dictionary within that count can still cost seconds. Needs a budget
  hook upstream or a pre-pass that bounds the dictionaries. hayro's main
  branch has both, unreleased after 0.4.0: decoding stops on exhausted
  arithmetic data (PR 1372; a file that took 36 s ends in 10 ms) and
  `DecodeSettings::memory_limit` (PR 1789, 1 GiB by default). Recheck on its
  next release.
- **Image decode time**, measured on a build with optimisations: JBIG2
  regions decode at about 230 Mpx a second when the data is empty (a few times
  slower on real data), JPEG 2000 at about 50 Mpx a second, and the grey
  conversion and Lanczos resize of a large JPEG (an 805-byte file that decodes
  to a few million pixels) take 0.4 s. A decode is bounded by the
  memory budget (at most `DECODE_MAX`, 512 MiB, for a JBIG2 file's regions and
  for every image through `exav_render::image::decode`, and the same for the
  PDF decoders' regions), so a native decode is seconds; the decoders have no
  work budget of their own, which a JBIG2 symbol dictionary also escapes (see
  above). In the viewer the worker's 60 s timeout stops what is slower. The QR
  search holds a JBIG2 image's regions and page to `--max-qr-pixels` and its
  decoders to the buffer limit; a decode within those can still take about a
  second of a thread that the QR deadline cannot interrupt, and is checked when
  it ends.
- **PowerPoint 2, 3 and 4**: exav-render's `slides` recognises them (Windows, Mac,
  BinHex, `PP40` stream) and reports `unsupported`. Text-only decoding would
  have to come from seven sample files alone; no
  specification exists to check against.
- **PowerPoint 95 pictures, freeforms and arcs**: the reader (`ppt95.rs`) was
  written from one sample and leaves these out; more samples are needed.
- **Office converters, open decisions** (exav-render's `sheets`, `slides` and `docs`):
  - docs converter: commit a small Word 6 fixture for the fuzz seeds and e2e;
    Pages tables, pictures and headers. Which converter goes first is decided
    (Viewer).
  - slides: draw the first slide while the rest converts (needs ranged
    delivery); propose a random-access archive source to @silurus/ooxml; Keynote
    table borders follow the style (hidden means none); about 20 ODP chart documents differ because of the sheets chart
    writer (axes, legends).
  - Three OfficeArt readers (`common/escher.rs`, `slides/ppt/escher.rs`,
    `sheets/xls/escher.rs`) and two ZIP readers (`common/package.rs` and
    `slides/package.rs`, which handles an encrypted member in its own way) are
    still apart. The byte
    cursor, compound file, code pages, iWork archive, base64 and the ODF colour,
    percentage and text helpers are shared.
- **Demo examples**: `demo:build` downloads 85 MB (`--offline` copies
  the committed files only; CI and the e2e rig may want it), and a site that
  changes a file breaks the build until its pin is updated (Innerscene's two
  drawings gained a one-line CC0 comment at the top, seen 2026-11-15); the CAD
  files, the ISO and the encrypted archives are not byte-reproducible; the
  sidebar is long and wants collapsible sections; viewer gaps the examples
  showed: `.pages` has
  no matcher in `ts/core/formats.ts`, G3 fax TIFF is not decoded (G4 only),
  Minolta MRW has no preview. No clean sample exists for Pentax PEF, Sigma X3F,
  Phase One IIQ, Hasselblad 3FR, Samsung SRW, Kodak DCR, IWA Pages or a real OBJ.
- **Camera RAW**: the detection rule that makes a TIFF a RAW on a maker's name
  plus a SubIFD or thumbnail (opens old Sony SRF and Nikon scanner NEF); a
  default cap on the preview size in the viewer (today up to about 67 Mpx);
  CR3 previews stored as HEIF, Minolta MRW and Kodak DCR thumbnails.
- **CAD**: level of detail for large drawings (the potsdam fit frame spends 760
  of 864 ms in strokes), annotative objects (annotation scales per owner and
  viewport), an external file resolver (xrefs, images); 46 DWG oracle
  differences left unexplained (36 MULTILEADER context scales in sample
  0e74f0aa, DWG-only material dictionaries in edf22e18); 3D is out of scope.
- **PE emulator**: TELock (11 samples, needs a trace on real Windows, see the
  Windows VM item), Yoda's Protector, and the `PROGRESS_WINDOW` tuning.

## Viewer

- **The host and its frame, from a review before 0.0.3**:
  - A file of the tree opened from a URL or `resolve`, whose size is not
    known, is downloaded whole before `TREE.maxFileBytes` is checked
    (`fetchFile`). Decided: the download is capped (the source reader and
    `http.ts`), and a file that reaches the limit is refused.
  - The lists a frame sends (archive members, warnings) have a cap per field
    and none on the total or the rate.
  - A `controllers` message with one value the host refuses is dropped whole,
    where its comment says the known keys are kept: a DXF's warnings with a
    long name do that.
  - An `open` or `replace` whose file the frame refuses is never answered, and
    a `replace` that never settles holds every later one.
  - A second `ready` sends `open` again and gives document 0 its reads back.
  - `confirmLink` is given the mounted file after a `replace`.
  - `AbortSignal.any` is used where the browser floor may not have it.
- **DWG picture export, what it leaves open**: a single viewport of a paper
  layout cannot be addressed (the scene data on the TS side holds no viewport
  transform, clip or frozen-layer list: it needs a viewport table in
  `sheetJson` from the Rust side; model coordinates are reached with
  `layout: ""`); a truncation by `maxPrimitives` is not reported on the
  `Raster`; `rasterTile` cannot be set in the sandboxed frame; DESIGN.md of the
  DWG module has no section on pictures yet.
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
  `format_registry.rs`), feeds the site's formats page, and generates the
  viewer summary sentence and the viewer's extensions and types
  (`ts/core/formats.generated.ts`, which `formats.ts` builds its matchers
  from; `make test-formats` fails when it is out of date). What the registry
  does not hold stays in `formats.ts`: the matching steps (container types,
  the types an extension answers over), the text kinds' split and which image
  entries the browser draws. The scanner's and the extractor's magic tables
  stay written by hand: they carry offsets, minimum lengths and priorities a
  flat table does not hold, and `make test-formats` catches a disagreement.
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
- **`mailto:` links, decided**: the host's link check (`linkTarget`) accepts
  `mailto:` and asks before opening the mail program; the frame still cannot
  open one itself. Today a Markdown `mailto:` link shows as its label with the
  address beside it, not clickable.
- **One set of hidden characters, decided**: names and text hide the
  characters that reorder or hide text in six places, each with its own copy;
  the Markdown link targets (Rust and TypeScript) and the text view miss
  U+061C, U+200E and U+200F. The TypeScript copies are to take a table
  generated from Rust's (`exav-unpack` `tree/name.rs`) at build time; how each
  place shows one, and the text view's tab, LF and CR, stay as they are.
- **One viewer default per ZIP limit, decided**: the gate (`core/detect.ts`),
  the archive plugin (`archive/renderer.ts`) and the Office plugins each have
  their own default for the members and bytes of a ZIP (20,000 and 5,000
  members), so a plain ZIP of 5,001 to 20,000 members passes the gate and fails
  in the archive view. One table of viewer defaults that every step reads:
  20,000 members and 512 MiB extracted, below the scanner's (a browser tab has
  less memory), and said so in the viewer's docs.
- **Which converter a text document goes to, decided: per format, the other
  as the fallback.** The package's plugins take a `converter` each; the
  frame's one `conversion.converter` is to take one entry per format too
  (`{ doc: "exav", odt: "external" }`; one word still means every format).
  Whichever goes first, a file it cannot read goes on to the other when both
  are there: today with `"exav"` a file exav recognises and cannot read
  (Pages '09, Word 1 and 2) fails, and with `"external"` a file the external
  converter refuses is not handed to exav. Nothing chosen stays as it is:
  text documents to the external converter when one is installed.
- **Tracked changes in Word 2003 XML, decided: the markup view, as DOC.** The
  DOC reader strikes deleted text through and underlines inserted text, in
  dark red (`doc/story.rs`); the Word 2003 XML reader leaves deleted text out
  (`wml/mod.rs`). It is to show what the file holds, as DOC does.
- **Text previews**: line numbers, a collapsible JSON and XML tree, search in the file, reading only the first
  2 MiB of a URL source (the source reader has no prefix read), per-record
  `.jsonl` formatting, GFM task lists and bare-URL autolinks, and refusing a
  binary file named `x.txt` at detection rather than at open.
- **3D models**: glTF triangle strips and fans, `KHR_mesh_quantization`, Draco
  and meshopt (counted as unsupported today); PLY point clouds drawn as points
  (refused today); OFF and 3MF; smooth normals for OBJ and PLY files without
  them; detecting the up axis of OBJ and PLY (Y up is assumed); a model-specific
  error message in the viewer. The `mesh` fuzz target is in the nightly
  campaign.
- **Which PDF reading is the scanner's, decided: a differential test first.**
  The scanner takes a PDF's members (embedded files, the streams signatures run
  on, JavaScript) from exav-unpack's PDF parser and its visible text (link and
  text checks) from hayro-syntax, and the viewer draws it with pdf.js. A PDF
  the two parsers repair differently gives members from one reading and text
  from the other. A test and a fuzz target are to run each PDF through both
  and compare the objects and streams each finds; moving either reading waits
  for what they show.
- **hayro instead of pdf.js** once it supports encrypted PDFs, blend modes and
  knockout groups: the PDF path would be Rust end to end. Compare pixel output
  against pdf.js on a corpus first.
- **wpd for WebP** (halidecx/wpd, BSD-2-Clause): revisit when it is published
  on crates.io with releases; measure its safe build (no assembly) against
  `image-webp` and `dwebp` on a corpus, and its wasm size.
- **The Office engines refuse a ZIP with bytes after its end record**
  ("ZIP central directory preflight failed"), which `unzip` and most libraries
  read (0.89.3 and 0.89.11). The viewer trims such a tail itself, at the end
  exav-unpack's ZIP reader reports, until the engines read it; a report to
  @silurus/ooxml is written and not filed yet.
- **Pictures of Word pages and slides past 16 million pixels**: the engines
  draw a whole page at most that large (they return a smaller bitmap without
  saying so) and cannot draw a part of one, so a small region of a page is cut
  from a drawing of the whole page and refused as too large past the limit.
  A request to the engines for a sub-rectangle (or a tile size) would lift it.
- **Pictures of an Office document share the viewer's copy**: a second copy of
  the document is parsed for the pictures. `fromDocument`, `fromPresentation`
  and `fromWorkbook` borrow one (a borrowed workbook draws nothing until a sheet
  is gone to); a CSV's pictures are drawn from the XLSX exav-render makes of
  it, which the screen opens too, so the CSV is parsed twice by the engine
  only. Sharing would spare the second parse once the engine documents that
  start-up.
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
- **The Office converters' routing sniffers in Rust**: a compound file's
  streams, a ZIP's members and PowerPoint 2 to 4 are told by `officeKinds` of
  the sniff module (`src/sniff/office.rs`). What is left of `sniffSheet`,
  `sniffSlides` and `sniffDocs` (`ts/office/`) is the byte sniffing of text:
  markers in flat XML, HTML and SYLK, the start of an RTF file, a BIFF2 to
  BIFF4 first record. Their Rust twin is exav-render's private
  `office/visible.rs::kind`, which asks the name and reads Word first in a
  compound file. One public `detect` per converter (`sheets::Format`,
  `slides::Format`, `docs::Format`), used by the three viewer modules and by
  `visible.rs`, would remove both.
- **Audio, video and HEIC are told by name and type only**: no detection of the
  scanner's names them; each reader in exav-render could own an `is_x(head)`
  for the sniff module, as PLY, GLB and IFC do.
- **More engines saying `FormatMismatch`**: only the image engine does. PDF
  (streamed by address), archive, text and the Office pages could, where they
  hold the bytes.
- **Package checks for more formats**: `inspect` knows DOCX, XLSX, PPTX, ODT,
  ODS, ODP (parts) and PDF (signature); legacy Office, iWork, EPUB and images
  could report `invalid` or `wrong_type` the same way.
- **Head request overlap**: the host reads the first 64 KiB for the detection
  and again for the delivery of a PDF or archive by ranges; the first could be
  handed to the second.
- **Limits on a ZIP's directory in the sandboxed host**: only the frame checks
  `maxExtractedBytes`, `maxMembers` and `maxCompressionRatio`, after the file
  was delivered; the host could check the end of a file by ranges before it
  hands the file over.
- **One locator for a ZIP's directory in exav-unpack**: `directory_shift_within`,
  `prefixed_zip` and `directory_is_consistent` share the end-record candidates
  (`zip_end`) but each still walks from it to the first entry on its own.
- **Archive naming, what stays in TypeScript**: `decompressedName` (`.tar.gz`
  to `.tar`, `.gz` to nothing) is in `ts/archive/names.ts`; exav-unpack has no
  equivalent, and `Archive.open` receives no file name. `NameKind::Stream` is
  set from `stream_member`.
- **Text pipeline, what stays in TypeScript**: `sanitize`, the line splitting
  of plain text, `clip` and the limits (`ts/text/decode.ts`), and the drawing.
  `text_view` takes the already sanitized text; moving sanitizing means a rule
  shared with the module and a second pass over a 2 MiB string in the worker.
- **JSON readers**: exav-render has the glTF value-tree reader and the
  `text_view` token printer; a shared strict lexer would remove the second
  grammar (the glTF reader reads numbers more loosely and limits depth to 64).
- **CAD glyphs in Rust**: the glyph atlas, SDF, text layout, text resolution
  and fonts (about 1,150 lines of TypeScript), so that MTEXT is placed with the
  same metrics it is wrapped with (`dwg/metrics.rs`; glyphs are placed with the
  browser's advances today). Costs a font parser, a rasterizer and brotli for
  WOFF2, and a CJK fallback; list the crates against an in-tree reader first.
- **The sandboxed host and the frame's navigation**: the host could fail a
  session on a `securitypolicyviolation` of `frame-src` or `child-src` and
  ping the frame after `ready`; the navigation e2e could cover a 204 answer and
  a response that never ends.

## CI

- **Two native tests time a debug build.** `the_cpu_limit_is_per_job_not_per_worker`
  (`exav/tests/daemon_client.rs`) gives a scan of 8 MiB of random bytes
  `--max-scan-secs 1`, and its first job passed it once under a full
  `make test-native` beside a fuzzing campaign. The DWG
  `a_long_paragraph_of_several_runs_is_wrapped_in_linear_time` asserts 500 ms:
  130 to 200 ms alone, 531 ms once under a full `make test-native`.
- **`markdown.test.ts` "bounds the work and the page for long table" is near
  its time.** 2.3 s alone on a busy arm64 host, of the 3 s it asserts and the
  5 s test timeout, which it passed under a full `make test-viewer` beside a
  fuzzing campaign.
- **The frame host's tests wait set times**: `ts/frame/host.test.ts` waits
  a fixed `tick(n)` before 36 expectations on steps that run in a worker. One
  failed under the full suite's load once the detection took one more
  asynchronous step, and now waits for its answer (`vi.waitFor`); the others
  are to follow.
- **Delete the viewer e2e diagnostics** (`screenshot: "only-on-failure"` in
  `crates/exav-viewer/playwright.config.ts` and the `viewer-e2e-results`
  upload step in `.github/workflows/ci.yml`) once the three PDF tests that
  fail only on the GitHub runner are understood. The zoom test of
  `demo.spec.ts` failed there twice: it measured the page before the sections
  rail opened, when the outline came late, and waits for the rail now, as the
  drag test does (both failed with the outline delayed 3 s, and pass).
- **The release profiles in the binary packages' own manifests**, once cargo
  either stops warning about a profile in a workspace member or copies the
  workspace's profiles into the published package (cargo issue #8264).
  Until then `scripts/release.sh` adds them to the five packages with a
  binary at publish time, so those are published with `--allow-dirty` and
  their `.cargo_vcs_info.json` says `"dirty": true`.
- **Two manifest warnings of cargo 1.100**: `workspace.package.categories` is
  inherited by no package, and exav's `homepage` is the same URL as its
  `documentation`.

## Robustness

- **Limits per format.** A count limit could take one value for all formats
  plus overrides by format name, in the `--partial-as` syntax:
  `--max-members 10000,ntfs=1000000`. A volume of a million files and a ZIP
  of a million members are not the same risk, and one value has to fit both.
  Candidates: `--max-members`, `--max-object-bytes`, `--max-extracted-bytes`.
  A format name exav does not know is refused, as `--partial-as` refuses an
  unknown category. The names would be those of `formats/registry.json`.
- **The last byte of a damaged RAR5 block can differ from unrar's.** In one
  fuzz mutant exav and unrar write the same 38,009 bytes of a member but the
  last: that symbol straddles the end of its block and is decoded partly from
  bits past it, which exav reads as zeros. What unrar reads there is not
  known yet.
- **An LZMA stream cut short gives less than `xz -dc` outside ZIP and 7z.**
  `LzmaStream`, the decoder `lzma-rust2` offers without I/O, does not decode
  the symbols of the last bytes it was given (up to hundreds of bytes of text).
  ZIP and 7z LZMA members are read with `LzmaReader` and its deferred errors
  (`lzma::member_reader`), which gives them, a few bytes more than `xz -dc`.
  A `.lzma` file cut short is still read with `SansIo` and reported as not
  fully examined; lzip, EGG, NSIS, Inno, EROFS, squashfs, SWF and UPX streams
  still lose those bytes at a cut. Moving them to the deferred reader would
  give them.
- **A ZIP read without its central directory takes a member's short stream
  for a cut.** A member found by its local header whose data runs to the end
  of the file and whose decoder runs out of input there is taken as cut by the
  end of the file, so it passes `exav-unpack -t` with what decoded, nothing
  for a PPMd stream of fewer than 4 bytes (7-Zip: data error; with a central
  directory exav says "PPMd stream truncated"). Nothing is hidden from the
  scan, which scans what is there. The local sizes cannot be trusted as the
  central directory's are, which is why the rule exists; telling the two
  apart is left.
- **An XDP's chunk in a CDATA section, or with a comment in it, is not
  decoded.** The chunk is read by a byte scan that resolves character
  references; an XML reader also reads a CDATA section's text and drops
  comments. The XDP is `UNSCANNABLE` then. The same scan reads only UTF-8
  (an XDP in UTF-16 is not typed XDP), finds `<chunk>` without a namespace
  prefix, and copies a chunk's text before it checks the budget (bounded by
  the input).
- **The buffer entry points do not apply `max_scan_size` or the object
  limit.** `analyze` and `analyze_all_with_outcome` scan a slice of any
  length whole, where `scan_seekable` reports the same bytes over
  `--max-input-bytes` or reads them through the block cache; the doc of
  `ScanOptions::max_scan_size` says otherwise. The CLI and the daemon use the
  seekable functions; a library caller of `analyze` gets the other answer.
- **At the depth limit, what a bytecode unpacker made ends its object's
  scan.** `scan_unpacked` returns the depth limit at once, and the checks
  after it (carving, DLP, phishing, Authenticode, TLSH, the import hash) do not
  run on that object; the payload paths keep such a limit aside and go on.
- **The clamd listener, from a review before 0.0.3** (none is a clean reply
  for a file that was not scanned):
  - Past `MAX_DRAIN_BYTES` the reply's `file size` is what was read, not the
    stream's size.
  - `CONTSCAN` passes over symbolic links, FIFOs, sockets and devices with no
    line; a root path of that kind answers `OK`.
  - A walked file whose name is not UTF-8 is opened by its lossy name, which
    fails (`ERROR`).
  - `ALLMATCHSCAN` of a directory does not join multi-volume sets, which
    `CONTSCAN` does.
  - Some errors close the connection with no reply line (a command that is not
    UTF-8 or too long, an I/O error of an `INSTREAM` spill).
  - Descriptors passed with `SCM_RIGHTS` are kept until the connection ends,
    with no cap.
  - `CONTSCAN` replies are written once the walk ends: in the pool, the job's
    alarm loses the detections already made.
  - The stream verbs have no `catch_unwind` where `SCAN` and `FILDES` do.
- **`--max-hole-bytes` defaults to the matcher budget or below.** The holes
  of sparse files in an image are handed over as zeros up to 64G across the
  image, far past `--max-matcher-bytes` (10G), and making them costs time
  whatever the image's own size. Decided: the default goes down, its number
  from a measure of what real sparse images need (VM disks, the corpus), so
  a real one is still read whole. The fuzz targets of images now set a small
  one, as their other budgets are.
- **A self-extractor's stub is not read as its packer.** An executable typed
  as a self-extractor is read as its archive, and its UPX or packer reading
  does not run. Typing it as the packer instead (the scanner then carves the
  archive) was tried for 0.0.3 and gave false partials on installers whose
  stub exav does not unpack or only looks packed, and lost the archive of a
  large one and of the walks that carve nothing. A second reading of the stub,
  in the scanner, keeping only a detection, is what is left.
- **A container that ends in a limit or a stop drops the reasons kept
  before it.** `walk_members` reads the reasons only when the walk completed,
  so an encrypted member followed by a limit is `LIMITS-EXCEEDED`, not
  `PASSWORD-PROTECTED`, against the precedence the reasons fold by.
- **`exav-unpack -r` says nothing of a container member that decoded only in
  part and was opened.** Its members are extracted and the exit status does
  not change; exav-grep reports the same node (`Grep::leave`).
- **Two charges of the scan budget too many.** A member read in place that is
  its whole container is charged and then declined (`intake.rs`), and a part
  of a set that did not join is charged when read and again when visited.
  Either can only bring a limit sooner.
- **`Cx::derived` returns before the reason of a capped kind when nothing was
  found.** No caller passes such a kind today (the scanner reads the base64
  kinds itself).
- **`ScanOptions::structured_cc_count` or `structured_ssn_count` at
  `Some(0)` makes every text a detection**, as `count >= 0` always holds. The
  CLI takes 1 or more (`--dlp-credit-cards`, `--dlp-ssns`); the library does
  not check.
- **`read_member` skips a member whose bytes are its container's.** A
  `Container:`-scoped signature cannot fire on that copy. Contrived, and the
  copy is scanned as the container.
- **Limits set from a `u64` use `as usize` in the volume-set functions.** On
  wasm32 a limit above 4 GiB wraps to a small one, which fails closed
  (`Unscannable`). `usize::try_from` with a saturating fallback would say what
  is meant.
- **Word's `{\rt` as RTF.** exav types RTF by `{\rtf` at offset 0 only; whether
  Word opens `{\rt` and what follows is untested.
- **The saturation sweep leaves JPEG XL out**: exav-render's tests build the
  published zenjxl-decoder 0.3.10, which sizes a section's buffer by the length
  the file declares (a gigabyte for one header). The viewer's copy has
  upstream's fix (`vendor/zenjxl-decoder/EXAV.md`), as upstream's main branch
  does; the sweep can take JPEG XL once the workspace builds a release with it.
- **A Prometheus and HTTP metrics endpoint.** The daemon has no metrics
  endpoint, only the clamd `STATS` command. The counters behind it are shared
  by the processes of the pool since the health listener was added, so the
  endpoint is the small part left: `--listen-health http://host:port` serving
  `GET /metrics` in the Prometheus text format and `GET /healthz` from the
  health child, so Kubernetes has a native probe and Prometheus a scrape
  target without touching the scan path.
- **`make stack-frames` in CI.** The audit of release frames runs by hand. It
  needs a release build of `exav` and of the `exav-render` nesting test (about
  two minutes), which the `test` job does not otherwise make; a job of its own
  after `msrv` would run it on every push.
- **Nesting sweeps for the formats with no fixture or no tool here.** The
  `nesting` suites build their documents by hand or with `zip`, `7z`, `tar`,
  `cpio`, `ar`, `mksquashfs`, `genisoimage`, `gcab`, `gzip`, `bzip2`, `xz`,
  `zstd` and `lz4`. A container inside itself is not yet built for LHA, ARJ,
  ZOO, ACE, ALZ, EGG, TNEF, OLE, CHM, DMG, the virtual disks, WIM, NSIS, Inno
  and the packers; the 26-layer chain of `matryoshka` crosses each once.
  `scripts/stack-frames.py --all --min-kib 8` lists the frames that would
  matter for them.
- **Fuzzing the viewer's TypeScript**: property tests (fast-check, MIT, in
  vitest) for the two places a hostile document's output meets code the viewer
  trusts: the host's validation of the messages a sandboxed frame sends
  (`ts/frame/index.ts`, `protocol.ts`: every message shape, sizes, ports). The
  Rust side is fuzzed (docs/FUZZING.md); this half is not. The CSV reader is
  Rust now (`sheets::convert_csv`) and wants a fuzz target of its own (random
  bytes and limits).
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
- **Several listeners on one protocol, decided.** Two `--listen` addresses
  on one protocol are refused today (`endpoint::listeners_of`: "both serve
  icap; give one"), where clamd serves a Unix socket and TCP at once
  (`LocalSocket` with `TCPSocket`, `TCPAddr` repeated). Every address is to be
  served, each with the settings on its own address: in the worker pool each
  worker waits on all the clamd sockets, and ICAP gets one child per address.
- **ICAP `lingering_close`** reads up to 4 MiB with the per-read timeout after
  a connection ends by idle timeout.
- **Pool workers end on any accept error that is not a lost race.** The worker
  logs `worker accept error`, exits and is respawned, so an out-of-descriptors
  error costs a fork where the in-process listener pauses and retries.
- **The accept error list is Unix only.** On Windows an out-of-descriptors
  error (`WSAEMFILE`, `WSAENOBUFS`) still ends the in-process clamd listener.
- **The HTTP client resolves a host on a thread of its own** (ureq, for its
  timeout). One stuck in `getaddrinfo` past the 300 s timeout of the initial
  `--auto-update` fetch would still be running when the updater child and the
  workers are forked.
- **Names an ELF or .NET file refers to many times are copied once per
  reference.** The PE import and export tables are done: a name is read as a
  range of at most 512 bytes (a library's 256; an export's 1,024), copied
  at most 256 bytes (the import hash) or 512 (the YARA module) per function,
  charged to `--max-object-bytes`. The `elf` and `dotnet` modules need the
  same limits on name length and table entries (settings, an incomplete scan
  when hit), or ranges into the object.
- **PE import table, differences kept**: a descriptor with an unreadable
  library name or tables inside its directory marks the scan `UNSCANNABLE`
  where clamscan makes no hash and libyara skips it; delay-load imports are not
  read by the `pe` module; section hashes and entropy read a section from its
  pointer as the header gives it, the import and export tables round it down to
  0x200; for an RVA that two sections hold, exav's reading for the `.imp` hash
  maps it through the first and clamscan through the later one.
- **The PE dumped by the x86 emulator** (`runtime-emulated-allocation-*`) often
  has an import table that does not parse; with `.imp`, a YARA `pe` rule or
  `--detect exav-heuristics` the scan ends `UNSCANNABLE` on it. Rebuild the
  import table in the dump. The dump of the Petite files has a stray entry 0x40
  in an address table, which the header mapping reads as a name in the DOS
  header.
- **An MZ file with a PE signature whose headers do not parse** is read as not
  a PE (reported by `--detect broken` only).
- **YARA's `dotnet` offsets against yara-x 1.23**: yara-x gives
  `dotnet.field_offsets` and `resources[].offset` as file offsets converted
  from their RVAs; exav gives the values as stored. The module's tests compare
  with yara-x 1.19.0, not yet checked for the same.
- **YARA's step budget counts nodes, not the bytes a node reads**: `math.*` and
  `hash.*` over a range, and string operators on module strings, are one step
  each. Digests are not cached per scan, so N rules with
  `hash.md5(0, filesize)` read the object N times.
- **A YARA pattern past a million matches** makes the scan `LIMITS-EXCEEDED`
  unless a rule matched, where yara-x keeps the first million and answers.
  One a rule uses at one offset only is looked for there alone, as yara-x
  does; one used at two offsets (`$a at 0 or $a at 2`), counted or
  unanchored, still reaches it (`{ 00 00 }` in a file of zeros). The reason
  does not name the rule or the pattern. Decided for the next cycle: the
  verdict stays, and the reason names the rule and the pattern ("YARA rule R:
  pattern $v1 has more than 1,000,000 matches"). yara-x also anchors a
  pattern used bare beside an `$a at K` that the whole condition needs
  (`$a and $a at 0`, `all of them and $a at 0`), and takes any constant
  expression as the offset; exav anchors only when every use names the
  offset as a number.
- **`--max-regex-steps` is a count of steps, not time**: on 6,921 corpus
  objects with the full ClamAV database its default moves none to `PARTIAL`
  (462 s against 535 s with `off`). Left: whether a signature whose prefilter
  passes on a 100 MB object is worth a start-position skip (the VM makes one
  backtrack per offset).
- **The JavaScript normaliser renames every identifier, from `n001`**; clamscan
  1.4.3's renames the declared ones (`var` names, function names and
  parameters), from `n000`, and keeps the others as written. A signature written
  against clamscan's normalised script that names one does not match exav's
  view.
- **Constants that are not limits yet**: the header detection window
  (`DETECT_HEAD`, 4 MiB + 1 KiB) and `RAR5_MAX_HEADER`; NTFS's most runs read
  from one run list (65,536), references followed in an attribute list
  (65,536) and runs of one file (1,048,576), which are reported when reached;
  exav-unpack's `vdisk::CACHE_BYTES` and `udif::RUN_CACHE_BYTES` (32 MiB each),
  which could follow `--object-cache-bytes`, `source::BLOCK_SIZE`
  (64 KiB), the library default, which differs from the scanner's 1 MiB, and
  the JavaScript normaliser's output (`jsnorm::MAX_OUTPUT`, 32 MiB), past
  which the scan of a page or script is marked incomplete (a plain 40 MB HTML
  page is PARTIAL). Each wants a field, a flag and `off`.
- **UDF and ISO at the member limit** end the walk without visiting the members
  they had enumerated first.
- **Email past `--max-object-bytes`: attached messages are one part.** A
  `message/rfc822` part is handed over as its raw bytes and reported, not taken
  apart as it is in memory (`email_stream.rs` `by_parts`); the scanner takes it
  apart when it types the bytes as mail. Taking it apart in the reader means
  reading its headers as the next header block, and a depth parameter in place
  of the 64 of the in-memory reader.
- **Email past `--max-object-bytes`: a boundary the streamed reader reads
  differently is reported, not read.** `param()` splits at every `;` and does
  not read RFC 2231 forms, and a delimiter must start a line and equal the
  boundary where the parser in memory takes `--boundary` anywhere. Such a
  message ends `UNSCANNABLE`.
- **Messages inside other files**: ClamAV reads the body of a message that has
  no MIME headers as a message of its own, from its first header-like line;
  exav reads a body as text, and a message inside it when it holds a pair of
  header lines. ClamAV also reads a file's first block of header-like lines as
  the message headers whatever comes later, and the text after the closing
  boundary of a multipart when its boundary opens again.
- **Mail inside unknown binary files**: exav reads a message from inside any
  binary file it has no type for (except PNG, GIF, JPEG, TIFF, BMP); ClamAV
  does not for the types it knows (MP3, Ogg, RIFF, SQLite, PostScript, disk
  images, ...).
- **Mail typed by its first line**: a text file of 256 MiB or more that starts
  with a mail magic, or holds a pair of header lines at a line start, and has
  no empty line after it, is `LIMITS-EXCEEDED` ("a header block is over the
  buffer limit").
- **ARJ headers**: at the start of a file the main header is taken by its shape
  and the header CRC-32s are read through. An archive carved out of another
  file keeps the CRC-32 of its main header and file type 2, so one with a wrong
  CRC-32 behind other bytes is not opened, where ClamAV would open it. A header
  size field a few bytes off, which ClamAV reads past, is not.
- **Codec reach under `--clamav-compat`**: ZIP methods 1, 2, 14, 95, 98, 7z
  BZip2, Deflate and Delta, EGG LZMA, AZO and solid, DMG xz and lzfse, UDF-only
  ISO, RAR5 carving and begin-base64 uuencode are opened under compat and not by
  clamscan; a per-codec switch has to live in the readers.
- **7z**: the first CRC'd member of an encrypted folder is decoded twice (to
  choose the password, then to scan).
- **RAR**: a truncated last volume of a RAR5 set makes the set unjoinable,
  where joining the volumes before it would scan what they hold.
- **Limits that still end a walk from the outside**: `Member::into_bytes` and
  `read_entry` (what `extract` and `@exav/unpack-wasm` read a member with)
  end the walk at a member over the object limit; the EROFS physical cluster
  over the buffer limit and a 7z PPMd input over it are found once the member's
  stream is read, so they reach the visitor as a failed read (damage), not as a
  limit.
- **Reader reasons, what is left**: `MemberMeta::reason_kind` is set for the
  unsupported methods and the size limits; the other reasons (a missing
  decoder, a CRC mismatch) read as damage. About 60 reader texts say
  "scanned", and `Budget`'s "scanned bytes > N" too, where they mean examined.
- **exav-grep's constants**: `READ`, `BINARY_PROBE`, `KIND_PROBE` and the
  stream head could be settings; `looks_binary` repeats 8192.
- **A member decoded as it is read and longer than 4 MiB + 1 KiB** cannot be
  told to be a container by its end (a VHD footer, a prefixed ZIP): spill it,
  or drop the two checks for streams.
- **`ByteSpan` for the scanner**: `rejoin_byte_split` still holds the parts of
  a byte-split set in memory.
- **Members the scanner skips that the readers emit**: an MBR entry from sector
  0 and a Mach-O slice from offset 0 are the container itself; skip them in the
  readers.
- **Buffers that double**: the `zip` crate's Reduce decoder (ZIP methods 2 to
  5) drops what it decoded in a read that ends in an error (report it
  upstream, or read it in small pieces, so the bytes before the damage are
  scanned); exav-render reads office parts, escher blobs, OLE streams and TIFF
  strips with `take(max).read_to_end`, which doubles the buffer up to twice
  the limit: use exav-unpack's stepped read.
- **`ModuleCtx::build` reads a streamed object whole** for `import "pe"` even
  when it is not a PE.
- **Numbers table merges**: `push_merge` is quadratic in the merges, and
  `merge_owners` is neither capped nor charged.
- **ODF style resolution**: `Props::get` is a linear search, duplicate
  attributes are kept, and a style that names itself as its parent is followed
  33 times. Stop at a repeated name, drop duplicates, and cache the resolved
  styles.
- **ICO `decode_largest`** may decode up to 512 entries, each copying the rest
  of the file.
- **ODT and Pages list styles** hold nine levels per style that are not
  charged to the memory limit.

The arithmetic audit (kept outside the repository; its row names are used
below) found about a hundred sites where a header's number is added
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
  (vhd, vmdk, qcow2, vhdx, vdisk, volumes, ntfs, wim without its two codecs, the
  filesystem readers, lzo, partition, iso, dmg, udif, udf); the codecs `wim/lzx.rs` and `wim::xpress`
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
- **fancy-regex back to a dependency**: 0.20.2 has the two pull requests the
  vendored copy was taken for, two of exav's own fixes and the seven later
  upstream fixes the copy now carries (README of `src/fancy_regex/`). What is
  left is the saturating size analysis, whose test panics inside 0.20.x, the
  optimizer guard for `(?:a+b?a*)+` (still unsound in 0.20.2), and the work
  accounting of `--max-regex-steps`, which would have to live outside the
  engine. Two upstream reports are written and not filed. Then follow the
  README's steps back; that also drops `matches`, `quickcheck` and the direct
  `bit-set`.
- **fancy-regex: a variable lookbehind with a hard part does not build**
  (a single high byte such as `\xe9`, a back reference inside it): the scan is
  marked incomplete, not clean. The hard variable lookbehind of 0.20 (upstream
  PR 286, then 331) would run them; a re-vendor of 0.20.2 brings both.
- **`image` brings `moxcms` and `pxfm`** (about 570 `unsafe` keywords in the
  default tree) for ICC transforms exav never calls; no feature turns them off
  and the pin is ClamAV's version. Options: vendor the containers and codecs
  `exav-render` uses from `image` as was done for JPEG and TIFF, or ask
  upstream for a feature. 0.25.10 still requires moxcms 0.8 with its default
  (SIMD) features. Others asked already (image issues 2617 and 2626, open); a
  maintainer answered that colour management cannot be made optional.
- **`quick-error` and `bitstream-io` stay**: `image-webp` and `zip`'s
  `legacy-zip` bring them whatever exav's own code does.
- **`encoding_rs` stays at 0.8.40 or later, with `simdutf8`** (135 `unsafe`
  keywords): 0.8.40 to 0.8.44 fix decoder buffer boundaries and a size
  computation panic on 32-bit targets, which a pin back to 0.8.35 would lose.
- **`ppmd8` back to `ppmd-rust`**, at the next early pass: its return
  condition holds (1.5.2 is `forbid(unsafe_code)`). Compared on the 13
  method-98 members of the corpus (identical) and on 20,000 mutated streams
  (no panic on either side, no stream both decode differently). What the
  swap must keep: `Ppmd8Decoder` reads the end of its input as the end of the
  data, where the copy reports a stream cut short, so a member of unknown size
  cut short would read as complete; and it refuses a stream of fewer than 4
  bytes at its start. 1.5.0 also added `Ppmd7aDecoder`,
  with the carry-less range coder RAR 3 and 4 use: with RAR's escape codes on
  top it decodes 1,967 PPMd members of 55 real RAR 4 archives to their CRC. It
  cannot start its range decoder again on new input with the model kept,
  which a PPMd block without the reset flag needs (a solid member, PPMd after
  LZ). To be asked upstream; with it the `ppmd7` copy can go.
- **`html5gum` 0.9.0**: no changelog; diff the tokens over the text suites
  before following the pin.
- **`yara-x-parser` costs 12 crates** (`rowan`, `logos`, `hashbrown` 0.14,
  `rustc-hash` 1.x, `bstr`...; 416 `unsafe` keywords) for a parser whose AST
  the in-tree engine then lowers. An in-tree YARA parser is the only way out
  and a large one.
- **`chrono` is unmaintained (RUSTSEC-2026-0543, ignored in `deny.toml`).**
  `delharc` 0.8.0 needs it for LHA timestamps, with no feature to leave it
  out, and exav-unpack's CLI uses it for local times. Its maintainer points to
  `jiff`; the CLI can move, `delharc` needs an upstream change or a fork.
- **`paste` is a `deny.toml` ignore**: it is unmaintained, build-time
  only, and comes from `zenjxl-decoder-simd`'s `simd_function!`, which expands
  to `paste::paste!` in the decoder. Dropping it means copying that 9,000-line
  crate (and rewriting the macro) for no change in the module; not worth it
  until the macro changes upstream. It has: zenjxl-decoder's main branch uses
  `pastey` instead (commit 803d6ab, for its unreleased 0.4.0), so the ignore
  goes with that release.
- **`mail-parser` stays on 0.11.** 1.0 is a rewrite that needs Rust 1.98 and
  adds SIMD `unsafe`, `encodify` and a hard `simdutf8` dependency.
- **`lzma-rust2` 0.23 is still in the tree for tests only**, through
  `sevenz-rust2` 0.24; exav itself is on 0.25.
- **`zip` is required below 9.1** (register pin): from 9.1.0 it depends on
  `getrandom` whatever its features (the salts of the AES archives it
  writes), and from 9.4.2 on `zeroize` and `constant_time_eq`. Next cycle:
  drop the crate, with exav-unpack's PKZIP 1.x methods (Shrink, Reduce,
  Implode) and the converters' package reading and writing on exav's own ZIP
  code.
