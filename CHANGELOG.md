# Changelog

Notable changes per release. Dates are release dates; the format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) loosely, and versions
follow [semantic versioning](https://semver.org/).

## [Unreleased]

## [0.0.3] - 2026-10-29

Many more formats and installers read, in place and in bounded memory at any
size; QR codes and a visible-text layer; a much larger viewer; and review
rounds that closed the cases where exav read a file differently from the
program that opens it.

### Highlights

- **More formats, read where they lie.** Virtual disks (VHD, VHDX, QCOW2,
  VMDK), filesystems (exFAT, SquashFS, cramfs, romfs, EROFS, HFS+, APFS, with
  ext, FAT and NTFS), 7z, WIM, xar and tar are read from a seekable source
  without holding them. The registry lists 126 formats.
- **Installers opened**: Inno Setup 5.1.5 to 6.4.0, InstallShield cabinets
  and setup executables (2009 to 2011, 2015 and later), AppleSingle and
  AppleDouble, CryptFF.
- **Large files in bounded memory.** RAR archives of any size are decoded as
  they are read, stored members are scanned where they lie, and a large PE is
  parsed from its image. A file past `--max-object-bytes` inside a container
  is scanned in full; it was refused or `LIMITS-EXCEEDED`.
- **What a reader sees.** Markdown, HTML, Office, OpenDocument, AutoCAD and
  IFC files are also scanned as their visible text, with their links
  (`visible-text`, on by default). PDF and legacy Office text are opt-in.
  `exav-grep --text` searches it.
- **QR codes** (`--qr`, off by default): the codes in images, documents and
  archives are matched as text and their links checked by
  `--detect phishing`. `exav-qr` prints them.
- **Read as the program that opens it.** ZIP, PDF, mail, PE, Office packages
  and a dozen other formats were read differently by exav in some cases; they
  now agree, and more of what exav cannot read is reported instead of
  answered `OK`.
- **Office documents converted in safe Rust** (`exav-render`, opt-in
  features): legacy, OpenDocument and Apple spreadsheets, presentations and
  documents to XLSX, PPTX and DOCX, which the viewer shows.
- **Smaller, faster binaries**: exav 25.2 MB to 16.7 MB, a corpus scan about
  8% faster. `cargo install` builds with the release profile (about 3 GiB of
  memory at its peak); `--profile fast-build` is the shorter build.
- **The viewer** opens many more files (camera RAW, JPEG XL, SVG, 3D models,
  older Office, more archives), tells a file by its bytes with exav's own
  detection, can be driven by the host's own UI, and speaks German, Spanish
  and Dutch.

### Breaking changes

- Rust 1.95 or later (it was 1.92); every crate is edition 2024.
- Refused now: a `.cvd` whose header md5 does not match or that is cut short,
  a source with no end (`exav /dev/zero`, it was `OK`), a YARA rule nested
  more than 10 parentheses deep (12 before), and an HTTP answer whose
  `Content-Range` is not the one asked for.
- A one-shot scan that `--max-scan-secs` ends keeps the exit status of what it
  found (`1`, then `2`), else follows `--partial-as`; it was always `3`.
- One memory setting: `ScanOptions::deep_analysis_max` is removed, and the
  largest object held is `--max-object-bytes` (`limits.max_buffer_bytes`).
  `--clamav-compat` uses the default 256 MiB (it held 400 MiB). The block
  cache is 32 MiB in 1 MiB blocks (8 MiB in 64 KiB).
- **Import hashes**: an `.imp` signature's size is the length of the string
  hashed, as `clamscan --debug` prints it, and `imphash:` lines use pefile's
  hash. A signature written the old way stops matching. Saved databases are
  format 5: rebuild one made by 0.0.2.
- The seven `--icap-*` flags are options of the ICAP address now
  (`?idle-secs=`, `?max-requests=`, `?max-header-bytes=`, `?preview-bytes=`,
  `?transfer-preview=`, `?options-ttl-secs=`, `?infection-header=`); the old
  flags stop the run with a message.
- Libraries: exav-unpack reads ext, FAT, HFS+ and APFS itself (member names no
  longer begin with `/`); exav-render's office features depend on
  exav-unpack, whose `ole` feature no longer pulls `cfb`. exav-unpack's
  `Prescan` and `detect_prescanned` are removed: detection no longer searches
  a whole object, so it has no search to share with a caller's read.
- Viewer: CSS prefix `exav-viewer-` (it was `exv-`), frame protocol 7 (it
  was 3), `controllers.viewport` computed only while used. `Detector.sniff`
  and `detectBytes` return promises; `SIGNATURES`, `sniff`,
  `FormatMatcher.signatures`, `confirmSniff` and `DetectionTable.signatures`
  are removed, and `archive()` and `@exav/unpack-wasm` take no
  `maxCompressionRatio`. It needs `@exav/unpack-wasm` 0.0.3 and `pdfjs-dist`
  6.4.299 or later.

### Added

- Limits, each with its `EXAV_*` variable and `off`: `--max-regex-steps` (a
  work budget for PCRE subsignatures and YARA regexps), `--max-matcher-steps`
  (body signatures with wildcards and gaps), `--max-compression-ratio` (also
  in exav-grep and exav-unpack), `--max-hole-bytes` (the holes of sparse
  files), `--max-carved-executables`, `--max-carved-archives`,
  `--max-base64-payloads`, `--max-base64-runs` and `--max-page-assets` (they
  were fixed), the `--max-qr-*` bounds, `--max-extracted-bytes` (back),
  `--max-bytecode-memory-bytes`, `--object-cache-bytes`,
  `--object-cache-block-bytes` and `--http-request-bytes`.
- Daemon: `--listen-health ADDR`, a listener that answers while the workers
  are busy, and a `STATS` that reports the whole pool. Each listener's
  address takes `?idle-secs=` (120; reads waited a fixed 60 seconds, writes
  forever), `?request-secs=` (600), `?session-secs=` and `?reply-secs=`.
- HTTP: `--http-timeout-secs`, `--http-max-redirects`,
  `--http-redirect-private`, `--http-spill`. A server that does not answer
  range requests has the object downloaded whole, up to `--max-input-bytes`.
- Scanning: `Target:3` and `Target:7` signatures match the scripts of an HTML
  page, as in clamscan; a mail message inside a text or binary file is read,
  as ClamAV reads one; an ARJ archive inside another file is carved;
  `Heuristics.PDF.ObfuscatedNameObject` applies inside PDF object streams;
  `tlsh:` lines are matched against an installer's executable; `-v` shows
  `pe-imphash`.
- `exav-qr FILE...` (`cargo install exav-grep --features qr`) prints the QR
  codes in images and in what holds them.
- exav-unpack `-r` opens the archives inside an archive; exav-unpack and
  exav-grep take exav's cache and spill settings, read its `EXAV_*`
  variables and take `off` for no limit.
- Formats: the `ishieldcab`, `applesingle` and `ishieldmsi` features; LZFSE,
  LZVN and InstallShield Z in-tree; camera RAW, DDS, ICO, PLY, OBJ, glTF and
  more TIFF variants.
- Libraries: `exav_unpack::tree` (`Walker`, `Visitor`, `Typing`,
  `type_object`), the one walk of nested containers exav, exav-grep,
  `exav-unpack -r` and the wasm share; `MemberMeta::reason_kind`,
  `Budget::set_rasters`.
- Viewer: detection by exav in a worker (`sniffBytes`, `sniffTimeoutMs`,
  `FormatMismatch`); a ZIP's directory checked before it is opened
  (`maxExtractedBytes`, `maxMembers`, `maxCompressionRatio`),
  `maxArchiveEntries` and `maxEntities`; highlights on a PDF's pages and on a
  quote found in a text (`ViewerFile.highlights`, `focusHighlight`,
  `goToHighlight`); `linkQuietMs`; a sandboxed frame published for some
  formats only (`formats`, `--format`); an external converter hook; 233
  freely licensed example files for the demo.
- exav.org/formats/: every format in one table, with what the scanner, the
  extractor and the viewer do with it, and the extractor's module and crates
  for it. `scripts/bench-speed.sh` compares speed with `clamscan`.

### Changed

- **Limits leave a part out and go on.** A member over the compression ratio
  or `--max-object-bytes` is left out, the members after it are scanned, and
  the container is `LIMITS-EXCEEDED` unless something is found. The ratio is
  asked only of a member that decodes past `--max-object-bytes` (it was
  4 MiB).
- A member left out for its size is `LIMITS-EXCEEDED`, not `UNSCANNABLE`; a
  file a reader cannot parse is `UNSCANNABLE`, not `LIMITS-EXCEEDED`; a panic
  in a member is reported there and the rest of its container is scanned.
- A large file, a spilled member and an HTTP input are read once for all the
  checks, where each needed a read of its own: 4.1x the size down to 1.45x
  with YARA rules, 211 HTTP requests down to 110. An object already scanned
  clean in the same place is scanned once per scan.
- `--clamav-compat` opens only what clamscan 1.4.3 opens (ZOO, StuffIt, ACE,
  WIM, the filesystem images and others stay closed; DMG is opened).
- Files are typed as ClamAV types them: one that starts with a mail header is
  a message, before HTML; an ARJ archive is told by its main header; a
  Markdown file that is not UTF-8 is windows-1252.
- `--max-unpack-depth 0` opens no container, in every CLI (exav refused it;
  the others reported every archive unreadable).
- exav-grep walks as the scanner does (depth limit, members read where they
  lie, split files, appended ZIPs) and holds a file up to `--max-object-bytes`
  (it was 16 MiB). exav-unpack's `--max-memory` and `--max-size` are
  `--max-object-bytes` and `--max-extracted-bytes`; the old names still work.
- Names in reasons and locations have control and bidirectional characters
  replaced by `_` and are cut at 200 characters, in every CLI.
- `--build-db` counts as unsupported a logical signature whose PCRE neither
  regex engine builds.
- A daemon setting given only by its `EXAV_*` variable to a run without that
  listener is ignored with a warning.
- The Docker image runs as a named user (65532), read-only, with every
  capability dropped and `no-new-privileges`, on Alpine 3.23; the examples
  publish the ports on localhost only.
- YARA: `pe.number_of_exports` counts the exports by ordinal alone too, as
  yara-x does.
- Dependencies at their latest versions, except the image decoders pinned to
  libclamav 1.5.4's and `zip` below 9.1. Seven crates fewer, and the QR reader
  is rqrr 0.11.0 vendored as `exav-qr` with `forbid(unsafe_code)`.
  `fuzzy_img` JPEGs are decoded by zune-jpeg 0.5.15: the hashes differ from
  libclamav's 0.5.8 only for baseline JPEGs with a scan for each component.
- Viewer: text, CSV, TSV and a ZIP's directory are read by exav's readers in
  a worker; a CSV past 16,384 columns or 1,048,576 rows is refused.

### Fixed

- **Read as the program that opens it.** ZIP, PDF and its object streams,
  mail (folded and long boundaries, attached messages, base64 parts), ISO and
  UDF, `ar`, `cpio`, bzip2, xz, CAB, NSIS, PowerPoint, NTFS, MBR logical
  partitions, 7z and ARJ are read as their own tools read them, where exav
  differed in some cases.
- **PE files are read as Windows, clamscan and libyara read them**: the YARA
  `pe` module gives libyara's values on all 952 PEs of a corpus (268
  differed), and an `.imp` signature from clamscan's import hash matches all
  853 PE32 files that have one (708 before).
- **An Office package is told by its ZIP directory, not its name**: a DOCX,
  XLSX or PPTX named `.zip` gets its text view and link checks, and its
  `Container:` type is OOXML, as clamscan types it.
- **A string a format is found by** (a PDF header, an XDP tag, the BinHex,
  AutoIt and Script Encoder markers) no longer takes the type of a file whose
  own header gives one. A text that names XDP's tags is no longer
  `UNSCANNABLE`, and an XDP's character references are read.
- **Detection reads a file's start, its end and the places its structure
  names, never all of it.** A Script Encoder marker, an NSIS, AutoIt or
  self-extractor payload and a UPX header are looked for in the first 4 MiB,
  or after an executable's image where the program keeps them. A large file
  of any kind holds `#@~^` by chance and was typed an encoded script, then
  `LIMITS-EXCEEDED` past `--max-object-bytes`; an archive's magic deep in an
  executable's code made it a self-extractor; exav-unpack, exav-grep and the
  viewer read all of a large file to type it.
- **No clean answer for what was not read**: a regexp stopped at
  `--max-regex-steps`, a PCRE past `--max-pcre-bytes` or one the engine cannot
  build, a RAR5 member of an unknown compression version, a split set inside
  an archive over the limit or cut, an input past 4 GiB on 32-bit targets, an
  unreadable DWG or CHM part, an email whose delimiter never comes, an Inno
  Setup installer before 5.1.5, and more.
- **A limit is not damage, and what decoded is scanned**: a 7z or SWF
  dictionary over `--max-object-bytes` is a limit (it was decoded with a
  smaller window and reported damaged); a member cut by the end of its
  archive, a RAR member whose header declares less than its stream, and what
  decoded before damage in RAR, ZIP, 7z, filesystems and CHM are scanned as
  far as they go. exav-unpack reports a cut member as an error, as tar and
  unzip do.
- **PCRE**: seven wrong answers of the backtracking engine (lookaround, back
  references, conditionals, atomic groups) are fixed.
- **Resource bounds** on executables' tables, YARA ranges and regexps, Excel,
  XAR, tar and RAR5 headers, Office conversion, nested documents, PPMd, zstd,
  JPEG XL, JBIG2, bytecode, 7z headers and XML trees; recursive readers no
  longer overflow the stack.
- Detections kept: one made before a read of the input failed (it was an
  error), one inside a compressed member that then passes
  `--max-matcher-bytes` (it was `LIMITS-EXCEEDED`), and one behind a damaged
  carved executable (it was `PARTIAL` or `OK`). `--all-matches` and
  `ALLMATCHSCAN` give YARA rules the file's name, as a scan does.
  `--detect packed` names only the packers exav tells.
- Signatures: a nibble wildcard with `::i` counted too many matches; YARA's
  `pe.exports(ordinal)` matches an export's ordinal and `math.abs` of the
  smallest integer is undefined; database lines that do not parse are
  counted as unsupported.
- YARA: a pattern a rule uses at one offset only (`not $a at 0`) is looked
  for there alone, as yara-x does. With a million matches elsewhere
  (`{ 00 00 }` in a file of zeros) the scan was `LIMITS-EXCEEDED`.
- Formats: ZOO (large LZD tables, long names), ARJ GOST 40-bit passwords,
  password-protected DWG, compound files with several documents, InstallShield
  cabinets of version 4 and older, more archive types in the base64 of
  scripts and pages; an encrypted PDF that opens with an empty password is
  no longer password-protected for a `\b` or `\f` in its strings.
- Daemon: `FILDES` scans a descriptor from its start (one left at its end was
  scanned as empty, `OK`); an `IDSESSION` is closed after a stream it did not
  read to its end, as clamd closes; the listener retries a transient accept
  failure instead of ending; with `--auto-update` in the pool the signature
  check runs in a child of its own; the Unix socket is bound in a private
  directory; `VERSIONCOMMANDS` lists `SHUTDOWN` and `QUIT` only when allowed.
- exav-unpack no longer makes symbolic links that lead out of the extraction
  directory, and `-t` no longer says "No errors detected" after an error.
- Viewer: links with a user name or password are refused; names show control
  and bidirectional characters as U+FFFD; an Office file goes to the reader
  its directory names, not its extension; a `resolve` source is signed again
  on 401 or 403 for every request; a range read is answered with a copy (the
  host's buffer was emptied); rendering fixes across TIFF, BMP, PNM, ICO, DWG,
  DXF, IFC, STL, glTF, JPEG 2000, DDS and Office files.

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
