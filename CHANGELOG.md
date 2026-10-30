# Changelog

Notable changes per release. Dates are release dates; the format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) loosely, and versions
follow [semantic versioning](https://semver.org/).

## [Unreleased]

## [0.0.3] - 2026-10-29

Many more formats read, in place and in bounded memory; a visible-text layer;
a much larger viewer; and a review round that closed the cases where exav read
a file differently from the program that opens it.

### Highlights

- **More formats, read where they lie.** Virtual disks (VHD, VHDX, QCOW2,
  VMDK), filesystems (exFAT, SquashFS, cramfs, romfs, EROFS, HFS+, APFS, with
  ext, FAT and NTFS) and 7z, WIM and xar are read from a seekable source
  without holding them. A file past `--max-object-bytes` inside one is
  scanned in full, not skipped. The registry lists 126 formats.
- **A visible-text layer** (`visible-text`, on by default, off under
  `--clamav-compat`): Markdown, HTML, Word, PowerPoint, Excel, OpenDocument and
  AutoCAD files are also scanned as the text a reader sees, for `Target:0` and
  `Target:7` signatures and `--alert-phishing`. PDF text and the text of legacy
  and flat office files (DOC, XLS, PPT, RTF, FODT and others) are opt-in
  (`visible-text-pdf`, `visible-text-office`). `exav-grep --text` searches it.
- **Office documents converted in safe Rust, in `exav-render`** (features
  `office-sheets`, `office-slides`, `office-docs`, `office`; none is a
  default): XLS, ODS, FODS, Numbers, Excel 2003 XML, HTML tables and SYLK to
  XLSX; PowerPoint 95 to 2003, ODP, FODP and Keynote to PPTX; DOC, ODT, FODT,
  RTF, Word 2003 XML and Pages to DOCX; ODG, FODG and Visio (VSDX) to PPTX.
  The viewer shows them through `xlsx()`, `pptx()` and `docx()`. Each file is
  bounded in input, memory and decompressed size, and an encrypted, oversized
  or damaged file is reported with its reason.
- **One reader per format.** The scanner and `exav-render` share the readers
  for OLE2 (`exav_unpack::cfb`), Excel decryption, RTF, BIFF and code pages.
- **Bounded memory and time.** Deterministic sweeps (`saturate`, `nesting`,
  `office_memory`) and new limits for the block cache, bytecode memory and
  archive entries; `exav-grep` searches a file of any size in bounded memory.
- **The viewer** (`@exav/viewer`) opens many more files (RAW cameras, JPEG XL,
  SVG, OBJ, PLY, glTF, more IFC, older Office, more archives), draws pages of
  documents, 3D models and drawings, can be driven by the host's own UI, and
  speaks German, Spanish and Dutch.
- **Daemon**: `--listen-health ADDR`, a listener that answers while the
  workers are busy, and a `STATS` that reports the whole pool.

### Breaking changes

- The minimum Rust version is 1.95 (it was 1.92) and every crate is edition
  2024.
- A `.cvd` whose header md5 does not match, or that is cut short, is refused.
- A source with no end (`exav /dev/zero`) is an error, not `OK`.
- A YARA rule nested more than 10 parentheses deep is refused (12 before): the
  parser's time doubles with each level.
- A one-shot scan that `--max-scan-secs` ends keeps the exit status of what it
  found (`1`, then `2`) and otherwise follows `--partial-as`; it was always `3`.
- The `Content-Range` of an HTTP answer is checked; a server that answers
  with another range or object is an error.
- `--object-cache-block-bytes` defaults to 1 MiB (it was 64 KiB, fixed).
- The viewer's CSS prefix is `exav-viewer-` (it was `exv-`), the sandboxed
  frame's protocol is version 5 (it was 3), and `controllers.viewport` is
  computed only while used.
- exav-render's office features depend on `exav-unpack`. `exav-unpack`'s `ole`
  feature no longer pulls the `cfb` crate, now a dev-dependency.
- `exav-unpack` ext, FAT, HFS+ and APFS readers are in-tree: member names no
  longer begin with `/`, and a damaged volume ends with an error after the
  files before the damage.
- Objects already scanned clean in the same place are scanned once per scan.

### Added

- Settings: `--max-extracted-bytes` (back), `--max-bytecode-memory-bytes`,
  `--object-cache-bytes`, `--object-cache-block-bytes`, `--http-request-bytes`,
  `maxArchiveEntries` and `maxEntities` in the viewer.
- Formats: LZFSE, LZVN and InstallShield Z in-tree, camera RAW, DDS, ICO and cursors, PLY, OBJ, glTF, TIFF variants (fax,
  CMYK, Zstandard, tiled, planar and more), and an external converter hook for
  the viewer.
- `scripts/bench-speed.sh`, a speed benchmark against `clamscan`.
- 243 freely licensed example files for the viewer demo.

### Changed

- Dependencies are at their latest versions, except the image decoders pinned
  to libclamav 1.5.4. Fewer dependencies and less `unsafe`: 8 crates and
  1,155 `unsafe` uses fewer in a default build.
- `fuzzy_img` JPEGs are decoded by zune-jpeg 0.5.15, not libclamav's 0.5.8: the
  hashes are the same except for baseline JPEGs with a scan for each component,
  which 0.5.8 drew flat (`8000000000000000`), and damaged files it panicked on.
- A damaged CAB or archive keeps more of what it decoded.

### Fixed

The ones that could change a verdict:

- **Files that a reader opens differently from exav are read as that reader
  reads them:** ZIP, PDF, mail, ISO and UDF, `ar`, `cpio`, bzip2, xz, CAB,
  NSIS and PowerPoint objects, and files holding a second archive. A message
  attached to an email is now scanned.
- **Base64 in scripts and pages:** more archive types are decoded, and a cap
  on the number of decoded files is reported (`LIMITS-EXCEEDED`).
- A damaged executable carved from a file no longer turns a detection behind
  it into `PARTIAL` or `OK`.
- Large files over HTTP no longer cost a request per executable candidate.
- `exav-unpack` no longer makes symbolic links that lead out of the extraction
  directory, and no longer panics on a closed pipe. `VERSIONCOMMANDS` no longer
  lists `SHUTDOWN` and `QUIT` on a daemon that refuses them.
- Resource bounds: nested documents, YARA rules, Visio formulas, PPMd, zstd,
  JPEG XL, JBIG2, bytecode, 7z headers, RAR key derivation, and the memory of
  XML trees, converters and drawings are bounded. Several recursive readers
  no longer overflow the stack.
- Rendering and decoding fixes across TIFF, BMP, PNM, ICO, DWG, DXF, IFC, STL,
  glTF, JPEG 2000, DDS, Word, Excel and PowerPoint files.
- PDF strings `\b` and `\f`, which made encrypted PDFs that open with an empty
  password report password-protected.

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
