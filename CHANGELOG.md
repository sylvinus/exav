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
  without holding them, and a file past `--max-object-bytes` inside one is
  scanned in full. The registry lists 126 formats.
- **Installers opened**: Inno Setup 5.1.5 to 6.4.0 (every compression Setup
  uses), InstallShield InstallScript cabinets and the setup executables of
  InstallShield 2009 to 2011 and 2015 and later (the MSI and the files beside
  it), AppleSingle and AppleDouble, CryptFF. An encrypted file is
  `PASSWORD-PROTECTED`, and a version or layout exav does not read is reported.
- **Large objects in bounded memory.** RAR archives and volume sets of any
  size are decoded as they are read, in their own dictionary; a stored member
  (ZIP, tar, ISO and the like) is scanned where it lies, through the block
  cache; compound files, email and mailboxes, CHM, 7z folders with BCJ2 or AES,
  and the compressed files of NTFS, HFS+, APFS and EROFS are read a piece at a
  time; a PE past `--max-object-bytes` is parsed from its image, so an
  installer with a large overlay gets the checks that read a PE's structure.
  They were refused or `LIMITS-EXCEEDED`. Over HTTP an object is checked for
  change while it is read.
- **A visible-text layer** (`visible-text`, on by default, off under
  `--clamav-compat`): Markdown, HTML, Word, PowerPoint, Excel, OpenDocument,
  AutoCAD and IFC files are also scanned as the text a reader sees, with the
  hyperlinks of OOXML documents, PDFs and drawings, speaker notes and an
  email's headers, for `Target:0` and `Target:7` signatures and
  `--detect phishing`. PDF text and the text of legacy and flat office files
  are opt-in (`visible-text-pdf`, `visible-text-office`). `exav-grep --text`
  searches it.
- **QR codes** (`--qr`, feature `qr`, off by default and under
  `--clamav-compat`): the codes in images, in archives, documents and the
  images of a PDF, are matched as text and their links judged by
  `--detect phishing`. `exav-grep --qr` searches them and `exav-qr` prints them.
- **Office documents converted in safe Rust, in `exav-render`** (features
  `office-sheets`, `office-slides`, `office-docs`, `office`; none is a
  default): XLS, ODS, FODS, Numbers, Excel 2003 XML, HTML tables and SYLK to
  XLSX; PowerPoint 95 to 2003, ODP, FODP and Keynote to PPTX; DOC, ODT, FODT,
  RTF, Word 2003 XML and Pages to DOCX; ODG, FODG and Visio (VSDX) to PPTX.
  The viewer shows them through `xlsx()`, `pptx()` and `docx()`.
- **One reader per format, one walk.** The scanner and `exav-render` share the
  readers for OLE2, Excel decryption, RTF, BIFF and code pages; exav,
  exav-grep, `exav-unpack -r` and the wasm share one typer and one walk of
  nested containers (`exav_unpack::tree`).
- **Smaller and faster binaries.** Each reader is compiled once and the release
  profile uses fat LTO and one codegen unit: exav 25.2 MB to 16.7 MB, exav-grep
  13.6 to 8.6 MB, exav-unpack 7.6 to 5.4 MB, a corpus scan about 8% faster.
  `cargo install` now builds with this profile and its overflow checks (about
  3 GiB of memory at its peak); `--profile fast-build` is the shorter build.
- **The viewer** (`@exav/viewer`) opens many more files (RAW cameras, JPEG XL,
  SVG, OBJ, PLY, glTF, more IFC, older Office, more archives), tells a file by
  its bytes with exav's own detection, draws pages of documents, 3D models and
  drawings, can be driven by the host's own UI, and speaks German, Spanish and
  Dutch. A sandboxed frame can be published for some formats only (`formats`,
  `--format`).
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
- The block cache is 32 MiB (it was 8 MiB), the library's default too (the
  browser build keeps 8 MiB), in 1 MiB blocks (64 KiB, fixed).
- `ScanOptions::deep_analysis_max` is removed: the largest object held in
  memory is `limits.max_buffer_bytes` (`--max-object-bytes`), one setting
  where there were two. `--clamav-compat` no longer holds objects up to
  400 MiB: it uses the default 256 MiB, and a larger one is read through the
  block cache.
- **Import hashes**: the size of an `.imp` signature is the length of the
  string hashed, as `clamscan --debug` prints it (exav compared the number of
  imports), and the `imphash:` lines of a `.fdb` file are matched with the
  usual import hash (`pe.imphash()`, pefile's). A signature written the old way
  stops matching. The saved database is format version 5: one made by 0.0.2 is
  rebuilt.
- Viewer: the CSS prefix is `exav-viewer-` (it was `exv-`), the sandboxed
  frame's protocol is version 7 (it was 3), and `controllers.viewport` is
  computed only while used. `Detector.sniff` and `detectBytes` return promises;
  `SIGNATURES`, `sniff`, `FormatMatcher.signatures`, `confirmSniff` and
  `DetectionTable.signatures` are removed. `archive()` and `@exav/unpack-wasm`
  no longer take `maxCompressionRatio`. It needs `@exav/unpack-wasm` 0.0.3 and
  `pdfjs-dist` 6.4.299 or later.
- exav-render's office features depend on `exav-unpack`. `exav-unpack`'s `ole`
  feature no longer pulls the `cfb` crate, now a dev-dependency.
- `exav-unpack` ext, FAT, HFS+ and APFS readers are in-tree: member names no
  longer begin with `/`, and a damaged volume ends with an error after the
  files before the damage.
- Objects already scanned clean in the same place are scanned once per scan.
- The seven `--icap-*` flags (and their variables) are removed: the ICAP
  address takes `?idle-secs=`, `?max-requests=`, `?max-header-bytes=`,
  `?preview-bytes=`, `?transfer-preview=`, `?options-ttl-secs=` and
  `?infection-header=`, and the flag or the variable stops the run with a
  message saying so. `?transfer-preview=` takes `*` or `off` only: exav sends no
  other `Transfer-*` header, and RFC 3507 asks that one of them hold `*`.

### Added

- Settings, each with its `EXAV_*` variable and `off` (or `0`):
  `--max-regex-steps` (100,000,000), one work budget for PCRE subsignatures
  with lookaround or back references and for YARA regexps;
  `--max-matcher-steps` (2,000,000 per MiB of an object, at least 256 MiB's
  worth), the verification of body signatures with wildcards and gaps and a
  32nd of it for one group sharing an anchor, which were fixed and left a
  large executable incomplete whatever was set;
  `--max-compression-ratio` (1000, also in exav-grep and exav-unpack);
  `--max-carved-executables` (16 of each kind), `--max-carved-archives` (32),
  `--max-base64-payloads` (8), `--max-base64-runs` (64) and
  `--max-page-assets` (16), which were fixed; `--max-hole-bytes` (64G) for the
  holes of sparse files in a filesystem image; the `--max-qr-*` bounds of
  `--qr` (pixels, time, codes, finder patterns, grids), in exav-grep too;
  `--max-extracted-bytes` (back) and `--max-bytecode-memory-bytes`. Also
  `--object-cache-bytes`, `--object-cache-block-bytes` and
  `--http-request-bytes`.
- Daemon, on a listener's address: `?idle-secs=` (at least 1), the most one
  read or one write waits for a clamd client (120, it was a fixed 60 seconds
  for reads and none for writes) or an ICAP connection for its client (600),
  and the time a `--listen-health` client has (5); `?request-secs=` (600, or
  `off`), the most time one clamd command or ICAP request takes to arrive;
  `?session-secs=` and `?reply-secs=`, off unless given: how long a
  connection stays open (no new command or request after it), and the most
  the writes of one reply wait for the client in all. A client cut for not
  reading its reply is logged, on ICAP too. A `--listen-health` address
  refuses the options it does not read (`?service=` was accepted and ignored).
- HTTP: `--http-timeout-secs` (120), `--http-max-redirects` (10),
  `--http-redirect-private` and `--http-spill`. A server that does not answer
  range requests has the object downloaded whole, up to `--max-input-bytes`.
- Scanning: `Target:3` and `Target:7` signatures also match the `script`
  elements of an HTML page, normalised as script, where clamscan matched them
  and exav did not; a message is read from inside a text or binary data when
  two of its header lines are close together, as ClamAV reads one; an ARJ
  archive stapled inside another file is carved;
  `Heuristics.PDF.ObfuscatedNameObject` applies inside PDF object streams;
  `--detect exav-heuristics` matches `tlsh:` lines against an installer's
  executable and `-v` shows `pe-imphash`.
- `exav-qr FILE...` (`cargo install exav-grep --features qr`): the payloads of
  the QR codes in images and in what holds them, one per line with its
  location. Exit 0 when a code is found, 1 when none, 2 on an error, 3 when
  none was found but something could not be read.
- exav-unpack: `-r` (`--recursive`) opens the archives inside the archive, to
  `--max-unpack-depth` (16); exav-unpack and exav-grep take
  `--object-cache-bytes` and `--object-cache-block-bytes` (32M and 1M, shared
  by the parts of a split archive), open a container inside a member past
  `--max-object-bytes` through a spill file (`--spill-dir`,
  `--max-total-spill-bytes`, 2G), read exav's `EXAV_*` variables, and take
  `off` or `0` for no limit. exav-grep takes `--max-extracted-bytes`.
- Features `ishieldcab`, `applesingle` and `ishieldmsi` of exav-unpack,
  forwarded by exav-core and exav. Formats: LZFSE, LZVN and InstallShield Z
  in-tree, camera RAW, DDS, ICO and cursors, PLY, OBJ, glTF, TIFF variants, and
  an external converter hook for the viewer.
- Libraries: `exav_unpack::tree` (`Walker`, `Visitor`, `Typing`,
  `type_object`), `MemberMeta::reason_kind`, `Budget::set_rasters`;
  `@exav/unpack-wasm`'s `list()` marks the member of a single-stream format
  `synthetic`.
- Viewer: detection by exav in a worker (`sniffBytes`, 65,536;
  `sniffTimeoutMs`, 30,000); `damaged` and `wrong_type` from exav's readers,
  and `FormatMismatch`; a ZIP's directory checked before it is opened
  (`maxExtractedBytes` 512 MiB, `maxMembers` 20,000, `maxCompressionRatio`
  1000); `maxArchiveEntries` and `maxEntities`; a question about a link only
  after a click or a key, and `linkQuietMs` (2000).
- Viewer: highlights (`ViewerFile.highlights`, `focusHighlight`): boxes on a
  PDF's pages, or a quote found in the text of a PDF, a text, Markdown, JSON
  or XML file whatever its case, accents, spaces, punctuation and words cut
  at the end of a line, `...` for text left out; `controllers.highlights` and
  the `ref` of `ViewerBody` and `ViewerDialog` (`goToPage`, `goToHighlight`),
  in the sandboxed frame too.
- `scripts/bench-speed.sh`, a speed benchmark against `clamscan`, and 233
  freely licensed example files for the viewer demo.
- exav.org/formats/: every format exav reads in one table, built from the
  format registry, with what the scanner, the extractor and the viewer do with
  it and an example in the demo (it replaces the format matrix page).

### Changed

- **Limits leave a part out and go on.** A member over the compression ratio
  or over `--max-object-bytes` is left out, the members after it are scanned,
  and the container is `LIMITS-EXCEEDED` unless something is found. The ratio
  is asked only of a member that decodes past `--max-object-bytes` (it was
  4 MiB). A member said to be larger than what is left of
  `--max-extracted-bytes` is left out before it is decoded; one that decodes
  past what it said is charged and ends the container. A limit reached in what
  is found inside a file (a carved archive, an executable's payload, a message
  in a text) is kept aside like a password, and what is found after it is
  scanned. What the PDF reader parses again counts against
  `--max-extracted-bytes`, not caps of its own.
- `--max-unpack-depth 0` opens no container, in every CLI: exav scans each
  file as it stands and reports an archive's members not scanned, exav-grep
  and exav-qr search each file as it stands, and `exav-unpack -r` takes the
  archive named as one file (exav refused 0; the others reported every
  archive unreadable).
- `--build-db` counts as unsupported the logical signatures with a PCRE
  subsignature that neither regex engine builds. Loading the files directly
  does not; a scan that reaches one is incomplete either way.
- A member left out for its size is `LIMITS-EXCEEDED`, not `UNSCANNABLE`; a
  file a reader cannot parse is `UNSCANNABLE`, not `LIMITS-EXCEEDED`; a panic
  while examining a member is reported at that member and the rest of its
  container is scanned.
- A file past `--max-object-bytes`, a spilled member or view and an HTTP input
  are read once for detection, carving, the digests, the signatures, YARA and
  the static model, where each needed a read of its own: 4.1x the
  size down to 1.45x with YARA rules, 3.25x to 1.5x with 182,000 signatures,
  211 HTTP requests down to 110. A pass over an object larger than the cache
  streams through two blocks of its own.
- `--clamav-compat` opens only what clamscan 1.4.3 opens: ZOO, StuffIt, ACE,
  ARC, lz4, zstd, lrzip, WIM, InstallShield cabinets, AppleSingle and
  AppleDouble, the filesystem images, `.lnk`, `.pyc`, Java classes, AI models,
  KWAJ and the SZDD files it rejects stay unopened, as do gzip, bzip2 and xz
  streams and ELF and Mach-O images stapled behind another file, and a PE
  stapled behind anything but a PE. DMG is opened.
- Typing as ClamAV types: a file that starts with a mail header is a message,
  typed before HTML, and the files uuencoded in its body are decoded; an ARJ
  archive at the start of a file is taken
  by the shape of its main header; a Markdown file that is not UTF-8 is
  windows-1252. For exav-grep and `exav-unpack -r` an executable is read as an
  installer, a disk image or a packed program.
- exav-grep walks with the scanner's engine (depth limit, members read where
  they lie, partly decoded bytes searched with the reason, split files inside
  an archive, appended ZIPs), holds a file up to `--max-object-bytes` where it
  was a fixed 16 MiB, and stops at a closed pipe.
- Names in verdict reasons and locations have control characters,
  bidirectional controls and U+2028/9 replaced by `_` and are cut at 200
  characters; exav-grep and exav-unpack print names and reasons the same way.
- exav-unpack: `--max-memory` is `--max-object-bytes` and `--max-size` is
  `--max-extracted-bytes` (the old names still work); the exit status of a
  member that was not decoded follows the kind of its reason.
- A daemon setting given only by its `EXAV_*` variable to a run without that
  listener is ignored with a warning; on the command line it is still refused.
- The Docker image names its user (65532), owns `/run/exav`, runs with
  `--read-only`, `--cap-drop ALL` and `no-new-privileges`, and pins Alpine
  3.23; the examples publish the clamd and ICAP ports on localhost only.
- YARA: `pe.number_of_exports` counts the functions of the export address
  table, those exported by ordinal alone included, as yara-x does; it counted
  the named ones.
- Dependencies are at their latest versions, except the image decoders pinned
  to libclamav 1.5.4 and `zip`, required below 9.1 (from 9.1 it always brings
  a random number crate). Fewer crates and less `unsafe`: `tar`, `filetime`,
  `byteorder`, `salzweg`, `lru`, `foldhash` and `g2p` are gone, and the QR
  reader is `exav-qr`, rqrr 0.11.0 vendored with `forbid(unsafe_code)`.
  `fuzzy_img` JPEGs are decoded by zune-jpeg 0.5.15, not libclamav's 0.5.8:
  the hashes differ only for baseline JPEGs with a scan for each component,
  which 0.5.8 drew flat, and damaged files it panicked on.
- Viewer: text, CSV, TSV and a ZIP's directory are read by exav's readers in
  WebAssembly, in a worker, and the TypeScript readers are gone; IFC models
  are framed by exav-render, off the main thread. A CSV past 16,384 columns or
  1,048,576 rows is refused.

### Fixed

The ones that could change a verdict:

- **Files that a reader opens differently from exav are read as that reader
  reads them:** ZIP, PDF (with its object streams), mail (folded and long
  boundaries, base64 without the URL-safe digits), ISO and UDF, `ar`, `cpio`,
  bzip2, xz, CAB, NSIS and PowerPoint objects, NTFS compression units and data
  attributes, MBR logical partitions, 7z coder graphs, an ARJ archive behind a
  stub written on Unix, files holding a second archive. A message attached to
  an email is now scanned, and a base64 part the mail parser cannot decode is
  decoded in memory as it is streamed (pieces encoded apart and joined were
  misread). A `.lzma` file cut short is reported as not fully examined.
- **PE files are read as Windows, clamscan and libyara read them** (headers
  inside the DOS header, names in the headers, an entry point in the headers,
  rounded section pointers, imports by ordinal): the YARA `pe` module gives
  libyara's values on all 952 PEs of a corpus (268 differed), and an `.imp`
  signature made of clamscan's `hash:size` matches all 853 PE32 files with a
  clamscan import hash (708 before), installers included. A PE whose other
  directories do not parse keeps its import hash, YARA values and static
  model; one whose import table does not parse is `UNSCANNABLE` when a check
  needs it. exav's own PE readers (the packer check, the Inno Setup resource,
  icons) read the headers through one reader and map an address the way the
  loader does (a section to the end of its page, the headers below the
  sections); the packer check read no data directory of a 64-bit image, and
  YARA's `dotnet` module maps its addresses as yara-x does.
- **An Office package is told by its ZIP directory, not its name**: a DOCX,
  XLSX or PPTX named `.zip`, or with no name, has its text view and link
  checks (from its local headers when its directory is lost), and the viewer
  opens it in its document plugin. As a `Container:` type it is OOXML when its
  directory says so, as clamscan types it: an XLSB too, and no longer a ZIP
  that only quotes the part names, or one cut before its directory.
- **A string a format is found by** (a PDF header, an XDP tag, the BinHex
  line, the AutoIt and Script Encoder markers) no longer takes the type from
  an object whose own header gives one; the format is read as well. A text
  that names XDP's tags with no PDF in them is no longer `UNSCANNABLE`, and
  the character references in an XDP's chunks are read.
- **No clean answer for what was not read**: a PCRE subsignature or YARA
  regexp stopped at `--max-regex-steps`, a PCRE subsignature on an object past
  `--max-pcre-bytes` (outside `--clamav-compat`, where clamscan says nothing)
  or one the backtracking engine cannot build, a RAR5 member of an unknown
  compression version, a Numbers, Pages or Keynote stream past the memory
  limit, a page at the depth limit with encoded
  payloads, a split set inside an archive over the limit or cut, an input past
  4 GiB on 32-bit targets, a DWG or CHM part that could not be read, an NTFS
  sparse file whose runs end early, an email whose delimiter never comes, and
  an Inno Setup installer before 5.1.5, told by its header and reported.
- **A limit, not damage, and a cut the same at any size**: a 7z LZMA or LZMA2
  folder and an SWF movie whose dictionary is over `--max-object-bytes` are a
  limit reached, as in ZIP and RAR (they were decoded with a smaller window,
  and a valid stream was reported damaged). A member cut by the end of its
  archive is scanned as far as it goes whatever its size (one over
  `--max-object-bytes` was UNSCANNABLE), and exav-unpack's `-t`, `-x` and `-p`
  report it as an error, as tar and unzip do.
- **A RAR member is its whole stream**: one whose header declares less is
  scanned to the stream's end (RAR5 made it UNSCANNABLE, RAR4 cut it at the
  declared size), one that ends first as far as it goes
  (RAR4 made it UNSCANNABLE). Over the object limit, by its declared size or
  its window, a member held in memory is that limit (it was reported as
  undecodable or unsupported). A match that reaches before the start of the
  stream is zeros, as unrar writes it (part of it was copied from the
  stream's first bytes).
- **What decoded before a cut or damage is scanned**: a member over
  `--max-object-bytes` whose stream fails part way, a RAR member (stored or
  compressed) cut by the end of the archive, an LZMA member of a ZIP or 7z
  cut by the end of the file (to its last bytes), a 7z BCJ2 folder, a file of a
  filesystem that breaks part way (reported with its cause), a CHM cut inside
  a stored file. A RAR whose block header does not parse is reported damaged,
  and a RAR volume set no longer joins the blocks after a volume's end.
- **PCRE subsignatures with lookaround, back references or conditionals**:
  seven wrong answers of the backtracking engine are fixed (`a+b?a+` and
  `(?:a+b?a*)+` matched more than they should, a conditional whose true
  branch is a group of alternatives took one of them as its false branch, a
  lookahead backtracked into another capture, a failed condition ended an
  atomic group early, a repeat with an empty body stopped below its minimum,
  a back reference inside its own group panicked), and a lookbehind of
  variable length reads byte classes as bytes.
- **Resource bounds**: names an executable's tables refer to many times, an
  import or export table of one long run of names (exports are read by exav's
  own reader now, as imports are), the section names of a PE (each read
  once, within the file's size) and the bytes hashed for its sections; YARA
  ranges over many matches and regexps with long matches; Excel external
  workbooks, XAR tables of contents, tar extended headers; a RAR5 dictionary
  larger than what its run decodes to, and the RAR5 filters waiting for their
  block (8,192, as RAR4's); a member held in memory, which took
  twice the limit; Office conversion loops; nested documents, YARA rules,
  Visio formulas, PPMd, zstd, JPEG XL, JBIG2, bytecode, 7z headers, RAR key
  derivation and XML trees. Several recursive readers no longer overflow the
  stack.
- A logical signature subsignature with a nibble wildcard and `::i` counted
  too many matches; ZOO LZD members past 4,096 table entries decode, a ZOO
  archive whose last directory entry is short is read whole, and ZOO long
  names and directory names are read (they were looked for one byte too
  late, so a member took its 8.3 name); ARJ members
  encrypted with GOST 40-bit open with the right password; a password-protected
  DWG is `PASSWORD-PROTECTED`; a compound file with several documents has the
  text of each read; InstallShield cabinets of version 4 and older are read.
- A line of a hash, section hash, fuzzy, import hash, container, icon or file
  type database that does not parse is counted with the unsupported
  signatures, as the other formats' are. YARA: `pe.exports(ordinal)` matches
  an export's ordinal, `math.abs` of the smallest integer is undefined, and
  `--all-matches` and `ALLMATCHSCAN` give rules the file's `filename`,
  `filepath` and `extension`, as a scan does.
- A damaged executable carved from a file no longer turns a detection behind
  it into `PARTIAL` or `OK`; a detection made before a read of the input
  failed is reported (it was an error), and one inside a compressed member
  when the member then passes `--max-matcher-bytes` (it was
  `LIMITS-EXCEEDED`); base64 in scripts and pages decodes more archive types;
  PDF strings `\b` and `\f` made encrypted PDFs that open with an empty
  password report password-protected.
  `--detect packed` names only the packers exav tells: an archive member
  called `X-packed image` gave `Heuristics.Packed.X`.
- Daemon: `FILDES` scans a descriptor from its start (one the client left at
  its end was scanned as empty, `OK`); an `IDSESSION` is closed after a
  stream it did not read to its end (more than 64 MiB past
  `--max-input-bytes`, or an `EXINSTREAM MULTI` answered part-way), as clamd
  closes; the clamd listener retries a transient
  accept failure instead of ending; with `--auto-update` and the pool the
  signature check runs in a child of its own; the Unix socket is bound in a
  private directory, not under a
  changed umask; `--listen-health` closes a client that is slow to send;
  `VERSIONCOMMANDS` no longer lists `SHUTDOWN` and `QUIT` on a daemon that
  refuses them. Large files over HTTP no longer cost a request per executable
  candidate.
- exav-unpack no longer makes symbolic links that lead out of the extraction
  directory or panics on a closed pipe; `-t` no longer ends with "No errors
  detected" after an error. `--build-db` makes the directory of its output.
- Viewer: links with a user name or password are refused, names show control
  and bidirectional characters as U+FFFD and are isolated from the text around
  them, a module whose stack ran out is replaced rather than used again, an
  encrypted ODP or Keynote part is said to be encrypted and a Pages file with
  no document damaged, a web page with a picture of an enormous size converts,
  the files a frame asks for are held
  to `TREE.maxFileBytes`, and a formatter that fails shows plain text. Which
  Office reader a file goes to is told by exav's readers from its directory
  (a Word document named `.xls` went to the sheets converter, and a stream
  name quoted inside another file could route it); a `resolve` source is
  signed again on 401 or 403 for every request, not only range reads, and
  every range answer is checked against what was asked. A read the frame asks
  of a `ranges` source is answered with a copy: a buffer the host's `read`
  returned whole was transferred, and emptied on the host's side.
  Rendering and decoding fixes across TIFF, BMP, PNM, ICO, DWG, DXF, IFC, STL,
  glTF, JPEG 2000, DDS, Word, Excel and PowerPoint files.

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
