# Changelog

Notable changes per release. Dates are release dates; the format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) loosely, and versions
follow [semantic versioning](https://semver.org/).

## [Unreleased]

### Added

- exav.org/project/stats/: the figures of each release, from speed and
  memory against `clamscan` to lines of Rust, dependencies, `unsafe`, tests,
  formats and sizes, written by `scripts/stats.py`.
- Viewer: the text view and a Markdown link's target (in the viewer and in
  exav-render) hide the left-to-right, right-to-left and Arabic letter marks
  (U+200E, U+200F, U+061C) as names already did: one set, exav-unpack's,
  which the viewer's TypeScript takes from a generated table a test keeps in
  step.
- `--max-yara-steps` (`EXAV_MAX_YARA_STEPS`, `ScanOptions::max_yara_steps`):
  the steps the conditions of the YARA rules may take in one scan, all the
  rules together, 20 million by default as before (also under
  `--clamav-compat`), `off` for none. A scan that runs out of them names the
  rule and the flag (`YARA rule R: condition ran out of --max-yara-steps`).
- `--max-pe-stub-steps` (`EXAV_MAX_PE_STUB_STEPS`, `Limits::max_pe_stub_steps`)
  and `--max-pe-idle-steps` (`EXAV_MAX_PE_IDLE_STEPS`,
  `Limits::max_pe_idle_steps`), in exav, exav-grep and exav-qr: the
  instructions the emulator may run for one packed executable, 500 million by
  default (a fixed 120 million before), and how long its stub may go without
  writing a new page, 64 million (8 million before); `off` for none. A stub
  that runs out of its budget is `LIMITS-EXCEEDED` unless something is found,
  where it read `OK` or `UNSCANNABLE`; what it rebuilt is still scanned. 200
  of the 276 corpus samples now reach the unpacked program, and Alienyze,
  BeRoEXEPacker, EXpressor, MPRESS, NsPack and PECompact on every sample.
- Inno Setup installers made with 6.4.2 to 7.1.0 are opened, their files
  scanned, where the scan ended `PARTIAL` (ported from innoextract's pull
  request 210); one whose setup data is encrypted (6.5's `Encryption=full`)
  is reported password protected. `make test-inno` checks the reader on Inno Setup's own
  installer of each release, every file whole against its stored SHA-256,
  and the nightly runs it.
- Viewer: Apple Pages files open (`pages()` from `@exav/viewer/office`, and
  the sandboxed frame): Pages 5 (2013) and later are converted to DOCX in the
  browser, and a Pages '09 file ends in the converter's "unsupported" error,
  or goes to the external converter where one is set. They were listed as
  ZIP packages.
- Viewer: a Markdown `mailto:` link opens the mail program, in the sandboxed
  frame after the host's question (`confirmLink` is given `mailto:`
  addresses too); it was shown as text.
- Sandboxed viewer: a host page whose Content-Security-Policy refuses the
  frame (`frame-src`, `child-src` or `default-src`) fails the session at once,
  naming the origin to add, where it waited for `startTimeoutMs`. After
  `ready` the host pings the frame and fails the session when a ping stays
  unanswered for `frameTimeoutMs` (default 30,000 ms, `0` for none), so a
  frame that crashed, was navigated away or hangs is reported. Frame protocol
  8: the page and the frame come from the same release.
- Released files hold no path of the machine that built them: the checkout
  and the cargo and rustup homes are mapped to `/exav`, `/cargo` and `/rustup`
  in the binaries, the WASI module and the npm packages' wasm (the 0.0.3 npm
  packages named a workstation's home directory), and a gate
  (`scripts/check-build-paths.py`) refuses a crate, binary, archive, npm
  tarball or chart that holds one. The npm packages are published from the
  tarballs the release workflow builds (`@exav/viewer` added), so npm and the
  release carry the same bytes.
- The release opens every file of the viewer's demo in a browser
  (`e2e/examples.spec.ts`, in `make test-viewer`), and again on the deployed
  demo.
- exav.org/formats/: each format says where its detection looks and how (a
  test runs the detector over the repository's files of 77 formats and fails
  when it finds or reads them anywhere else), and links its specification, or
  the best public description of it, for 97 of the 126.

### Changed

- `--max-hole-bytes` defaults to 10G (was 64G), the default of
  `--max-matcher-bytes`: the holes of a sparse file in a filesystem image
  cost the matcher what the same bytes of data cost. A larger value or `off`
  reads a larger sparse file whole. exav-unpack's own command keeps 64G, and
  takes `--max-hole-bytes` too (and `EXAV_MAX_HOLE_BYTES`), as
  `@exav/unpack-wasm` takes `maxHoleBytes`: neither could change it. So do
  exav-grep and exav-qr, with `--max-matcher-bytes` and
  `--max-pe-emulation-steps` (and, for exav-qr, `--max-members` and
  `--max-compression-ratio`): their walk applied those limits with no flag.
- Word 2003 XML: tracked changes are shown as DOC's are, the deleted text
  struck through and the inserted text underlined, in dark red; the deleted
  text was left out. It is in the document's text for the scan too.
- The office converters the scan runs for the text of DOC, XLS, PPT, iWork
  and flat XML files follow `--max-object-bytes`: their input, memory and
  decompressed-part sizes are the limit itself (memory past 1 GiB too), and
  their counts (cells, paragraphs, sheets, slides, shapes) grow in proportion
  from today's numbers, which the default limit gives. A large document had
  no text view past a fixed limit no setting could raise. With the limit off
  they follow `--max-extracted-bytes`.
- Viewer, converted formats: `converter` takes one word for every format or
  one per format (`{ doc: "exav", odt: "external" }`), in the plugins and in
  the sandboxed frame's options; and whichever converter goes first, a file it
  cannot read goes on to the other. A file exav-render recognises and cannot
  convert (Word 1 and 2, PowerPoint 2 to 4, Keynote '09, an encrypted one) went
  to no external converter, and a file the external converter failed on went
  to no exav-render converter.
- `--listen` can name several addresses of one protocol, as clamd's
  `LocalSocket` with `TCPSocket` and a repeated `TCPAddr` do: a Unix socket
  and a TCP port for clamd, two ICAP ports with their own `?service=` and
  options. Each address is served with the options on it; under the pool
  every worker waits on all the clamd addresses and each ICAP address runs in
  a child of its own. The same socket given twice is refused, where any second
  address of a protocol was. `--listen-health` takes several addresses too.
- A YARA search that cannot finish still ends the scan `LIMITS-EXCEEDED`
  (unless a rule matched), and the reason says why: a pattern with more than
  a million matches names the rule and the pattern (`YARA rule R: pattern $a
  has more than 1,000,000 matches`), a rule set that runs out of condition
  steps names the rule that spent them, a regexp that runs out of
  `--max-regex-steps` or needs the object read whole past
  `--max-object-bytes` names its rule and pattern, and a `pe`, `elf` or
  `dotnet` module that lacks values names the module and the limit (`YARA
  module pe: the object is past --max-object-bytes`).
- hayro 0.9 (PDF text) and its image decoders hayro-jpeg2000 0.5,
  hayro-jbig2 0.4 and hayro-ccitt 0.5: the viewer shows more of a damaged
  JPEG 2000 or JBIG2 file (the scan still reports it not fully read), a JBIG2
  file of several pages shows its first page, and text drawn in the clipping
  mode (mode 7) is part of a PDF's text, as invisible text is. `foldhash` and
  `hayro-font` join the dependencies of the opt-in `text-pdf`.
- ZIP members of the PKZIP 1.x methods (Shrink, Reduce, Implode) are decoded
  by exav's own code, written from PKWARE's specification, as they are read:
  a member of any size no longer needs a buffer of its declared size, the
  bytes decoded before a damaged or cut place are scanned, and orphan local
  headers of these methods are decoded too.
- The `zip` crate is out of the tree: exav reads ZIP archives (the central
  directory, the members the directory omits, ZipCrypto and WinZip AES) and
  the office packages, and writes the converters' packages, with its own code.
  The scanner's tree is 2 crates and 57 `unsafe` keywords smaller, the browser
  builds 5 crates and 523 keywords. A ZIP whose end record points elsewhere
  than its directory, with a member that runs into the end record, is scanned
  with the end record's bytes as the file holds them. A member that decodes in
  full but whose CRC disagrees is scanned and no longer makes the scan
  `PARTIAL`, as in the other archive formats (`exav-unpack -p` still prints the
  mismatch).
- `base64` is built without its SIMD engines (`simd-unsafe`) and `delharc`
  without its `assert_unchecked` hints: 38 fewer `unsafe` keywords in what
  exav-core compiles. LHA decodes 5 to 15 percent slower.
- HMAC and PBKDF2, which derive the keys of AES ZIP, RAR5 and encrypted disk
  images, are exav's own code, written from RFCs 2104 and 8018 and checked
  against the vectors of RFCs 2202, 4231, 6070 and 7914: `hmac`, `pbkdf2`,
  `cmov` and `ctutils` are gone, about 120 `unsafe` keywords with them.
- YARA's `elf` module reads ELF records through the `elf` crate (no
  dependencies, no `unsafe`), and goblin is built with its PE parsers only: 90
  fewer `unsafe` keywords. The module now gives yara-x's values, compared with
  yara-x 1.23.0 on 2,508 damaged and 61,575 crafted files and 1,128 intact
  ones: dynamic symbols come from the `SHT_DYNSYM` section, `osabi`, symbol
  `visibility` and all the module's constants are defined, `dynamic` does not
  list its end marker, `entry_point` is undefined for an entry of 0, and a
  table missing or damaged leaves the rest of the module defined (one name
  that is not UTF-8, or one bad relocation table, left every `elf.*` value
  undefined).
- YARA: `.len()` on a module array (`pe.sections.len()`, `elf.dynsym.len()`,
  on a `for` or `with` variable too) compiles and gives yara-x's count, 0 for
  an array the file lacks; `elf.import_md5()` and `elf.telfhash()` give
  yara-x 1.23's values; `dotnet.field_offsets` and `dotnet.resources[].offset`
  are file offsets, as in yara-x 1.23 (they were the values as stored). The
  first two were compile errors.
- YARA's `dotnet` module reads damaged assemblies as yara-x does: at most 96
  section headers, an absent or short table stream leaves an assembly with no
  tables, the tables are read up to the first that does not parse, names and
  blobs that cannot be read are undefined, and user strings and
  `number_of_classes` count as yara-x counts them. `dotnet.is_dotnet` was
  false on 58 of 564 damaged .NET files where yara-x says true.
- `make test-yara-diff` fails when yara-x's `yr` is not found or no rule
  corpus is named, where it passed having checked nothing; `make
  test-yara-diff-rules` needs only `yr`, and CI runs it with yara-x 1.23.0.
- Petite, FSG and NsPack files are unpacked by running their stubs, as other
  packers are: the aPLib decoder tried first opened none of the 36 sample
  files of these packers exav is tested on. A build without the `pe-emu`
  feature reports them `UNSCANNABLE`.
- The scan totals in the log (every `--metrics-secs`) are written once for
  the whole daemon and labelled `daemon`. Under the worker pool the
  supervisor writes them, clamd's and ICAP's scans together: a pool with
  clamd addresses only wrote none, and one with two ICAP addresses wrote the
  same totals twice. ICAP served alone labelled them `icap`: a log reader
  matching `exav: icap: SCANSTATS` now matches `exav: daemon: SCANSTATS`.

### Fixed

- **Packed executables.** The emulator follows Petite (all 12 sample files)
  and Exe32pack to the unpacked program and finds NsPack's start, where they
  ended with what the stub had rebuilt by then, scanned as a partial image;
  PECompact's run stops
  at its program rather than in its stub. It maps a PE's headers read-only and
  runs an exception handler as Windows does, resolves imports by ordinal from
  every system DLL, and answers the calls a Visual C++ program makes at
  start-up (`EncodePointer`, `FlsAlloc` and others). `VirtualAllocEx` and
  `VirtualProtectEx` read the process handle as the address.
- **What a scan left out or cut.** A file whose header is `{\rt` (`{\rt0`),
  which clamscan types as RTF and Word opens, was read as text: its embedded
  objects are now extracted and scanned. PDF: a stream whose dictionary
  nested past 20 levels or held a bare `stream`, `endobj` or `endstream`
  keyword was left out; one whose data holds `endstream` was cut there (its
  `/Length` is used when `endstream` follows it, after up to 256 bytes of
  white space); a value nested past 64 levels, or past the 32 the search for
  scripts and links went to, was passed over without a word: the search now
  goes as deep as the parser reads, and a value past that makes the scan
  `UNSCANNABLE`, naming the object; the predictor of a stream that is not an
  image was not undone (the QR check reads TIFF-predicted images with the
  same code). An XDP whose PDF chunk is in a CDATA section or has a comment
  in it was `UNSCANNABLE`: it is read as an XML reader reads it. The
  normalised script of a page's `script` elements is written as clamscan
  writes it, so that signatures written on clamscan's view match: only the
  names a script declares are renamed (`var` names, function names and
  parameters, from `n000` in each element; every name was), the text of a
  `//` comment is read as code (exav's view ended there), template literals
  lose their backquotes, `#` is dropped, names that differ by case are told
  apart, a number is written apart from the letters after it (`50em` is `50
  em`), `String.fromCharCode` and `decodeURI` are left as written and
  `unescape` is folded one level. exav's whole-page view of a page and its
  view of a script file still decode `String.fromCharCode`, `decodeURI` and
  nested `unescape` (not made under `--clamav-compat`). A 1.26 MB minified
  script scans in 0.61 s, where it took 0.49 s. A
  self-extractor whose stub is packed with UPX is read as UPX as well as an
  archive, as clamscan reads a 32-bit PE: a signature that matches the
  unpacked stub is found; only a detection comes of that second reading, and
  a stub that does not unpack changes neither the verdict nor its reason. A RAR set whose last volume is cut short, or
  missing where a member goes on, is joined and read as far as its volumes go,
  where it was refused whole. An ISO walk stopped by the member limit scans
  the files it had found before it reports the limit. At the depth limit, a
  bytecode unpacker's output no longer ends its object's scan before carving,
  DLP, phishing, Authenticode, TLSH and the import hash.
- **Verdicts.** A compiled terminfo entry (hundreds on any Linux system) was
  taken for a truncated ARC archive and the scan was `LIMITS-EXCEEDED`. An
  archive whose walk stopped at a limit or at damage after an encrypted member
  is `PASSWORD-PROTECTED`, as when the walk completes. A limit reported as
  found (`--partial-as limits-exceeded=found`) is a detection and wins over
  password protection and a stop at damage, whether the walk stopped at it or
  a reader noted it on one member and went on (a RAR whose one member is
  encrypted and another's dictionary is over `--max-object-bytes` was
  `PASSWORD-PROTECTED`). `ScanOptions::structured_cc_count` or `structured_ssn_count` at
  `Some(0)` made every text a detection: 0 is 1, as in clamscan. A
  SpreadsheetML or flat OpenDocument file with a table in its first kilobyte
  was read as HTML; an OpenDocument spreadsheet of no table (an empty
  template, which ODF allows) was refused as damaged and is an empty workbook.
- **Time and memory.** An MTEXT paragraph of several runs (DWG, DXF) and a
  Numbers table's merges took time that grew with the square of their size
  (160,000 words: 1.4 s, now 54 ms); an OpenDocument style that is its own
  parent was followed 33 times, and the text, presentation and spreadsheet
  converters, which each had their own copy of the style code, now share one that
  resolves a style once per name rather than at each use and counts what it
  keeps in the memory limit; ODT and Pages list styles, list restarts and
  Numbers' calculation-engine merges were not counted in the memory limit;
  the office converters read parts, pictures and PowerPoint storages into
  buffers that doubled to twice their limit; each image of an ICO or CUR file
  was tried with a copy of the rest of the file; a rule set importing YARA's
  `pe`, `dotnet` or `elf` read every object not held in memory whole, PE or
  not; an executable past `--max-object-bytes` had its start read twice when
  the object cache could not hold it (detection now says from its own read
  whether the start holds a UPX header); two charges of the scan budget too
  many brought `--max-matcher-bytes` sooner, and so did the holes of a sparse file small enough to be held
  whole (under `--max-object-bytes`), which went to that budget rather than
  to `--max-hole-bytes`.
- **The daemon.** clamd listener: a FIFO, socket or device named as the path
  answers `Not supported file type ERROR` as clamd does (it answered `OK`, and
  `SCAN` of a FIFO waited for a writer), also when a file turns into one before
  the open; `CONTSCAN`, `MULTISCAN`, `ALLMATCHSCAN` and `SCAN` of a directory
  write each file's line as it is done, so `--max-scan-secs` no longer loses
  them, and `ALLMATCHSCAN` rejoins split archives and lists every signature
  the archive matches on each part's lines, as `--all-matches` does on the
  command line (both stopped at the first); on Unix the path of `SCAN`,
  `CONTSCAN`, `MULTISCAN` and `ALLMATCHSCAN` is bytes, as in clamd, so a file
  whose name is not UTF-8 is scanned, named in the command or met in a walk,
  and every reply and `--log` line names it by its bytes, and `--connect`
  sends and prints the bytes too; a command longer than 64 KiB is refused
  when its end arrives in the same read (up to about 72 KiB got through); a
  panic while scanning a streamed file answers `ERROR` and the connection
  goes on; a command it cannot read, and a spill that cannot be
  written, are answered with an `ERROR` line, on the health listener too; past
  the drain limit the size reads `at least N`, in ICAP and on stdin too.
  `FILDES` scans the one descriptor that came with it: two or more are
  answered `No file descriptor received. ERROR`, and one sent with no command,
  with another command or after a finished `FILDES` is a `PROTOCOL ERROR`, as
  in clamd, and the connection closes with every descriptor it passed closed
  (up to 60 a message were kept until the connection ended, and the last one
  received was scanned, so one sent ahead could stand for the one sent with
  the command); the descriptor's byte of clamd's client, read with the command,
  is no longer taken for the next command of a session. A panic while
  scanning reads `scan failed (internal error)` in the clamd listener, ICAP
  and the command line, from one guard. A pool
  worker out of descriptors or memory waits and accepts again instead of
  exiting (on Windows the in-process listener too, for Winsock's codes; not
  tested on Windows here). A socket named both in `--listen` and in
  `--listen-health` is refused: the second bind replaced the first one's.
- **exav-unpack.** `-r` exited 0 on an archive inside another whose own bytes
  were decoded only in part (a `.tar.gz` without its gzip trailer); it is an
  error, as without `-r`. `-x` wrote a tar hard link as an empty file: it is a
  hard link to its target's file, as GNU tar makes it (`MemberMeta::hard_link`
  names the target). `Cx::derived` of a kind cut short before it found
  anything gave no reason.
- **A file name that is not UTF-8 on the command line** made exav,
  exav-unpack, exav-pe-emu, exav-imagehash and exav-wasm panic at start; the
  name is now opened as given (exav-unpack's archive, `-d`, `--volume` and
  `--spill-dir` byte for byte). exav-unpack ignored an `EXAV_SPILL_DIR` that is
  not UTF-8 and spilled to the default directory: it is used, and any other
  `EXAV_*` variable that is not UTF-8 is an error. `--spill-dir` and
  `EXAV_SPILL_DIR` of exav, exav-grep and exav-qr take a directory whose name
  is not UTF-8, which they refused.
- **The viewer.** A file read from an address whose server compresses its
  answers (GitHub Pages does, for XML, glTF, PLY, IFC and other types) could
  reach its engine cut or garbled, as the browser joined a range it had kept to
  the whole file: the 0.0.3 demo's FODT, FODS, GLB, PLY, IFC, CRW and JBIG2
  examples failed. Range requests stay out of the browser's cache, and a
  compressed answer to one is not taken as the bytes asked for. A ZIP of 5,001
  to 20,000 members passed the detection and was refused by the archive view
  (`archive()` takes 20,000 members and 512 MiB, as the Office plugins do); an
  Office or OpenDocument package inside an archive under a name that does not
  say so opens as its document. CCITT Group 3 fax TIFF files open (one or
  two-dimensional, with or without fill bits, in either fill order): the
  image module was built without the fax decoder and read Group 4 only.
  OpenDocument presentations read a style's
  properties by their kind: a paragraph style's background was drawn as the
  highlight of its text (a table cell's colour too), and `(1)` numbering is
  recognised. OpenDocument spreadsheets follow the parent of a table,
  column, row, drawing or text style: an inherited column width or font was
  lost. In the three OpenDocument converters a style's own value replaces
  its parent's whichever attribute sets it (a border or padding over the
  parent's sides, a colour over an automatic one, a font family over a font
  face), and a percentage font size is taken of the parent style's size.
  The text and presentation converters read the `fo:margin` shorthand,
  which they dropped, and a percentage paragraph margin is taken of the
  parent style's margin.
- **The sandboxed frame.** One name past its limit (a warning's file, an
  outline title, a layer, storey, layout or sheet name) dropped every control
  of the message: the frame cuts its names to fit. An address longer than the
  frame takes (2,048 characters: a long signed URL) ended in an error; the host
  reads the file instead. A refused `open` or `replace` is answered, where the
  file stayed loading and later replacements waited; a second `ready` is
  ignored; `confirmLink` is given the file on screen after a replacement; a
  file of the tree whose size is not known ahead is downloaded up to the 256 MiB
  the frame may be given, all fetches together; the host no longer needs
  `AbortSignal.any` (Safari 17.4).

## [0.0.3] - 2026-11-18

Many more formats and installers read, in place and in bounded memory at any
size; QR codes and a visible-text layer; a much larger viewer; and review
rounds that closed the cases where exav read a file differently from the
program that opens it. Fuzz targets went from 26 to 50, and a sweep reads
every fixture again with each length or count it declares set to an extreme.

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
  IFC files are also scanned as their visible text, with their links, for
  `Target:0` and `Target:7` signatures and `--detect phishing`
  (`visible-text`, on by default, off under `--clamav-compat`). PDF and
  legacy Office text are opt-in (`visible-text-pdf`, `visible-text-office`).
  `exav-grep --text` searches it.
- **QR codes** (`--qr`, off by default): the codes in images, documents and
  archives are matched as text and their links checked by
  `--detect phishing`. `exav-qr` prints them.
- **Read as the program that opens it.** ZIP, PDF, mail, PE, Office packages
  and a dozen other formats were read differently by exav in some cases; they
  now agree, and more of what exav cannot read is reported instead of
  answered `OK`.
- **Office documents converted in safe Rust** (`exav-render`, opt-in
  features `office-sheets`, `office-slides`, `office-docs`, `office`):
  legacy, OpenDocument and Apple spreadsheets, presentations, documents and
  drawings (ODG, Visio) to XLSX, PPTX and DOCX, which the viewer shows. Each
  file is bounded in input, memory and decompressed size, and one that cannot
  be converted is reported with its reason.
- **Smaller, faster binaries**: exav 25.2 MB to 16.7 MB, a corpus scan about
  8% faster. `cargo install` builds with the release profile (about 3 GiB of
  memory at its peak); `--profile fast-build` is the shorter build.
- **The viewer** opens many more files (camera RAW, JPEG XL, SVG, text,
  Markdown, JSON and XML, 3D models, older Office, more archives), tells a
  file by its bytes with exav's own detection, draws the pages of documents,
  drawings and models as pictures to export or print, can be driven by the
  host's own UI, and speaks German, Spanish and Dutch.

### Breaking changes

- Rust 1.95 or later (it was 1.92); every crate is edition 2024.
- Refused now: a `.cvd` whose header md5 does not match or that is cut short,
  a source with no end (`exav /dev/zero`, it was `OK`), a YARA rule nested
  more than 10 parentheses deep, and an HTTP answer whose
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
  address takes `?idle-secs=` (120 for clamd, 600 for ICAP; reads waited a
  fixed 60 seconds, writes forever), `?request-secs=` (600), `?session-secs=`
  and `?reply-secs=`.
- HTTP: `--http-timeout-secs`, `--http-max-redirects`,
  `--http-redirect-private`, `--http-spill`. A server that does not answer
  range requests has the object downloaded whole, up to `--max-input-bytes`.
- Scanning: `Target:3` and `Target:7` signatures match the scripts of an HTML
  page, as in clamscan; `EP` and section offsets resolve on ELF files, and
  section offsets on Mach-O, as clamscan resolves them (a signature anchored
  there never matched); an XLM macro's formulas are written as Excel shows
  them, with the defined names and text cells; a mail message inside a text
  or binary file is read,
  as ClamAV reads one; an ARJ archive inside another file is carved;
  `Heuristics.PDF.ObfuscatedNameObject` applies inside PDF object streams;
  `tlsh:` lines are matched against an installer's executable; `-v` shows
  `pe-imphash`.
- Split archives: RAR, ZIP and CAB volume sets are joined and scanned as one
  archive, in a directory, from one volume named alone (its siblings are found
  by name) and in the daemon (`EXINSTREAM MULTI`, `CONTSCAN`); a set with a
  volume missing is `UNSCANNABLE`, not clean. `@exav/unpack-wasm` has
  `volumeSet` and `joinSet`, and the viewer opens a part of a set with the
  rest of its folder.
- `exav-qr FILE...` (`cargo install exav-grep --features qr`) prints the QR
  codes in images and in what holds them.
- exav-unpack `-r` opens the archives inside an archive; exav-unpack and
  exav-grep take exav's cache and spill settings, read its `EXAV_*`
  variables and take `off` for no limit.
- Formats: RPM packages and `.lzma` files (`rpm`, `lzma`); the `ishieldcab`,
  `applesingle` and `ishieldmsi` features; LZFSE, LZVN and InstallShield Z
  in-tree; camera RAW, DDS, ICO and cursors, PLY, OBJ, glTF and more TIFF
  variants.
- Libraries: `exav_unpack::tree` (`Walker`, `Visitor`, `Typing`,
  `type_object`), the one walk of nested containers exav, exav-grep and
  `exav-unpack -r` share; `MemberMeta::reason_kind`,
  `Budget::set_rasters`. The readers the scanner and exav-render share are
  public in exav-unpack: `cfb`, `offcrypto`, `rtf`, `biff`, `charset`,
  `html` and `text`.
- Viewer: detection by exav in a worker (`sniffBytes`, `sniffTimeoutMs`,
  `FormatMismatch`); a ZIP's directory checked before it is opened
  (`maxExtractedBytes`, `maxMembers`, `maxCompressionRatio`),
  `maxArchiveEntries` and `maxEntities`; highlights on a PDF's pages and on a
  quote found in a text (`ViewerFile.highlights`, `focusHighlight`,
  `goToHighlight`); `linkQuietMs`; pictures of pages
  (`controllers.pictures`, `printPictures`); the files around a file
  (`tree`), where a drawing's external references and a glTF's buffers are
  found; the frame's `theme`, `keys` and `restyle()`; a sandboxed frame
  published for some formats only, with the files of their engines alone
  (`formats`, `--format`); an external converter hook; 233 freely licensed
  example files for the demo.
- exav.org/formats/: every format in one table, with what the scanner, the
  extractor and the viewer do with it, and the extractor's module and crates
  for it. `scripts/bench-speed.sh` compares speed with `clamscan`.

### Changed

- **Limits leave a part out and go on.** A member that decodes past
  `--max-object-bytes` at more than the compression ratio is left out, the
  members after it are scanned, and the container is `LIMITS-EXCEEDED` unless
  something is found. The ratio was asked of every member past 4 MiB.
- A member left out for its size is `LIMITS-EXCEEDED`, not `UNSCANNABLE`; a
  file a reader cannot parse is `UNSCANNABLE`, not `LIMITS-EXCEEDED`; a panic
  in a member is reported there and the rest of its container is scanned.
- A large file, a spilled member and an HTTP input are read once for all the
  checks, where each needed a read of its own: 4.1x the size down to 1.45x
  with YARA rules, 211 HTTP requests down to 110, and an executable carved
  from such an object no longer costs a read of its own. An object already
  scanned clean in the same place is scanned once per scan.
- `--clamav-compat` opens only what clamscan 1.4.3 opens (ZOO, StuffIt, ACE,
  WIM, the filesystem images and others stay closed; DMG is opened).
- Files are typed as ClamAV types them: one that starts with a mail header is
  a message, before HTML; an ARJ archive is told by its main header; a
  Markdown file that is not UTF-8 is windows-1252.
- `--max-unpack-depth 0` opens no container, in every CLI (exav refused it;
  the others reported every archive unreadable).
- exav-grep walks as the scanner does (depth limit, members read where they
  lie, split files, appended ZIPs) and reads a file past `--max-object-bytes`
  where it lies (it reported it unreadable). exav-unpack's `--max-memory` and
  `--max-size` are `--max-object-bytes` and `--max-extracted-bytes`; the old
  names still work.
- Names in reasons and locations have control and bidirectional characters
  replaced by `_` and are cut at 200 characters, in every CLI.
- `--build-db` counts as unsupported a logical signature whose PCRE neither
  regex engine builds.
- A daemon setting given only by its `EXAV_*` variable to a run without that
  listener is ignored with a warning.
- The Docker image names its user (65532) and is built on Alpine 3.23; the
  compose example runs it read-only, with every capability dropped and
  `no-new-privileges`. A pre-release no longer moves the `latest` tag.
- YARA: `pe.number_of_exports` counts the exports by ordinal alone too, as
  yara-x does.
- The PE emulator runs a module's TLS callbacks before its entry point, as
  Windows does, and its system DLLs list their documented exports.
- Dependencies at their latest versions, except the image decoders pinned to
  libclamav 1.5.4's and `zip` below 9.1; ruzstd is 0.9.1, which bounds what
  a block decodes to (RUSTSEC-2026-0344). The `exav` binary builds 19 crates
  fewer, and the QR reader is rqrr 0.11.0 vendored as `exav-qr` with
  `forbid(unsafe_code)`.
  `fuzzy_img` JPEGs are decoded by zune-jpeg 0.5.15: the hashes differ from
  libclamav's 0.5.8 only for baseline JPEGs with a scan for each component,
  and for the damaged files 0.5.8 panicked on.
- Viewer: text, CSV, TSV and a ZIP's directory are read by exav's readers in
  a worker; a CSV or TSV past 250,000 fields or 64 MiB of memory is refused.

### Fixed

- **Read as the program that opens it.** ZIP, PDF and its object streams,
  mail (folded and long boundaries, attached messages, base64 parts), ISO and
  UDF, `ar`, `cpio`, bzip2, xz, CAB, NSIS, PowerPoint, NTFS, MBR logical
  partitions, 7z and ARJ are read as their own tools read them, where exav
  differed in some cases. A ZIP behind a PDF, a tar or a gzip is found by
  its end record, as `unzip` finds it, and an ISO or ext image that starts
  with an archive's magic is walked as the image too.
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
  `UNSCANNABLE`, an XDP's character references are read, and an element
  whose name starts with `chunk` (`<chunk-id>`) is no longer read as a chunk.
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
  Setup installer before 5.1.5, a `.lzma` file cut short, and more.
- **A limit is not damage, and what decoded is scanned**: a 7z or SWF
  dictionary over `--max-object-bytes` is a limit (it was decoded with a
  smaller window and reported damaged); a member cut by the end of its
  archive, a RAR member whose header declares less than its stream, and what
  decoded before damage in RAR, ZIP, 7z, CAB, filesystems and CHM are
  scanned as far as they go. exav-unpack reports a cut member as an error, as
  tar and unzip do.
- **PCRE**: seven wrong answers of the backtracking engine (lookaround, back
  references, conditionals, atomic groups) are fixed.
- **Resource bounds** on executables' tables, YARA ranges and regexps, Excel,
  XAR, tar and RAR5 headers, Office conversion, Visio formulas, drawings,
  nested documents, PPMd, zstd, JPEG XL, JBIG2, bytecode, 7z headers, XML
  trees and password key derivations (7z, RAR5, disk images); recursive
  readers no longer overflow the stack.
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
- Phishing: a link whose `<a` is followed by a tab or a line break is
  checked, as browsers read it, and a domain under a country's two-label
  suffix (`co.uk`, `com.au`) is told from the others under it.
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
  directory, `-t` no longer says "No errors detected" after an error, and a
  closed pipe (`exav-unpack -l x.zip | head`) ends it with status 141, not a
  panic.
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
