# Changelog

Notable changes per release. Dates are release dates; the format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) loosely, and versions
follow [semantic versioning](https://semver.org/).

## [Unreleased]

### Changed

- A file larger than `--max-object-bytes` (256 MiB by default) gets the full
  scan: wildcard and logical signatures, PCRE, YARA, bytecode, normalised text,
  carving, embedded payloads and heuristics, read through an 8 MiB block cache
  instead of held in memory. It got a literal-and-hash pass only. So does its
  archive's own bytes, and an archive member that large once it is spilled to
  disk; with `--spill-dir off` such a member is not scanned, and the file is
  `LIMITS-EXCEEDED`. What still needs the object in memory (PE structure: EP and section
  offsets, section hashes, imphash, icons, Authenticode, UPX and packer
  unpacking; YARA's `pe`, `elf` and `dotnet` modules; containers read whole,
  such as RAR, 7z or OLE) makes the file `LIMITS-EXCEEDED` naming the size
  limit, unless something is found.
- `--max-object-bytes` no longer decides which signatures run, only what may
  be held in memory at once.
- A DMG is walked without decompressing its whole disk, so an image whose disk
  is larger than `--max-object-bytes` gives up its files; it was refused as
  `LIMITS-EXCEEDED`. Each file is still held whole, under the same limit. A
  file the image holds but that cannot be read out of it makes the scan
  `UNSCANNABLE` unless something is found; it was skipped. LZ4 and Unix
  `compress` (`.Z`) are decoded as they are read, as gzip is, instead of
  whole.
- `--all-matches` and `ALLMATCHSCAN` list every detection at any size; past
  `--max-object-bytes` they fell back to a single match. Past
  `--max-input-bytes` they list what the first bytes hold and report the rest
  unscanned, as a single-match scan does; they fell back to a single match
  there too, without saying the search stopped short.
- Every environment variable without a flag is named `EXAV_DEBUG_*`:
  `EXAV_BC_WARN`, `EXAV_BC_TRACE`, `EXAV_BC_FN` and `EXAV_FORCED` are
  `EXAV_DEBUG_BC_WARN`, `EXAV_DEBUG_BC_TRACE`, `EXAV_DEBUG_BC_FN` and
  `EXAV_DEBUG_BC_FORCED`; `EXAV_YR_BIN`, `EXAV_YARA_CORPUS` and
  `EXAV_YARA_BENCH_RULES` (tests and examples) are `EXAV_DEBUG_YR_BIN`,
  `EXAV_DEBUG_YARA_CORPUS` and `EXAV_DEBUG_YARA_BENCH_RULES`.
  `EXAV_SPLIT_MATCH`, `EXAV_VERIFY_BUDGET`, `EXAV_SIM_BUDGET` and
  `EXAV_YARA_NO_GATE` are gone, along with the backtracking signature verifier
  `EXAV_SPLIT_MATCH=0` selected.
- The `exav-unpack` command has `unzip`'s command line, as a subset: every
  option it takes means what it means to Info-ZIP `unzip` 6.00 (`-l`, `-t`,
  `-p`, `-c`, `-Z1`, `-d`, `-x`, `-o`, `-n`, `-P`, `-j`, `-C`, `-q`, `-D`), an
  `unzip` option it does not take is an error, and its exit statuses are
  `unzip`'s. `exav-unpack ARCHIVE` extracts; the `list` and `extract`
  subcommands are gone (`-l`; `-d DIR`). It extracts every format the library
  reads, writes each member as it is decoded rather than holding the archive
  and its members in memory, restores ZIP and tar times, permission bits and
  symbolic links, never writes through a link, and asks before replacing a
  file. A ZIP split by `zip -s` (`.z01`, ..., `.zip`) and a RAR volume set
  (`.part1.rar`, ... or `.rar`, `.r00`, ...) are read from any part, and
  `--volume` names parts that are elsewhere.
- Releases carry `exav-unpack`, `exav-grep` and `exav-pe-emu` archives beside
  `exav`'s, and every archive carries `LICENSE` and `NOTICE`.
- `--partial-as password-protected=found` reports any encrypted member as
  `Heuristics.Encrypted.*`, as ClamAV's `--alert-encrypted` does: one exav
  decrypted with a password, and one whose encryption flag is set over plain
  content (APK packers set it on every member), included. A detection in the
  content still wins. Before, a scan without `--all-matches` reported neither,
  and a falsely flagged member was not even `.cdb`-matchable as encrypted.
  `PASSWORD-PROTECTED` is still only content exav could not decrypt. For a ZIP
  member the alert reads the local header as ClamAV does (bit 0 set, bit 13
  clear), and a `.cdb` encryption field matches either the local header or the
  central directory record; both read only the central directory before.
- A YARA pattern keeps at most a million matches, as yara-x does; one with more
  makes the scan `LIMITS-EXCEEDED` unless a rule matches.
- exav-core: `ScanOptions::spill` gives a scan somewhere to write what it makes
  of an object too large to hold (see the `spill` module); `exav` passes its
  `--spill-dir` files and budgets. `analyze_all_seekable` is the all-match scan
  over a seekable input. `unpack::source` exposes random access over an object
  not held in memory.
- Every object goes through one pipeline, the input and whatever is unpacked,
  decoded or carved out of it, at any size and depth:
  - An archive's members are scanned before its own bytes at every depth, so a
    detection in a member stored in a nested archive names the member; the
    nested archive's own bytes were matched first.
  - The buffers a bytecode unpacker makes are scanned as objects, carving and
    heuristics included, under `--max-unpack-depth` and `--max-matcher-bytes`;
    they had a separate path capped at 4 levels and 256 MiB.
  - The `.fp`/`.sfp` allowlist applies to every object, decoded payloads and
    carved images included.
  - YARA's filename externals are set for a top-level archive and under
    `--all-matches`, as for any other top-level file.
  - The signature engine is the only matcher: the separate literal automaton
    for large inputs is gone. The `.exavdb` format is at version 4; rebuild
    with `--build-db`.
- exav-unpack: `walk(fmt, source, budget, visit)` is the one walk. A member
  comes as `Member::Bytes` or, decoded as it is read, `Member::Stream`;
  `Member::into_bytes` reads either whole, and `MemberMeta::size` is the size
  the archive declares. `walk`, `detect`, `extract` and the heuristics take a
  `ByteSource` (a slice, a `Vec`, or a `source::BlockCache` over a reader).
  Removed: `extract_each`, `Sink`, `stream_members`, `StreamVisit`,
  `is_streamable`, `BudgetReader`, `Archive`, `MemberInfo`, the `*_source`
  variants and `source::Slice`. exav-core: `patterns::PatternSet` and
  `LoadError::Patterns` are removed.
- A streamed member is held to the compression-ratio guard, as a member
  decoded whole is.
- `ScanOptions::deep_analysis_max` also holds `Limits::max_buffer_bytes` for a
  scan, so no object is held in memory past it.
- exav-unpack-wasm: `list()` decodes nothing it can avoid, and reports
  `uncompressedSize` as the archive declares it, -1 where it declares none;
  `extract(i)` walks the archive up to member `i`.
- YARA detections are named `YARA.<rule>` outside `--clamav-compat`; the
  `.UNOFFICIAL` suffix is compat-only, as for every other signature.
- A signature reload lets scans in progress finish: old workers and the old ICAP
  child exit once idle instead of being killed. One still busy after
  `--max-scan-secs` plus 5 seconds (an open session, a client that never
  finishes) is stopped.
- A worker stopped mid-job (shutdown, reload deadline, supervisor gone) answers
  the job with `ERROR` instead of closing the connection without a reply.
- `off` and `0` on `--max-object-bytes` and `--max-matcher-bytes` mean no limit,
  as their help said; they used to set a limit of zero.
- Every input goes through one scan: a file, stdin, a FIFO given as a path,
  `INSTREAM`, `EXINSTREAM`, ICAP and `http(s)://`. In particular:
  - Past `--max-input-bytes`, the first bytes get the whole scan. A file got
    only literal signatures and hashes there, and stdin and the daemon's stream
    verbs no scan at all.
  - A stream larger than the spill budgets is scanned as far as it was held and
    reported `LIMITS-EXCEEDED`. It was `UNSCANNABLE`, unscanned.
  - Both follow `--partial-as` as a file does; under `found` they are
    `Heuristics.Limits.Exceeded.MaxFileSize` everywhere.
  - A container over `--max-object-bytes` gets the full scan over its own
    bytes on every entry point, not only a file path.
  - Stdin honours `--all-matches`, `--profile` and `--max-process-bytes`, and
    counts in the summary.
- exav-core: `scan_stream` is removed (the one scan is `scan_seekable`, and
  `scan_path` hands a file to it); `warm_up` builds the lazily-initialised
  structures before a fork.
- A stream that ends before its terminator is answered `ERROR` on `INSTREAM`
  and `EXINSTREAM`, whatever `--partial-as` says. `EXINSTREAM` used to answer
  `PARTIAL` with a `TRUNCATED` category, and `INSTREAM` `UNSCANNABLE`.
- A compressed stream damaged part way (gzip, ZIP, PDF, embedded PowerPoint
  storages) is `UNSCANNABLE` when the part before the damage holds no
  detection, wherever it sits; a checksum mismatch after a full decode is not.
  Nested in another container it used to be `OK`, and a gzip with only a bad
  CRC was `UNSCANNABLE` at the top level.
- The daemon's signals match clamd's: `SIGUSR2` reloads the signatures and
  `SIGHUP` reopens the `--log` file (for logrotate), under the worker pool, the
  thread model and ICAP alone. Both used to kill the process.
- `--workers threads` and an ICAP-only listener reload on `SIGUSR2`, `RELOAD` and
  a change in the signature directory, as the pool does.
- The systemd unit is `exav.service` (it was `exav-clamd.service`). It reads
  `/var/lib/clamav`, reloads with `systemctl reload exav` (`SIGUSR2`), and says
  how to stop `clamav-daemon.socket` alongside `clamav-daemon`.
- `--max-extracted-bytes` is removed. What a scan holds is 1 GiB (400M under
  `--clamav-compat`), and `--max-process-bytes` lowers it to what fits the
  memory a scan gets. The flag, or `EXAV_MAX_EXTRACTED_BYTES`, stops the run with a
  message naming the change. It also set the largest object held in memory, so
  `--max-extracted-bytes 0` loaded any file whole.
- `--max-process-bytes` also lowers `--max-object-bytes` to a quarter of the
  memory a scan gets, and the total held to what leaves room for an image
  decoded from the largest object and its grey copy plus a tenth, so a file
  past them is `LIMITS-EXCEEDED`; it was `out of memory ERROR`. The default 2G
  changes neither the default limits nor `--clamav-compat`'s.
- Matching an object no longer copies it whole. PCRE subsignatures ran over a
  Latin-1 string of the object, up to twice its size, and case-insensitive
  bodies over a lowercased copy: the first now match the bytes directly, the
  second lowercase what they read past 16 MiB. A crafted image no longer takes
  more memory than an object may: its decoded pixels are held to
  `--max-object-bytes` (past it, and short of the 512 MiB ClamAV decodes, the
  scan is `LIMITS-EXCEEDED`), and it is turned grey
  without a full-size RGB copy. A decoder panic leaves the image unhashed
  rather than stopping its scan.
- `0` and `off`, flag by flag: `--max-members 0`/`off` and
  `--max-jobs-per-worker 0`/`off` mean no limit; `--max-unpack-depth` and the
  `--dlp-` counts refuse `0` (and depth refuses `off`); `--update-interval-secs
  off` fetches at startup only; `--spill-threshold-bytes`, `--icap-idle-secs`
  and `--icap-max-header-bytes` (at least `1K`) have no `off`;
  `--icap-preview-bytes off` and `--icap-options-ttl-secs off` leave their
  header out of the `OPTIONS` answer.
- `--quiet` keeps error lines, and error lines are written to `--log`; the
  summary counts `Partial files` apart from `Total errors`.
- A scan that fails behind the ICAP listener is a block, with
  `X-Exav-Status: ERROR` and `Heuristics.Exav.ScanError`.
- A bytecode program that runs out of instructions makes the scan
  `LIMITS-EXCEEDED` unless something else is found. So does one stopped by an
  opcode or host API exav does not model, or by the interpreter's call-depth or
  frame-size cap; its result was discarded as though it had found nothing. A
  program's own fault (an out-of-bounds access, a division by zero) is still
  discarded, as ClamAV discards it.
- Bytecode follows ClamAV 1.4.3 in four more places:
  - A program that aborts has its detection discarded; it was reported.
  - `malloc` returns NULL from 128 MiB less 8 bytes; it allocated up to
    256 MiB.
  - `__clambc_pedata` reads as zeros on a file that is not a PE; reading it
    discarded the program's result. On a PE that exav has no header data for
    (too large to load, or not parsed), it makes the scan `LIMITS-EXCEEDED`
    unless something else is found.
  - What a program wrote before its run failed is scanned; it was dropped
    with the program's detection. A program that asks `disasm_x86` about bytes
    the decoder does not know now stops there, so nothing it writes after that
    point is scanned.
- A bytecode program that writes more than 256 MiB into one extracted file
  makes the scan `LIMITS-EXCEEDED` unless something else is found; the rest
  of its output was dropped silently.
- A bytecode `write` fails with -1 once one extracted file would pass
  `--max-object-bytes`, or the run's output would pass what is left of
  `--max-matcher-bytes`, as ClamAV's does at its file and scan size limits.
  The program carries on and the scan is `LIMITS-EXCEEDED` unless something
  else is found; the write used to succeed.
- The `docker-compose.yml` example publishes the clamd port on localhost only.
- `make lint` runs the clippy passes CI runs, and `make test-www` checks that
  every internal link and anchor of the documentation site resolves.
- A signature path that loads nothing is an error: one that does not exist, or a
  directory holding only a prebuilt `.exavdb` (load that with `-d`).
- `clamscan`'s `--alert-encrypted`, `--alert-encrypted-archive`,
  `--alert-encrypted-doc` and `--alert-exceeds-max` are refused with the
  `--partial-as` value that replaces them.
- The `exav` crate's `checksums` feature is removed; no flag used it.
- exav-unpack: the bzip2 decoder is vendored from `bzip2-rs` (with the fix
  below) instead of depending on it; the internal `bzip2-decoder` feature
  groups it. ALZ and EGG decode their bzip2 and LZMA members in a build without
  the `bzip2` and `lzip` features.
- A build without the `yara` feature warns when rule files are loaded; they
  never match.
- A long run of one byte value costs the signature engine about what its first
  few hundred bytes do. The search skips the run's interior, and a signature
  anchored inside it is checked once for the whole interior and one position at
  a time only near its edges. Where several matches lie inside one run, a
  first-match scan may report a different one of them.
- Scanning is faster on ordinary files too:
  - The signature engine finds its signatures through one index of their
    literal anchors, looked up at each position of the object, instead of
    running automatons (four for a PE) over it. An anchor longer than five
    bytes is indexed by the seven of its bytes the signatures share least,
    looked up at every other position.
    Case-insensitive anchors are looked up on the bytes
    lowercased as they are read; the object is copied lowercased only when a
    case-insensitive signature has to be checked.
  - A signature whose offset window is at most 4096 bytes wide, counted from
    the start, the end, the entry point or a section, is checked where it can
    start, not searched for through the object.
  - A PE section's MD5 is computed only when a section-hash signature names
    its size.
  - The bytecode interpreter lays out a function's values once per run rather
    than at every call, and reads and writes them whole.
  - Bytecode triggers are matched in the same sweep as every other
    signature, not in a second sweep of their own.
  - A literal a signature searches for after a gap is looked up in the
    blocks of the object its check reaches, each searched once per scan, not
    through the whole object the first time it is met.
  - Whole-file digests are computed once for the allowlist and the hash
    signatures together, and only those some signature of the object's size
    can match: most objects need no SHA-1 or SHA-256 at all, and SHA-256 uses
    the processor's instructions where it has them.
  - The group cost check is skipped until a group passes its cap.
- An object read through the block cache, such as a large file or one fetched
  over HTTP, is read far fewer times over: format detection's search, carving
  and the digests share one read of it, the signature sweep is a second,
  carving confirms an archive by its first bytes, and YARA's prefilter looks
  up its atoms in one read and its literal and base64 patterns share another. Over HTTP, a request that
  continues the previous one fetches twice as much, up to 8 MiB.
- A prebuilt database loads faster: the signature index, anchor groups, hash
  tables and the indexes derived from the signatures are stored as the build
  made them and read back with a copy, the file is read once rather than once
  to check its digest and again to decode it, and the bodies and logical
  signatures decode on threads of their own while the index is read. The file
  is smaller, and building it takes less memory. Its trailer is a CRC-32 of the
  contents instead of a SHA-256: it is there to catch a torn or damaged file,
  which is all the digest was checked for.
- `--build-shard-bytes` is removed: the signature index has no automaton to
  split, and builds in far less memory. The flag, or `EXAV_BUILD_SHARD_BYTES`,
  stops the run with a message naming the change. exav-core:
  `loader::load_with_options_mem` and `Builder::set_max_build_mem` are removed.
- Bytecode triggers are evaluated with the object's container, as every other
  logical signature is, so a trigger with a `Container:` condition can fire.
  exav-core (`unstable-internals`): `BytecodeRuntime::from_sources` adds the
  triggers to the `EngineBuilder` it is given, and `BytecodeRuntime::standalone`
  builds a runtime with an engine of its own, for tools.
- A first-match scan meets first the signatures their offsets pin, then the
  others in the order the object's bytes hit them, rather than one file-type
  automaton after another, so when several match it may report a different
  one of them. Carving keeps the first
  candidates of each kind by position when more than its cap are found.
- The RustCrypto crates move to their current generation (`digest` 0.11,
  `cipher` 0.5: `sha2`, `sha1`, `md-5`, `aes`, `cbc`, `des`, `hmac`, `pbkdf2`).
- Dependencies: `bincode` (unmaintained, RUSTSEC-2025-0141) and `serde` are
  gone from `exav-unpack`, the encrypted-DMG header being read field by field;
  `tlsh2` 1.x; `ext4-view` 1.0 (panics and infinite loops on corrupt
  filesystems fixed upstream); `lzma-rust2` 0.21 (malformed-input fixes
  upstream); `ureq` 3 for the `http` features, which drops `url` and the ICU
  crates from that build and, as ureq 3 does by default, follows the
  `HTTP_PROXY`/`HTTPS_PROXY`/`NO_PROXY` environment.

### Added

- `exav-imagehash`, a crate and a command of its own: perceptual image hashes
  with every step a parameter, and presets equal to `sigtool --fuzzy-img`
  (ClamAV's `fuzzy_img` hash, which the scanner now computes through it) and
  to Python `imagehash.phash`. No `unsafe` in it, its image decoders or its
  DCT (rustdct's, vendored); its checksum and cast dependencies do use some.
- The `image-hash` build feature (on by default): without it, `fuzzy_img#`
  signatures load as unsupported and no image is decoded.
- `--max-pcre-bytes`: the largest object PCRE subsignatures run on, as
  ClamAV's `PCREMaxFileSize` (`clamscan --pcre-max-filesize`), per object. No
  limit by default; 100M under `--clamav-compat`, ClamAV's default.
- `--min-scan-bytes` (default 6): an object smaller than this, file or
  member, is not scanned and counts as clean, as ClamAV scans no object under
  6 bytes. Such objects were scanned, so a 3-byte signature body could match
  a 5-byte file ClamAV reports clean. `0` scans every object, as before.
- `--max-pe-emulation-steps` (default 1,000,000,000): instructions the PE
  unpacking emulator may run across one top-level file, reported as
  `LIMITS-EXCEEDED` / `Heuristics.Limits.Exceeded.MaxScanTime`.
- An encrypted ZIP appended to a picture or document is reported
  `PASSWORD-PROTECTED` when its central directory checks out.
- `make miri`.
- ZIP Shrink, Reduce and Implode members (methods 1 to 6) are decoded; they were
  `UNSCANNABLE`.
- `.msu` databases (the PUA section-hash list) load under `--detect pua`.
- The `phishing` feature on `exav`, in its default set.
- The WASI binary (`exav-core --features wasi-bin`) loads a signature directory
  as the CLI does, reports each result as JSON with the file name, and exits
  0/1/2/3 like `exav`.
- A guide to sizing a server, with the flags for a 4 GB host.
- `exav_unpack::Prescan` and `exav_unpack::detect_prescanned`: detection's
  search through an object not held in memory, fed by the caller's own read of
  it, so that one read serves detection and the caller's searches.
  `exav_unpack::detect_archive_start`: the archive an object starts with, from
  its first bytes alone, for an archive carved out of another object.
- `exav_unpack::MemberMeta` and `Entry` carry a member's modification time
  (`Mtime`), Unix mode and link target where ZIP or tar records them, and
  `MemberMeta::zip_method`; both implement `Default`.
  `Budget::set_visit_directories` has a walk visit directory entries.
  `exav_unpack::span::ZipSpan` reads a `zip -s` split set as one archive, and
  `exav_unpack::join_rar_volumes` joins a RAR volume set into one archive. The
  `cli` feature (default) builds the `exav-unpack` command and is the only one
  that pulls in `chrono`.
- Encrypted RAR archives are decrypted with the caller's passwords and the
  defaults tried on ZIP (`infected` and the like): RAR5's AES-256 and RAR
  2.9-4's AES-128, file data and, under `rar -hp`, the headers too. A member
  decrypted is still reported encrypted. They were all `PASSWORD-PROTECTED`.
- A RAR5 hard link or file copy is the member it names; it was empty.
- RAR5 headers written for the RAR 7 algorithm: 80 distance codes, and
  dictionary sizes that are not a power of two.

### Fixed

- A crafted ARC member (69 bytes is enough) made the scan allocate until it
  ran out of memory: its LZW decoder accepted a code past the next free one,
  which could make a code its own prefix. Such a member is now reported
  undecodable.
- A ZOO member compressed with LZD was decoded to whatever size its stream
  expanded to, not the size it declares, which is what the budget checks: a
  megabyte member could take gigabytes. Decoding stops at the declared size,
  and the member is reported.
- The PE emulator panicked on a packed file whose import directory, or an
  output structure it passes to an emulated Windows call, runs past 4 GiB.
- The x86 decoder sized UMONITOR's register by the operand size rather than
  the address size, and accepted gathers and scatters under an address-size
  prefix, and gathers whose registers overlap, all of which a processor
  refuses.
- A RAR5 archive whose headers are encrypted (`rar -hp`) was read as having
  no members, so it scanned clean. Without a password that opens it, it is
  `PASSWORD-PROTECTED`.
- An encrypted stored RAR5 member was handed over as its ciphertext, as
  though it were the file, and not reported encrypted.
- In a RAR archive every member was decoded on the first member's window, so a
  later member whose dictionary is larger failed its CRC and was not scanned;
  each member that is not solid now gets its own. A RAR5 header's dictionary
  size was read from 4 of its 5 bits.
- The x86 and Itanium (RAR 2.9-4) and x86 and ARM (RAR5) filters converted
  addresses relative to the start of the first member decoded, not of their
  own member, so an executable after it in the archive failed its CRC.
- In a solid RAR 2.9-4 group, an empty member left the next one decoding from
  the middle of the stream; a PPMd block header that sets no escape symbol had
  it reset to the default instead of kept; and a member following one that
  ended in PPMd was read without the block header it starts with. Each failed
  every member after it.

- Scanning a URL took a server that answered a range request with the whole
  object (`200` instead of `206`) as the range, and scanned bytes from the
  start of the object as though they were from the offset asked for. It is
  an error now.
- A ZIP member whose compression method is a value no specification defines
  is read as Android reads it, stored and its uncompressed size long; it was
  `UNSCANNABLE`. APK packers give `AndroidManifest.xml` such a method, often
  with a compressed size shorter than the data, so that other tools skip it.
- NSIS installers compressed with bzip2 are decoded: NSIS's bzip2 has no
  stream header, marks blocks with one byte and carries no checksums, so every
  block was `UNSCANNABLE`. And the CRC-32 at the end of an installer was read
  as one more block, which made every installer built with a CRC (NSIS's
  default) `UNSCANNABLE` whatever its codec.
- A file in an HFS+ disk image with a resource fork is reported
  `UNSCANNABLE`: only data forks are read, and a file macOS compressed keeps
  its bytes in its resource fork with an empty data fork, which was scanned as
  an empty file.
- The daemon's watch of its signature source missed changes. It compared only
  the newest mtime, which a filesystem stamping from a coarse clock gives a
  file written within one tick of the last change, and it took its baseline
  after the database had loaded and the workers had forked, so a file a
  sidecar wrote in between was part of it. Either way the new signatures were
  not loaded until the source changed again. The watch now compares every
  entry's name, size, mtime and inode, against a baseline taken before the
  load.
- A ZIP with other bytes before it whose offsets count from its own start (a
  self-extractor's payload, an archive appended to another) was located from
  the first central directory found after its declared offset, which, with
  two archives back to back, is the first one's; every member was read at
  the wrong place and reported `UNSCANNABLE`. The directory is now located
  from the end record, as Info-ZIP does.
- An executable holding the 7z signature in its own data (a tool that handles
  7z) was carved as a self-extractor with a broken archive and reported
  `UNSCANNABLE`. A 7z candidate is taken only when its start-header CRC
  checks out, as 7-Zip requires.
- A PE whose full parse fails over one malformed directory (a certificate
  table sized past the end of the file, say) had no section hashes, icon,
  entry-point layout or bytecode PE data, and each bytecode program reading
  that data left the scan `LIMITS-EXCEEDED`. Those come from the headers and
  section table now, read without the directories.
- A PDF stream that fails to decode from its first byte has its raw bytes
  scanned, as ClamAV does, and is still reported `UNSCANNABLE`. Nothing of it
  was scanned, so a ZIP behind a `/FlateDecode` filter went unopened.
- An object embedded in an Office document as a package (`Ole10Native`) with
  its temp path counted, as Office writes it, was carved from the middle of
  its header, so a document or executable inside was never recognised.
- A VBA project whose compressed chunks have signature bits other than the
  fixed `0b011` is decoded, as Office runs it; the whole project was dropped,
  and with it every macro signature and `Heuristics.OLE2.ContainsMacros`.
  Emotet documents do this.
- A compound file read by the lenient reader (a malformed directory, which
  the strict one refuses) keeps each stream's path; its VBA project, found by
  its `VBA` storage, was never assembled.
- A stream of a malformed compound file whose sector chain ends before the
  size its directory entry gives was reported cut short by the size budget,
  and the file `UNSCANNABLE`; there is nothing more of it to read.
- An encrypted workbook embedded in a document, as Excel stores an inserted
  workbook, is decrypted too; only the first workbook stream was looked at.
- An encrypted workbook or Word document exav cannot decrypt still has its
  other streams scanned: only the document stream is encrypted, and the VBA
  project beside it went unscanned.
- A GIF whose extension sub-block runs past the end of the file was taken for
  a well-formed image; under `--detect broken-media` it is
  `Heuristics.Broken.Media.GIF.TruncatedExtensionSubBlock`, as ClamAV names it.
- HTML (`Target:3`) and text (`Target:7`) signatures matched raw bytes as
  well as the normalised renderings they are written for, mail (`Target:4`)
  ones any text-like file, and a text file was also matched through an HTML
  rendering (entities decoded) and an HTML file through a text one. Each now
  matches where clamscan's does: 3 the HTML rendering of an HTML file, 7 the
  text rendering of a text file, 4 a mail's raw bytes. An RTF keeps both
  renderings, as before.
- `--detect broken-media` checks a JPEG as ClamAV does, which crafted inputs
  showed differs from the format's rules: a file is checked only from 6 bytes
  and `FF D8 FF`; up to 14 bytes of junk before a marker are skipped; every
  marker up to the start of scan carries a length, checked against the file,
  the start of scan's own included; and JFIF and SPIFF headers have
  their position checked, after nothing but comments and APP1 segments. Only
  an APP0 saying `JFIF` counts as one, so a JFXX thumbnail after it is no
  longer a duplicate. `JPEG.NoImages` and `JPEG.CantReadMarker`, which ClamAV
  did not report on any of them, are gone.
- `fuzzy_img#` hashes are computed with the image decoders ClamAV 1.4.6 and
  1.5.4 ship (image 0.25.9, zune-jpeg 0.5.8). The older JPEG decoder exav used
  gave a different hash for 116 of 9,751 photos, so a signature for one of
  them did not match; the hashes now equal `sigtool --fuzzy-img`'s on all of
  them, and on TIFFs of 31 encodings. The JPEG decoders, the one TIFF uses
  included, are built without their SIMD code, their only `unsafe`; they
  decode the same pixels.
- Under `--clamav-compat`, a WebP image matched `Target:5` (graphics)
  signatures, which clamscan's do not: its graphics are PNG, GIF, JPEG, TIFF
  and BMP, and those five are also the only images it hashes for `fuzzy_img#`.
  Otherwise a WebP, ICO, PNM, QOI, DDS, farbfeld or HDR image is graphics too,
  and hashed as `sigtool --fuzzy-img` hashes it.
- PCRE subsignatures matched differently from ClamAV's PCRE2 on bytes above
  0x7F and on PCRE syntax the Rust regex engines read otherwise: `\xe9` matched
  é's UTF-8 encoding instead of the byte, `.`, `[^a]` and `\W` missed high
  bytes, `$` did not match before a final newline (a signature ending
  `</svg>$` missed most SVG files), octal escapes such as `\0` or `[\22]` left
  the signature unable to compile, `\<` was a word boundary, `\v` a vertical
  tab and `\h` a hex digit. Each pattern is now parsed with PCRE2's grammar and
  rewritten in a subset both engines read as PCRE2 does, each construct
  settled against clamscan; one with no exact equivalent leaves its signature
  unsupported and counted (none of the 1,220 in the official databases). The
  `x`, `E`, `U` and `A` flags were ignored and are applied.
- A PCRE subsignature with an offset was looked for from the start of the
  file and kept when a match started at the offset, so an earlier match
  overlapping it hid it. As in ClamAV, the part from the offset on is now the
  subject (`^`, `\A` and a lookbehind start there), the match starts at the
  offset unless `r`, a shift bounds where it starts and `e` where it ends.
- A PCRE subsignature with `g` counted once, so a logical signature
  requiring it more than once (`1>3`) never fired; it counts every match.
- A CHM decoded only the first 32 KiB frame of each LZX reset interval and
  left the others zeroed, so a page or image past it was scanned as zeros or
  as a cut-off file (a help file's PNG came out `Broken.Media.PNG`). Every
  frame is decoded, and an entry over a frame that fails is reported rather
  than zero-filled.
- An encrypted DMG whose header declares a salt longer than 32 bytes or a key
  blob longer than 64 panicked in its decoder; it is reported corrupt.
- A revision 4 encrypted PDF (AES-128, or RC4 under a crypt filter) whose
  permissions allow assembling the document, qpdf's default, was taken to
  leave its metadata unencrypted, which changes the key: the empty password
  never matched and the file was `PASSWORD-PROTECTED`, its content unread.
  A crypt filter's key length written in bits, as the specification gives it,
  is read as bits; it was read as bytes only.
- A PDF encrypted with a 40-bit RC4 key had its streams and strings decrypted
  with a 5-byte object key instead of the 10-byte one the format derives, so
  what was scanned was garbage, and an object with a generation number other
  than 0 was decrypted with the wrong key at any key length.
- A PDF stream whose `stream` keyword is followed by spaces before its line
  end had the spaces taken as data, so its FlateDecode content was not decoded
  and the file was reported `PARTIAL`; 0.0.1 decoded from a later 0x78 byte and
  scanned the garbage.
- The end of line before a PDF stream's `endstream` was taken as data, so an
  empty stream (`/Length 0`) was reported undecodable.
- An executable inside an OLE2 file (Word, Excel, MSI) was carved only from the
  stream holding it. It is also carved from the file's own bytes now and
  scanned to the end of the file, as ClamAV does, so a signature that matches
  what follows it in the file finds it (`Win.Loader.Covenant-10058832-0` on a
  Word dropper, for one).
- Typing an archive not held in memory read its first 4 MiB even when its
  first bytes named it, so exav-unpack-wasm's `Archive.open` over a `File` or a
  `{ read, size }` reader fetched a small archive whole before listing it.
- A `.db` file with one line exav cannot read loaded none of its signatures.
  The line is skipped on its own, and counted with every other signature exav
  could not load (`Unsupported sigs skipped` in the `-v` summary), as is a
  `.cbc` program that does not parse.
- A URL target exav will not scan (no `--allow-http-scan`, or a build without
  `http-scan`) is written to `--log` and reported as a JSON record, as any other
  error is.
- The scan summary's `Data scanned` (`data_scanned_bytes` in JSON) counts the
  first `--max-input-bytes` of a larger input, the bytes actually scanned,
  rather than its whole size.
- A top-level archive now gets the full engine over its own bytes (wildcard and
  logical signatures, YARA, bytecode, whole-file hashes), as a nested one did, on
  every entry point including stdin, `INSTREAM` and ICAP.
- `.ign`/`.ign2` entries and `.fp`/`.sfp` allowlists apply on every scan path,
  and an ignored signature no longer hides a later detection in the same file.
- ZIP members absent from the central directory are scanned on the streamed path
  the top-level scan takes.
- Clean ZIP members compressed with LZMA, bzip2, XZ, zstd or Deflate64 were also
  reported as an unsupported codec on the streamed path.
- `.db` signatures were never matched; PUA literal signatures matched without
  `--detect pua`.
- A read error from the source is reported instead of being taken for the end of
  a container, for every format.
- A self-extracting executable whose archive starts past `--max-object-bytes`
  was typed as one and then walked for nothing; the archive is found as far
  into the file as it was detected.
- A signed PE whose sections run past the end of the file no longer panics the
  Authenticode check a loaded `.crb` database runs; its signature does not
  cover it.
- An LHA member compressed with a method there is no decoder for makes the scan
  `UNSCANNABLE` unless something is found; it was skipped.
- A job stopped by `--max-scan-secs` is answered `LIMITS-EXCEEDED` instead of the
  connection closing with no reply.
- A YARA rule set that runs out of evaluation steps makes the scan
  `LIMITS-EXCEEDED` instead of a silent non-match.
- A reload no longer adds a worker to the pool for every worker it retires.
- A worker exit, `RELOAD` or shutdown signal that arrives while the daemon's
  supervisor is busy is handled at once, not up to 10 seconds later.
- `EXINSTREAM` answers a stream it cannot hold with a verdict, as `INSTREAM`
  does, instead of an error; `EXINSTREAM MULTI` answers that file alone and
  continues.
- A FIFO given as a path is scanned; it was an `Illegal seek` error.
- The daemon reads its cgroup memory limit from its own cgroup and its parents.
- Percent-encoded credentials in update URLs are decoded before use.
- The signature count no longer counts literal signatures twice.
- What a deflate stream (gzip, ZIP, PDF, PowerPoint storages) decoded in the
  read that met damage, tens of KiB, was dropped unscanned; a detection just
  before the damage was missed.
- The bytes a damaged CAB or ZOO member decoded before the damage are scanned;
  they were reported as scanned and skipped.
- The `ole` feature builds on its own.
- The files of a UDF-only ISO image are scanned; the image was reported `OK`
  without them. A corrupt ISO 9660 directory record is reported instead of
  hiding the entries after it.
- UDF 2.50 and later images that keep their tree in a metadata partition are
  read, through the metadata file or its mirror. The partition holding the file
  set was read from the wrong bytes of the volume descriptor.
- An ISO or UDF image, or a self-extracting executable, larger than
  `--max-object-bytes` is walked member by member. It got the literal and hash
  pass only.
- `--dlp-credit-cards`, `--dlp-ssns` and `--detect phishing` cover textual
  objects past 16 MiB, which they skipped, and phishing checks every link in a
  document, not the first 4096. A link with no `href` no longer borrows the next
  link's.
- The deobfuscated JavaScript view of a script runs to 32 MiB, up from 8 MiB. A
  script whose view is longer is `LIMITS-EXCEEDED` unless something is found;
  the view was cut without a word.
- The JavaScript normaliser reads a script in one pass instead of holding it as
  a token list: scanning a 30 MiB script peaked at 1.8 GB and now at 100 MB.
  Nested decode calls unroll at any depth (they stopped after 24 levels), and
  `eval` layers up to 32.
- `--detect phishing` did nothing in a build of the `exav` crate alone, which
  includes the published image and `cargo install exav`: the feature was not
  forwarded to `exav-core`.
- `ALLMATCHSCAN`, and `exav --connect --all-matches`, answered a file that was
  not fully examined without `ERROR`, so a client read it as clean. It follows
  `--partial-as` as `SCAN` does.
- A zstd file of several frames had only its first frame scanned.
- A bzip2 stream with an incompressible block was `UNSCANNABLE`, for `.bz2`, ZIP
  method 12, 7z, DMG and every other bzip2 user: the decoder buffered less
  input than such a block takes.
- A ZIP member compressed with bzip2, LZMA, zstd, XZ, Deflate64 or PPMd and
  larger than `--max-object-bytes` stopped the walk, so the members after it
  were never scanned. It streams, and spills like any other member.
- The daemon's CPU limit (`--max-scan-secs`) applied to a worker's whole life
  rather than to each job: once the jobs a worker had served used it between
  them, the kernel killed the worker in the middle of the next job, however
  small, and that job got no reply. The log called it `OOM / RLIMIT_AS`.
- The PE header given to bytecode programs had its data directories shifted
  down past the first absent one, so on most executables (which have no export
  table) a program reading the import or resource directory read the wrong one.
  A PE with the reserved 16th directory set was an `ERROR` (a panic in
  `goblin`).
- Compiled AutoIt scripts in the newer EA06 format are decoded: the script,
  as the same text ClamAV extracts, and the files it installs. They were `UNSCANNABLE`. A member cut short is
  scanned as far as it goes and reported.
- In an AES-encrypted PDF (AES-128 or AES-256, the default of current tools)
  the decrypted streams and strings kept the 16-byte IV in front. Every
  compressed stream then failed to inflate, went unscanned and made the scan
  `UNSCANNABLE`, and extracted URIs and JavaScript carried 16 bytes of noise.
- A CAB member that shares its bytes with the one before it (MSI cabinets list
  a file installed under two names twice at one offset, as ScreenConnect
  installers do) made the scan `UNSCANNABLE`: the streamed walk reads forward
  only. The folder is now decoded again from its start, charged to the scan
  budget.
- An object that happened to start with ARJ's two-byte magic was opened as a
  damaged ARJ and made the scan `UNSCANNABLE`, which happened inside ordinary
  APKs. ARJ is now recognised by its header CRC, as ClamAV's `.ftm` typing is
  checked for bzip2, CAB and gzip.
- On 32-bit targets, which include the WebAssembly builds, a corrupt UPX stream
  could overflow the NRV decoder's arithmetic, a panic under the release
  profile's overflow checks. The bound it was checked against was `u32::MAX`,
  which a 32-bit `usize` never exceeds.
- `--detect broken` judges only the headers a loader needs to map a PE, ELF or
  Mach-O image, as clamscan does. It flagged any file a full parse rejected:
  DLLs with a non-UTF-8 export name, resource or import directories pointing
  nowhere, Android libraries with junk section headers. It missed PEs whose
  alignment or section layout no loader accepts, and it no longer needs the
  whole object in memory.
- `--detect broken` no longer reports an executable carved out of another file
  at an offset. A clean PE whose last bytes held the start of a second,
  truncated one was reported as broken.
- 7z members packed with the x86, ARM or ARM64 branch filter (7-Zip's default
  for executables) are decoded correctly. The filters did not undo 7-Zip's
  conversion, so branch targets came out wrong: hash
  signatures on those executables could not match, and patterns spanning a
  call could not either.
- An input holding about 100 MiB or more of one repeated byte (or of a short
  repeated pattern) could abort the scan on an allocation failure, at any
  memory limit, whenever a loaded signature had an unbounded gap followed by
  bytes the run is made of. The positions such a gap can reach are kept as
  ranges, so a run is one range however long, and a set that still grows past
  about a million ranges makes the scan `LIMITS-EXCEEDED` instead.

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
