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
  `--max-object-bytes` they fell back to a single match.
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
    for large inputs is gone. The `.exavdb` format is at version 5; rebuild
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
  `--clamav-compat`), and `--max-process-bytes` lowers it to half the memory a
  scan gets. The flag, or `EXAV_MAX_EXTRACTED_BYTES`, stops the run with a
  message naming the change. It also set the largest object held in memory, so
  `--max-extracted-bytes 0` loaded any file whole.
- `--max-process-bytes` also lowers `--max-object-bytes` to half the memory a
  scan gets, so a file past it is `LIMITS-EXCEEDED`; it was `out of memory
  ERROR`.
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
  `LIMITS-EXCEEDED` unless something else is found.
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
  few hundred bytes do. Once more of the byte has been read than any anchor
  holds, the automaton skips the rest of the run, and a signature anchored
  inside it is checked once for the whole interior and one position at a time
  only near its edges. Where several matches lie inside one run, a first-match
  scan may report a different one of them.
- Scanning is faster on ordinary files too:
  - The automatons a file type runs (four for a PE) advance together, byte
    by byte, in one read of the object, so the processor waits on their
    memory at once; case-insensitive ones read the bytes lowercased as they
    go, with no lowercased copy of the object.
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
  carving confirms an archive by its first bytes, and YARA's prefilter runs
  its automatons in one read and its
  literal and base64 patterns share another. Over HTTP, a request that
  continues the previous one fetches twice as much, up to 8 MiB.
- A prebuilt database loads faster: automatons, anchor groups and the indexes
  derived from the signatures are stored as the build made them and read back
  with a copy, the file is read once rather than once to check its digest and
  again to decode it, and the bodies and logical signatures decode on threads
  of their own while the automatons are read. The file is smaller.
- Bytecode triggers are evaluated with the object's container, as every other
  logical signature is, so a trigger with a `Container:` condition can fire.
  exav-core (`unstable-internals`): `BytecodeRuntime::from_sources` adds the
  triggers to the `EngineBuilder` it is given, and `BytecodeRuntime::standalone`
  builds a runtime with an engine of its own, for tools.
- A first-match scan meets signatures in the order the object's bytes hit
  them, rather than one file-type automaton after another, so when several
  match it may report a different one of them. Carving keeps the first
  candidates of each kind by position when more than its cap are found.
- The RustCrypto crates move to their current generation (`digest` 0.11,
  `cipher` 0.5: `sha2`, `sha1`, `md-5`, `aes`, `cbc`, `des`, `hmac`, `pbkdf2`).

### Added

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

### Fixed

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
- `--build-shard-bytes off` (or `0`) built one automaton per anchor instead of
  no cap.
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
