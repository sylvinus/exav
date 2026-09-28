# Changelog

Notable changes per release. Dates are release dates; the format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) loosely, and versions
follow [semantic versioning](https://semver.org/).

## [Unreleased]

### Changed

- A file or archive member larger than `--max-object-bytes` (256 MiB by
  default) is reported `LIMITS-EXCEEDED` unless a literal signature or a
  whole-file hash matches it. It was reported `OK` after a literal-and-hash pass
  that skipped wildcard and logical signatures, YARA and bytecode. An archive over
  the limit is walked as before and reported `LIMITS-EXCEEDED` too.
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
  - A container over `--max-object-bytes` gets the literal and hash pass over
    its own bytes on every entry point, not only a file path.
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

### Added

- `--max-pe-emulation-steps` (default 1,000,000,000): instructions the PE
  unpacking emulator may run across one top-level file, reported as
  `LIMITS-EXCEEDED` / `Heuristics.Limits.Exceeded.MaxScanTime`.
- An encrypted ZIP appended to a picture or document is reported
  `PASSWORD-PROTECTED` when its central directory checks out.
- `make miri`.

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
  a container.
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

## [0.0.1] - 2026-09-16

First public release. Everything below is new, so this section describes what
the project *is* rather than what changed in it.

### The scanner

- **ClamAV-compatible.** Reads CVD/CLD containers and the `.ndb`/`.ldb`/`.hdb`/
  `.mdb`/`.cdb`/`.hsb`/`.pdb`/`.cbc` signature families, speaks the clamd
  protocol, and matches `clamscan`'s output and exit codes — except the
  documented fourth exit code: where ClamAV answers `OK` for a file it gave up
  on, exav answers `PARTIAL` (exit 3).
- **Never a silent clean.** A file that could not be fully examined is reported
  `LIMITS-EXCEEDED`, `UNSCANNABLE` or `PASSWORD-PROTECTED` — never `OK`. This is
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
  running the packer's own stub and capturing the image it rebuilds — so the
  original program is scanned whatever it was packed with.

### Memory safety

`#![forbid(unsafe_code)]` on every crate except `exav`, whose only
exception is the prefork daemon's process management (`fork`, `waitpid`,
`setrlimit`, descriptor passing). No scanned byte reaches any of it.

The x86 decoder — the one component a scanned file drives directly, supplying
control flow rather than data — is `exav-x86`: dependency-free, safe, and
checked instruction by instruction against an independent decoder over
94,245,255 decode sites from real packed malware, agreeing on every one.

### Not included

- No bundled signature URLs. Update sources are supplied by the operator.
- No digital-signature verification of downloaded databases, and no rsync.
- The x86 decoder covers 32-bit protected mode in full — including VEX, EVEX
  and XOP — but only 32-bit mode: no REX, no RIP-relative addressing, no 64-bit
  forms. The emulator runs 32-bit packer stubs.
