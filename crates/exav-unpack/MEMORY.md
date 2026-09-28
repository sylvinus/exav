# Forced-materialization inventory & the peak-memory limit

Where `exav-unpack` and `exav-core` hold a whole object (file, archive,
member, decoded sub-container, LZ window, decrypted blob, parsed TOC) in one
contiguous buffer, why each one must, and which limit bounds it.

## Two independent knobs: memory vs. reach

Peak **memory** and scan **reach** are separate, because a streamed member is
never held in RAM.

**1. `--max-object-bytes`: the largest *single* buffer.**
- API: `unpack::Limits::max_buffer_bytes` and core
  `ScanOptions::deep_analysis_max`, both **256 MiB** by default.
  `--max-object-bytes` sets both.
- Every forced-materialization site caps its largest allocation here.

  It is **not** a cap on peak memory. Several buffers are alive at once (a
  container, its member and that member's own member are each mid-scan while
  the walk is inside them), so what bounds the total is
  `Limits::max_extracted_bytes` below.

**1b. `Limits::max_extracted_bytes`: what bounds live extraction memory.**
- Default **1 GiB**. `Budget::reserve`/`commit` charge it cumulatively and never
  release, so it is both the total-output bound and the ceiling on how much
  extracted data can be resident at one moment.
- It has to fit inside the address space the process is given. The daemon's
  `fit_limits_to_job_memory` clamps it to half of the per-job memory grant, so
  the in-core limit produces `LIMITS-EXCEEDED` instead of `RLIMIT_AS` killing
  the worker.

**2. `--max-matcher-bytes`: scan reach (CPU/time).**
- API: `Limits::max_scanned_bytes`, default **10 GiB**.
- Bounds the cumulative bytes fed to the matcher for one top-level input
  (streamed members plus re-carved/re-scanned regions). Not a memory cost: a
  streamed member is decoded on demand (`stream_members` + `BudgetReader`), and
  `exav-core` holds at most `deep_analysis_max` of it. Raising this knob buys
  scan time only; its job is DoS resistance.

## How an input reaches the extractors

Every entry point runs `exav-core::scan_seekable` (`scan_path` opens the file and
hands it over).

- **Typing.** From the first 4 KiB. An input over `deep_analysis_max` whose
  type is not walkable off the reader is typed again from a wider head, because
  an ISO 9660 descriptor sits at 32 KiB and a UDF one up to 64 KiB in; an
  executable is also searched for an appended archive in its first
  `max_buffer_bytes`, read a window at a time (`unpack::is_sfx`).
- **Walkable containers** (`exav-core::streams_natively`) are walked member by
  member off the reader, at any size. Up to `deep_analysis_max` the container is
  also read whole, once, for the full engine and the whole-object checks. Past
  it the constant-memory `stream_core` (literal signatures and whole-file
  hashes) runs over its bytes, the members are walked, and the result is
  `LIMITS-EXCEEDED` unless something is found.
- **Everything else** up to `deep_analysis_max` is read whole and analysed.
  Past it, `stream_core` runs over it and the result is `LIMITS-EXCEEDED` unless
  something is found.

## Streaming coverage

`stream_members` walks every `is_streamable` format with each member produced
on demand, never materialized whole: gzip, bzip2, xz, zstd, lzip, tar, zip,
lha, ar, cpio, machofat, pyc, sfx, tnef, partition, iso, onenote, swf, szdd, 7z
and cab.

- **Single-stream compressors**: a `Read` decoder over the source. bzip2 and xz
  buffer their compressed input (bounded by `max_buffer_bytes`); the win is on
  the output side.
- **Stored-offset containers** parse a small header or table through
  `Read + Seek`, then seek and `take` each member (`stream_stored`): ar, cpio,
  partition, machofat, tnef, onenote, sfx, pyc, and the ISO 9660 trees of iso.
  Where a test holds a streamed walk to the buffered `extract`, it is
  `assert_stream_matches_buffered` in `stream.rs`, or the `udf` suite for ISO.
- **ISO** walks its ISO 9660 trees and then its UDF tree, skipping files the
  first already emitted, as the buffered walk does. The UDF walk reads the image
  through the same code in both cases (`udf::Image`) and streams each file from
  the runs of the image it occupies.
- **SFX** finds the appended archive in the first `max_buffer_bytes` a window at
  a time and streams `[offset, EOF)` as one member.
- **swf**: CWS/ZWS bodies decode through a zlib/LZMA `Read` behind the rebuilt
  FWS header. **szdd**: SZDD's LZSS as a streaming `Read`; KWAJ falls back to a
  bounded buffered decode.
- **Solid blocks (7z, cab)**: the block or folder is a forward-only `Read`;
  each file is a `take(size)` window after skipping to its offset, so the
  decompressed solid unit is never buffered. 7z still buffers its compressed
  input, and AES members take the buffered CRC/password path.

**At every depth.** `deep_analyze` walks any `is_streamable` format through
`scan_streamed_container` over a `Cursor` of the member, so a small nested
member decompressing to gigabytes is scanned in full (memory bounded by
`deep_analysis_max`). Formats with no streaming walk stay on the buffered
`extract_each` path.

**Members.** One that fits in `deep_analysis_max` is held and fully analysed.
A larger one is not materialized: its buffered prefix is chained with the
still-streaming tail through `stream_core`, and the member is reported
`LIMITS-EXCEEDED` unless that finds something.

**Panic containment**: `stream_members` runs its dispatch inside
`catch_unwind`, like `extract_each`, so a decoder panic becomes `Unscannable`.

Every format not in `is_streamable` is buffered: the container is held whole,
bounded by `max_buffer_bytes`.

## Why some buffering is unavoidable

A site must hold a whole object when:
- a decoder or parser needs **random access** over the decoded bytes (a
  ZIP/7z central directory or TOC, a PDF xref, the filesystem inside a DMG);
- **decryption** needs the full ciphertext (ZipCrypto, WinZip-AES, an encrypted
  7z header);
- an **LZ sliding window** is inherent to the codec (RAR3/RAR5, LZX);
- a third-party crate's API takes `&[u8]` or returns `Vec<u8>`.

There the rule is to bound the buffer at `max_buffer_bytes`, not to eliminate
it.

---

## Enforcement status

### Bounded by the knob (`max_buffer_bytes` / `deep_analysis_max`)

- **exav-core buffers**: the whole input, a container read for the full engine,
  and a member's structural prefix are each read up to `deep_analysis_max`; one
  larger goes through `stream_core` instead.
- **Streaming member API**: `BudgetReader` caps each member and errors (never
  truncates) past it.
- **Per-format member buffers**: every `Entry.data` and decoded blob goes
  through `bounded_read` / `bounded_read_salvage` or an explicit `len > cap`
  check, with `cap = budget.reserve() = min(max_extracted_bytes − used,
  max_buffer_bytes)`. The UDF walk checks a file's size before copying it out,
  so unwritten extents (zeroes) cost nothing until then.
- **Decoders that thread `max_buffer`**: CAB (`Cabinet::new`, each folder and the
  combined buffer), 7z solid blocks, PPMd input and output, BCJ filters, UDIF
  (`decompress_udif`), DMG HFS+/APFS files (`reserve`/`commit` before
  `Entry::new`), encrypted ZIP members
  (`read_encrypted_member`), ARJ (the whole archive on entry), VBA
  (`decompress`, `build_artifacts`), the `ar` name table, the RAR3 window
  (rejected past the limit), ISO and UDF directory reads.
- **Bounded by the default limit, not the knob**: the 7z encoded header (a
  header carries no `Budget`), the DMG decrypt block size, and
  `Archive::open`'s buffered fallback, a public API that predates the budget.

### Input-bounded

These copy a slice of their input, which the caller already capped at
`max_buffer_bytes`, so they cannot exceed it:
- PDF stream bodies and filter working copies (the decoded output is bounded
  like any member);
- the RAR3/RAR5 compressed-member copy and its padding;
- `cab.rs` `repair_cab_size`, a clone of the input CAB to patch 4 bytes.

### Fixed literals, at or below the knob's default

Routing these through the knob would only let an operator lower them:
- `rar5_unpack.rs` `MAX_WINDOW_SIZE` (64 MiB), the `xar.rs` TOC (64 MiB),
  `udif.rs` runs and xz dictionary (64 MiB);
- `PREALLOC_CAP` (16 MiB): a pre-allocation clamp only, growth is capped
  elsewhere;
- core's JavaScript normaliser output (32 MiB). The raw bytes are scanned in
  full; when the normalised view is cut, the scan is reported incomplete
  (`LIMITS-EXCEEDED` unless something is found). The normaliser reads the
  script in one pass and holds only the output, the identifiers it renamed and
  the calls still open (at most 256, a `fromCharCode` list as 4-byte values),
  so the output cap is what bounds it.

### Excluded by design

- The **trusted signature database** (`exav-core` `database.rs`, `cvd.rs`): not
  scan input; hashed and deserialized whole, bounded by `CvdLimits` when
  unpacked.
- Fixed small protocol and detection buffers: the 64 KiB HTTP range block
  (`source.rs`), the 64 KiB head `Archive::open` detects from, the typing heads.
- Format constants: the deflate 32 KiB and Deflate64 64 KiB dictionaries, the
  4096-entry LZW table, 255-byte names.
