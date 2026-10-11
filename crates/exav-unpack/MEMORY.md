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
  `--max-object-bytes` sets both, and a scan holds the first to the second.
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
  (members plus re-carved/re-scanned regions). Not a memory cost: a member
  decoded as it is read is bounded by a `BudgetReader`, and `exav-core` holds
  at most `deep_analysis_max` of it. Raising this knob buys scan time only;
  its job is DoS resistance.

## How an input reaches the extractors

Every entry point runs `exav-core::scan_seekable` (`scan_path` opens the file and
hands it over), and every object, the input and whatever is unpacked from it,
goes through the same pipeline (`scan_object`).

- **Up to `deep_analysis_max`** the input is read whole and analysed in memory.
- **Past it** the input is read through a `source::BlockCache` (64 KiB blocks,
  8 MiB held) and gets the same scan: every check runs over a
  `source::ByteSource`, reading what it needs of the object. The cache bounds
  memory, not reach: a block evicted is read again. Typing is exact (`detect`
  reads the start, the end, or searches the object).
- **Containers** are walked by `walk` over the same source, at every depth.
- **What cannot run over a source** needs the object in memory and is skipped
  past `deep_analysis_max`, which makes the result `LIMITS-EXCEEDED` naming the
  size limit unless something is found: goblin-parsed PE structure (layout,
  icons, section hashes, imphash, Authenticode, UPX and packer detection),
  YARA's `pe`/`elf`/`dotnet` modules, the structural heuristics that parse a
  whole file, and every container format read whole (`read_whole`).
- **What a scan makes** of an object that large, its normalised text views,
  goes to spill files when the host provides them (`ScanOptions::spill`; the
  `exav` binary passes its `--spill-dir` ones). Without them those views are
  skipped and the result is `LIMITS-EXCEEDED`.

## The walk

`walk` is the one way in. Each member reaches the visitor as a `Member`:
`Bytes` for one decoded whole, `Stream` for one decoded as it is read.

- **Single-stream compressors** (gzip, bzip2, xz, zstd, lzip, lzw, lz4): a
  `Read` decoder straight off the source, no buffering on either side.
- **Stored-offset containers** parse a small header or table through
  `Read + Seek`, then seek and `take` each member (`stream_stored`): ar, cpio,
  partition, machofat, tnef, onenote, sfx, pyc, and the ISO 9660 trees of iso.
  A part of a table left unwalked (too many partitions or ISO directories, a
  truncated table) is a member of its own, reported unsupported.
- **ISO** walks its ISO 9660 trees and then its UDF tree, skipping files the
  first already emitted. The UDF walk streams each file from the runs of the
  image it occupies.
- **SFX** finds the appended archive as far into the file as detection looks, a
  window at a time, and streams `[offset, EOF)` as one member.
- **swf**: CWS/ZWS bodies decode through a zlib/LZMA `Read` behind the rebuilt
  FWS header. **szdd**: SZDD's LZSS as a streaming `Read`; KWAJ is decoded whole.
- **Solid blocks (7z, cab)**: the block or folder is a forward-only `Read`;
  each file is a `take(size)` window after skipping to its offset, so the
  decompressed solid unit is never buffered. 7z still holds its compressed
  input, and AES members take the buffered CRC/password path.
- **DMG**: the UDIF disk is a `Read + Seek` over its decoded runs, and its
  HFS+/APFS files are read from it.
- **Everything else** is read whole (`read_whole`: zero-copy when the source is
  in memory, bounded by `max_buffer_bytes`), and its members come out as
  `Bytes`.

Every member is charged to the scan budget; a streamed one is also held to the
compression-ratio guard. A read that failed on the source ends the walk as an
error, never as the end of the container.

**Members, in exav-core.** One that fits in `deep_analysis_max` is held and
fully analysed. A larger one is written to a spill file and scanned from there
like any object too large to hold. With no spill it is not scanned, and the
scan is reported `LIMITS-EXCEEDED`.

**Panic containment**: `walk` runs its dispatch inside `catch_unwind`, so a
decoder panic becomes `Unscannable`.

## Why some buffering is unavoidable

A site must hold a whole object when:
- a decoder or parser needs **random access** over the decoded bytes (a
  ZIP/7z central directory or TOC, a PDF xref);
- **decryption** needs the full ciphertext (ZipCrypto, WinZip-AES, an encrypted
  7z header);
- an **LZ sliding window** is inherent to the codec (RAR3/RAR5, LZX);
- a third-party crate's API takes `&[u8]` or returns `Vec<u8>`.

There the rule is to bound the buffer at `max_buffer_bytes`, not to eliminate
it.

---

## Enforcement status

### Bounded by the knob (`max_buffer_bytes` / `deep_analysis_max`)

- **exav-core buffers**: the whole input and a member are each held up to
  `deep_analysis_max`; one larger is read through a block cache (the input, a
  spilled member). A check that needs a larger object whole reads it only up
  to the same limit.
- **Streaming member API**: `BudgetReader` caps each member and errors (never
  truncates) past it.
- **Per-format member buffers**: every `Entry.data` and decoded blob goes
  through `bounded_read` / `bounded_read_salvage` or an explicit `len > cap`
  check, with `cap = budget.reserve() = min(max_extracted_bytes − used,
  max_buffer_bytes)`. The UDF walk checks a file's size before copying it out,
  so unwritten extents (zeroes) cost nothing until then.
- **Decoders that thread `max_buffer`**: CAB (`Cabinet::new`, each folder and the
  combined buffer), 7z solid blocks, PPMd input and output, BCJ filters, DMG
  HFS+/APFS files (read into a writer capped at `reserve()`), an encrypted
  DMG (decrypted whole), encrypted ZIP members
  (`read_encrypted_member`), ARJ (the whole archive on entry), VBA
  (`decompress`, `build_artifacts`), the `ar` name table, the RAR3 window
  (rejected past the limit), ISO and UDF directory reads.
- **Bounded by the default limit, not the knob**: the 7z encoded header (a
  header carries no `Budget`) and the DMG decrypt block size.

### Input-bounded

These copy a slice of their input, which the caller already capped at
`max_buffer_bytes`, so they cannot exceed it:
- PDF stream bodies and filter working copies (the decoded output is bounded
  like any member);
- the RAR3/RAR5 compressed-member copy and its padding.

### Fixed literals, at or below the knob's default

Routing these through the knob would only let an operator lower them:
- `rar5_unpack.rs` `MAX_WINDOW_SIZE` (64 MiB), the `xar.rs` TOC (64 MiB),
  `udif.rs` runs and xz dictionary (64 MiB), the decoded runs `DmgReader`
  keeps (32 MiB), the LZ4 streaming reader's block (8 MiB decoded, 16 MiB
  read);
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
  (`source.rs`), the typing heads.
- Format constants: the deflate 32 KiB and Deflate64 64 KiB dictionaries, the
  4096-entry LZW table, 255-byte names.
