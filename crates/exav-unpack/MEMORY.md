# Forced-materialization inventory & the peak-memory limit

This document is the **exhaustive list of every place in `exav-unpack` and
`exav-core` that materializes a whole object (file / archive / member / decoded
sub-container / LZ window / decrypted blob / parsed TOC) into a single contiguous
in-memory buffer**, why each one must, and which limit bounds it.

## Two independent knobs: memory vs. reach

Peak **memory** and scan **reach** are now separate, because a streamed member is
never held in RAM.

**1. `--max-buffer` — the peak-memory knob.**
- API: `unpack::Limits::max_buffer_bytes()` (backed by `Limits::max_entry_bytes`),
  default **256 MiB**; and core `ScanOptions::deep_analysis_max`, default
  **256 MiB** (the structural-buffer ceiling). `--max-buffer` sets both.
- Every forced-materialization site caps its single largest allocation here, so
  lowering it lowers the scanner's peak memory.

**2. `--max-scan-total` — the scan-reach (CPU/time) knob.**
- API: `Limits::max_scan_bytes`, default **10 GiB**.
- Bounds the cumulative bytes fed to the matcher across one top-level file
  (streamed members + re-carved/re-scanned regions). This is **not** a memory
  cost: the streaming member API (`stream_members` + `BudgetReader`) decodes a
  member on demand and the caller (`exav-core::scan_stream_member`) holds only a
  bounded prefix (≤ `deep_analysis_max`) in RAM, streaming the rest through the
  constant-memory matcher. So this knob can be raised **far higher** (10 GiB,
  100 GiB, …) to fully scan enormous members — paying only in scan *time*, with
  peak RAM still fixed by `--max-buffer`. Its only job is DoS resistance
  (re-scanning bombs / runaway scan time).

Concretely: a member decompressing to `N` bytes is scanned in full when
`N ≤ max_scan_bytes`, using `≈ deep_analysis_max` RAM regardless of `N`. Buffered
(non-streaming) formats still hold their member whole, so for them
`max_buffer_bytes` remains both the memory and the size cap.

## Streaming coverage (reader-based, never materialize a member)

**Streamed top-level** (`exav-core::streams_natively`, walked via `stream_members`
off the file handle — 15 formats):
- **Single-stream compressors**: gzip, zstd, lzip (a `Read` decoder over the source).
- **Seekable stored/decoded containers**: tar, zip, lha.
- **Stored-offset containers** (parse a small header/table via `Read+Seek`, then
  seek+take each member — `stream_stored`): ar, cpio, iso, partition, machofat,
  tnef, onenote, sfx, pyc.
- **swf**: CWS/ZWS bodies decode through a zlib/LZMA `Read` chained behind the
  rebuilt FWS header.
- **Incremental custom decoders**: szdd (SZDD's 4 KiB-window LZSS rewritten as a
  streaming `Read`; KWAJ falls back to a bounded buffered decode).
- **Solid-block containers (pattern A)**: 7z and cab. The former random-access
  "decode the whole solid block/folder to a `Vec`, then slice members by offset"
  is replaced by "build the block/folder as a forward-only `Read`, skip to each
  file's offset, hand it a `take(size)` window" — so the decompressed solid unit
  is never buffered. 7z: `decode_block_reader` over the existing coder chain
  (LZMA/LZMA2/PPMd/BCJ); AES members keep the buffered CRC/password path. cab:
  `FolderReader` decodes CFDATA blocks one at a time (the LZX/MSZIP dictionary is
  the only retained state), driven by a parse-without-decompress `Cabinet::layout`.
  Both verified with `assert_stream_matches_buffered` (7z across lzma/lzma2-solid/
  copy/deflate/bzip2 fixtures).

**Raw-container scan**: `exav-core::scan_path` runs a constant-memory
`stream_core` (whole-file hash + patterns) over a streamed container before
walking members — restoring the whole-file-hash / raw-pattern detections the
buffered `scan_bytes_core` did. (`scan_seekable`/range-GET skips it to preserve
fetch economy.) This also means single-output transforms are safe to stream:
their raw bytes are always scanned regardless of the decoder.

Each STORED-OFFSET conversion has a `stream_offsets(source) -> [(name,off,size)]`
parser validated by an `assert_stream_matches_buffered` equivalence test (streamed
members byte-for-byte match `extract`).

**Nested (recursive) streaming**: the single-stream compressors gzip/zstd/lzip are
streamed *inside* other archives too (`deep_analyze_streamed`), so a small nested
member decompressing to gigabytes is scanned in full (RAM bounded by
`deep_analysis_max`) instead of being truncated at `max_entry_bytes`. Multi-member
nested containers stay on the buffered `extract_each` path there, preserving
`.cdb`/OLE per-member metadata matching.

**Panic containment**: `stream_members` runs its dispatch inside `catch_unwind`
(like `extract_each`), so a decoder panic (e.g. delharc on crafted LHA) becomes a
clean `Unscannable`, never a process abort.

**Not yet streamed** — two categories:
1. *Convertible (incremental `Read` decoder needed)*: swf, nsis, uuencode, xdp,
   szdd, screnc, rtf. bzip2/xz are excluded (concatenated-stream boundary needs a
   whole-buffer scan). These decode sequentially to a `Vec` today.
2. *Fundamentally random-access* (the decoder needs the whole decoded object, so
   only the buffer *size* is boundable, via `max_buffer_bytes`): 7z solid blocks,
   cab folders, rar LZ window, dmg/iso-as-filesystem crates, ole/pdf/email/chm
   structured parsers, autoit/upx/pepack, binhex/aimodel/javaclass/vba.

## Why some buffering is unavoidable

A site *must* hold a whole object when:
- a decoder/parser needs **random access** over the decoded bytes (7z member
  offsets into a solid block; a ZIP/7z central directory or TOC; PDF xref;
  filesystem crates over a whole DMG image);
- **decryption** needs the full ciphertext before it can produce plaintext
  (ZipCrypto / WinZip-AES / encrypted 7z header);
- an **LZ sliding window** is inherent to the codec (RAR3/RAR5, LZX);
- a third-party crate's API takes `&[u8]` / returns `Vec<u8>`.

For these, streaming is impossible without replacing the decoder — so the rule is
**bound the buffer at `max_buffer_bytes`**, not eliminate it.

---

## Enforcement status

### Tier 1 — bounded now (obey `max_buffer_bytes` / `deep_analysis_max`)

- **exav-core scan buffers** — `scan_path`, `scan_seekable` (whole top-level file
  for structural analysis) and `scan_stream_member` (per-member structural
  prefix) all use `.take(deep_analysis_max + 1).read_to_end`; a larger member is
  chained through the constant-memory `stream_core`, never materialized.
- **Streaming member API** — `stream.rs::BudgetReader` caps each member at
  `budget.reserve()` and errors (never truncates) past it.
- **`Archive` Lazy/Buffered arms & `Archive::open` buffered fallback**
  (`lib.rs`) — now read `≤ max_buffer_bytes` and error past it (previously a
  hardcoded `256*1024*1024` and an unbounded `read_to_end`).
- **All Class-C per-format sites** (the majority — see table C) — every
  `Entry.data` and decoded blob goes through `bounded_read(_, cap)` /
  `bounded_read_salvage` / an explicit `len > cap` check with
  `cap = budget.reserve() = min(max_total_bytes − used, max_entry_bytes)`.
- **The former Tier-2 amplifiers — now wired** (each threads
  `budget.limits.max_buffer_bytes()`, or the default limit where the decoder
  parser carries no `Budget`, and errors past it):
  - **A2/A3 CAB** — `Cabinet::new`/`Folder::new` take `max_buffer`; each folder
    and the combined buffer are bounded.
  - **A5 7z solid block** — `decode_block` uses `bounded_read(_, max_buffer)`.
  - **A6 7z encoded header/TOC** — `decompress_encoded_header` bounded by the
    default limit (a header carries no `Budget`; metadata, not a tuning surface).
  - **A7/A8 7z PPMd** — both the compressed input and the decode-symbol output
    loop are bounded.
  - **A9 7z BCJ (x86/arm/arm64)** — each filter threads `max_buffer` and bounds
    its `read_to_end`.
  - **A10 UDIF/DMG image** — `decompress_udif(_, max_buffer)` bounded.
  - **A11/A12 DMG HFS+/APFS files** — each `read_file` result is
    `reserve()`/`commit()`-checked before `Entry::new`.
  - **A13 DMG decrypt** — attacker `blocksize` bounded (and zero-guarded).
  - **A14/A15 ZIP encrypted member** — `read_encrypted_member(_, max_buffer)`
    caps the ciphertext read; the decrypt copies then inherit that bound.
  - **A19/A20 ARJ** — whole-archive buffer bounded on entry; the per-member
    slice is a subset of it.
  - **A23 VBA** — `decompress`/`build_artifacts` take `cap`; the RLE output and
    the combined artifact buffers are bounded.
  - **A24 `ar` name table** — bounded by `max_buffer_bytes`.
  - **B6 RAR3 window** — the up-to-1 GiB sliding window is rejected if it exceeds
    `max_buffer_bytes`.

### Tier 2 — input-bounded (obey the limit transitively; no separate cap added)

These copy a slice of their **input** buffer, which the caller already caps at
`max_buffer_bytes` (a member/file passed into the extractor). They therefore
cannot exceed the limit; no independent guard was added.

| id | file:line — fn | what | why already bounded |
|----|----------------|------|---------------------|
| A16/A17/A18 | `pdf_parse/parse.rs`, `pdf.rs` — stream bodies | PDF stream body / whole-tail copy / filter working copy | slices of the input PDF (≤ `max_buffer`); decoded *output* is Class C |
| A21/A22 | `rar3_unpack.rs`, `rar5_unpack.rs` — input pad / PPMd remainder | compressed-member copy (+pad) | copy of `packed`, the compressed member (≤ `max_entry_bytes`) |
| A4 | `cab.rs:65` — `repair_cab_size` | clone of input CAB to patch 4 bytes | clone of the input member (≤ `max_buffer`) |

### Tier 3 — remaining hardcoded literals (Class B), lower priority

Bounded today, but by a literal rather than the knob. Left as follow-ups:

- LZ/decompress-run caps: `rar5_unpack.rs` `MAX_WINDOW_SIZE = 64 MiB`; `xar.rs:52`
  (64 MiB TOC), `udif.rs:28,262` (64 MiB run + xz dict), `chm.rs`, `nsis.rs`,
  `pdf.rs:182` (4 MiB). These are already ≤ the default `max_buffer_bytes`, so
  they never *raise* peak memory above the knob's default; routing them through
  the knob would let an operator *lower* them further.
- `lib.rs` `256*1024*1024` in the `Archive` Lazy arm → **done** (`max_buffer_bytes()`).
- `PREALLOC_CAP = 16 MiB` — a *prealloc* clamp only (growth is capped elsewhere),
  not a peak-memory determinant; left as-is.

### Excluded by design

- `cache.rs:172` / `cvd.rs` — the **trusted signature DB** payload (not scan
  input); must be hashed/deserialized whole. Bounded by `CvdLimits` when unpacked.
- `source.rs` 64 KiB HTTP range block, `Archive::open` 64 KiB detection head,
  `ole.rs` 8 KiB sniff — fixed small protocol/detection buffers.
- Protocol constants (deflate 32 KiB dict, LZW 4096-entry table, 255-byte names)
  — fixed by the format, not memory-tunable.

---

## Full audit tables

<!-- The complete A/B/C classification produced by the materialization audit.
     A = unbounded, B = hardcoded literal, C = already bounded by budget/limit.
     Keep this in sync when adding a decoder or changing a buffer. -->

See the "Enforcement status" section above for the actionable A (Tier 2) and B
(Tier 3) sites. Class C (already compliant) covers every other format: gzip,
bzip2, zstd, lzip, xz, tar, ZIP cleartext, xar, ole, iso, chm, onenote, cab
copy-out, rar output, arj output, lha, upx, swf, nsis, pdf decoded output, cpio,
ar file arm, partition, machofat, szdd, tnef, screnc, uuencode, binhex, pyc, sfx,
autoit, email, aimodel — each caps its member buffer at `budget.reserve()`.
