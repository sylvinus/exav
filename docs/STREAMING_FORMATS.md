# Streaming the last container formats

exav optimises for memory, not bandwidth. `walk` hands a format's members over
straight off the seekable source, each decoded as it is read, so peak memory is
one member's window rather than the whole decoded object. Most containers
already work that way (every arm of `dispatch` in `stream.rs` but the last),
including tar, zip, 7z, cab, lz4, `.Z` and DMG; the rest are read whole
(`read_whole`). Two of those matter, for different reasons, and only one of them
is worth changing.

**DMG: done.** The HFS+/APFS readers get the disk as a `Read + Seek` over
`DmgReader`, which decompresses a BLKX run when the filesystem first reaches it
and keeps the last 32 MiB of decoded runs. The virtual disk is never held
whole. Each file is still returned whole by the filesystem crates, so a file is
bounded by the peak-buffer limit. An encrypted image is decrypted whole, under
the same limit.

**RAR: real work, deliberately not rushed.** `rar3_unpack.rs` and
`rar5_unpack.rs` are vendored decoders that build the complete output `Vec`.
Streaming them means turning both into resumable `Read` state machines that
retain only the already-capped LZ window: major surgery on fuzzed,
differential-tested code, where a subtle break costs correctness on a format
attackers actively use. It is a focused effort of its own, not a change to slip
in alongside others.

**PDF: measured, and not worth doing.** `extract_pdf` already decompresses
stream objects one at a time into a budget-bounded buffer, and the file itself
has to be buffered regardless because the xref table lives at the end and the
recovery path scans the whole file. Peak is therefore already input plus one
bounded object; streaming would save a single bounded body.
