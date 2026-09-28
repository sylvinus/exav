# Streaming the last three container formats

exav optimises for memory, not bandwidth. A streamable format is walked member by
member straight off the seekable source, so peak memory is one member's window
rather than the whole decoded object. Most containers already work that way (see
`is_streamable`), including tar, zip, 7z and cab. Three do not, for different
reasons, and only two of them are worth changing.

**DMG: the tractable one, and the next concrete step.** `decompress_udif`
materialises the entire virtual disk into one `Vec` because the HFS+/APFS
readers need random access over it, so a 4 GB image costs 4 GB of resident
memory (bounded by the peak-buffer limit, which means large images are refused
rather than scanned). The reader is already the right shape: `DmgReader` is
position-based, mapping an offset to a BLKX run and decompressing that run. Two
pieces are missing. First a decompressed-run cache: `read` currently
re-decompresses the containing run on every call, which is fine for a linear
pass and unusable under the seek storms a filesystem crate generates. Then
`impl Seek`, after which the reader can be handed to the filesystem crates
directly instead of a materialised image. Roughly 150 lines, and it converts a
whole-image allocation into one cached run.

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
