---
title: Archive extraction
description: How exav unpacks containers, from the parity principle and bounded in-memory extraction to dual indexing, salvage, and why a member exav cannot read is reported rather than skipped.
---

Most malware does not arrive as a bare executable. It arrives inside something: a
ZIP, an ISO, a 7z, a Word document, an installer. A scanner's real job is less
"match bytes" than "reach the bytes", and the unpacker is where that happens.

exav's extraction lives in `exav-unpack`, a standalone crate with no dependency
on the scanning engine, `#![forbid(unsafe_code)]`, and usable on its own as a safe
extraction library.

## The parity principle

If the software on the target's machine can open a container and exav cannot,
that container is an evasion vector: the payload lands intact and the scanner
said nothing useful about it.

The attacker picks the delivery format, so the target is the union of what real
extractors handle: 7-Zip, WinRAR, WinZip, The Unarchiver, Windows Explorer, macOS
Archive Utility, libarchive. Not the intersection, and not what showed up in last
month's corpus.

[Supported formats](/reference/formats/) tracks this as a matrix: every container
and codec those extractors open, exav's status against each, and
[the gap list](/reference/formats/#the-complete-gap-list) of what is still
missing.

Every input is extracted through a seekable source: a file, an HTTP range reader
(fetching only the directory and the members it scans), or a stream buffered
first (see [Streaming & memory](/concepts/streaming-memory/)).

## The shape of the unpacker

A member is bytes plus a budget, a container is something that yields members,
and nesting is the same step applied to what comes out.

<svg viewBox="0 0 790 456" role="img" aria-labelledby="unpn unpd" style="width:100%;height:auto;max-width:790px">
  <title id="unpn">The two doors into extraction</title>
  <desc id="unpd">A source is typed by identify(). Formats that stream natively
  go through door A, stream_members and dispatch_stream, which holds one member
  at a time. Everything else goes through door B, extract_each, which needs the
  whole container in memory. Both doors yield a member carrying the same Budget,
  and each member re-enters identify(), bounded at max_recursion of 16. One
  Budget covers the whole tree, not each container.</desc>
  <defs>
    <marker id="unp-arrow" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="7" markerHeight="7" orient="auto">
      <path d="M0 0 L8 4 L0 8 z" fill="currentColor"/>
    </marker>
  </defs>
  <g fill="currentColor" font-family="system-ui, sans-serif" font-size="11" font-weight="600" letter-spacing=".08em" opacity="0.6">
    <text x="8" y="160">DOOR A: STREAMING</text>
    <text x="452" y="160">DOOR B: BUFFERED</text>
  </g>
  <g fill="none" stroke="currentColor" stroke-width="1.5">
    <rect x="8" y="24" width="162" height="52" rx="6"/>
    <rect x="320" y="24" width="150" height="52" rx="6"/>
    <rect x="8" y="170" width="330" height="110" rx="6"/>
    <rect x="452" y="170" width="330" height="110" rx="6"/>
    <rect x="255" y="360" width="280" height="64" rx="6"/>
  </g>
  <g fill="currentColor" font-family="ui-monospace, SFMono-Regular, Menlo, monospace" font-size="13" font-weight="600">
    <text x="89" y="46" text-anchor="middle">source</text>
    <text x="395" y="46" text-anchor="middle">identify()</text>
    <text x="24" y="196">stream_members → dispatch_stream</text>
    <text x="468" y="196">extract_each(fmt, &amp;[u8], …)</text>
    <text x="395" y="386" text-anchor="middle">member</text>
  </g>
  <g fill="currentColor" font-family="system-ui, sans-serif" font-size="11.5" opacity="0.72">
    <text x="89" y="64" text-anchor="middle">file · reader · bytes</text>
    <text x="395" y="64" text-anchor="middle">first 4 KiB</text>
    <text x="24" y="218">holds ONE member at a time,</text>
    <text x="24" y="236">the container is never fully resident</text>
    <text x="24" y="254">zip · tar · 7z · cab · iso · …</text>
    <text x="468" y="218">needs the WHOLE container as one slice,</text>
    <text x="468" y="236">bounded before it is allocated</text>
    <text x="468" y="254">rar · ole · pdf · chm · …</text>
    <text x="395" y="408" text-anchor="middle">bytes + the SAME Budget</text>
    <text x="395" y="444" text-anchor="middle">one Budget for the whole tree, not per container</text>
    <text x="400" y="140" text-anchor="end">each member re-enters</text>
    <text x="420" y="140">identify() · max_recursion (16)</text>
  </g>
  <g fill="none" stroke="currentColor" stroke-width="1.5" marker-end="url(#unp-arrow)">
    <path d="M170 50 H316"/>
    <path d="M355 76 V120 H173 V166"/>
    <path d="M470 60 H680 V166"/>
    <path d="M173 280 V320 H320 V356"/>
    <path d="M617 280 V320 H470 V356"/>
    <path d="M410 360 V80" stroke-dasharray="4 4"/>
  </g>
</svg>

`identify()` types the bytes, and `streams_natively` decides which door opens.
Door A hands back members one at a time and never has the container resident;
door B needs the whole container as one slice before it can start. Which door a
format uses is a property of its decoder, not of how exav was invoked.

Past the door both are the same: a member is bytes carrying the same `Budget` as
its parent, and scanning it re-enters `identify()`. So nesting needs no special
case, and the extraction budget bounds an archive tree rather than each container
in it.

### Where the code departs from the picture

**There are two dispatches.** `dispatch_stream` and `dispatch_extract` are
separate functions with separate format coverage. A change to one does not
appear in the other, and a format can be reachable through one door only. When a
hook or check does not fire, suspect this first.

**The `Archive<R>` API has its own split.** `ArchiveInner` has native arms for
`Zip`, `Tar` and `Gzip`, a `Lazy` arm for the single-stream compressors (bzip2,
xz, zstd), and a `Buffered` arm that reads the source into memory and hands it to
door B, which is where every other format sits in that API.

**An empty `Archive::list()` means "no directory", not "no members".** Only
formats with an index can be listed without extracting: a ZIP's central
directory, a tar's headers. A gzip's single member has no name or size until it
is decompressed, which is why the wasm bindings walk the archive instead of
passing an empty list outward.

**A ZIP has more members than its directory admits to.** Extraction also scans
the bytes the central directory does not claim (see below). Both doors do this;
a listing reports those members at indices straight after the directory's own.

## Bounded, in memory, budget before allocation

Every extraction runs under one `Budget`, reserved before a member is read rather
than checked after:

| Limit | Bounds |
|---|---|
| output bytes | total decompressed size across the whole tree |
| per-member size | one member's decompressed size |
| compression ratio | output ÷ input, the decompression-bomb guard |
| file count | members across the archive and everything nested |
| recursion depth | archives inside archives |
| matcher bytes | bytes fed to the matcher across the tree, a CPU bound |
| emulation steps | instructions the PE unpacking emulator runs across the tree |

Reserving first keeps the peak bounded: a "1 GB from 4 KB" member never
allocates 1 GB and then gets rejected.

Nothing is written to disk. Members exist in memory only, so zip-slip, path
traversal and symlink attacks do not apply: there is no filesystem write for a
`../../` path to escape into.

## Containers have two indexes

A ZIP lists its members twice: a local file header before each member's data, and
a central directory at the end. Every normal reader trusts the central directory,
because that is what the specification says is authoritative.

So a member can be hidden: leave it out of the central directory and keep its
local header and data in the file. Plenty of extractors still write it out.

exav does dual indexing: after the central-directory pass it scans the raw bytes
for local headers the directory did not cover, and extracts those too. The same
path is the salvage route when the central directory is corrupt, forged or
truncated.

`PK\x03\x04` is four bytes and occurs by chance in ordinary binaries, so a
credibility check (version, reserved flag bits, a real compression method, a
NUL-free path within the length limit) decides what counts as a member.

ISO images have the same shape: a CD image carries several volume descriptors,
each with its own directory tree over the same sectors. A malicious ISO lists its
payload only in the Joliet tree and leaves the primary tree empty, so a reader
that parses the primary one sees an empty disc. exav walks every tree.

## Recovering what a naive reader would skip

**Deferred sizes.** A streaming ZIP writer sets a flag and puts the member's sizes
in a data descriptor after the data, so the local header does not say where the
member ends. exav recovers the extent from the descriptor's `PK\x07\x08` marker
when its declared size is consistent, otherwise by running to the next header.
The latter is only done for deflate, which terminates itself; a stored member
would swallow the descriptor and the following headers into its content.

**Truncated streams.** A gzip cut short mid-DEFLATE is common, and `zcat` recovers
everything before the cut, so exav scans the salvaged prefix too. Nesting works: a
truncated `gzip(tar(...))` decompresses the gzip, walks the intact tar entries,
and scans each one.

If nothing matches, the verdict is `OK`. exav is not a file-integrity validator:
when a sequential stream runs out of input, every byte that exists was scanned,
and the missing tail is absent rather than hidden. Indexed formats are different:
a damaged ZIP index can leave member data present but never enumerated, which is
why dual indexing exists.

## A member exav cannot read is reported

When extraction cannot produce a member's content (an unsupported codec,
encryption without a working password, a size deferred beyond recovery, an extent
running past the end of the file), exav emits a metadata-only member carrying the
name, size and reason, and the scan resolves to `UNSCANNABLE` or
`PASSWORD-PROTECTED`. A credible header means those bytes are a member the target
will extract, so leaving it out would be a clean verdict on something nobody
looked at.

The metadata is still matched: `.cdb` container signatures match on member name,
size, encryption flag and position, so a fake `invoice.pdf.exe` inside an archive
is caught by name even when its content is unreadable.

## Encryption

exav decrypts what it can: ZIP (ZipCrypto and WinZip AES), 7z AES-256 including
encrypted headers, encrypted DMG, PDF, and Office (legacy XLS RC4 and XOR
obfuscation, OOXML standard and agile AES).

Two defaults need no configuration. Office documents are tried with
`VelvetSweatshop`, Excel's built-in default password, which opens without a
prompt for the victim but looks opaque to a scanner that stops at "encrypted".
ZIPs are tried against a short built-in list of passwords malware distribution
uses (`infected`, `virus`, …). `--passwords` and ClamAV `.pwdb` databases add
your own.

An archive that stays encrypted is still a signal: "this member is encrypted" can
be matched by `.cdb` signatures, and `--partial-as password-protected=found`
turns it into a detection. An encrypted ZIP appended to a picture or document
(a polyglot that archive tools open by its trailing directory) is reported
`PASSWORD-PROTECTED` too, once its directory is found consistent.

## Hostile input

The extractor's entire input is attacker-controlled, so:

- `#![forbid(unsafe_code)]`, compiler-enforced, across every decoder.
- Release builds enable `overflow-checks`, so a wrapping size calculation traps
  instead of bypassing a limit.
- Each file is scanned under `catch_unwind`; a parser panic on one input is an
  error for that file, not an aborted batch.
- The decoders are tested on `wasm32`, where `usize` is 32-bit and overflows on
  parsed offsets that a 64-bit host would hide show up. It is also the build the
  [WASM sandbox](/guides/wasm-sandbox/) ships.
- A read error from the source is reported, never taken for the end of the
  container.
- Checksums are not enforced by default. A wrong CRC is a corrupt archive, not a
  reason to stop scanning; making it fatal would give an attacker a one-byte way
  to make a member unscannable.

## Validating a decoder

Every decoder is checked against a reference implementation's output, never only
against an encoder written next to it: a round trip through a matching encoder
proves that the two agree, and passes when both misread the format the same way.
The `.Z` (LZW `compress`) decoder once passed such a round trip while decoding
real `compress` output to garbage after a few hundred bytes.

So each decoder gets an external oracle:

| Format | Oracle |
|---|---|
| `.Z` | ncompress 5.0, built from source |
| CAB Quantum | `cabextract` / libmspack, over 107 generated streams |
| 7z BCJ2 | official 7-Zip 25.01 (`7zz x`) |
| UDF, VHDX, QCOW2, VMDK | `7zz x`, `qemu-img convert -O raw` |
| NTFS | `ntfscat` |
| LZ4 | `lz4 -dc` |
| ARC | `arc` 5.21q and `nomarch` |
| Office OOXML/XLS crypto | msoffcrypto-tool reference vectors |
| ZIP PPMd | the `ppmd-rust` encoder |
| ARJ | a real archive, mutated to produce each failure case |

Where the format carries one, the integrity check does the same job from inside
the data: RAR CRC-32, WIM SHA-1, ARC CRC-16, UPX Adler-32, 7z AES CRC. A subtly
wrong decoder produces plausible bytes rather than an error, so a checksum is
often the only sign.

A new decoder should come with an oracle; not having one is why several formats
in the [gap list](/reference/formats/#the-complete-gap-list) stay closed.

## See also

- [Supported formats](/reference/formats/): the container and codec list.
- [Interesting quirks](/concepts/quirks/): the stories behind several of the
  behaviours above.
- [Design principles](/concepts/design-principles/#never-a-silent-clean): the rule
  this all serves.
