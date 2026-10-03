---
title: Archive extraction
description: How exav unpacks containers, from the parity principle and bounded in-memory extraction to dual indexing, salvage, and why a member exav cannot read is reported rather than skipped.
---

Most malware does not arrive as a bare executable. It arrives inside something: a
ZIP, an ISO, a 7z, a Word document, an installer. The unpacker is what gets the
scanner to the bytes it has to match.

exav's extraction lives in `exav-unpack`, a standalone crate with no dependency
on the scanning engine, `#![forbid(unsafe_code)]`, and usable on its own as a safe
extraction library.

## The parity principle

If the software on the target's machine can open a container and exav cannot,
that container is an evasion vector: the payload lands intact and the scanner
said nothing useful about it.

An attacker picks the delivery format, so exav targets everything real extractors
open (7-Zip, WinRAR, WinZip, The Unarchiver, Windows Explorer, macOS Archive
Utility, libarchive), not the formats seen in recent samples.

[Supported formats](/reference/formats/) tracks this as a matrix: every container
and codec those extractors open, exav's status against each, and
[the gap list](/reference/formats/#the-complete-gap-list) of what is still
missing.

Every input is extracted through a seekable source: a file, an HTTP range
reader, or a stream buffered first (see
[Streaming & memory](/concepts/streaming-memory/)).

## The shape of the unpacker

exav finds the format, then hands each member to the scanner one at a time, all
under one set of limits (the `Budget`). A container is something that yields
members, and nesting is the same step applied to what comes out.

<svg viewBox="0 0 790 456" role="img" aria-labelledby="unpn unpd" style="width:100%;height:auto;max-width:790px">
  <title id="unpn">One walk into extraction</title>
  <desc id="unpd">A source is typed by detect(), then walk() hands its members
  to a visitor one at a time. A format whose decoder reads forward yields each
  member as a reader that decodes as it is read. A format whose decoder needs
  random access is read whole, bounded before it is allocated. Either way a
  member carries the same Budget, and each member re-enters detect(), bounded
  at --max-unpack-depth of 16. One Budget covers the whole tree, not each
  container.</desc>
  <defs>
    <marker id="unp-arrow" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="7" markerHeight="7" orient="auto">
      <path d="M0 0 L8 4 L0 8 z" fill="currentColor"/>
    </marker>
  </defs>
  <g fill="none" stroke="currentColor" stroke-width="1.5">
    <rect x="8" y="24" width="162" height="52" rx="6"/>
    <rect x="300" y="24" width="190" height="52" rx="6"/>
    <rect x="8" y="170" width="732" height="110" rx="6"/>
    <path d="M374 196 V270" opacity="0.4"/>
    <rect x="255" y="360" width="280" height="64" rx="6"/>
  </g>
  <g fill="currentColor" font-family="ui-monospace, SFMono-Regular, Menlo, monospace" font-size="13" font-weight="600">
    <text x="89" y="46" text-anchor="middle">source</text>
    <text x="395" y="46" text-anchor="middle">detect()</text>
    <text x="374" y="190" text-anchor="middle">walk(fmt, source, budget, visit)</text>
    <text x="395" y="386" text-anchor="middle">member</text>
  </g>
  <g fill="currentColor" font-family="system-ui, sans-serif" font-size="11.5" opacity="0.72">
    <text x="89" y="64" text-anchor="middle">file · reader · bytes</text>
    <text x="395" y="64" text-anchor="middle">start · end · a search</text>
    <text x="24" y="218">decoded as it is read: a reader,</text>
    <text x="24" y="236">nothing resident but what is read</text>
    <text x="24" y="254">zip · tar · cab · iso · gzip · …</text>
    <text x="390" y="218">read whole, bounded before it is</text>
    <text x="390" y="236">allocated, up to --max-object-bytes</text>
    <text x="390" y="254">rar · 7z · ole · pdf · chm · …</text>
    <text x="395" y="408" text-anchor="middle">metadata, content, same Budget</text>
    <text x="395" y="444" text-anchor="middle">one Budget for the whole tree, not per container</text>
    <text x="757" y="120" text-anchor="end">each member re-enters</text>
    <text x="757" y="138" text-anchor="end">detect() · --max-unpack-depth (16)</text>
  </g>
  <g fill="none" stroke="currentColor" stroke-width="1.5" marker-end="url(#unp-arrow)">
    <path d="M170 50 H296"/>
    <path d="M395 76 V166"/>
    <path d="M395 280 V356"/>
    <path d="M535 392 H770 V50 H494" stroke-dasharray="4 4"/>
  </g>
</svg>

`detect()` names the format, from the start of the object, its end, or a search
of it. `walk()` then hands the members to a visitor one at a time. A format whose
decoder reads forward (ZIP, tar, CAB, ISO, the single-stream compressors, …)
produces each member as a reader that decodes as it is read, so neither the
container nor the member is resident. A format whose decoder needs random access
over the whole container (7z, RAR, OLE, PDF, CHM, the virtual disks and
filesystem images, …) is read
whole, bounded before it is allocated, up to `--max-object-bytes`; past it the
container is `LIMITS-EXCEEDED`. 7z's members still stream once the container is
in memory. Which it is is a property of the decoder, not of how exav was
invoked; [Supported formats](/reference/formats/#size-what-is-read-as-it-goes-and-what-is-read-whole)
lists both.

Past the walk both are the same: a member carries the same `Budget` as its
parent, and scanning it re-enters `detect()`. So nesting needs no special case,
and the extraction budget bounds an archive tree rather than each container in
it.

A member's metadata comes before its content, and a visitor that leaves a member
unread costs nothing for it: a ZIP is listed from its central directory, and a
tar's headers are read in turn with the data between them skipped, so listing
decodes nothing.

## Bounded, budget before allocation

Every extraction runs under one `Budget`, reserved before a member is read rather
than checked after:

| Limit | Bounds | Default |
|---|---|---|
| output bytes | what formats decoded whole produce across the tree | 1 GiB, within half of `--max-process-bytes` |
| per-member size | a member decoded whole (a streamed member is bounded by the ratio and matcher budgets) | `--max-object-bytes` 256M |
| compression ratio | output ÷ input, the decompression-bomb guard | 1000 |
| file count | members across the archive and everything nested | `--max-members` 100000 |
| recursion depth | archives inside archives | `--max-unpack-depth` 16 |
| matcher bytes | bytes fed to the matcher across the tree, a CPU bound | `--max-matcher-bytes` 10G |
| emulation steps | instructions the PE unpacking emulator runs across the tree | `--max-pe-emulation-steps` 1,000,000,000 |

Reserving first keeps the peak bounded: a "1 GB from 4 KB" member never
allocates 1 GB and then gets rejected.

`exav-unpack` itself never writes to disk. The scanner may write a member too
large to hold to a temporary file (see
[Streaming & memory](/concepts/streaming-memory/)). That file is created with
`O_EXCL`, mode `0600`, under a name exav chooses, never the member's path, so
zip-slip, path traversal and symlink attacks still have nowhere to write.

## Containers have two indexes

A ZIP lists its members twice: a local file header before each member's data, and
a central directory at the end. Every normal reader trusts the central directory,
because that is what the specification says is authoritative.

So a member can be hidden: leave it out of the central directory and keep its
local header and data in the file. Plenty of extractors still write it out.

exav does dual indexing: after the central-directory pass it scans the raw bytes
for local headers the directory did not cover, and extracts those too. The same
path is the salvage route when the central directory is corrupt, forged or
truncated. On a ZIP read from its source rather than held in memory, the search
covers at most 16 MiB of unclaimed bytes, and a search cut short there is
reported, not taken as complete.

`PK\x03\x04` is four bytes and occurs by chance in ordinary binaries, so a
credibility check decides what counts as a member: version at most 6.3, no
reserved flag bits, a non-empty path within the length limit and free of NULs,
and a known compression method or, failing that, a readable UTF-8 name. A
header with an unknown method and a clean name is still a member, reported
unscannable, because a packer can stamp a nonsense method on a member to hide
it from readers that check the method.

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

A stream damaged part way is different: the compressed bytes after the damage
are present but were never decoded, so a clean prefix is `UNSCANNABLE`. A
checksum that fails after a full decode is not damage of that kind: everything
was decoded and scanned.

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

exav decrypts ZIP, 7z, DMG, PDF, Office and garbled ARJ members; the schemes
are listed in [Supported formats](/reference/formats/#encryption-support).
Office documents are tried with `VelvetSweatshop`, Excel's built-in default
password, and ZIPs with a short list of passwords malware distribution uses
(`infected`, `virus`, …), so neither needs configuration.
`--passwords` and ClamAV `.pwdb` databases add your own.

An archive that stays encrypted is still a signal: "this member is encrypted" can
be matched by `.cdb` signatures, and `--partial-as password-protected=found`
turns it into a detection. An encrypted ZIP appended to a picture or document
(a polyglot that archive tools open by its trailing directory) is reported
`PASSWORD-PROTECTED` too, once its directory is found consistent.

## Hostile input

The extractor's entire input is attacker-controlled, so:

- `#![forbid(unsafe_code)]`, compiler-enforced, across exav's own decoders (for
  third-party ones, see [Dependencies](/reference/dependencies/)).
- Release builds enable `overflow-checks`, so a wrapping size calculation traps
  instead of bypassing a limit.
- Each container walk and each file runs under `catch_unwind`: a decoder panic
  makes that container `UNSCANNABLE`, and a panic elsewhere is `ERROR` for that
  file, not an aborted batch.
- The decoders are tested on `wasm32`, where `usize` is 32-bit and overflows on
  parsed offsets that a 64-bit host would hide show up. It is also the build the
  [WASM sandbox](/guides/wasm-sandbox/) ships.
- A read error from the source is reported, never taken for the end of the
  container.
- Most formats scan a member whose checksum fails: a wrong CRC is a corrupt
  archive, not a reason to stop scanning. RAR, WIM, ARC and EGG, where the
  checksum is the only check on a decoder, report such a member `UNSCANNABLE`
  instead; ZOO scans it and flags the mismatch.

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
| ZIP PPMd | the `ppmd-rust` encoder, an implementation independent of exav's decoder |
| bzip2 | the `bzip2` crate's encoder, a port of libbzip2 |
| ARJ | a real archive, and mutations of it for each failure case |

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
