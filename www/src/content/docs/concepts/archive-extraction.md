---
title: Archive extraction
description: How exav unpacks containers — the parity principle, bounded in-memory extraction, dual indexing, salvage, and why every member exav cannot read is reported rather than skipped.
---

Most malware does not arrive as a bare executable. It arrives inside something:
a ZIP, an ISO, a 7z, a Word document, an installer. So a scanner's real job is
less "match bytes" than "reach the bytes", and the unpacker is where that fight
happens.

exav's extraction lives in `exav-unpack` — a standalone crate with **no
dependency on the scanning engine**, `#![forbid(unsafe_code)]`, and usable on its
own as a safe extraction library.

## The parity principle

Coverage is not a feature list, it is a boundary. **If the software on the
target's machine can open a container and exav cannot, that container is an
evasion vector by construction** — the payload lands intact and the scanner said
nothing useful about it.

The attacker picks the delivery format, so the target to match is the *union* of
what real extractors handle: 7-Zip, WinRAR, WinZip, The Unarchiver, Windows
Explorer, macOS Archive Utility, libarchive. Not the intersection, not the common
case, and emphatically not "what showed up in last month's corpus" — a format
appearing zero times in a sample says nothing about the file someone is sent
tomorrow.

[Supported formats](/reference/formats/) tracks this as an audited matrix:
every container and codec those extractors open, with exav's status against each,
and [one authoritative gap list](/reference/formats/#the-complete-gap-list) of
what is still missing.

## Two input modes

What exav can do depends on whether it can seek:

- **Stream** (stdin, a pipe) — the constant-memory pattern and hash core only.
  Unlimited size, but structural unpacking needs to seek, so a pure pipe gets
  pattern+hash matching over the raw bytes.
- **Seekable** (a file, or an HTTP range reader) — full recursive extraction,
  fetching only the directory and the members actually scanned.

This is why `cat archive.zip | exav -` and `exav archive.zip` are not equivalent,
and why the streaming path is honest about it rather than pretending.

## The shape of the unpacker

One sentence carries most of it: **a member is bytes plus a budget, a container
is something that yields members, and nesting is that same step applied to what
comes out.**

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
    <text x="8" y="160">DOOR A — STREAMING</text>
    <text x="452" y="160">DOOR B — BUFFERED</text>
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
    <text x="24" y="254">zip · tar · gzip · …</text>
    <text x="468" y="218">needs the WHOLE container as one slice,</text>
    <text x="468" y="236">bounded before it is allocated</text>
    <text x="468" y="254">7z · rar · cab · iso · …</text>
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

The two doors are the thing to hold on to. `identify()` types the bytes, and
`streams_natively` decides which one opens. Door A hands back members one at a
time and never has the container resident; door B needs the whole container as a
single slice before it can start. Which door a format uses is a property of that
format's decoder, not of how you invoked exav.

Everything past the door is the same for both: a member is bytes carrying the
**same** `Budget` as its parent, and scanning it re-enters `identify()`. That is
why nesting needs no special case — and why `maxExtractedBytes` bounds an archive
tree rather than each container in it.

### Where the code departs from the picture

The map is clean; the territory has four bumps to know about before you read the
source.

**There are two dispatches, not one.** `dispatch_stream` and `dispatch_extract`
are separate functions with separate format coverage. A change made to one does
not appear in the other, and a format can be reachable through one door only. If
you are tracing why a hook or a check does not fire, this is the first thing to
suspect.

**Door B is the default, not the exception.** Most formats land in it, and which
door a given one uses is answered by `streams_natively` rather than by any count
written down here.
`ArchiveInner` — the seekable `Archive<R>` API — has native arms for `Zip`,
`Tar` and `Gzip`, a `Lazy` arm for the single-stream compressors (bzip2, xz,
zstd), and a `Buffered` arm that reads the reader into memory and hands it to
door B. That last arm is where 7z, rar, cab, iso and the rest sit.

**An empty `Archive::list()` means "no directory", not "no members".** Only
formats that carry an index can be listed without extracting: a ZIP's central
directory, a tar's headers. A gzip has no index by construction — its single
member's name and size are not knowable without decompressing. Callers that
treat an empty list as an empty archive get that wrong, which is why the wasm
bindings walk the archive instead of passing the empty slice outward.

**A ZIP has more members than its directory admits to.** Extraction also scans
the bytes the central directory does not claim, because a member with a local
header and no directory entry is hidden from every reader that walks the
directory alone — while the tool that opens the archive extracts it anyway. Both
doors do this; a listing reports those members at indices straight after the
directory's own.

## Bounded, in memory, budget-before-allocation

Every extraction runs under a `Budget`. Five limits, all reserved *before* a
member is read rather than checked after:

| Limit | Bounds |
|---|---|
| output bytes | total decompressed size across the whole tree |
| per-member size | one member's decompressed size |
| compression ratio | output ÷ input, the decompression-bomb guard |
| file count | members across the archive and everything nested |
| recursion depth | archives inside archives inside archives |

Reserving first is what makes the peak bounded rather than merely detected: a
"1 GB from 4 KB" member never allocates 1 GB and then gets rejected.

**Nothing is written to disk.** The extractor materializes members in memory
only, which removes zip-slip, path traversal and symlink attacks as a class —
there is no filesystem write for a `../../` path to escape into.

## Containers have two indexes

A ZIP lists its members twice: a local file header before each member's data, and
a central directory at the end. Every normal reader trusts the central directory,
because that is what the specification says is authoritative.

Which means you can hide a member: leave it out of the central directory and keep
its local header and data in the file. Plenty of extractors still write it out.

exav does **dual indexing** — after the central-directory pass it scans the raw
bytes for local headers the directory didn't cover, and extracts those too. The
same path doubles as salvage when the central directory is corrupt, forged or
truncated.

The gate matters as much as the scan. `PK\x03\x04` is four bytes and occurs by
chance in ordinary binaries, so a credibility check (version, reserved flag bits,
a real compression method, a NUL-free path within the length limit) decides what
counts as a member. Across 3,000 live malware samples it produced no false hits.

ISO images have the same shape and the trick is used more openly: a CD image
carries several volume descriptors, each with an independent directory tree over
the same sectors. A malicious ISO lists its payload in only the Joliet tree and
leaves the primary tree empty, so a reader that parses the other one sees an
empty disc. exav walks **every** tree.

## Recovering what a naive reader would skip

Two cases where the easy behaviour is to give up, and giving up is wrong:

**Deferred sizes.** A streaming ZIP writer sets a flag and puts the member's
sizes in a *data descriptor after the data*, so the local header alone doesn't
say where the member ends. exav recovers the extent — from the descriptor's own
`PK\x07\x08` marker when its declared size is self-consistent, otherwise by
running to the next header (only for deflate, which self-terminates; a stored
member would silently swallow the descriptor and the following headers into its
content).

**Truncated streams.** A gzip cut short mid-DEFLATE is common in the wild, and
`zcat` happily recovers everything before the cut. Discarding that prefix would
be a real miss, because the payload is often right there in it. exav scans the
salvaged prefix, and the nesting works: a truncated `gzip(tar(...))` decompresses
the gzip, walks the intact tar entries, and scans each one.

And if nothing matches, the verdict is **`OK`** — not "not fully scanned". exav
scans for malware, it is not a file-integrity validator. When a *sequential*
stream simply runs out of input, every byte that exists was scanned; the missing
tail is *absent*, not *hidden*.

That distinction is the whole game, and it is why indexed formats are treated
differently: a damaged ZIP index can leave member data *present but never
enumerated*, which is content that exists and was not read. Hence dual indexing —
without it, "clean" on a damaged ZIP would be a claim about bytes nobody looked
at.

## A member exav cannot read is reported, never dropped

This is the rule the whole design bends around. When extraction cannot produce a
member's content — unsupported codec, encryption without a working password, a
size deferred beyond recovery, an extent running past EOF — exav emits a
**metadata-only member** carrying the name, size and reason, and the scan
resolves to `UNSCANNABLE` or `PASSWORD-PROTECTED`.

It does not quietly omit it. Omitting one member is how a scanner reports a file
clean on the strength of a scan that never looked inside it, and a credible
header means those bytes *are* a member the target will extract.

The metadata still earns its keep: `.cdb` container signatures match on member
name, size, encryption flag and position, so a fake `invoice.pdf.exe` inside an
archive is caught by name even when its content is unreadable.

## Encryption is not a wall, and it is a signal

exav decrypts what it can rather than stopping at "encrypted": ZIP (ZipCrypto and
WinZip AES), 7z AES-256 including encrypted headers, encrypted DMG, PDF, and the
Office family — legacy XLS RC4 and XOR obfuscation, plus OOXML standard and agile
AES.

Two defaults do most of the work with no configuration. Office documents are
tried with **`VelvetSweatshop`**, Excel's hard-coded default password, which
opens zero-click for the victim while looking opaque to a scanner that stops at
"encrypted". ZIPs are tried against a small built-in list of the passwords
malware distribution actually uses (`infected`, `virus`, …). Beyond that,
`--passwords` and ClamAV `.pwdb` databases supply your own.

An archive that stays encrypted is still not nothing: "this member is encrypted"
is itself a detectable property via `.cdb` signatures, and
`--partial-as password-protected=found` turns it into a detection.

## Hostile input, everywhere

The extractor's entire input is attacker-controlled, so:

- `#![forbid(unsafe_code)]`, compiler-enforced, across every decoder.
- Release builds enable `overflow-checks`, so a wrapping size calculation traps
  instead of silently bypassing a limit.
- Each file is scanned under `catch_unwind`; a parser panic on one crafted input
  is an error for that file, never an aborted batch.
- The decoders are tested on **`wasm32`**, where `usize` is 32-bit. Integer and
  capacity overflows on parsed offsets are invisible on a 64-bit host and abort
  there — and it is the same build the [WASM sandbox](/guides/wasm-sandbox/)
  ships.
- Checksums are **not** enforced by default. A wrong CRC is a corrupt archive,
  not a reason to stop scanning, and treating it as fatal would hand attackers a
  one-byte way to make a member unscannable.

## Validating a decoder

Every decoder here is checked against a **reference implementation's output**,
never against an encoder written next to it. A round-trip through a matching
encoder proves only that the two agree with each other, and passes happily when
both misread the format the same way.

That is not hypothetical. While writing the `.Z` (LZW `compress`) decoder a
seven-case round-trip went green — and real `compress` output decoded to garbage
after the first few hundred bytes. The round-trip had validated a shared
misreading of when the code width increases.

So each decoder gets an external oracle, built or downloaded locally:

| Format | Oracle |
|---|---|
| `.Z` | ncompress 5.0, built from source |
| CAB Quantum | `cabextract` / libmspack, over 107 generated streams |
| 7z BCJ2 | official 7-Zip 25.01 (`7zz x`) |
| UDF, VHDX, QCOW2, VMDK | `7zz x`, `qemu-img convert -O raw` |
| NTFS | `ntfscat` |
| LZ4 | `lz4 -dc` |
| ARC | `arc` 5.21q and `nomarch` |
| Office OOXML/XLS crypto | the `ppmd-rust` and RustCrypto implementations |
| ARJ | a real archive, mutated to produce each failure case |

Where the format provides one, the integrity check does the same job from inside
the data: RAR CRC-32, WIM SHA-1, ARC CRC-16, UPX Adler-32, 7z AES CRC. A decoder
that is subtly wrong produces *plausible bytes* rather than an error, so a
checksum is often the only signal that anything went wrong.

Anything added here should come with an oracle. Being unable to name one is
itself the reason several formats in the
[gap list](/reference/formats/#the-complete-gap-list) stay closed.

## See also

- [Supported formats](/reference/formats/) — the current container and codec list
- [Interesting quirks](/concepts/quirks/) — the war stories behind several of the
  behaviours above
- [Design principles](/concepts/design-principles/#never-a-silent-clean) — the
  invariant this all serves
