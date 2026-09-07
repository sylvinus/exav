---
title: Interesting quirks
description: Things about malware scanning that surprise competent developers — hard-coded Excel passwords, signature databases that ship executable programs, archives with two indexes, and why a wrong checksum must never stop a scan.
---

Malware scanning is full of behaviour that looks like a bug until you learn the
adversary reason for it. This page collects the ones that surprised us while
building exav, with the code that implements each.

Everything here is either exav's own design decision, a **public** specification
(Microsoft/RFC/APPNOTE), or documented/observable ClamAV behaviour. exav derives
nothing from ClamAV's GPL source; where exav matches a ClamAV behaviour it does
so from the public spec, and that is noted.

## `VelvetSweatshop`: the password that isn't a secret

Build a malware corpus, scan the spreadsheets, and a striking number report as
**encrypted / password-protected** — yet they open in Excel with no prompt at
all. The trick is a single hard-coded string: **`VelvetSweatshop`**.

`VelvetSweatshop` is the *default* password Excel uses when a workbook is
encrypted with default settings. Excel tries it automatically on open, so a
document "encrypted" with it opens **silently**. That is exactly what a malware
author wants:

- To a scanner that stops at "encrypted", the payload is **opaque** — it can't
  see the macros or the embedded objects, so it reports clean (or, in exav's
  case, `PASSWORD-PROTECTED`).
- To the victim, the file opens **normally** and the macros run.

Encrypt-to-hide while staying zero-click on the target. It applies to legacy
`.xls` (BIFF, RC4 / RC4-CryptoAPI) and to OOXML `.xlsx`/`.docx` (AES). The
mechanism is fully public: **[MS-OFFCRYPTO]** documents the key derivation and
ciphers, **[MS-XLS] §2.4.117** documents the legacy `FilePass` record that marks
a workbook stream encrypted.

The three schemes, from [MS-OFFCRYPTO]:

- *Legacy XLS (BIFF8)* — the `Workbook`/`Book` stream begins `BOF` then
  `FilePass`; encryption type 1 is RC4 (basic) or RC4-CryptoAPI. The key comes
  from the UTF-16LE password plus a salt (MD5 for basic RC4, SHA-1 for
  CryptoAPI), a verifier block confirms it, then the stream is RC4-decrypted in
  1024-byte blocks, re-keyed per block, with a handful of records left plaintext.
- *OOXML standard encryption* — an OLE2/CFB wrapper holds `EncryptionInfo` +
  `EncryptedPackage`; the key is `SHA-1(salt ‖ UTF-16LE(password))` spun
  **50000** times, an AES-128-**ECB** verifier confirms it, and the package
  decrypts back into the real `.xlsx` ZIP.
- *OOXML agile encryption* (the modern default) — AES-256-CBC with a per-blob
  KDF.

**What exav does:** decrypts all three families in
`crates/exav-unpack/src/formats/ole_crypto.rs` — legacy XLS RC4-basic and
RC4-CryptoAPI, the older XOR obfuscation scheme (§2.3.7), and both OOXML schemes,
standard (AES-ECB) and agile (AES-CBC). `ole.rs` routes an `EncryptionInfo` +
`EncryptedPackage` compound file through the decryptor and hands the recovered
`.zip` back to the ZIP path, so the document's parts get scanned normally.
`VelvetSweatshop` and the empty password are tried by default (plus any
`--passwords`), so the common case needs no configuration at all.

Implemented clean-room from [MS-OFFCRYPTO] §2.3.4/§2.3.5/§2.3.6/§2.3.7 and
[MS-XLS] §2.4.117, verified byte-exact against an independent oracle on real
samples and against real-Office key-derivation vectors for the agile scheme. On a
live corpus, ~240 XLS that were opaque `PASSWORD-PROTECTED` now decrypt — 180
surfacing `Heuristics.OLE2.ContainsMacros`. Files using a *non-default* password
stay `PASSWORD-PROTECTED`, correctly: we don't know it.

> The string has been the Excel default since the late 1990s. It looks like an
> inside joke that shipped, and two decades later it is still active malware
> infrastructure.

## The signature database ships executable programs

Most people assume a signature is a pattern. ClamAV's most expressive signature
type is a **program**: a `.cbc` file in `bytecode.cvd` is C compiled to a custom
LLVM-IR-like VM bytecode, shipped inside the signature feed, which runs against a
candidate file and decides whether it is malicious.

So a scanner that wants to be compatible does not get to write a matcher. It has
to **embed an interpreter** — with everything that implies: an instruction
budget, a scratch-memory cap, a call-depth limit, a bounds-checked pointer model,
and a panic boundary per program.

The format is line-oriented: a `ClamBC` header with a nibble-encoded integer
scheme (a byte `0x6N` carries nibble `N`), a **trigger line** that is itself a
`.ldb` logical signature (the program runs *only* when that matches), then
records for types, API declarations, globals, function headers, basic-block
instruction streams, and strings. Programs cannot make syscalls; they reach the
world through a fixed API of ~96 functions — `read`/`seek`/`file_find`, PE/PDF/
JSON accessors, hashing, `disasm_x86`, and `setvirusname` to report a hit.

The live database (v339, Sep 2025) holds **85** programs. 71 of the 85 have a
single function. The most valuable are the ~6 **unpackers** — some of ClamAV's
unpacking is implemented *as bytecode*, so a missing one silently weakens
detection across every packed sample rather than costing one signature.

The second surprise: **the signature database is untrusted input.** It is a
file, fetched over the network, parsed by your process, and in this case
*executed* by it. ClamAV's bytecode subsystem has a documented code-execution
history ([CVE-2020-37167](https://www.cve.org/CVERecord?id=CVE-2020-37167),
CVSS 8.4 — the `bytecode_vm` sandbox escape, exploit-db 47687; the optional LLVM
JIT that generated native code from database content). exav treats the container
the same way it treats a scanned file — `crates/exav-core/src/cvd.rs` bounds
CVD/CLD extraction with explicit caps because "the database is
attacker-controllable in the threat model".

exav's interpreter (`crates/exav-core/src/bytecode/`) is pure safe Rust, no JIT
ever, with `catch_unwind` per program. One detail worth stealing: the budget is
**step count, not wall-clock** (`bytecode/exec.rs`) — a wall-clock deadline
would make detection depend on machine load, letting an attacker (or a busy
server) push a program past the deadline to evade detection.

See [Bytecode sandbox](/concepts/bytecode-sandbox/).

## The file extension is a lie, and so is the magic number

Nobody who has worked on this trusts an extension. File type comes from content
only — `crates/exav-core/src/filetype.rs` is explicit that it "never trust[s] the
file extension". Signatures are *scoped by type* (`Target:` in a signature, and
`CL_TYPE_*` container constraints), so getting the type wrong doesn't just skip a
parser, it silently deselects a whole class of signatures.

The part people don't expect is that **magic bytes aren't enough either**.

- **`CA FE BA BE` is two formats.** It is the Mach-O universal ("fat") binary
  magic *and* the Java `.class` magic. exav resolves it structurally, not by
  guessing: `formats/machofat.rs` claims a fat binary only when `nfat_arch` is in
  `1..=64`, the whole arch table is present, and every slice lies within the
  file; `.class` detection additionally requires a plausible major version (≥ 45,
  i.e. JDK 1.1+), which a fat header's architecture count never is.
- **Short magics collide with ordinary binary data.** bzip2 is `BZh`, CAB is
  `MSCF`, gzip is two bytes. A false hit inside a PE overlay or an ISO member
  gets routed to that decoder, fails deep in parsing, and would report the whole
  object `UNSCANNABLE`. So `Db::identify` (`crates/exav-core/src/lib.rs`)
  confirms each weak magic against a stronger structural check first — the CAB
  spec's `reserved1` field must be zero, gzip's compression method must be
  deflate with valid flag bits — and a failed confirmation is scanned as raw
  bytes rather than poisoning the verdict.
- **HTML has no magic at all.** `filetype.rs` detects it heuristically, and
  deliberately conservatively, because ClamAV applies `Target:3` signatures only
  to HTML — so over-typing makes an HTML-exploit signature fire on obfuscated
  JavaScript that merely contains `Uint32Array(0x..)`.
- **Text detection has to be generous about high bytes.** `looks_textual`
  accepts `0x80..=0xff` freely (it gates on NUL and a >5% density of
  non-whitespace control bytes) — otherwise non-English text malware types as
  binary and loses its `Target:7` ASCII-text coverage entirely.
- **The same container is several types.** A `.docx`, `.xlsx`, `.apk` and `.jar`
  are all ZIPs. exav reads a bounded 1 MiB prefix and classifies by member name —
  `[Content_Types].xml` plus `word/document.xml` / `xl/workbook.xml` /
  `ppt/presentation.xml` — because many signatures are scoped to `CL_TYPE_OOXML_*`
  and would otherwise either miss real Office documents or fire on plain ZIPs.

Type detection then re-runs on every extracted child, with one deliberate
override: textual content pulled out of an OLE2 document is forced to OLE type,
so `Target:2` macro signatures apply and generic `Target:7` text signatures do
*not* — without that, a generic text macro signature false-positives on the
standard `Name="Project"` PROJECT stream of benign macro documents.

## `cat malware huge.pad > evil` is a one-line bypass

Every scanner has a maximum file size. The naive implementation — "file is over
the limit, skip it, report OK" — hands the adversary a bypass they can execute
with one shell command: append padding until you cross the threshold.

The strongest published example is ClamAV's long-standing large-file behaviour:
a file over roughly 2 GB is **read but scanned as zero bytes, and still reported
`OK`**. Not "skipped", not "error" — clean.

exav's rule, stated in the `exav-core` crate docs as anti-evasion invariant 2, is
**never refuse by size without scanning**. `scan_path` and `scan_seekable`
(`crates/exav-core/src/lib.rs`) run the flat pattern+hash core over the budgeted
prefix *first*; only if that finds nothing does the file get a limit verdict:

```text
file size 5368709120 exceeds max-scan-size 104857600; scanned first 104857600 bytes only
```

Invariant 1 is the companion: **a detection always beats a limit.** A hit is
never downgraded to `LIMITS-EXCEEDED` or `CLEAN` because some *other* part of the
input tripped a budget.

And invariant 3 is the one the rest hangs on: not-fully-scanned is never
`CLEAN`. See [Design principles](/concepts/design-principles/#never-a-silent-clean)
and [Verdicts & exit codes](/reference/verdicts/).

> exav's streaming core makes this mostly moot for the size case anyway: it
> matches in a single forward pass with a flat ~2 MiB working set, so a 6 GiB file
> on a 4.8 GiB machine is scanned end to end. See
> [Streaming & memory](/concepts/streaming-memory/).

## Containers have two indexes, and malware uses the one you don't read

A ZIP file lists its members twice: once as a **local file header** immediately
before each member's data, and once in the **central directory** at the end. Every
normal reader — including the `zip` crate, including your language's stdlib —
trusts the central directory, because that's what APPNOTE says is authoritative.

That means you can hide a member: leave it out of the central directory while
leaving its local header and data in the file. Many extractors will still write it
out. A scanner that only enumerates the central directory never sees it.

exav does **dual indexing** in `formats/zip.rs`: after the normal central-directory
pass, `scan_orphan_locals` builds a set of every known `header_start()`, scans the
raw bytes for `PK\x03\x04` local headers not in that set, and extracts those too.
The same path doubles as salvage — if the central directory is unparseable
(corrupt, forged, truncated), exav doesn't give up, it falls through to the raw
local-header scan.

The subtle part is what to do with an orphan you *can't* read. Skipping it is the
tempting default and it is wrong: the header is credible, so the bytes are a
member the target will extract, and dropping it lets the containing file be
called clean on a scan that never looked inside. So every failure is reported
instead — encrypted, unsupported codec, size deferred to a trailing data
descriptor, or a declared extent running past EOF each yield a metadata-only
`Entry::unsupported` and an `UNSCANNABLE` verdict.

The counterweight is that `PK\x03\x04` is four bytes and turns up by chance in
ordinary binaries, so reporting every hit would make clean files unscannable.
`plausible_local_header` gates on the fields a real writer must fill in
consistently — version ≤ 6.3, no reserved flag bits, a method APPNOTE actually
defines, and a name that is non-empty, within the path limit and free of NULs.
Across 3,000 live malware samples that gate produced no spurious hits at all.

There is deliberately **no** separate cap on orphan count: each one is charged to
the archive-wide `max_members` budget, so exceeding it raises `LIMITS-EXCEEDED`
rather than quietly stopping. An arbitrary cap was in fact the bug — a real JAR
turned up whose End Of Central Directory record was simply gone, leaving 414
members reachable only as local headers, and a few hundred members is completely
ordinary for a JAR.

One more distinction in the code: an unparseable central directory is classified
`corrupt` → `UNSCANNABLE`, never `LIMITS-EXCEEDED`, because a resource bound and
a forged index are different claims.

**ISO images have the same shape, and the trick is used more brazenly.** A CD
image carries several volume descriptors, each with its own independent directory
tree over the same sectors — the primary ISO9660 tree and the Joliet
supplementary tree (long Unicode names). A malicious ISO lists its payload in
**only one** of them, typically Joliet, leaving the primary tree empty, so a
reader that parses the other sees an empty disc. `formats/iso.rs::vd_roots`
enumerates every volume descriptor from sector 16 until the terminator and walks
the root of *each* primary and Joliet tree, Joliet first so the real long names
win when a file appears in both. The regression test names the shape it was
written for: an `Invoice.pdf.lnk` delivered inside an ISO.

**gzip has this problem too, in miniature.** RFC 1952 §2.2 allows a `.gz` to be
several concatenated members, and `gzip`/`zcat` decompress all of them. Rust's
`flate2::GzDecoder` stops after the first. `formats/gzip.rs` uses
`MultiGzDecoder` because of an observed false negative: a two-member gzip whose
first member is a 1 KiB header and whose second holds the malware.

Related, and the reason "type by content" isn't sufficient on its own: the same
carving logic runs for **appended** archives. `pe::embedded_archive_offsets`
enumerates ZIP/gzip/bzip2/xz/7z/RAR/CAB magics at offset > 0 — SFX stubs, PE
overlays, droppers that staple a ZIP onto a carrier. The dedicated SFX carver
(`formats/sfx.rs`) only claims one when the file *starts* with `MZ`/`ELF` **and**
an archive magic appears at least `MIN_SFX_OFFSET = 64` bytes in.

A subtle rule falls out of that: when a carve guess fails to decode, exav must
**silently drop it**, not mark the carrier `UNSCANNABLE`. A false `1f8b08` byte
run inside a PE is not an encrypted archive; the carrier was already fully
pattern-scanned, and poisoning it would be a false positive against a scanner
that (correctly) calls such files clean.

## "Encrypted" is itself a detection

Once you accept that malware encrypts things to blind scanners rather than to
protect them, encryption stops being an obstacle and becomes a feature you can
match on.

**ClamAV's `.cdb` container-metadata format makes it a field.** The line is

```text
VirusName:ContainerType:ContainerSize:FileNameREGEX:FileSizeInContainer:FileSizeReal:IsEncrypted:FilePos:Res1:Res2[:MinFL[:MaxFL]]
```

`IsEncrypted` is three-state (`1`, `0`, `*`), so a signature can say *"a ZIP
containing an encrypted member whose name matches `(?i)invoice.*\.exe`"* and fire
without ever decrypting anything. exav implements this in
`crates/exav-core/src/container.rs`. A real signature from `daily.cvd` shows how
much a metadata-only rule can do:

```text
Archive.Filetype.DualExtJS-6168221-2:CL_TYPE_ZIP:*:^[^/\\]+\.(doc|xls|ppt|pdf|png|gif|jpeg)\.js$:*:*:*:1:*:
```

That is a double-extension detector — it catches
`PurchaseOrder_006231_Shanghuigou_20260605.pdf.js` by **name and position alone**,
with no content signature at all. (The `FilePos` field is 1-based. exav numbered
from 0 at first and missed every one of these — the test in `container.rs`
records the regression.)

Two more places encryption shows up as signal:

- `--partial-as password-protected=found` turns a password-protected member
  into an actual detection,
  `Heuristics.Encrypted.Zip` / `.RAR` / `.7Zip` / `.PDF` / `.Doc`
  (`encrypted_heuristic_name` in `crates/exav-core/src/lib.rs`).
- exav ships a **default password list**. `formats/zip.rs`:

  ```rust
  const DEFAULT_ZIP_PASSWORDS: &[&str] = &["infected", "virus", "malware", "password", "123456"];
  ```

  These are the malware-distribution conventions — "infected" is the standard
  password for sharing samples — so a password-protected dropper cracks with zero
  configuration, exactly as `VelvetSweatshop` does for Office. A `.pwdb` database
  file and `--passwords` extend the pool.

## A wrong checksum must never stop the scan

This one reads like a bug in every code review. exav extracts archive members
**without verifying their CRCs**, and `Budget::verify_checksums` is off by
default (`crates/exav-unpack/src/lib.rs`).

The reason is in the comment: a malware scanner scans decompressed content
regardless of integrity metadata, because *"a wrong CRC must never stop a
member's bytes from being scanned — that would let an attacker downgrade a
detection by flipping a checksum byte."* One byte, anywhere in a trailer, and a
strict extractor stops looking. (This matches ClamAV, which ignores CRCs when
scanning. Turning verification on requires both the `checksums` Cargo feature and
an explicit opt-in, and is for extract-for-real use where a bad CRC is a genuine
"corrupt file" signal.)

The same instinct generalises. A CAB whose `CFHEADER.cbCabinet` total-size field
is overwritten with `0xFFFFFFFF` defeats a strict parser; exav clamps it and
extracts the member anyway. A gzip with a deliberately corrupted CRC-32 trailer
still yields its payload. A truncated deflate stream is salvaged up to the cut,
because the malware is usually in the recovered prefix — half-downloaded
droppers and deliberately mangled tails are common in the wild, and `zcat`
recovers them too.

Where the leniency has to *stop* is structure, not integrity. `formats/ole.rs`
falls back to a flat directory walk when a strict CFB reader rejects a compound
file (a broken red-black-tree sibling ordering, e.g. `_VBA_PROJECT` sorted before
`dir`, which many real Office documents and much malware carry) — but a member
that is *present and unreadable* still surfaces as not-fully-scanned rather than
clean.

> The nuance for truncation: exav scans for malware, it is not a file-integrity
> validator. When a *sequential* stream runs out of input, every byte that exists
> has been scanned — the missing tail is absent, not hidden — so a clean result is
> a real clean. The not-fully-scanned verdicts are reserved for content that is
> **present but unscanned**: an encrypted member, an unsupported codec, or a
> member skipped to stay under a limit.

## Identity that survives the bytes changing

Two files can share nothing byte-for-byte and still be provably the same malware.
Three mechanisms in the signature formats do this, each surprising in its own way.

**imphash** (`crates/exav-core/src/pe.rs`) is the MD5 of the PE's *import table*
— comma-joined lowercase `dll_without_extension.function`, in import-table order
(the Mandiant definition). Recompile, repack, change every string, pad the
sections: as long as the binary links the same API functions in the same order,
the imphash is identical. exav loads these from `.imp` signatures
(`PEImportTableHash:PEImportTableSize:MalwareName`) where the "size" field is not
a byte count at all — it is the **number of imports**.

The trap is ordinals. Imports by ordinal contribute `dll.ord<n>`, not a function
name. If your PE parser renders an ordinal import as the string `ORDINAL 42` and
you hash that, or you drop ordinal imports entirely, you get a different hash and
miss every `.imp` signature. This was a real differential-testing finding.

**Section hashes** (`.mdb` MD5, `.msb` SHA) hash one PE section instead of the
file, so an unchanged code section is still recognised after the resources,
overlay, or certificate table change. Two quirks:

- The field order is **transposed** relative to whole-file hashes. `.hdb` is
  `HASH:SIZE:NAME`; `.mdb` is `SIZE:HASH:NAME`. `crates/exav-core/src/hashes.rs`
  keeps two separate parsers for exactly this reason. (The digest algorithm is
  inferred from hex length: 32 → MD5, 40 → SHA-1, 64 → SHA-256.)
- The size key and the hashed bytes can legitimately disagree. `pe::section_slices`
  keys on the section's **declared** `SizeOfRawData` but digests only the bytes
  that actually exist on disk — overlay-trimmed and truncated PEs declare a raw
  size that overruns EOF, and dropping those sections loses real detections.

**TLSH** (`crates/exav-core/src/fuzzy.rs`) goes further: a locality-sensitive
whole-file hash matched by **distance**, not equality, so near-variants of a known
sample are caught. The signature carries its own threshold
(`tlsh:HASH:Name[:MaxDistance]`, default 100), which means the lookup is a linear
scan with a distance computation rather than a hash-table probe — a completely
different cost shape from every other signature type. It also silently declines on
inputs under ~50 bytes or too uniform to digest, so small droppers simply have no
fuzzy identity.

## Scanning icons, because malware dresses up

A trojan that wants to be double-clicked wears a familiar icon — Chrome, Adobe
Reader, a Word document, a folder. So AV engines hash icons **perceptually**, and
a signature can require *"these bytes AND this executable is wearing that icon."*

exav implements ClamAV's `.idb` format in `crates/exav-core/src/icon.rs`. The
surprising parts:

- The "hash" is not a digest. It is a 124-nibble hex blob that unpacks into a
  struct: for each of six derived fields — colour, grayscale, bright, dark, edge,
  non-edge — the average value and (x, y) location of the three most extreme
  non-overlapping k×k windows, plus RGB sums and a colour-pixel count. The edge
  field is a CIE-Lab colour-distance map, Sobel-filtered, normalised, bordered and
  Gaussian-blurred.
- Matching is a **confidence score against a threshold**, not equality: ≥ 70 for
  black-and-white icons, and 72/68/64 for 16/24/32-pixel colour icons. Only those
  three icon sizes exist in the format; any other side length is dropped.
- The icon is never a detection by itself. It is an extra AND-clause: a logical
  signature's `IconGroup1:`/`IconGroup2:` TDB fields add "…and the PE's icon
  perceptually matches an `.idb` entry in these groups". Without an icon context
  the constraint can't be satisfied, so the signature does not fire.
- Getting the icon out means walking PE resources: find `RT_GROUP_ICON` (type 14),
  read the icon count, walk 14-byte `GRPICONDIRENTRY` records, resolve each
  `icon_id` under `RT_ICON` (type 3), then decode the DIB.

exav also supports the separate `fuzzy_img#<16-hex>` logical subsignature, which
is a **different algorithm entirely** — the 64-bit DCT perceptual hash from
Python's `imagehash` (`phash()`, median variant), matched by Hamming distance
(`crates/exav-core/src/fuzzy_img.rs`). Reproducing it byte-exactly means pinning
things that normally don't matter: BT.601 grayscale coefficients with round-half-
away-from-zero, a Lanczos3 resize to exactly 32×32 with no aspect preservation,
a ×2 scale after each 1-D DCT pass, the top-left 8×8 block including DC, a strict
`>` median threshold, MSB-first packing. Any one of those wrong and you match
nothing.

## Signature matching is a regex engine, and a step budget is a trap

`.ndb` bodies are hex with wildcards, and the wildcard set is richer than most
people expect (`crates/exav-core/src/engine/parse.rs::parse_elems`):

| Construct | Meaning |
|---|---|
| `??` | any byte |
| `a?` / `?a` | nibble wildcard (high or low nibble fixed) |
| `*` | unbounded gap |
| `{n}` `{n-m}` `{-m}` `{n-}` | exact / range / at-most / at-least gap |
| `[n-m]` | same matching semantics as `{n-m}` |
| `(aa\|bb)` / `!(aa\|bb)` | alternation / negated alternation |
| `(B)` `(L)` `(W)` | **not** alternations — word/line/word-marker boundaries |

That last row is the trap: `(B)`, `(L)` and `(W)` look exactly like one-option
alternations and are actually character-class boundary markers. A negated
alternation additionally requires all branches to be the same length, or the
whole signature is rejected.

Two consequences follow.

**A pattern with gaps is a regex engine, and the obvious way to run one is
exponential.** Verifying `A*B*C` by recursive descent means trying every gap
length at every gap; on repetitive content (a run of one byte, obfuscated
JavaScript) the branches multiply and a single signature can eat the CPU. The
usual answer is a step budget — but for a scanner a budget is a trap, because
"gave up looking" and "looked and found nothing" are the same return value, and
reporting the first as clean is exactly the silent-clean bug.

So exav doesn't backtrack at all. In `crates/exav-core/src/engine/mod.rs` a token
program is run as a Thompson-style simulation over a set of reachable position
*intervals* (`gap_split_match` forward, `gap_split_match_backward` for a pattern
whose anchor sits past a gap). An unbounded gap becomes one interval expansion
instead of a per-length loop, and the literal after a gap is located once across
the whole window rather than once per surviving branch. The cost goes polynomial
and the answer is identical — including *which* start position is reported, which
the backward simulator reconstructs by replaying the old walk's preference order
against the reachable sets rather than by searching.

A recursive walk is kept behind `EXAV_SPLIT_MATCH=0`, purely so a scan can be
run both ways and the verdicts diffed. It keeps the tight
`VERIFY_BUDGET` / `SCAN_VERIFY_BUDGET` caps; the simulator draws from a far
larger `SIM_BUDGET`, kept separate so the safe path's headroom can never relax
the dangerous path's cap.

And the part that matters either way: when a pool runs out, the matcher has
*stopped* looking, not *finished* looking. Returning "no match" at that point
would report the file clean on the strength of a search that never completed —
the silent-clean bug, arrived at through the back door. So exhausting a pool
instead sets a `SCAN_TRUNCATED` flag, and the top-level scan reports
`LIMITS-EXCEEDED` rather than `CLEAN`.

**The prefilter's anchor choice is counter-intuitive.** Everything is fed through
one shared Aho-Corasick automaton keyed on a literal "anchor" extracted from each
pattern, and the obvious heuristic — pick the longest literal run — is wrong. A
long run of a constant byte (zero padding, `0xFF` fill, BSS) matches repetitive
content millions of times, so it is a terrible prefilter *because* it is long.
`anchor_score` down-ranks by distinct-symbol count: a constant run scores 1, a
two-symbol repeat scores at most 3, and only a varied run scores its length. For
some patterns the best anchor sits *past* a variable gap, so exav anchors there
and verifies backwards across the gap — which cuts automaton hits by orders of
magnitude.

A related size fact: in a real `daily.cvd` (~356k
signatures), `.ldb` logical signatures are **282,947** of them and `.ndb` bodies
are **312**. All the memory is the automaton. See
[Signatures](/guides/signatures/) and the
[architecture overview](/concepts/architecture/).

## Six bounds, and the worst bomb isn't a zip bomb

A decompression bomb defence that is only a maximum output size doesn't work:
set it low and you break legitimate large archives, set it high and a few
kilobytes of input still buys the attacker gigabytes of work. So there is no one
bound — there are six, and they measure different things
(`crates/exav-unpack/src/lib.rs`):

| Bound | Default | What it stops |
|---|---|---|
| `max_compression_ratio` | 1000 | one stream that expands absurdly |
| `max_extracted_bytes` | 1 GiB | cumulative decompressed bytes across the whole recursion |
| `max_buffer_bytes` | 256 MiB | the largest **single** forced-materialisation — one buffer, of the several live at once |
| `max_members` | 100000 | member-count blowup |
| `max_recursion` | 16 | nesting depth |
| `max_scanned_bytes` | 10 GiB | cumulative bytes fed to the *matcher* |

Every counter is crate-private and mutable only through `reserve`/`commit`/
`charge_scan`/`count_entry`, so a caller can't bypass the defence by writing
them. Note that the ratio check is explicitly the *weak* one: the input size it
divides by is an attacker-declared header field, so `ratio_guard` is only a fast
reject and the absolute caps are the real bound.

**The last row is the surprising one, and it isn't about decompression at all.**
Malware gets appended into carriers, so a scanner carves embedded PE images and
re-scans each one. A crafted disk image full of embedded executables makes that
**quadratic**: every carved suffix is itself a buffer containing all the later
embedded PEs. A 58 MB VHD was enough to run for hours. Two fixes, both in
`deep_analyze` (`crates/exav-core/src/lib.rs`): recursion into a carved image
passes `carve = false`, because the parent already enumerated every embedded
offset and a carved suffix is a subset; and every carve is charged against
`max_scanned_bytes`, which is deterministic and therefore trips identically on every
machine — unlike a wall-clock deadline, which makes verdicts depend on load.

The subtlest bug in this whole area is a one-liner. The obvious way to cap a
member is `reader.take(cap)` — and at the cap, `take` returns `Ok(0)`, which is
**byte-for-byte indistinguishable from EOF**. The scanner reads its 256 MiB,
sees a clean end-of-stream, finds nothing, and reports a 50 GB bomb as fully
scanned and clean. exav's `BudgetReader` (`crates/exav-unpack/src/stream.rs`)
reads **one extra byte** at the cap purely to tell "ended" from "truncated":

```rust
// At the cap. Probe one byte: if the member has more, it is a bomb.
```

If that probe returns data, the read fails with a `BUDGET_OVERFLOW` sentinel that
the extraction walk converts into `LIMITS-EXCEEDED` — so an over-budget member is
reported, never silently cut short and treated as fully scanned.

A third class never decompresses anything: a header field that *lies about a
size* to drive a huge `Vec::with_capacity`. No data ever arrives; the allocation
alone is the DoS (and a capacity-overflow abort is **not** catchable by
`catch_unwind`).
exav caps attacker-driven pre-allocation at `PREALLOC_CAP = 16 MiB` and lets
buffers grow on demand under the budget instead. The 7z header parser goes
further and bounds a declared sub-stream count by `r.remaining()` — the bytes
physically left in the header — since every declared stream must cost header bytes
to describe.

## The string `EXEC` is not in the file

Excel 4.0 macros — XLM — predate VBA by years. The macro lives in the cells of a
dedicated *macro sheet* in the BIFF stream, not in a VBA project, so it slips
straight past VBA-only macro detection. That alone made XLM a popular delivery
mechanism long after the format was obsolete.

The part that breaks naive scanning is *how* the formulas are stored. A macro
sheet is marked by a `BOUNDSHEET` record (`0x0085`) with sheet type 1; the macros
live in `FORMULA` records as `ptg` token streams. Built-in function names —
`EXEC`, `CALL`, `ALERT` — are stored as **numeric ids**. The literal bytes `EXEC`
never appear in the file, so a byte-pattern signature for them cannot match.

exav's `formats/xlm.rs` walks the BIFF record stream and synthesises an
`xlm_macro` artifact carrying the macro-sheet names, the recovered `ptgStr`
string constants, and each formula's tokens *with the function ids decoded back
to names* — so `Target:2`/`Doc.*` signatures match the real calls and
`--detect macros` fires for XLM the way it does for VBA.

Adjacent, same theme — content that must be decoded, or re-normalised, before any
signature can see it:

- **RTF embedded objects** are ASCII hex inside an `\objdata` destination, and
  the hex may be split across lines and interleaved with control words. That is
  a deliberate parser-differential: the control words' letters (`a`–`f`) would be
  eaten as hex digits by a naive scraper, shifting every subsequent nibble.
  Decoding needs a real RTF tokenizer (`formats/rtf.rs`), including the rule that
  a single trailing space belongs to the control word.
- **VBA line continuations** split identifiers across lines. `Sub _`⏎
  `UserForm_Activate` is the same code as `Sub UserForm_Activate`, but no
  signature written against the second matches the first. The source has to be
  re-joined before matching — with the extra subtlety that an underscore *inside*
  an identifier must be left alone (`formats/vba.rs`).
- **PDF name objects** can hex-escape characters that never needed escaping:
  `/J#61vaScript`, `/Ope#6eAction`. The PDF spec only requires `#`-escaping for
  whitespace, the delimiters, and bytes outside `0x21..=0x7E`, so escaping a plain
  alphanumeric is gratuitous — and the gratuitous escape *is* the signal.
  `has_obfuscated_name_object` (`formats/pdf.rs`) fires only when the de-escaped
  name is one of a fixed sensitive list (`JavaScript`, `OpenAction`, `Launch`,
  `EmbeddedFile`, …), because a lone incidental escape like `/C#31` is common in
  benign PDFs. That module also ignores the xref table entirely and byte-scans for
  `N G obj`, since a broken xref is normal in malicious PDFs.
- **Microsoft's Script Encoder** (`#@~^` … `^#~@`, shipped as `.vbe`/`.jse` or
  inside `<script language="VBScript.Encode">`) has **no key**. It is a fixed,
  published substitution where each byte maps to one of three plaintext bytes,
  chosen by a rotating index cycling through a 64-entry sequence
  (`formats/screnc.rs`). "Encoded" here means obfuscated, not encrypted.
- **MSI stream names** are *compressed*. Windows Installer packs table names into
  OLE2's 31-character directory-entry limit with an undocumented codec that
  encodes two characters per UTF-16 code point in `0x3800..0x4800` (and one per
  code point in `0x4800..=0x4840`) over a 65-entry alphabet. Filenames inside the
  container are themselves an encoding you must reverse before name-based
  matching works (`formats/ole.rs::decompress_msi_name`).
- **Pickle files are programs.** A `.pkl`/`.bin` in an ML model is a stack machine
  whose `GLOBAL` + `REDUCE` opcodes import an arbitrary callable and invoke it at
  *load* time. `formats/aimodel.rs` never executes one — it statically
  disassembles the opcode stream and surfaces every referenced global as
  `module\nname\n` plus every string literal, so signatures match on `os\nsystem`
  and friends.

## Signatures match text the file doesn't contain

`Target:3` (HTML), `Target:4` (text) and `Target:7` (mail) signatures are not
written against the file's bytes. They are written against a **canonicalised
rendering** of it, so one pattern survives letter case, HTML entity encoding,
inserted comments and whitespace padding. Which means the scanner has to
reconstruct that rendering before matching, and get it byte-compatible with
whoever authored the signature.

exav does this in `crates/exav-core/src/normalize.rs` (HTML entity decode +
lowercase + whitespace collapse; text; quote-aware comment stripping) and, for
scripts, the heavier `jsnorm.rs`, which decodes string escapes, folds
`"ab"+"cd"` concatenation, evaluates `String.fromCharCode(<literals>)` and
`unescape("…%XX…")`, and **re-parses the argument of `eval("…")` as JavaScript**
for one static layer so `eval("un"+"escape(...)")` loaders unroll. It never
executes anything; runtime-assembled payloads are explicitly out of scope. The
budgets are `MAX_OUTPUT = 8 MiB`, `MAX_EVAL_DEPTH = 8`, `MAX_FOLD_PASSES = 24`.

The consequence is that a single textual buffer gets scanned up to **five times**
— raw, HTML-normalised, text-normalised, and for scripts both the light and the
heavy JS normalisation.

The detail that will bite anyone implementing this: **a stripped comment must not
leave a space behind.** `EVAL(/* x */unescape('%61'))` has to normalise so that
`eval(` is immediately followed by `unescape(`, because that is what the
signature says. The obvious implementation — replace each comment with a
separator — breaks every such signature. exav emits the separator during comment
stripping and then drops it unless it sits between two identifier characters
(where removing it would merge two tokens instead).

Two smaller ones from the same area:

- HTML entity decoding keeps only the **low byte** of the code point, and only
  looks for the closing `;` within a 12-byte window.
- Comment markers inside string literals must survive, so the stripper is
  quote-aware for `'`, `"` and backticks.

Type gating on the normalised pass is FP-driven, not theoretical: `Target:3` is
restricted to HTML and RTF because `Html.Exploit.CVE_2017_11861` was observed
firing on obfuscated npm JavaScript that merely contained `Uint32Array(0x..)`,
and `Target:5/13/14` are skipped entirely because exav can't positively identify
those content types. `Target:12` (Java) went the same way at first — a Java CVE
signature was observed firing on APK members — but is now gated on the
`cafebabe` magic instead, because the blanket skip cost real detections.
`Target:11` (Flash) followed: every SWF variant is positively typed, so the gate
is exact and 257 signatures that had never run now do. That leaves
[11 of ClamAV's 15 targets](/project/comparison-with-clamav/#targets--11-of-15)
implemented.

### A pure-ASCII RTF is text, and that widens what matches

An RTF file containing no byte outside printable ASCII satisfies
`normalize::is_textual`, so exav produces the text-normalised rendering for it
and scans that too. ClamAV types the same file as RTF and never runs its text
normaliser over it. Because that rendering is lowercased, every **case-sensitive**
signature effectively also gets matched case-insensitively against such a file.

This is a consequence of **file typing**, not a decision to case-fold text.
Adding a single NUL byte makes `is_textual` false, the extra pass is not
produced, and the two scanners agree again.

exav keeps the wider behaviour deliberately, because on the observed files it is
the better answer: three samples matched `Rtf.Exploit.CVE_2026_21509` and
`Win.Exploit.CVE_2026_21514` in exav and not in ClamAV, and they are the same
exploit — the signature writes the CLSID hex in lowercase and those
files carry it uppercase. Catching a case-varied hex constant is a detection, not
a false positive.

It is worth being precise about the scope of that choice: it does **not** mean
exav matches more than the signature asks for wherever it can. A modifier that
*restricts* matching is honoured — the `::f` (fullword) subsignature modifier
narrows the match exactly as written. The widening here comes from offering an
additional normalised view of the file, which is the same mechanism that makes
`Target:3`/`4`/`7` signatures work at all.

## Being a drop-in means claiming to be someone else

Compatibility forces three behaviours that look wrong in isolation.

**exav reports a ClamAV functionality level.** `EXAV_FLEVEL = 213`
(`engine/parse.rs`). Signatures carry an engine `min-max` flevel window and
ClamAV loads a signature only when its own level falls inside it. Claiming the
flevel of the release whose databases you read (1.4.x ⇒ 213) means you load
*exactly* the signatures ClamAV would — skipping ones written for a newer engine,
and skipping **deprecated** ones (`max < 213`) that ClamAV does not run and
which would otherwise false-positive. The second half is the one that costs you
if you get it wrong.

**The daemon identifies itself as ClamAV.** `VERSION` over the wire returns
`ClamAV <flevel-release>/<db-version>/<db-build-time>`, with the build time
reformatted into the ctime-style stamp `clamdtop` parses for its DBTIME column
(`crates/exav/src/daemon.rs`). Health checks and monitoring tools parse that
string; returning anything else means they don't recognise a scanner is running.

The `clamd` protocol itself has four oddities:

- **The framing mode is decided by peeking exactly one byte.** A `z` prefix means
  NUL-terminated, `n` means newline-terminated, and the reply mirrors whichever
  the request used. Anything else and that byte is pushed back *into the command
  text* and the connection falls into legacy newline mode. So `PING\n`, `zPING\0`
  and `nPING\n` all work — and `zPING\n` hangs waiting for a NUL.
- **`IDSESSION` tags only the first line of a reply.** In session mode each reply
  *message* carries a `N: ` sequence prefix, but a multi-line reply (the `STATS`
  block) sends its remaining lines raw. exav prefixed every line at first;
  `clamdtop` then saw `2: STATE:` / `2: THREADS:` instead of bare field lines and
  silently rendered an empty table. The regression test pins it.
- **One command can answer any number of times, and nothing marks the last
  one.** `SCAN` over a directory, `CONTSCAN` and `ALLMATCHSCAN` all reply once
  per file, with no count in front and no terminator behind. Outside a session
  the daemon closing the connection is the end marker; inside `IDSESSION` there
  is none, so exav's client sends a `PING` behind each scan and reads up to the
  `PONG`. A client that reads a fixed one line per command reports the first
  verdict, drops the rest, and then reads the leftovers as the *next* command's
  answer — a detection lost and a verdict misattributed, from one read.
- **`INSTREAM` is `<u32 be len><data>` chunks ended by a zero length** — the only
  binary field in an otherwise text protocol, big-endian, read from the same byte
  stream as the terminated command line. And because exav stops at the first
  detection, remaining chunks must be *drained* or the next command in an
  `IDSESSION` gets parsed out of leftover payload bytes.

**A related one that surprises people: you cannot scan a ZIP from a pipe.** The
central directory is at the *end*, so container-aware scanning needs seeking.
`cat archive.zip | exav -` works because the CLI's stdin path, the daemon's
`INSTREAM` and the ICAP listener all materialise the payload to a seekable
source — RAM below `--spill-threshold-bytes` (16 MiB by default), a temp file
above it.
The flat streaming core would scan those bytes and find nothing inside the
archive.

And a wart the protocol forces: clamd has no third status. "Not fully scanned"
goes on the wire as `ERROR`, so exav's own client re-derives the distinction by
string-matching three tags (`LIMITS-EXCEEDED`, `UNSCANNABLE`,
`PASSWORD-PROTECTED`) out of the error line, purely so that a remote scan's
summary and exit code match a local one. Exit code 2 covers both hard errors and
merely-not-fully-scanned files — that is the CLI-level expression of never a
silent OK.

And the third, which surprised us most: **exav has a mode that deliberately makes
it worse.** `restrict_extractors` / `--clamav-compat` turns *off* capabilities
ClamAV lacks — the `ar` and `lzip` extractors, UPX unpacking outside the PE path,
the Petite/FSG/NsPack/aPLib packers, base64-blob rescanning, TLSH fuzzy matching,
the static suspicion scorer. Without it, every extra thing exav finds shows up as
a "false positive" in a differential run against `clamscan` and drowns the real
disagreements. It is a testing aid, explicitly not for production. See
[Differential testing](/concepts/differential-testing/).

## The signature format is not what the signature format says

Getting from "99.994% of a daily set loads" to "all of it" meant discovering,
one line at a time, that the documented format and the shipped format are
different things. Not one big missing feature — seven small ones, each found by
loading the offending line into `clamscan` with a crafted input and watching what
it did, because the spec would have sent us the wrong way in every case.

**A semicolon inside a regex splits the line.** Field separators are semicolons,
and the format says a `;` inside a PCRE must be written `\x3B`. Live signatures
do not comply — one matches `…{4,10};\s+…`, another lists `;;` as a branch in an
alternation of symbol pairs — and they load anyway, because the pieces get
rejoined. exav rejoins on unescaped-slash parity: a complete PCRE subsignature is
`Trigger/regex/flags` and so holds two slashes, and a field with an odd count is
a regex cut in half. The catch is that this must apply **only to subsignature
fields**, since signature *names* contain slashes too
(`TwinWave.EvilDoc.DOCXRSTRGOOD.CMDSPCE/.200402`) — counting those swallowed
eight loadable signatures into one "malformed line".

**`0:0&(…)` is a valid expression.** A subsignature reference can carry a
`:`-suffix, which is discarded. Three probes were needed to pin down what it
means, because guessing had two plausible answers: `0:1&0` fails to load with
"the number of subsignatures doesn't match the IDs" while `0:1&1` loads, so the
reference is the number *before* the colon; and `0:1&1` then requires both
subsignatures, so the reference is live rather than inert. The suffix is not
always numeric — two `.lnk` signatures put the header bytes they match there
(`0:4C202020011402`), so skipping "the digits after the colon" is not enough.
`(8==9)` for equality and a trailing comma in `0=2,&1&2` are two more spellings
that are not in the grammar and load fine.

**`SEn:` constrains where a match *starts*, not where it fits.** A pattern
anchored `SE0:` fires on bytes that begin in section 0 and run on into section 1.
The upper bound is inclusive by one byte, so a match starting at exactly the
first byte of the next section is still accepted — which looks like an
off-by-one, and reproducing it is deliberate: being stricter would drop
detections. Both facts came from a two-section PE with a marker moved 0x40 bytes
across the boundary; with the marker sitting exactly *on* the boundary the first
probe gave the wrong answer entirely.

**`VI:` is an anchor set, not a window.** It reads like "somewhere in the version
resource" and it is not: the match must begin exactly at a `VS_VERSION_INFO`
string key (`CompanyName`, `FileDescription`, …). One byte either side does not
match, and neither does the resource header. `clamscan` accepts a *subset* of
those keys — on one binary the first eight of nine, on another six of nine, with
no positional or uniqueness rule that accounts for which — so exav anchors on all
of them. That is a superset, so nothing that fires there fails to fire here, and
it cannot invent a match: the pattern still has to equal the bytes at the anchor.

**An alternation branch is not necessarily a literal, and may be empty.**
`(2d4120|)` means "this run, or nothing" — variable-width, so the branch has to
propagate the current position rather than search for a needle. `(5?|b?)`,
`(?4|?c)` and `(130?|0?)` carry nibble wildcards, and unequal lengths with them.
Branches now compile to `(value, mask)` pairs, with the all-literal case keeping
its substring-search fast path. The engine's simulator-versus-backtracker
differential test caught the empty-branch case immediately once its generator
learned to emit one — which is the entire reason that test exists.

## Smaller ones

- **Archive member names reach your terminal.** A hostile archive can put ANSI
  escape sequences (or megabytes of text) in a member name, which then lands in
  the scanner's output. `sanitize_member_name` strips control characters and caps
  the length at 200. Scanner output is an attack surface.
- **Decoder panics have to be a non-event.** exav is
  `#![forbid(unsafe_code)]`, but third-party decoders (`cab`, `lzxd`, `delharc`,
  `sevenz`, `pdf`) panic on crafted input instead of returning an error. A single
  `catch_unwind` boundary in `extract_each` turns any decoder panic into a clean
  `UNSCANNABLE` — uniformly, for every decoder, without patching each dependency.
  The daemon adds a second layer for what `catch_unwind` can't catch (OOM, stack
  overflow): a prefork pool with per-job `RLIMIT_AS`/`RLIMIT_CPU`/`SIGALRM`, where
  the alarm handler `_exit`s and the supervisor respawns.
- **A type token exav can't model now refuses the signature.** A `CL_TYPE_*`
  exav doesn't model makes a `.cdb` signature *never match* (fail-closed). The
  `.ldb` `Container:` path used to go the other way — leave the constraint
  *unenforced*, to avoid a false negative — which is the same silent
  constraint-dropping that made unimplemented TDB attributes a precision bug: a
  signature scoped to one container fired everywhere. It now refuses the
  signature and counts it, and the types the official database actually uses
  (`MSCHM`, `DMG`, `NULSFT`, `AUTOIT`, `MSEXE`, `RTF`, `HTML`, `XML_WORD`,
  `XML_XL`) are all determined, so nothing is currently refused for it.
- **PUA signatures are a separate alphabet.** The `.ndu`/`.ldu`/`.hdu`/`.hsu`/
  `.mdu` databases are ClamAV's potentially-unwanted-application sets, loaded only
  with `DetectPUA`. exav skips them by default — hash-based PUA has no `PUA.` name
  gate, so loading them would flag adware on a default config.
- **The signature ABI is 32-bit even where the engine isn't.** exav's offsets are
  `u64` throughout, but `.ldb` subsignature match offsets are handed to bytecode
  programs as a `u32` array in which `u32::MAX` means "no match". A genuine match
  at exactly 4 GiB would read as *didn't match*, so it is clamped to
  `0xFFFFFFFE` (`engine/mod.rs`, `scan_logical_offsets`).
- **An unpacker that isn't sure must emit nothing.** `formats/pepack.rs` gates
  every unpacked PE on the result reconstructing a valid `MZ`/`PE\0\0` image, and
  refuses to synthesise output for the packers it can only *detect*
  (emulation-defeating schemes) — "emitting a mis-decoded buffer would be worse
  than not trying". A wrong guess is discarded, never fed to the matcher as data.
- **Reading one byte past the limit is a recurring idiom.** `take(cap)` cannot
  distinguish "exactly at the cap" from "over it", so exav reads
  `take(cap.saturating_add(1))` at every size gate — the same trick as the
  decompression-bomb probe, in five different places.

## How these were found

Almost all of them came out of **differential testing**: running exav and
`clamd` over the same live-malware corpus with the same signature set
and diffing every verdict, plus coverage-guided fuzzing of every parser under
AddressSanitizer. The disagreements and the "not fully scanned" bucket are where
the interesting behaviour hides — the imphash ordinal encoding, the `FilePos`
off-by-one, section hashes on truncated PEs, embedded-PE scanning, and the gzip
salvage gap all surfaced that way.

See [Differential testing](/concepts/differential-testing/).
