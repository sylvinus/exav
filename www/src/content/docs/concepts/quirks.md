---
title: Interesting quirks
description: Things about malware scanning that surprise competent developers, from hard-coded Excel passwords and signature databases that ship programs to archives with two indexes and why a wrong checksum must never stop a scan.
---

Malware scanning is full of behaviour that looks like a bug until you learn the
adversarial reason for it. This page collects the ones that surprised us while
building exav.

Everything here is either exav's own design, a public specification (Microsoft,
RFC, APPNOTE), or documented or observable ClamAV behaviour. exav derives nothing
from ClamAV's GPL source.

## `VelvetSweatshop`: the password that isn't a secret

Scan a malware corpus's spreadsheets and a striking number report as encrypted,
yet they open in Excel with no prompt. The trick is one hard-coded string:
`VelvetSweatshop`, the password Excel uses when a workbook is encrypted with
default settings. Excel tries it automatically on open, so such a document opens
silently. For a malware author that is ideal:

- to a scanner that stops at "encrypted", the payload is opaque: it cannot see
  the macros or embedded objects;
- to the victim, the file opens normally and the macros run.

It applies to legacy `.xls` (BIFF, RC4 and RC4 CryptoAPI) and to OOXML
`.xlsx`/`.docx` (AES). The mechanism is public: [MS-OFFCRYPTO] documents the key
derivation and ciphers, and [MS-XLS] §2.4.117 the `FilePass` record that marks a
workbook stream encrypted. The three schemes:

- *Legacy XLS (BIFF8):* the workbook stream begins `BOF` then `FilePass`; the key
  comes from the UTF-16LE password plus a salt (MD5 for basic RC4, SHA-1 for
  CryptoAPI), a verifier confirms it, and the stream is RC4-decrypted in
  1024-byte blocks, re-keyed per block, with a few records left in plaintext.
- *OOXML standard encryption:* an OLE2 wrapper holds `EncryptionInfo` and
  `EncryptedPackage`; the key is `SHA-1(salt ‖ UTF-16LE(password))` spun 50000
  times, an AES-128-ECB verifier confirms it, and the package decrypts back into
  the real `.xlsx` ZIP.
- *OOXML agile encryption* (the modern default): AES-256-CBC with a per-blob KDF.

exav decrypts all three, plus the older XOR obfuscation, and hands the recovered
package back to the ZIP path so the document's parts are scanned normally.
`VelvetSweatshop` and the empty password are tried by default, so the common
case needs no configuration. A file with a non-default password stays
`PASSWORD-PROTECTED`.

> The string has been the Excel default since the late 1990s, and it is still
> active malware infrastructure.

## The signature database ships executable programs

Most people assume a signature is a pattern. ClamAV's most expressive signature
type is a program: a `.cbc` file in `bytecode.cvd` is C compiled to a custom VM
bytecode, which runs against a candidate file and decides whether it is
malicious. A compatible scanner therefore has to embed an interpreter, with an
instruction budget, a scratch-memory cap, a call-depth limit, a bounds-checked
pointer model and a panic boundary per program.

The format is line-oriented: a `ClamBC` header with a nibble-encoded integer
scheme (a byte `0x6N` carries nibble `N`), a trigger line that is itself a `.ldb`
logical signature (the program runs only when it matches), then records for
types, API declarations, globals, functions, basic blocks and strings. Programs
reach the outside world only through a fixed API of 107 functions
(`read`/`seek`/`file_find`, PE/PDF/JSON accessors, hashing, `disasm_x86`, and
`setvirusname` to report a hit). The most valuable programs are unpackers: part
of ClamAV's unpacking is implemented as bytecode, so a missing one weakens
detection across every sample of that packer.

The second surprise: the signature database is code your process runs. ClamAV's
bytecode subsystem has a code-execution history
([CVE-2020-37167](https://www.cve.org/CVERecord?id=CVE-2020-37167), CVSS 8.4, the
`bytecode_vm` sandbox escape; and the optional LLVM JIT that generated native
code from database content). exav's interpreter is safe Rust with no JIT and a
panic boundary per program, and its budget is a step count, not wall-clock time:
a deadline would make detection depend on machine load, letting an attacker (or
a busy server) push a program past it.

See [Bytecode sandbox](/concepts/bytecode-sandbox/).

## The file extension is a lie, and so is the magic number

File type comes from content only. Signatures are scoped by type (`Target:` and
`CL_TYPE_*` container constraints), so getting the type wrong does not just skip
a parser, it deselects a whole class of signatures. And magic bytes are not
enough either:

- **`CA FE BA BE` is two formats:** the Mach-O universal ("fat") binary magic and
  the Java `.class` magic. exav claims a fat binary only when the architecture
  count is between 1 and 64, the whole table is present and every slice lies
  within the file; `.class` detection also requires a plausible major version
  (45 or more), which a fat header's architecture count never is.
- **Short magics collide with ordinary data.** bzip2 is `BZh`, CAB is `MSCF`,
  gzip is two bytes. A false hit inside a PE overlay would be routed to that
  decoder, fail, and report the whole object `UNSCANNABLE`, so each weak magic is
  confirmed against a structural check (CAB's `reserved1` must be zero, gzip's
  method must be deflate with valid flag bits), and a failed confirmation is
  scanned as raw bytes.
- **HTML has no magic at all.** It is detected conservatively, because
  `Target:3` signatures apply only to HTML, and over-typing makes an HTML-exploit
  signature fire on obfuscated JavaScript that merely contains
  `Uint32Array(0x..)`.
- **Text detection has to be generous about high bytes.** Bytes `0x80..=0xff`
  count as text (the gate is on NUL and a density of control bytes); otherwise
  non-English text types as binary and loses its `Target:7` coverage.
- **The same container is several types.** `.docx`, `.xlsx`, `.apk` and `.jar`
  are all ZIPs. exav reads a bounded prefix and classifies by member name
  (`[Content_Types].xml` plus `word/document.xml`, `xl/workbook.xml` or
  `ppt/presentation.xml`), because many signatures are scoped to
  `CL_TYPE_OOXML_*`.

Typing re-runs on every extracted child, with one override: text pulled out of an
OLE2 document is typed as OLE, so `Target:2` macro signatures apply and generic
`Target:7` text signatures do not. Without that, a generic text signature fires on
the standard `Name="Project"` stream of benign macro documents.

## `cat malware huge.pad > evil` is a one-line bypass

Every scanner has a maximum file size. The naive implementation ("over the limit,
skip it, report OK") hands the attacker a bypass: append padding until the file
crosses the threshold. ClamAV's large-file behaviour is the known example: a file
over about 2 GB is read, scanned as zero bytes, and reported `OK`.

exav's rule is that refusing by size still scans. An input over
`--max-input-bytes` has its first `--max-input-bytes` bytes scanned first, as
any smaller input would be, and only then gets a limit verdict:

```text
file size 5368709120 exceeds max-input-bytes 104857600; scanned first 104857600 bytes only
```

A detection always beats a limit, and an incomplete scan is never `OK`. See
[Design principles](/concepts/design-principles/#never-a-silent-clean).

## Containers have two indexes, and malware uses the one you don't read

A ZIP lists its members twice: a local file header before each member's data,
and the central directory at the end. Every normal reader trusts the central
directory, because APPNOTE says it is authoritative. So a member can be hidden:
leave it out of the central directory and keep its local header and data. Many
extractors still write it out.

exav does dual indexing: after the central-directory pass it scans the raw bytes
for local headers the directory did not claim and extracts those too, and the
same path is the salvage route when the directory is corrupt or missing. An
orphan it cannot read (encrypted, an unsupported codec, a size deferred to a
data descriptor, an extent past the end of the file) is reported rather than
skipped: its header is credible, so it is a member the target will extract.

`PK\x03\x04` is four bytes and appears by chance in ordinary binaries, so a
local header only counts if the fields a real writer fills in are consistent
(version at most 6.3, no reserved flag bits, a defined method, a non-empty name
within the path limit and free of NULs). Orphans are charged to the archive-wide
member budget rather than to a separate cap: a real JAR whose end-of-directory
record was gone had over 400 members reachable only as local headers.

**ISO images have the same shape**, and the trick is used more openly. A CD image
carries several volume descriptors, each with its own directory tree over the
same sectors: the primary ISO9660 tree and the Joliet tree with long Unicode
names. A malicious ISO lists its payload in only one of them, leaving the other
empty, so a reader that parses the other sees an empty disc. exav walks every
tree, Joliet first so the long names win.

**gzip has the problem in miniature.** RFC 1952 allows a `.gz` to be several
concatenated members, and `gzip`/`zcat` decompress all of them, while Rust's
`flate2::GzDecoder` stops after the first. A two-member gzip whose first member
is a 1 KiB decoy and whose second holds the malware was a real false negative.

**Appended archives** are carved too: ZIP, gzip, bzip2, xz, 7z, RAR and CAB
magics after offset 0 (self-extractors, PE overlays, droppers that staple an
archive onto a carrier). A carve that fails to decode is usually a chance byte
run and is dropped rather than making the carrier `UNSCANNABLE`. The exception is
an encrypted ZIP appended to a picture or a document whose central directory
checks out: archive tools open such a polyglot through its trailing directory, so
it is reported `PASSWORD-PROTECTED`.

## "Encrypted" is itself a detection

Once malware encrypts to blind scanners rather than to protect anything,
encryption becomes something to match on. ClamAV's `.cdb` container-metadata
format makes it a field:

```text
VirusName:ContainerType:ContainerSize:FileNameREGEX:FileSizeInContainer:FileSizeReal:IsEncrypted:FilePos:Res1:Res2[:MinFL[:MaxFL]]
```

`IsEncrypted` is three-state (`1`, `0`, `*`), so a signature can say "a ZIP
containing an encrypted member whose name matches `(?i)invoice.*\.exe`" and fire
without decrypting anything. A real signature from `daily.cvd`:

```text
Archive.Filetype.DualExtJS-6168221-2:CL_TYPE_ZIP:*:^[^/\\]+\.(doc|xls|ppt|pdf|png|gif|jpeg)\.js$:*:*:*:1:*:
```

That is a double-extension detector: it catches
`PurchaseOrder_006231_Shanghuigou_20260605.pdf.js` by name and position alone
(`FilePos` is 1-based).

Two more places encryption is a signal:

- `--partial-as password-protected=found` turns a password-protected member into
  a detection, `Heuristics.Encrypted.Zip` / `.RAR` / `.7Zip` / `.PDF` / `.Doc`.
- exav tries a default password list on ZIPs: `infected`, `virus`, `malware`,
  `password`, `123456`. "infected" is the standard password for sharing samples,
  so a password-protected dropper opens with no configuration, as
  `VelvetSweatshop` does for Office. `.pwdb` databases and `--passwords` extend
  the pool.

## A wrong checksum must never stop the scan

This reads like a bug in every code review: exav extracts archive members without
verifying their CRCs, and verification is off by default. A wrong CRC must never
stop a member's bytes from being scanned, or an attacker could downgrade a
detection by flipping one checksum byte. (ClamAV also ignores CRCs when scanning.
Verification needs the `checksums` Cargo feature and an explicit opt-in, for
extraction where a bad CRC is a real "corrupt file" signal.)

The same instinct generalises. A CAB whose total-size field is overwritten with
`0xFFFFFFFF` defeats a strict parser; exav clamps it and extracts the member. A
gzip with a corrupted CRC-32 trailer still yields its payload. A truncated
deflate stream is salvaged up to the cut, because the malware is usually in the
recovered prefix, and `zcat` recovers it too.

Leniency stops at structure. An OLE file a strict reader rejects (a broken
red-black-tree ordering, common in real Office documents and malware) is walked
as a flat directory instead, but a member that is present and unreadable is
still reported, not treated as clean.

> When a sequential stream runs out of input, every byte that exists has been
> scanned: the missing tail is absent, not hidden, so a clean result is a real
> clean. The incomplete verdicts are for content that is present but unscanned:
> an encrypted member, an unsupported codec, a member over a limit.

## Identity that survives the bytes changing

Two files can share nothing byte for byte and still be provably the same malware.

**imphash** is the MD5 of the PE's import table: comma-joined lowercase
`dll_without_extension.function` in import order (the Mandiant definition).
Recompile, repack, change every string: as long as the binary links the same
functions in the same order, the imphash is identical. In `.imp` signatures
(`PEImportTableHash:PEImportTableSize:MalwareName`) the "size" is not a byte
count but the number of imports. The trap is ordinals: an import by ordinal
contributes `dll.ord<n>`, and a parser that renders it as `ORDINAL 42`, or drops
it, gets a different hash and misses every `.imp` signature.

**Section hashes** (`.mdb` MD5, `.msb` SHA) hash one PE section rather than the
file, so an unchanged code section is recognised after the resources, overlay
or certificate table change. Two quirks: the field order is transposed relative
to whole-file hashes (`.hdb` is `HASH:SIZE:NAME`, `.mdb` is `SIZE:HASH:NAME`),
and the size key and the hashed bytes can disagree: the key is the declared
`SizeOfRawData`, while only the bytes that exist are hashed, because truncated
PEs declare sections that run past the end of the file.

**TLSH** is a locality-sensitive whole-file hash matched by distance rather than
equality, so near-variants of a known sample are caught. The signature carries
its own threshold (`tlsh:HASH:Name[:MaxDistance]`, default 100), so lookup is a
linear scan with a distance computation rather than a hash-table probe. It
declines inputs under about 50 bytes or too uniform to digest, so small droppers
have no fuzzy identity.

## Scanning icons, because malware dresses up

A trojan that wants to be double-clicked wears a familiar icon (Chrome, Adobe
Reader, a Word document, a folder), so engines hash icons perceptually, and a
signature can require "these bytes and this icon". exav implements ClamAV's
`.idb` format:

- The "hash" is not a digest. It is a 124-nibble blob that unpacks into, for each
  of six derived fields (colour, grayscale, bright, dark, edge, non-edge), the
  average value and position of the three most extreme non-overlapping windows,
  plus RGB sums and a colour-pixel count. The edge field is a CIE-Lab
  colour-distance map, Sobel-filtered, normalised, bordered and Gaussian-blurred.
- Matching is a confidence score against a threshold: 70 or more for black and
  white icons, 72/68/64 for 16/24/32-pixel colour icons. Only those three sizes
  exist in the format.
- An icon is never a detection by itself. It is an extra condition: a logical
  signature's `IconGroup1:`/`IconGroup2:` fields add "and the PE's icon matches an
  `.idb` entry in these groups".
- Getting the icon out means walking PE resources: `RT_GROUP_ICON` (type 14), its
  14-byte entries, each `icon_id` under `RT_ICON` (type 3), then the DIB.

The separate `fuzzy_img#<16-hex>` subsignature is a different algorithm: the
64-bit DCT perceptual hash from Python's `imagehash` (`phash()`, median variant),
matched by Hamming distance. Reproducing it exactly means pinning details that
normally do not matter: BT.601 grayscale with round-half-away-from-zero, a
Lanczos3 resize to exactly 32×32, a ×2 scale after each 1-D DCT pass, the
top-left 8×8 block including DC, a strict `>` median threshold, MSB-first
packing. Get one wrong and nothing matches.

## The string `EXEC` is not in the file

Excel 4.0 macros (XLM) predate VBA. The macro lives in the cells of a macro sheet
in the BIFF stream, not in a VBA project, so it slips past VBA-only macro
detection. A macro sheet is a `BOUNDSHEET` record (`0x0085`) with sheet type 1,
and the macros are `FORMULA` records holding `ptg` token streams in which built-in
functions (`EXEC`, `CALL`, `ALERT`) are numeric ids. The bytes `EXEC` never
appear in the file, so a byte-pattern signature for them cannot match. exav walks
the record stream and produces an artifact with the macro-sheet names, the string
constants and each formula's tokens with function ids decoded back to names, so
signatures match the real calls and `--detect macros` fires for XLM as for VBA.

Other content that must be decoded before any signature can see it:

- **RTF embedded objects** are ASCII hex inside `\objdata`, possibly split across
  lines and interleaved with control words, whose letters `a` to `f` a naive
  scraper would eat as hex digits, shifting every later nibble. Decoding needs a
  real RTF tokenizer, including the rule that one trailing space belongs to the
  control word.
- **VBA line continuations** split identifiers: `Sub _`⏎`UserForm_Activate` is the
  same code as `Sub UserForm_Activate`, but a signature written against the
  second does not match the first. The source is re-joined before matching,
  leaving underscores inside identifiers alone.
- **PDF name objects** can hex-escape characters that never needed it:
  `/J#61vaScript`, `/Ope#6eAction`. The gratuitous escape is the signal. The check
  fires only when the decoded name is on a sensitive list (`JavaScript`,
  `OpenAction`, `Launch`, `EmbeddedFile`, …), because an incidental escape like
  `/C#31` is common in benign PDFs. PDF parsing ignores the xref table and scans
  for `N G obj`, since a broken xref is normal in malicious PDFs.
- **Microsoft's Script Encoder** (`#@~^` … `^#~@`, in `.vbe`/`.jse` files or
  `<script language="VBScript.Encode">`) has no key: it is a fixed, published
  substitution driven by a 64-entry index sequence. "Encoded" means obfuscated,
  not encrypted.
- **MSI stream names are compressed.** Windows Installer packs table names into
  OLE2's 31-character name limit with an undocumented codec (two characters per
  UTF-16 code point in `0x3800..0x4800`, one per code point in `0x4800..=0x4840`,
  over a 65-entry alphabet), which has to be reversed before name-based matching
  works.
- **Pickle files are programs.** A `.pkl` in an ML model is a stack machine whose
  `GLOBAL` + `REDUCE` opcodes import and call an arbitrary function at load time.
  exav never executes one; it disassembles the opcode stream and surfaces every
  referenced global as `module\nname\n` plus every string literal, so signatures
  match on `os\nsystem` and friends.

## Signatures match text the file doesn't contain

`Target:3` (HTML), `Target:4` (mail) and `Target:7` (text) signatures are written
against a canonicalised rendering of the file, so one pattern survives case, HTML
entities, inserted comments and whitespace. The scanner has to reproduce that
rendering byte for byte: HTML entity decoding, lowercasing and whitespace
collapsing; quote-aware comment stripping; and, for scripts, a JavaScript
normaliser that decodes string escapes, folds `"ab"+"cd"`, evaluates
`String.fromCharCode(<literals>)` and `unescape("…%XX…")`, and re-parses the
argument of `eval("…")` for one static layer. Nothing is executed. A single
textual buffer can be scanned up to five times: raw, HTML-normalised,
text-normalised, and through the light and heavy JavaScript normalisation.

The detail that bites: a stripped comment must not leave a space behind.
`EVAL(/* x */unescape('%61'))` has to normalise so that `eval(` is immediately
followed by `unescape(`, because that is what the signature says. exav drops the
separator unless it sits between two identifier characters, where removing it
would merge two tokens. Two smaller rules from the same area: HTML entity
decoding keeps only the low byte of the code point and looks for the closing `;`
within 12 bytes, and comment markers inside string literals survive, so the
stripper tracks `'`, `"` and backticks.

Type gating on the normalised views is driven by observed false positives:
`Target:3` is restricted to HTML and RTF because an HTML-exploit signature fired
on obfuscated npm JavaScript, Java signatures (`Target:12`) are gated on the
`cafebabe` magic because one fired on APK members, and the targets exav cannot
positively identify are skipped (see [Targets](/project/comparison-with-clamav/#targets)).

### A pure-ASCII RTF is text, and that widens what matches

An RTF with no byte outside printable ASCII counts as text, so exav also scans
its text-normalised rendering, which ClamAV never produces for a file it types as
RTF. Because that rendering is lowercased, a case-sensitive signature effectively
also matches case-insensitively against such a file. Adding a single NUL byte
makes the file non-text and the two scanners agree again.

exav keeps the wider behaviour because it gives the better answer: files matching
`Rtf.Exploit.CVE_2026_21509` and `Win.Exploit.CVE_2026_21514` in exav and not in
ClamAV carry the same exploit, with the CLSID hex in uppercase where the
signature writes it in lowercase. It does not mean exav matches more than a
signature asks for in general: a modifier that restricts matching, such as `::f`
(fullword), is honoured exactly.

## Being a drop-in means claiming to be someone else

**exav reports a ClamAV functionality level.** Signatures carry an engine
`min-max` flevel window, and ClamAV loads a signature only when its own level
falls inside it. Claiming the flevel of the release whose databases you read
(1.4.x, 213) means loading exactly the signatures ClamAV would: skipping ones
written for a newer engine, and skipping deprecated ones (`max < 213`) that
ClamAV does not run and that would otherwise produce false positives.

**The daemon identifies itself as ClamAV.** `VERSION` returns
`ClamAV <flevel-release>/<db-version>/<db-build-time>`, with the build time in the
ctime-style format `clamdtop` parses for its DBTIME column. Health checks and
monitoring tools parse that string.

The `clamd` protocol itself has oddities:

- **The framing mode is decided by peeking one byte.** `z` means NUL-terminated,
  `n` newline-terminated, and the reply mirrors the request. Anything else is
  pushed back into the command text and the connection falls into legacy newline
  mode. So `PING\n`, `zPING\0` and `nPING\n` all work, and `zPING\n` hangs waiting
  for a NUL.
- **`IDSESSION` tags only the first line of a reply.** Each reply message carries a
  `N: ` prefix, but the rest of a multi-line reply (the `STATS` block) is sent
  raw; prefixing every line makes `clamdtop` render an empty table.
- **One command can answer any number of times, and nothing marks the last one.**
  `SCAN` over a directory, `CONTSCAN` and `ALLMATCHSCAN` reply once per file with
  no count and no terminator. Outside a session the closed connection is the end
  marker; inside `IDSESSION` there is none, so exav's client sends a `PING` after
  each scan and reads up to the `PONG`. A client that reads one line per command
  loses a detection and attributes the leftovers to the next command.
- **`INSTREAM` is `<u32 be len><data>` chunks ended by a zero length:** the only
  binary field in a text protocol. When exav has its answer before the stream
  ends, it still reads the remaining chunks, or the next command in an
  `IDSESSION` would be parsed out of payload bytes.
- **The status vocabulary is closed.** A client reads anything but `OK`, `FOUND`
  and `ERROR` as `OK`, so a `PARTIAL` goes out as `ERROR` with the category just
  before it (`<reason> LIMITS-EXCEEDED ERROR`); exav's own client reads the
  category back so a remote scan's exit code matches a local one.

## Smaller ones

- **`(B)`, `(L)` and `(W)` are not alternations.** In `.ndb` bodies they look
  exactly like one-option alternations and are boundary markers (word, line,
  word). A negated alternation `!(aa|bb)` also requires every branch to be the
  same length, or the signature is rejected.
- **Archive member names reach your terminal.** A hostile archive can put ANSI
  escapes (or megabytes of text) in a member name that ends up in the scanner's
  output, so names are stripped of control characters and capped at 200 bytes.
- **Decoder panics have to be a non-event.** Third-party decoders panic on crafted
  input instead of returning an error. One `catch_unwind` boundary turns any
  decoder panic into `UNSCANNABLE`, for every decoder, without patching each
  dependency. The daemon adds a second layer for what `catch_unwind` cannot catch
  (OOM, stack overflow): a prefork pool with per-job `RLIMIT_AS`, `RLIMIT_CPU`
  and an alarm, after which the worker answers its client and is replaced.
- **A container type exav cannot model refuses the signature.** Leaving a
  `Container:` constraint unenforced to avoid a false negative would let a
  signature scoped to one container fire everywhere. Every type the official
  database uses is determined, so none is currently refused.
- **PUA signatures are a separate alphabet.** The `.ndu`/`.ldu`/`.hdu`/`.hsu`/
  `.mdu` databases are ClamAV's potentially-unwanted-application sets, loaded
  only with PUA detection on. Hash-based PUA has no `PUA.` name gate, so loading
  them by default would flag adware.
- **The signature ABI is 32-bit where the engine is not.** `.ldb` subsignature
  match offsets are handed to bytecode programs as `u32` values in which
  `u32::MAX` means "no match", so a real match at exactly 4 GiB is clamped to
  `0xFFFFFFFE` rather than read as a miss.
- **An unpacker that is not sure must emit nothing.** Every unpacked PE must
  reconstruct a valid `MZ`/`PE\0\0` image, and a packer exav can only detect gets
  no synthesised output. A wrong guess is discarded, never fed to the matcher.
- **Read one byte past the limit.** `take(cap)` returns end-of-file at the cap, so
  "exactly at the cap" and "over it" look the same; exav reads
  `take(cap + 1)` at every size gate to tell them apart, and reports the second.

## How these were found

Most came out of differential testing, running exav and `clamd` over the same
live-malware corpus with the same signature set and comparing every verdict,
plus coverage-guided fuzzing of the parsers. The disagreements and the "not fully
scanned" bucket are where the interesting behaviour hides: the imphash ordinal
encoding, the `FilePos` numbering, section hashes on truncated PEs, embedded-PE
scanning and the gzip salvage gap all surfaced that way.

See [Differential testing](/concepts/differential-testing/).
