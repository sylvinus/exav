---
title: Comparison with ClamAV
description: How exav relates to ClamAV, covering compatibility, memory and large files, performance, signature and format support, security posture, and licensing.
---

exav reads ClamAV's signature formats and speaks its wire protocol, so comparison
is a natural question. This page goes by theme, from philosophy down to detail,
rather than as a scoreboard. Where the engines differ, it is usually by design.

## Overview

ClamAV is a mature open-source engine written mostly in C, with a large curated
signature database maintained by Cisco/Talos and two decades of production use.

exav is a young reimplementation of the scanning engine in Rust. It brings no
signatures of its own and runs the ecosystem's, and it focuses on the engine:
memory safety, no runtime code generation, a lean dependency tree, and verdicts
that never hide an incomplete scan (see
[Design principles](/concepts/design-principles/)).

## Compatibility

- **Loads existing signature databases.** `.cvd`/`.cld` containers and the loose
  formats (body, logical, hash, section-hash, import-hash, container-metadata,
  bytecode, YARA, icon, allowlist, ignore, phishing and password databases) load
  from a directory or container. See [Signatures](/guides/signatures/).
- **Speaks the `clamd` wire protocol.** Run exav's daemon on `clamd`'s socket and
  `clamdscan`, milters and clamd client libraries keep working, with the
  differences below.
- **Prints `clamscan`'s output and exit codes.** `PATH: Signature FOUND` /
  `PATH: OK`, and `clamscan`'s exit codes plus `3` for an incomplete scan (see
  [exit codes](/reference/verdicts/#process-exit-code)). The flags are exav's
  own: a `clamscan` flag exav lacks is refused at startup rather than ignored.
  See [Migrating from ClamAV](/guides/migrating-from-clamav/) and the
  [ClamAV flag matrix](/reference/clamav-flag-matrix/).

Differences to know before swapping a socket (see
[on the clamd wire](/reference/verdicts/#on-the-clamd-wire)):

- **`INSTREAM` has no 100 MB default limit.** clamd defaults `StreamMaxLength` to
  100 MB and refuses a larger stream; exav accepts one up to `--max-spill-bytes`
  (2 GiB by default) unless you set `--max-input-bytes`. `--max-spill-bytes` is
  the direct translation of `StreamMaxLength`; `--max-input-bytes` is the scan
  policy that applies to local files too.
- **A stream past the budget is scanned as far as it was held.** clamd replies
  `INSTREAM size limit exceeded. ERROR` and closes; exav scans the bytes it kept
  and replies `stream: <reason> LIMITS-EXCEEDED ERROR` unless they hold a
  detection. A client matching clamd's exact string will not recognise it; the
  verdict class is the same.
- **`STREAM` is not implemented and `SHUTDOWN` is refused** unless
  `--allow-shutdown` is set. See the [daemon guide](/guides/daemon/).
- **Some detection names differ.** Outside
  [`--clamav-compat`](/reference/cli/#clamav-compatibility), a signature from an
  unofficial database has no `.UNOFFICIAL` suffix, and a few heuristics use
  exav's own names ([details](#heuristic-alerts)). A client that filters on
  exact names should check them.

## Memory & large files

ClamAV reads a file over about 2 GB, scans none of it, and reports `OK`.

exav gives every file the full engine. One up to `--max-object-bytes` (256 MiB
by default) is held in memory; a larger one is read through an 8 MiB block
cache. The few checks that parse a file whole, such as a PE's structure, do not
run past that limit, and a file they applied to is reported `LIMITS-EXCEEDED`
unless something is found, never `OK`. See
[Streaming & memory](/concepts/streaming-memory/).

## Performance

Both engines are bound by the same signature-matching work. exav's core is an
anchor-index pass plus cheap hash lookups, checked for correctness by
[differential testing](/concepts/differential-testing/) against ClamAV. Loading
a raw database builds the signature index, which costs time and memory; the
[prebuilt `.exavdb`](/guides/prebuilt-database/) moves that cost off the
scanning hosts, and the resident [daemon](/guides/daemon/) pays the load once.
Raw matching throughput on very large databases is still being optimised. No
speed comparison is claimed: the differential harness measures agreement, not
speed.

Wildcard-signature verification does not backtrack. A body's token program is
run as a simulation over reachable position intervals, so an unbounded gap costs
one interval expansion instead of a search per length. Highly repetitive input
(large obfuscated JavaScript against wildcard-heavy logical signatures is the
classic case) keeps the interval set small, so those scans finish. Only a set
that grows past about a million intervals stops, and the scan is then
`LIMITS-EXCEEDED`.

## Signature & format support: what's missing, what's added

exav loads every signature in the official databases and in the third-party
feeds listed [below](#signature-format-coverage); a few rare file extensions are
not loaded
([details](#database-extensions)). The interesting part is the difference on
each axis. (For the catalogue see [Supported formats](/reference/formats/) and
[Signatures](/guides/signatures/).)

| Area | Where exav falls short | Where exav goes further |
|---|---|---|
| **Signature types** | `.cat`, `.ioc`, `.sdb`, `.zmd` and `.rmd` files are not loaded; none is in the official database ([details](#database-extensions)). | Every line of the official databases and of the third-party feeds tracked here loads ([details](#signature-format-coverage)). A line exav cannot load is skipped and counted (the `-v` summary's `Unsupported sigs skipped`). |
| **Bytecode (`.cbc`)** | Part of ClamAV's host API is implemented; the rest are stubs returning fail-safe values, so a program depending on one could diverge from ClamAV. Every shipped program runs to completion, stub use is rare, and each use is recorded. | Runs on an interpreter with no JIT, removing the code-execution class that has affected a C/JIT bytecode VM. The unpackers ClamAV ships as bytecode, such as MPRESS, run too. |
| **Signature scope (`Target:`, TDB)** | Most `Target:` values ([details](#targets)), and every TDB attribute any engine implements. A signature with a constraint exav cannot evaluate is refused and counted ([details](#signature-metadata-tdb-attributes)). | none |
| **YARA** | none | Seven modules work (`pe`, `elf`, `dotnet`, `math`, `hash`, `string`, `time`); rules importing another (such as `macho`, `dex` or `cuckoo`) are rejected per rule and counted, so one unsupported rule cannot drop a feed. Matching is cross-checked against `yara-x`. No wasmtime or Cranelift behind it. In ClamAV no module works; even `pe` fails to load. |
| **Archive codecs** | none | ZIP members compressed with LZMA, bzip2, zstd, XZ or PPMd are decoded. Members whose sizes are deferred to a trailing data descriptor are carved and scanned. |
| **Container formats** | none | Virtual disks ClamAV does not open: VHD, VHDX, QCOW2 (compressed clusters included) and VMDK (sparse and streamOptimized, as inside an OVA), reconstructed to the guest disk and rescanned, with the NTFS and FAT filesystems inside them. Also UDF, WIM, KWAJ, LZ4, ARC and Unix `compress` (`.Z`). |
| **Decryption** | none | ZIP, 7z (encrypted headers included), encrypted DMG, PDF and Office are decrypted ([details](/reference/formats/#encryption-support)). RAR3/RAR5 and PKWARE Strong Encryption are reported `PASSWORD-PROTECTED` by default; ClamAV returns `OK` for them unless `--alert-encrypted-archive` is passed. |
| **PE unpacking** | none | UPX and the aPLib family are unpacked by decoders, and the result is rebuilt in ClamAV's layout so ClamAV hash signatures over its rebuilt image match. Everything else that looks packed has its stub run under a bounded x86 interpreter ([how](/concepts/pe-emulation/)); ClamAV ships a hand-written unpacker per family. |
| **PE trust** | Authenticode is parsed and matched against a block list; the certificate chain is not verified. | none |
| **Heuristics** | A few of ClamAV's default-on heuristics are missing, all per-family detection content written as engine code ([details](#heuristic-alerts)). Deep PDF-JavaScript analysis and VBA-stomping detection are partial; the static scorer is a hand-weighted baseline, not a trained classifier. | Opt-in heuristics of exav's own: TLSH fuzzy hashing, the static scorer, packer names and suspicious import sets (`--detect exav-heuristics`, `--detect packed`). |
| **Updating** | No `.cdiff` patching, no DNS `TXT` version probing, no database signature (`dsig`) verification: full downloads only. `freshclam` or `cvdupdate` fetch the official database; `--auto-update` fetches from a mirror you run ([details](/guides/signatures/)). | A prebuilt [`.exavdb`](/guides/prebuilt-database/) compiles a large set once and loads quickly everywhere, hot-reloading in the daemon. |
| **Signature content** | exav ships no signatures; it runs ClamAV's. | none |

### Silent false negatives

A silent false negative is clamd detecting malware where exav returns `OK`, as
opposed to exav returning `UNSCANNABLE`, `PASSWORD-PROTECTED` or
`LIMITS-EXCEEDED`, which misses the name but still warns. The differential
harness counts the two separately (`FN` and `CAREFUL_FN`). A dated run and its
results are in the repository's
[`docs/COMPARISON_NOTES.md`](https://github.com/sylvinus/exav/blob/main/docs/COMPARISON_NOTES.md).

A silent false negative is a bug: please
[open an issue](https://github.com/sylvinus/exav/issues). If crafted input can
make exav skip content or crash, report it privately as a
[vulnerability](/project/security/#reporting-a-vulnerability).

## Evidence for what ClamAV does not open

Each container, codec and decryption claim above was checked by building a container of the
format with the EICAR test file inside and scanning it with ClamAV 1.4.3 and
1.5.3: detection proves the container was decoded and walked, while recognising
the type proves nothing. Where EICAR could not be injected, real samples were
extracted with a third-party tool and their members hash-matched.

ClamAV has no support for NTFS, FAT12/16/32, VHD, VHDX, QCOW2 or VMDK: no file
type is defined for any of them, and images containing EICAR came back clean. It
walks an MBR partition table but logs the partition as "potentially unsupported";
the only in-partition filesystem it models is HFS+.

ClamAV has a UDF parser and it engages (`Matched signature for file type UDF`),
but across 13 generated images (four `mkudffs` revisions, three media types, two
block sizes, and a `genisoimage -udf` image) it extracted nothing, failing at the
volume descriptors each time. Its UDF magic is also registered only for offsets
0 to 32768, so hybrid ISO9660+UDF media goes down the ISO path.

ClamAV registers the ISO9660 magic at a wildcard offset, so any file with an ISO
descriptor anywhere inside is parsed as an ISO. A virtual disk wrapping an ISO
therefore appears to be handled, but the disk format itself is never decoded.

exav reports differencing disk images rather than skipping them, and reads NTFS
through an MFT walk (data runs, `$ATTRIBUTE_LIST` fragmentation, LZNT1
compression, and deleted-but-resident records a directory walk cannot see).

**Adversarial ZIP handling**
- Members present as local headers but absent from the central directory, the
  classic way to hide a payload from a tool that trusts the index.
- Members named with a trailing slash, which ZIP tools discard as folders while
  the JVM loads them as classes.
- Members flagged encrypted that are not: a packer sets the bit on every member
  because Android's ZIP reader ignores it. exav checks the claim against the
  member's CRC-32.
- An encrypted ZIP appended to a picture or document, opened by archive tools
  through its trailing directory, is reported `PASSWORD-PROTECTED`.

exav also ships [`exav-grep`](/subprojects/exav-grep/), a grep over the same
recursive extraction the scanner uses.

## Security posture

- **Memory-safe Rust.** exav's own scanning, extraction and emulation crates are
  `#![forbid(unsafe_code)]`. The remaining `unsafe` is the daemon's libc calls
  and code inside dependencies, some of them decoders
  ([inventory](/reference/dependencies/)). This rules out the classic C parser
  and integer-overflow code-execution bugs in exav's own code.
- **No runtime code generation.** Bytecode and YARA run on interpreters, so there
  is no writable and executable memory at scan time.
- **A WASM build.** The whole engine compiles to a WASI module, so untrusted
  signatures can be loaded with no host access (see
  [WASM sandbox](/guides/wasm-sandbox/)).
- **No silent clean.** An incomplete scan is reported `LIMITS-EXCEEDED`,
  `UNSCANNABLE` or `PASSWORD-PROTECTED` (see
  [design principles](/concepts/design-principles/#never-a-silent-clean)).

## How to read the gaps

exav is younger than ClamAV and does not match it everywhere. Most gaps below
show up as `UNSCANNABLE`, `LIMITS-EXCEEDED` or a counted skip: a gap costs
coverage, not a false all-clear. The exceptions are detections exav does not
implement (the [heuristics](#heuristic-alerts) and `Target:` values below): there
a file gets `OK` where ClamAV would alert. A signature with a constraint exav
cannot evaluate is refused rather than loaded without it, since that would make
it fire more broadly than the format allows. See the [roadmap](/project/roadmap/)
and [Verdicts & exit codes](/reference/verdicts/).

## Gaps by area

Compared against ClamAV 1.4.3 and 1.5.3. Gaps come in two shapes: capability gaps
(a file ClamAV decodes and exav does not) and coverage subsets (API and table
subsets where the shipped database has so far used only the implemented part).

### Formats and unpacking

| Gap | ClamAV | exav |
|---|---|---|
| **InstallShield MSI** | `CL_TYPE_ISHIELD_MSI` | Recognised, reported `UNSCANNABLE` |
| **CRYPTFF** | `CL_TYPE_CRYPTFF` | Recognised, reported `PASSWORD-PROTECTED` |

These rows come from ClamAV's own `CL_TYPE_*` enumeration (see
[the full format status](/reference/formats/#checked-against-clamavs-own-type-list)).
For everything exav does not decode, including formats neither engine opens, see
the [complete gap list](/reference/formats/#the-complete-gap-list).

ClamAV natively unpacks 10 PE packer families. exav unpacks four of them with
decoders (UPX, Petite, FSG, NsPack) and the other six by
[running the stub](/concepts/pe-emulation/), which also reaches packers nobody
has written a decoder for, MPRESS among them. ClamAV unpacks MPRESS only
through a bytecode program in its signature database, which exav runs too.

Two naming traps:

* **MPRESS, SUE and Yoda's Protector have no native unpacker in ClamAV.** They
  are covered by PUA packer signatures in the optional `.?du` databases, and
  MPRESS also by that bytecode unpacker.
* **`yC` is Yoda's Cryptor, not Yoda's Protector.** ClamAV unpacks the former and
  only detects the latter.

### Bytecode host APIs

exav implements part of ClamAV's bytecode host-API table; the rest are
fail-safe stubs, and every shipped program has so far run to completion on the
implemented part. The per-group list is in
[`docs/BYTECODE.md`](https://github.com/sylvinus/exav/blob/main/docs/BYTECODE.md).

### Signature metadata (TDB attributes)

A logical signature's Target Description Block narrows when it may fire. The
format names nineteen attributes; exav evaluates all ten that any engine
implements, and the other nine have never been implemented anywhere.

| Evaluated | Not evaluated |
|---|---|
| `Target`, `Engine`, `FileSize`, `Container`, `IconGroup1`, `IconGroup2`, `EntryPoint`, `NumberOfSections`, `HandlerType`, `Intermediates` | `SectOff`, `SectRVA`, `SectVSZ`, `SectRAW`, `SectRSZ`, `SectURVA`, `SectUVSZ`, `SectURAW`, `SectURSZ` |

The nine `Sect*` attributes parse into fields nothing reads, and ClamAV drops a
signature that uses one; exav does the same. None occurs in any official or
tracked third-party database. (Not to be confused with the `SEn:` subsignature
offset, which is live and [implemented](#signature-format-coverage).)

Three of the ten mean something other than their names suggest, established by
probing clamscan with single-signature databases:

- **`HandlerType:` is an action, not a condition.** When the rest of the
  signature holds, the file is re-typed and rescanned as the named type, and the
  signature itself never alerts. It is programmable file-type detection: a PDF
  exploit recognised by its object layout rather than a `%PDF` header still gets
  opened as a PDF. exav performs the re-type and reports what the rescan finds.
- **`Intermediates:A>B` is anchored at the immediate parent and reads right to
  left.** `B` must be the file's container and `A` that container's container. It
  need not reach the outermost archive (`A>B` matches `…>A>B>here`), but it may
  not float in the middle. exav tracks the ancestry chain through every
  extraction path.
- **`Container:CL_TYPE_ANY` is a wildcard.** clamscan fires such a signature at
  every depth, and exav treats it as unconstrained.

An attribute exav cannot evaluate, including a name the format does not define,
is refused and counted. Ignoring it would let a signature restricted to
`NumberOfSections:3` fire on any section count: a precision loss nobody would
see. The same applies to `Container:` and `Intermediates:` values: every
container type used by the official set is determined (`CL_TYPE_MSCHM`, `_DMG`,
`_NULSFT`, `_AUTOIT`, `_MSEXE`, `_RTF`, `_HTML`, `_XML_WORD`, `_XML_XL` included),
so no signature is refused for its container type. For `CL_TYPE_HTML`,
`_XML_WORD` and `_XML_XL` that meant extracting inline base64 assets from markup
(a brand logo in a phishing page, the lure image in a flat-XML Office dropper),
so the image-hash signatures scoped to those containers can match.

### Database extensions

exav loads most of the file extensions ClamAV recognises in a signature
directory. These it skips:

| Not loaded | What it is | Practical weight |
|---|---|---|
| `.cat` | Microsoft security catalogs | Not in the official database |
| `.ioc` | OpenIOC indicator documents | Not in the official database |
| `.sdb`, `.zmd`, `.rmd` | Legacy signature formats | Not in the official database |
| `.cfg` | DCONF, which switches ClamAV subsystems on or off | Not signature content |
| `.cud`, `.info` | Container and metadata members | Not signature content |

No skipped signature format appears in a stock `daily`/`main`/`bytecode` set,
but a third-party feed shipping `.ioc` or `.cat` would be skipped, unlike in
ClamAV.

### Targets

`Target:` scopes a signature to a file type. Signatures scoped to an unsupported
target do not run, because running a
type-scoped signature on content exav cannot positively type produces false
positives (observed: a Java CVE signature firing on APK members).

| Target | Type | exav |
|---|---|---|
| 0 | Any file | Supported |
| 1 | PE | Supported |
| 2 | OLE2 | Supported |
| 3 | HTML | Supported (restricted to HTML and RTF) |
| 4 | Mail | Supported |
| 5 | Graphics | Not gated: images are reached through a special case, not a target |
| 6 | ELF | Supported |
| 7 | ASCII text | Supported |
| 8 | *(unused)* | Not implemented; a reserved slot in ClamAV too |
| 9 | Mach-O | Supported |
| 10 | PDF | Supported |
| 11 | Flash / SWF | Supported (`FWS` uncompressed, `CWS`/`ZWS` compressed) |
| 12 | Java class | Supported (gated on the `cafebabe` magic) |
| 13 | Internal engine-generated data | Not implemented |
| 14 | Other | Not implemented |

### Signature-format coverage

Every signature in the official databases and in the `shelter`,
`malware.expert` and `twinclams` third-party feeds loads. Getting there meant
reproducing constructs whose actual behaviour differs from the documentation,
each settled by loading the line into clamscan with a crafted input:

| Construct | What it means |
|---|---|
| Alternation with an empty branch, `(2d4120\|)` | "this run, or nothing". Variable width, so the branch propagates the current position unchanged. |
| Alternation with nibble wildcards, `(5?\|b?)`, `(?4\|?c)`, `(130?\|0?)` | A branch is not a literal. Branches compile to `(value, mask)` pairs; the all-literal case keeps its substring-search fast path. |
| `SEn:` offsets | The match starts inside section n; it need not end there. A pattern beginning in section 0 and running into section 1 matches `SE0:`, and the upper bound is inclusive by one byte. |
| `VI:` offsets | An anchor set, not a window: the match must begin exactly at a `VS_VERSION_INFO` string key. |
| A literal `;` inside a PCRE | Splits the line into extra fields. The format says to write `\x3B`; live signatures do not, and clamscan rejoins them. exav rejoins on unescaped-slash parity, and only across subsignature fields, since signature names contain `/` too. |
| `0:0&(…)` in a logical expression | A `:`-suffix on a subsignature reference, discarded: the reference is the number before the colon. The suffix is not always numeric; two `.lnk` signatures put the header bytes they match there. |
| `(8==9)` and `0=2,&1&2` | `==` for equality and a trailing comma with no second count. Neither is documented; both load. |

Two more are TDB rather than syntax: `HandlerType:CL_TYPE_GRAPHICS` needs a
graphics type to re-type to, and `Container:CL_TYPE_MHTML` needs MHTML told apart
from mail, which turns on the mail envelope, not the multipart subtype: a
`multipart/related` document with `From:`/`To:` is mail, a `multipart/mixed` one
without them is MHTML.

### Engine options and parser toggles

ClamAV's engine exposes 37 tunables (`cl_engine_set_num`/`_str`) and 13
per-parser on/off bits (`CL_SCAN_PARSE_*`). exav implements the four headline
limits (scan size, file size, recursion depth, file count) and none of the rest.

| Missing | ClamAV default | Why it matters |
|---|---|---|
| `MAX_SCANTIME` | 120 s | exav has no in-engine wall-clock limit. Its in-core budgets count bytes, members and steps; wall clock is bounded by the kernel-level `--max-scan-secs` (120 s per job under the prefork daemon, opt-in on a one-shot run). There is none under `--workers threads`, on Windows, or in a library embedding. |
| `PCRE_MATCH_LIMIT` / `PCRE_RECMATCH_LIMIT` / `PCRE_MAX_FILESIZE` | 100000 / 2000 / 100 MB | Backtracking PCRE subsignatures run under a fixed step limit that is not tunable. |
| `CACHE_SIZE` / `DISABLE_CACHE` | 65536 entries | ClamAV caches clean-file hashes; exav does not, which costs time on trees with repeated files. |
| `MAX_EMBEDDEDPE`, `MAX_HTMLNORMALIZE`, `MAX_HTMLNOTAGS`, `MAX_SCRIPTNORMALIZE`, `MAX_ZIPTYPERCG`, `MAX_PARTITIONS`, `MAX_ICONSPE`, `MAX_RECHWP3` | various | Per-subsystem caps exav applies globally or not at all. |
| 13 `CL_SCAN_PARSE_*` toggles | all on | An operator can disable a single parser (`--scan-pe=no`, `--scan-ole2=no`, …); a migrated configuration that does so changes meaning under exav. |
| `FORCETODISK`, `KEEPTMP`, `TMPDIR`, `AC_ONLY`, `AC_MINDEPTH`/`MAXDEPTH`, `BYTECODE_TIMEOUT`/`MODE`/`SECURITY`, `PUA_CATEGORIES`, `DISABLE_PE_CERTS` | n/a | I/O policy, matcher tuning, bytecode policy. |

### Heuristic alerts

Heuristics are emitted by the engine, not the database: across `main` + `daily`
only a handful of signatures are named `Heuristics.*`. ClamAV routes `PUA.`,
`Heuristics.` and `BC.Heuristics.` names down the same potentially-unwanted path.

| exav | ClamAV | Status |
|---|---|---|
| `Heuristics.PDF.ObfuscatedNameObject` | same | exact parity, on by default |
| `Heuristics.Zip.OverlappingFiles` | same | exact parity, on by default |
| `Heuristics.XZ.DicSizeLimit` | same | exact parity, always on (ClamAV has no flag for it either) |
| `Heuristics.Limits.Exceeded.{MaxScanSize,MaxFileSize,MaxFiles,MaxRecursion,MaxScanTime}` | same | parity, via `--partial-as limits-exceeded=found` |
| `Heuristics.GPTPartitionIntersection`, `…APMPartitionIntersection`, `…MBRPartitionnIntersect` | same | parity, via `--detect partition-intersection`; the doubled `n` is upstream's and is kept, since the name is the API |
| `Heuristics.Broken.Executable` | same | parity, via `--detect broken`; an ELF whose section headers were stripped is `Heuristics.ELF.StrippedSectionHeaders` outside `--clamav-compat` |
| `Heuristics.Phishing.Email.SSL-Spoof` | same | parity, via `--detect phishing` |
| `Heuristics.Structured.{CreditCardNumber,SSN}` | same | exact parity |
| `Heuristics.Encrypted.{Zip,RAR,7Zip,PDF,OLE2}` | same | parity |
| `Heuristics.Encrypted.Archive` | ClamAV has `EGG`, no `.Archive` | exav's own name, for other formats |
| `Heuristics.OLE2.ContainsMacros.{VBA,XLM}` | same | exact name parity, via `--detect macros` |
| `Heuristics.Phishing.Email.Cloaked.NumericIP` | same | exact name parity |
| `Heuristics.Phishing.Email.{Cloaked.Username,SpoofedDomain}` | same | name parity; ClamAV runs these on by default, exav does not |
| `Heuristics.Authenticode.HashMismatch`, `…PE.PackedWithInjectionImports`, `…Static.Suspect.<score>`, `…Packed.<packer>` | none | exav only |
| `Heuristics.Broken.Media.{GIF,PNG,TIFF,JPEG}.*` | same | parity, via `--detect broken-media` |

Still missing, and on by default in ClamAV: `Exploit.W32.MS05-002`,
`W32.Parite.B`, `W32.Kriz`, `W32.Magistr.{A,A.dam,B,B.dam}`, `W32.Polipos.A`,
`Trojan.Swizzor.Gen`, `Worm.Mydoom.M.log`, `Phishing.URL.Blocked`,
`Safebrowsing.Suspected-{malware,phishing}`, `BoundsCheck`. Every opt-in ClamAV
alert class has an exav counterpart.

Most of the missing set is detection content for specific 2000s-era malware
families written as engine code. exav will not implement it, for licensing
reasons: a structural heuristic can be rebuilt from the file format it inspects,
but the matching logic for a particular virus family exists only in GPLv2 source,
with no specification behind it, and reproducing it would mean translating that
source, which exav's clean-room rule forbids. It costs detection of a few
long-dead families, and those files are still scanned against the full database.

`BoundsCheck` is raised by ClamAV's own yC unpacker. exav unpacks those files by
running the stub, which recovers the image but does not reproduce that
diagnostic.

`Phishing.URL.Blocked` and the `Safebrowsing.*` names come from a URL-hash
blocklist that is opt-in even in ClamAV (`SafeBrowsing yes`), a different
mechanism from the `.wdb`/`.pdb` lists exav loads. Hosting and refreshing a URL
blocklist is a distribution question more than an engine one, and it is out of
scope for now.

Heuristics are also how ClamAV expresses what exav models as verdicts:
`Heuristics.Limits.Exceeded.*` is `LIMITS-EXCEEDED`, `Heuristics.Encrypted.*` is
`PASSWORD-PROTECTED`, and `Heuristics.Broken.*` overlaps `UNSCANNABLE`. ClamAV's
form is a `FOUND`; exav's needs the `ERROR` line, which most clients read as "the
scanner broke". `--partial-as password-protected=found` converts the verdict into
`Heuristics.Encrypted.*`, and `--partial-as limits-exceeded=found` into
`Heuristics.Limits.Exceeded.<which limit>`, the name coming from a typed limit
kind rather than the reason text. `UNSCANNABLE` has no ClamAV-named equivalent;
under `found` it becomes `Heuristics.Exav.Unscannable`.

### ClamAV's feature surface, for scale

| Surface | ClamAV |
|---|---|
| `CL_TYPE_*` file types | 88 in 1.4.3, 90 in 1.5.3 |
| of those, unpacked into child files | 55 |
| parsed (inspected, no children emitted) | 12 |
| identified only | 23 |
| `Target:` values | 15 |
| TDB attributes | 19 |
| Bytecode host APIs | 107 |
| `clamd` protocol commands | 17 |
| Distinct `Heuristics.*` alert names | 82 |
| DCONF | Signature-controlled feature toggles |

A file-type count is a weak measure of an engine, because most of a type table is
recognition rather than extraction.

### Non-capability differences

* **Updating:** see the Updating row [above](#signature--format-support-whats-missing-whats-added).
* **Quarantine actions, `VirusEvent` and on-access scanning** are
  [out of scope](#out-of-scope-for-now).
* **RAR volume sets** are not joined by either engine. exav reports the split
  member and scans the part present in the volume it was given.

### Things that look like gaps and are not

Formats neither engine decodes, or both do:

| Format | ClamAV | exav |
|---|---|---|
| ACE, StuffIt, Inno Setup | No support | Recognised, reported |
| ZIP method 10 (DCL Implode) | Enumerates the entry, cannot extract | Reported per member |
| PDF `DCTDecode` / `CCITTFax` / `JBIG2` / `JPXDecode` | Not decoded; falls back to the raw stream | Not decoded |
| CAB Quantum | Decodes | Decodes |
| EGG (store, deflate, bzip2, LZMA, AZO), ALZ, HWP3 | Decodes | Decodes |

SZDD is decoded regardless of layout; ClamAV accepts it only when the tenth byte
is zero and reports "not supported" otherwise.

## Out of scope for now

exav prioritises CLI and server use: scanning files and directories, and
answering on a socket. Three ClamAV features are deliberately not implemented:

| Not implemented | What to do instead |
|---|---|
| **Quarantine actions** (`--move`, `--copy`, `--remove`) | Act on the [exit code](/reference/verdicts/#process-exit-code) or the result line; `--files-from` and `--log` give the same batch plumbing. |
| **`VirusEvent`** (run a command on detection) | Drive it from the daemon's reply or the scan output. |
| **On-access scanning** (`OnAccess*`, fanotify) | Not supported. Keep ClamAV if you depend on real-time protection. |

**`clamd.conf` is not read.** exav is configured with CLI flags and environment
variables (see [Configuration](/reference/configuration/)); there is no
`--config-file`. Migrating means translating the configuration once rather than
editing a file exav would half-honour: ignoring a tuning directive costs
performance, but ignoring `ExcludePath` or `OnAccessPrevention` changes what an
operator believes is running. The [ClamAV flag matrix](/reference/clamav-flag-matrix/)
lists every `clamd.conf` directive against the exav flag or variable that does
the same job. The intended migration is "change the container, set variables and
flags, read the docs", not a transparent binary swap.

## Licensing & distribution

ClamAV is GPLv2 and its signature database is GPL-licensed. exav is MIT-licensed,
written clean-room from public specifications. It reuses the signature formats
(interoperability, not derivation) but does not bundle or redistribute the GPL
signature database; you fetch it yourself (see [Signatures](/guides/signatures/)
and [License](/project/license/)). The scanner ships as one binary rather than a
set of system packages and libraries.
