---
title: Comparison with ClamAV
description: How exav relates to ClamAV — a thematic look at compatibility, memory and large files, performance, signature and format support, security posture, and licensing.
---

exav speaks ClamAV's signature formats, wire protocol, and CLI, so comparison is
a natural question. This page is organized by theme, from general philosophy down
to technical detail, rather than as a scoreboard. ClamAV is a mature, widely deployed engine (a Cisco/Talos
product); exav is a young, from-scratch reimplementation with different design
priorities. Where they differ, it is usually by design.

## Overview & philosophy

ClamAV is a ~20-year-old open-source engine written mostly in C, with a large
curated signature database maintained by Cisco/Talos. Two decades of production
use have made it broad and well-tested.

exav is a modern, memory-safe reimplementation of the *scanning engine* in Rust.
It brings none of its own signatures — it runs the ecosystem's existing
signatures — and instead focuses on the engine: memory safety, constant-memory
streaming, no runtime code generation, a lean dependency tree, and verdicts that
never hide an incomplete scan (see [Design principles](/concepts/design-principles/)).
The relationship is complementary: exav reuses the signature *formats* and
tooling, and reimplements the engine underneath them.

## Compatibility

exav is designed as a drop-in for common ClamAV workflows:

- **Loads existing signature databases.** `.cvd`/`.cld` containers and the loose
  formats (`.ndb`/`.ldb`/`.hdb`/`.hsb`/`.mdb`/`.msb`/`.cdb`/`.imp`/`.cbc`, YARA
  `.yar`/`.yara`, allowlists, phishing and password DBs) load directly from a
  directory or container.
- **Speaks the `clamd` wire protocol.** Run exav's daemon on the socket `clamd`
  used, and `clamdscan`, milters, and existing clamd client libraries keep
  working unchanged.
- **Matches the `clamscan` CLI.** The same core flags, `PATH: Signature FOUND` /
  `PATH: OK` output, and exit-code scheme — usually a one-line swap. A flag exav
  does not implement is refused rather than ignored, so a command line that needs
  translating says so at startup. See
  [Migrating from ClamAV](/guides/migrating-from-clamav/) and the
  [ClamAV flag matrix](/reference/clamav-flag-matrix/), which has every
  `clamscan`, `clamd` and `clamdscan` flag with its exav status.

The signatures, updater, and client tooling stay exactly as they are.

Two wire-level differences to know about before you swap a socket:

- **`INSTREAM` has no length limit by default.** clamd defaults
  `StreamMaxLength` to 25 MB and refuses a larger stream; exav accepts one up to
  `--max-spill-bytes` (2 GiB by default) unless you set `--max-input-bytes`. A
  client that relied on the daemon to bound its uploads no longer has that bound,
  so set one of those flags if you want it — `--max-spill-bytes` is the direct
  translation of `StreamMaxLength`, `--max-input-bytes` the scan-policy one that
  applies to local files too.
- **An over-limit stream is refused in exav's own words.** clamd replies
  `INSTREAM size limit exceeded. ERROR` and closes; exav replies
  `stream: LIMITS-EXCEEDED (size exceeds N) ERROR`. A client matching clamd's
  exact string will not recognise it. The verdict class is the same, and
  [never clean](/reference/verdicts/).

## Memory & large files

This is the sharpest behavioral difference. ClamAV has a long-standing large-file
limitation: files over ~2 GB are read but scanned as **zero bytes** and still
reported **`OK` / clean**.

exav scans files of any size in a single forward pass with a flat per-scan
working set (~2 MiB regardless of file size), so a payload at the end of a
multi-gigabyte file is still caught — demonstrated on a 6 GiB file on a
4.8 GiB-RAM machine. See [Streaming & memory](/concepts/streaming-memory/).

The trade-off today is at *database load* time: building the automaton for a very
large signature set is currently more memory-hungry in exav than in ClamAV. The
[prebuilt `.exavdb`](/guides/prebuilt-database/) moves that cost off the scanning
hosts (build once, load cheaply everywhere), and reducing the build peak is
active work.

## Performance

Both engines are ultimately bound by the same signature-matching work. exav's
scanning core is a constant-memory Aho-Corasick pass plus cheap hash-table
lookups, validated for correctness by [differential testing](/concepts/differential-testing/)
against ClamAV on the same inputs and database. The [prebuilt database](/guides/prebuilt-database/)
turns a tens-of-seconds cold start into a sub-second one, and the resident
[daemon](/guides/daemon/) amortizes load cost across scans. Absolute
signature-matching throughput on very large databases is an area of ongoing
optimization. For what a live differential run does and does not establish — it
measures agreement, not speed — see
[the 2026-07-28 run](#measured-against-clamd-the-2026-07-28-run).

Wildcard-signature verification does not backtrack. A body's token program is
run as a simulation over reachable position *intervals*, so an unbounded gap
costs one interval expansion instead of a per-length search. Highly repetitive
input — large obfuscated JavaScript against wildcard-heavy logical signatures is
the classic case — cannot make verification blow up combinatorially, so
exav *finishes* those scans and returns an honest `OK` instead of bounding the
work and reporting `LIMITS-EXCEEDED`.

## Signature & format support: what's missing, what's added

exav loads every signature type ClamAV does and runs the ecosystem's databases
unchanged, so the interesting content is the delta on each axis, not the list
itself. (For the full catalogue see [Supported formats](/reference/formats/) and
[Signatures](/guides/signatures/).)

| Area | Where exav falls short | Where exav goes further |
|---|---|---|
| **Signature types** | — | **Every signature loads.** 0 of 273,587 lines on daily 28074, 0 of 3.7M across `main`+`daily`, and 0 across the third-party feeds tracked here ([how that was closed](#signature-format-coverage)). Anything exav could not load would still be **counted and attributable by cause**, never silently ignored. |
| **Bytecode (`.cbc`)** | **34 of ClamAV's 107 host APIs** are implemented; the rest are stubbed and return fail-safe values, so a program depending on one can diverge from ClamAV ([which 73, and why it has not mattered yet](#bytecode-host-apis--34-of-107)). Measured on a live `bytecode.cvd`: **all 85 programs execute to completion with no unsupported opcode**, and across 400 real samples only one stub was ever reached (`get_environment`). Every stub use is **warned and counted**, never silent. | Runs on a from-scratch interpreter with **no JIT**, removing the RCE class that has repeatedly affected a C/JIT bytecode VM. Includes ClamAV's own unpackers — the MPRESS unpacker is a `.cbc` program exav executes rather than a codec it reimplements. |
| **Signature scope (`Target:`, TDB)** | **11 of 15 `Target:` values** and **every TDB attribute any engine implements** (10 of the 19 the format names; the other 9 are dead everywhere). A constraint exav cannot evaluate is **refused and counted**, never silently dropped ([detail](#signature-metadata-tdb-attributes--10-of-10-live)). | — |
| **YARA** | — | Rules needing `macho`, `dex` or `cuckoo` are rejected **per rule and counted**, so one unsupported rule can't drop a feed. Every module is cross-checked against the real `yara-x` in CI. No wasmtime/Cranelift subtree behind it. |
| **Archive codecs** | — | All three CAB codecs are decoded — MSZIP, LZX and **Quantum**, the last written from a format specification and validated byte-exact against libmspack over 107 generated streams. ZIP members compressed with **Deflate64**, LZMA, bzip2, zstd, XZ or **PPMd** are decoded — the `zip` crate handles none of those, so they are decoded from raw bytes on both the buffered and the streaming path. Streaming members whose sizes are deferred to a trailing data descriptor are carved and scanned rather than skipped. |
| **Container formats** | — | Opens virtual disks ClamAV does not touch at all — VHD, VHDX (which Windows mounts on double-click), QCOW2 (compressed clusters included) and VMDK (sparse and streamOptimized, the shape inside an OVA) are reconstructed to the guest disk and rescanned. Also **UDF**, so a UDF-only `.iso` is not an unknown blob; **WIM**, which Windows opens natively; **LZ4**; and Unix `compress` (`.Z`). |
| **Decryption** | — | Decrypts ZIP (ZipCrypto + WinZip AES), 7z AES **including encrypted headers**, encrypted DMG, PDF, and the full Office set: legacy XLS RC4-basic/CryptoAPI, XOR obfuscation, and OOXML **standard (AES-ECB) and agile (AES-CBC)**. All of it auto-tries Excel's default `VelvetSweatshop` and the empty password, so documents that look opaque to a scanner give up their macros. RAR3/RAR5 and PKWARE Strong Encryption stay `PASSWORD-PROTECTED` and are **reported by default**; ClamAV returns `OK` for them unless `--alert-encrypted-archive` is passed, so an encrypted archive is silently clean there and actionable here. |
| **PE unpacking** | — | UPX and the aPLib-family packers are unpacked in-process, including the bare-`PackHeader` layout that matches no `l_info` chain, with the recovered image verified against the Adler-32 the header records. The unpacked PE is then **rebuilt in ClamAV's layout**, so the large family of ClamAV hash signatures computed over *its* rebuilt artifact matches. **MPRESS** is unpacked by running ClamAV's own `.cbc` unpacker program on exav's bytecode interpreter — no separate decoder, and no JIT. Everything else that looks packed — ASPack, MEW, Upack, WWPack, PESpin, yC, and packers with no name — has its **stub run under a bounded x86 interpreter** that captures the image it rebuilds, so coverage is not a list of families ([how](/concepts/pe-emulation/)). ClamAV ships a hand-written submodule per family. |
| **PE trust** | Authenticode is parse- and block-list-only; no full signature-chain verification. | — |
| **Heuristics** | **3 of ClamAV's 15 default-on heuristic families** still missing, all of them per-family detection content expressed as engine code rather than structural checks: six `W32.*` PE entry-point heuristics, `Trojan.Swizzor.Gen`, `Worm.Mydoom.M.log`, `Exploit.W32.MS05-002`, plus `BoundsCheck` (raised by an unpacker exav lacks) and `Phishing.URL.Blocked`/`Safebrowsing.*` (an opt-in URL-hash database). Every structural alert now has parity ([detail](#heuristic-alerts)). Deep PDF-JavaScript analysis and VBA-stomping detection are partial; the static scorer is a hand-weighted baseline, not a trained classifier. | VBA-macro decompression, Excel 4.0 XLM surfacing, JS normalization, perceptual **icon hashing** and TLSH fuzzy hashing. |
| **Updating** | No `.cdiff` incremental patching, no DNS `TXT` version probing, no GPG verification — full reloads only, and `cvd`/`freshclam` remain the supported updater. | A prebuilt [`.exavdb`](/guides/prebuilt-database/) compiles a large set once and loads it in seconds everywhere, hot-reloading in the daemon. |
| **Signature content** | exav ships **no signatures**. ClamAV's curated set is mature and enormous; exav only *runs* it. | — |

## Measured against clamd: the 2026-07-28 run

8,978 live-malware samples, both engines loading the **same** daily-only
signature set (339,917 signatures). Only the 5,436 files where both engines
returned an answer are counted — the rest hit a resource ceiling in the
memory-capped clamd container and measure the harness, not the engines.

exav runs at **full capability** here (its own extractors and limits). The
harness defaults to `--clamav-compat`, which deliberately trades reach for
reproducibility; measuring exav's added coverage in that mode understates it by
roughly 3×, so these figures come from a `COMPAT=0` pass over the same files.

| | exav | clamd |
|---|---|---|
| detections | 897 | 796 |
| detected by this engine alone | **104** | 0 |

**104 exav-only detections — 11.6% of exav's detections, 1.91% of files
scanned.** (In `--clamav-compat` the same corpus yields 32, or 3.9%; the
difference is exactly the extraction reach that compat switches off.)

Every one was verified rather than assumed. 101 of the 104 report a nested match
location — the hit is inside a member clamd did not unpack, and re-scanning
exav's *own* extracted members with clamd (see
`exav-unpack/examples/dump_members.rs`) makes clamd flag them under the same
signature name while still calling the container clean. Of the remaining three,
two are `Target:0` RTF-exploit signatures legitimately matching RTF files, and
one is `Win.Trojan.Mimikatz` inside a PE that was **base64-encoded inside an
RTF** — none of the signature's seven subsignatures occurs in the raw file, and
all seven occur in the decoded image. **None was a false positive.**

### Zero known silent false negatives

A *silent* false negative is the specific case where clamd detected malware and
exav returned a clean `OK` — as opposed to exav returning `UNSCANNABLE` /
`PASSWORD-PROTECTED` / `LIMITS-EXCEEDED`, which is also a missed detection but
not a missed *warning*. The distinction is the difference between a user running
the file and a user quarantining it, and the differential harness scores the two
separately (`FN` versus `CAREFUL_FN`).

Across all 5,436 comparable files, the `FN` count is **zero**.

If you find one, [it is a bug — please report it](/project/security/). Not a
feature request, not an expected coverage gap: a silent miss is the one failure
this engine is built to make impossible, and it is treated with the same
seriousness as a crash.

The `CAREFUL_FN` count — clamd names the malware, exav declines to call the
file clean but cannot name it either — is also **zero**. The two samples that
sat there (an MPRESS-packed dropper and a UPX image carrying a bare
`PackHeader`) are now unpacked and detected under clamd's own signature names,
in both default and `--clamav-compat` modes.

One caveat remains, stated because a claim like the one above is worthless
without it:

### Performance

**No speed claim is made here, because the differential harness cannot support
one.** It is a compliance harness: it answers "do the two engines agree", and is
tuned for throughput so that question can be asked often. Its timings exist to
spot a wedged file or an engine that is dramatically slower, and they are
confounded in at least four ways that all push in different directions:

- **Scan ordering.** The two engines run in separate phases over the same corpus,
  clamd first. Whatever runs second reads a partly-warmed page cache, and a warm
  read is worth roughly 10× a cold one. That bias favours exav.
- **Concurrency contention.** Under more than one job, a file's elapsed time is
  mostly time spent competing with the other jobs, not time spent scanning it.
- **Unequal environments.** clamd ran memory-capped inside Docker; exav ran
  natively on the host.
- **Different work per file.** The compat-mode pass and the full-capability pass
  do not extract the same amount, so their per-file times are not comparable
  either.

The earlier revision of this page quoted a mean/median table from such a run and
concluded a 1.27× speed ratio. That conclusion was not supportable from the data
it cited, so it has been withdrawn rather than re-caveated.

What *can* be said on design grounds, and is visible as an absence of stalls
rather than as a ratio: wildcard verification cannot backtrack, and work on
pathological inputs is bounded, so exav has no pathological-input cliff. Turning
that into a number requires a dedicated benchmark — one job, warm cache, repeated
runs, equal environments — which is tracked separately and is not this harness.

## What exav does that ClamAV does not

Every claim in this section was checked by building a container of the format
with the EICAR test file inside and scanning it with ClamAV 1.4.3 and 1.5.3 —
detection proves the container was decoded and walked; recognising the *type*
proves nothing. Where EICAR could not be injected, real samples were extracted
with a third-party tool and their members hash-matched.

Results: ClamAV has **no support** for NTFS, FAT12/16/32, VHD, VHDX, QCOW2 or
VMDK — no file type is defined for any of them, and images containing EICAR came
back clean. It walks an MBR partition table but logs the partition as
"potentially unsupported"; the only in-partition filesystem it models is HFS+.

**UDF is the interesting one.** ClamAV *has* a UDF parser and it engages —
`Matched signature for file type UDF` — but across **13 images** (four `mkudffs`
revisions × three media types × two block sizes, plus a `genisoimage -udf`
image) it extracted nothing, failing at the volume descriptors every time. Its
UDF magic is also registered only for offsets 0–32768, so hybrid ISO9660+UDF
media is handled by the ISO path instead. Treat ClamAV's UDF support as present
but not effective on generated media.

One related quirk if you compare the two engines: ClamAV registers
the ISO9660 magic at a **wildcard offset**, so any file with an ISO descriptor
anywhere inside it is typed and parsed as an ISO. A virtual disk wrapping an ISO
therefore *appears* to be handled — but the disk format itself is never decoded.

The per-area table above splits this by axis; consolidated, the additions are:

**Containers ClamAV does not open at all**
- Virtual disks — **VHD**, **VHDX** (which Windows mounts on double-click),
  **QCOW2** (compressed clusters included) and **VMDK** (sparse and
  streamOptimized, the shape inside an OVA), reconstructed to the guest disk and
  rescanned. Differencing images are reported, not skipped.
- Filesystems inside those images — **NTFS** via an MFT walk (data runs,
  `$ATTRIBUTE_LIST` fragmentation, LZNT1 compression, and deleted-but-resident
  records a directory walk cannot see) and **FAT12/16/32** via the cluster chain.
- **UDF**, so a UDF-only `.iso` is not an unknown blob; **WIM**/`.esd`, which
  Windows opens natively; **LZ4**; **ARC**; and Unix `compress` (`.Z`).

**Codecs and decryption**
- ZIP members compressed with **LZMA, bzip2, zstd, XZ or PPMd** — the `zip`
  crate handles none of those. Members whose sizes are deferred to a trailing
  data descriptor are carved rather than skipped.
- **7z AES including encrypted headers**, encrypted DMG, PDF, and the full
  Office set: legacy XLS RC4-basic/CryptoAPI, XOR obfuscation, and OOXML
  **standard (AES-ECB) and agile (AES-CBC)** — auto-trying Excel's default
  `VelvetSweatshop` and the empty password.

**Adversarial ZIP handling.** Each of these was a live sample that scanned clean
before it was fixed:
- Members present as local headers but **absent from the central directory** —
  the classic way to hide a payload from a tool that trusts the index.
- Members named with a **trailing slash** so every ZIP tool discards them as
  folders while the JVM loads them as classes.
- Members flagged **encrypted that are not** — a packer sets the bit on every
  member because Android's ZIP reader ignores it, buying a
  `PASSWORD-PROTECTED` report on an archive that installs fine. exav checks the
  claim against the member's own CRC-32 instead of believing it.

**Engine and operations**
- **No JIT anywhere** — bytecode and YARA run on interpreters, so there is no
  writable-executable memory at scan time.
- **Wildcard verification that cannot backtrack**, so obfuscated JavaScript
  against wildcard-heavy logical signatures finishes instead of exhausting a
  bound.
- A **WASI sandbox** for loading untrusted signatures with no host access.
- A **prebuilt database** that loads in seconds, and `exav-grep` — grep over the
  same recursive extraction the scanner uses.
- **Never a silent clean**, and every skip counted and attributable.

## Security posture

exav's engine is built for a hostile-input threat model:

- **Memory-safe Rust.** The scanning and extraction crates are
  `#![forbid(unsafe_code)]`; residual `unsafe` is confined to audited dependency
  primitives, not parsing logic. This removes the classic C parser-overflow /
  integer-overflow RCE classes by construction.
- **No runtime code generation (W^X / no JIT).** Bytecode and YARA run on
  interpreters/evaluators — there is no writable-executable memory at scan time.
- **A WASM sandbox.** The whole engine compiles to a WASI module, so
  **untrusted** signatures can be loaded with no host access and zero custom host
  code (see [WASM sandbox](/guides/wasm-sandbox/)).
- **Never-silent verdicts.** An incompletely-scanned file is never reported
  clean — a bound surfaces as `LIMITS-EXCEEDED` / `UNSCANNABLE` /
  `PASSWORD-PROTECTED` rather than a silent `OK` (see
  [Never silently clean](/concepts/design-principles/#never-a-silent-clean)).

## How to read the gaps

exav is younger than ClamAV and does not match it everywhere. The framing that
matters: every gap above surfaces as `UNSCANNABLE` / `LIMITS-EXCEEDED` or an
explicit, counted skip — **never a silent clean**. A gap costs you coverage; it
never costs you a false all-clear.

Dropping an unimplemented TDB attribute rather than rejecting the signature
would let it fire more broadly than the format allows — a precision risk rather
than a coverage one, and invisible from the outside. exav evaluates every TDB
attribute any engine
implements, and refuses (rather than silently ignores) anything it cannot
([detail](#signature-metadata-tdb-attributes--10-of-10-live)). See the
[roadmap](/project/roadmap/) for what is being worked on, and
[Verdicts & exit codes](/reference/verdicts/) for how each outcome is reported.

## The complete gap list against ClamAV

Compared against ClamAV 1.4.3 and 1.5.3.

Three shapes of gap show up, and they are not equally serious:

1. **Capability gaps** — a file ClamAV decodes and exav does not. One remains,
   in formats and unpacking.
2. **Coverage surfaces** — API and table subsets, where exav implements less
   than ClamAV defines but the shipped database has so far exercised the
   implemented part. Each is stated with its measurement.

A third kind is absent by design: a **correctness gap**, where a signature fires
more broadly than the format allows because exav ignored a constraint it could
not evaluate. Anything unevaluable is refused and counted, so a gap shows up as
coverage rather than as a wrong answer.

### Formats and unpacking

| Gap | ClamAV | exav |
|---|---|---|
| **EGG** archive | `EGG` submodule, on by default | Decodes (store/deflate/bzip2/LZMA) |
| **ALZ** archive | `ALZ` submodule, on by default | Decodes (store/bzip2/deflate) |
| **HWP3** documents | `HWP` submodule, on by default, with its own recursion limit | Decodes the deflate body |
| **InstallShield MSI** | `CL_TYPE_ISHIELD_MSI` | Recognised, reported `UNSCANNABLE` |
| **CRYPTFF** | `CL_TYPE_CRYPTFF` | Recognised, reported `PASSWORD-PROTECTED` |

The five format rows come from checking against ClamAV's own `CL_TYPE_*`
enumeration rather than a hand-assembled list — a hand-assembled list can only
confirm itself. See
[the full format status](/reference/formats/#checked-against-clamavs-own-type-list).

Three items that were on this list are gone, for different reasons. **ZIP
Deflate64** is implemented. **The six emulation-required PE packers** are
covered, not one decoder at a time but by
[running the stub](/concepts/pe-emulation/), which reaches packers nobody has
written a decoder for as well. **RAR multi-volume joining** was never a gap:
ClamAV does not join volume sets either, which took a controlled experiment to
establish — see the correction below.

On packers specifically: ClamAV natively unpacks **10 families**. exav unpacks
**4** of them (UPX, Petite, FSG, NsPack); the other 6 are the row above. exav
also unpacks **MPRESS**, which ClamAV does not — and gets it by running ClamAV's
own `.cbc` unpacker program rather than by reimplementing the codec.

This is the only gap *against ClamAV*. For everything exav does not decode at
all — including formats neither engine opens — see the single
[complete gap list](/reference/formats/#the-complete-gap-list).

Two naming traps make the gap look larger or smaller than it is:

* **MPRESS, SUE and Yoda's Protector are detection-only for ClamAV.** There is no
  unpacker submodule for any of them; they are covered by **964 PUA packer
  signatures** shipped in the optional `.?du` databases.
* **`yC` is Yoda's *Cryptor*, not Yoda's *Protector*.** ClamAV unpacks the
  former and only detects the latter. Row 3 is about the former.

### Bytecode host APIs — 34 of 107

ClamAV's host-API table has **107 entries**, byte-identical in 1.4.3 and 1.5.3.
exav implements **34**.

The `maxapi 89` that shows up in debug output is not the table size, and reading
it as one is the easy mistake here: it is a **per-program declaration in each
`.cbc` header**, and 89 is simply the highest value any shipped program declares.
So indices **0–89** are the reachable surface — exav implements 34 of those 90,
and **56 are unimplemented**. Indices **90–106** (JSON accessors, LZMA and bzip2
stream contexts, `get_file_reliability`, `engine_scan_options_ex`) exist in
ClamAV, but no program in the shipped database references any of them.

| Group | Missing | APIs |
|---|---|---|
| Buffer pipes | 9 | `buffer_pipe_new`, `_new_fromfile`, `_read_avail`, `_read_get`, `_read_stopped`, `_write_avail`, `_write_get`, `_write_stopped`, `_done` |
| Debug / trace | 10 | `debug_print_str`, `debug_print_uint`, `debug_print_str_start`, `debug_print_str_nonl`, `trace_directory`, `trace_scope`, `trace_source`, `trace_op`, `trace_value`, `trace_ptr` |
| Engine / environment | 9 | `bytecode_rt_error`, `engine_scan_options`, `engine_db_options`, `extract_set_container`, `input_switch`, `disable_bytecode_if`, `disable_jit_if`, `check_platform`, `running_on_jit` |
| Maps | 8 | `map_new`, `map_addkey`, `map_setvalue`, `map_remove`, `map_find`, `map_getvaluesize`, `map_getvalue`, `map_done` |
| Hashsets | 6 | `hashset_new`, `_add`, `_remove`, `_contains`, `_done`, `_empty` |
| PDF extras | 6 | `pdf_get_obj_num`, `pdf_set_flags`, `pdf_getobj`, `pdf_getobjflags`, `pdf_setobjflags`, `pdf_get_dumpedobjid` |
| Decompression | 3 | `inflate_init`, `inflate_process`, `inflate_done` |
| JS normalisation | 3 | `jsnorm_init`, `jsnorm_process`, `jsnorm_done` |
| Self-test | 2 | `test1`, `test2` |
| **Total** | **56** | of the 90 reachable indices |

**The framing that matters:** 34 of 107 is 32% of the API surface, and yet **all
85 bytecode programs in the official database execute to completion**, and across
**400 real malware samples exactly one stub was ever reached** (`get_environment`).
A program declares a `maxapi` *ceiling*; it does not necessarily call every API
below it. So the honest reading is not "exav runs a third of the bytecode
subsystem" — it is "the third exav implements is the part the shipped database
uses, so far". Some of the 56 are unlikely to ever matter (the debug and trace
groups are compile-time instrumentation; `running_on_jit` and `disable_jit_if`
have an obvious answer on an engine with no JIT). Others — the pipes, maps and
`inflate` groups — would be real work if a future program used them.

### Signature metadata (TDB attributes) — 10 of 10 live

A logical signature's Target Description Block carries constraints that narrow
when it may fire. The format names nineteen attributes. **exav evaluates all ten
that any engine implements**; the other nine have never been implemented
anywhere.

| Evaluated | Not evaluated |
|---|---|
| `Target`, `Engine`, `FileSize`, `Container`, `IconGroup1`, `IconGroup2`, `EntryPoint`, `NumberOfSections`, `HandlerType`, `Intermediates` | `SectOff`, `SectRVA`, `SectVSZ`, `SectRAW`, `SectRSZ`, `SectURVA`, `SectUVSZ`, `SectURAW`, `SectURSZ` |

The nine `Sect*` attributes are a documented-but-dead corner of the format: they
parse into fields nothing reads, and a signature using one is dropped at load.
exav drops it too, which is parity rather than a gap. There are **zero
occurrences** across every official and third-party database tracked here. (Not
to be confused with the `SEn:` *subsignature offset* modifier, which is live, is
used, and is [implemented](#signature-format-coverage).)

Three of the ten took work beyond parsing, and each turned out to mean something
other than what it looks like — established by probing clamscan with
single-signature databases, not by reading the name:

- **`HandlerType:` is not a match condition.** It is an action: when the rest of
  the signature holds, the file is *re-typed* and rescanned as the named type,
  and the signature itself never alerts. It is programmable file-type detection,
  filling in where magic bytes cannot — a PDF exploit recognised by its object
  layout, not by a `%PDF` header, still gets opened as a PDF. exav performs
  the re-type, and reports whatever the rescan finds rather than the signature
  that triggered it.
- **`Intermediates:A>B` is anchored at the immediate parent and reads
  right-to-left.** `B` must be the file's container and `A` that container's
  container. The run need not reach the outermost archive — `A>B` matches
  `…>A>B>here` — but it may not float in the middle. exav tracks the ancestry
  chain through every extraction path to evaluate it.
- **`Container:CL_TYPE_ANY` is a wildcard.** The layer logic argues it should
  mean "top level only", since a missing parent reports exactly that type, and a
  source-reading pass concluded as much. clamscan fires such a signature at every
  depth. The probe settled it; exav treats it as unconstrained.

The failure mode this avoids is easy to build by accident. Parse TDB by looking for the attributes you know, and an attribute you
do not know is never read — its constraint silently vanishes. A signature
restricted to `NumberOfSections:3` fired on any section count, matching more
broadly than the format allows. Unlike a missing decoder, which costs coverage,
that costs *precision*, and it is invisible. Any attribute exav cannot evaluate
— including a name the format does not define at all — is **refused and
counted** like every other unsupported construct.

The same reasoning applies one level down, to `Container:` and `Intermediates:`
*values*. A container type exav cannot determine would leave the constraint
unenforced, which is the identical failure in miniature. Those types are
determined rather than dropped: `CL_TYPE_MSCHM`, `_DMG`, `_NULSFT`, `_AUTOIT`,
`_MSEXE`, `_RTF`, `_HTML`, `_XML_WORD` and `_XML_XL` all resolve, and a type
that still could not be determined would refuse the signature. As of the current
official set, **no signature is refused for a container type**.

Making `CL_TYPE_HTML`, `_XML_WORD` and `_XML_XL` real required extraction, not
just bookkeeping. A phishing page carries the brand logo it impersonates as a
`data:` URI, and a Word/Excel 2003 flat-XML dropper carries its "enable macros"
lure image as a base64 element body — in both cases the document is one
self-contained file with nothing for an unpacker to open. Signatures hash those
images and scope them with `Container:` exactly so they fire on the document and
not on a stray copy of the logo, which only works if the image is pulled out of
the document. exav extracts inline base64 assets from markup, so those
signatures are satisfiable at all.

### Database extensions — 29 of ~33

exav loads **29** of the roughly 33 file extensions ClamAV recognises in a
signature directory. ("Roughly" because ClamAV's list mixes signature databases
with container variants and metadata members, so the denominator depends on what
you count.)

| Not loaded | What it is | Practical weight |
|---|---|---|
| `.cat` | Microsoft security catalogs | Not present in the official database |
| `.ioc` | OpenIOC indicator documents | Not present in the official database |
| `.sdb`, `.zmd`, `.rmd` | Legacy signature formats | Absent from the official database |
| `.cud`, `.info`, `.msu` | Container/metadata members | Not signature content |

None of these appears in a stock `daily`/`main`/`bytecode` set, so the practical
cost today is zero — but a third-party feed shipping `.ioc` or `.cat` would be
skipped, and that is a real difference from ClamAV.

### Targets — 11 of 15

`Target:` scopes a signature to a file type. ClamAV defines **15** values; exav
gates on **11**. An unsupported target means signatures scoped to it do not run,
because running a type-scoped signature on content exav cannot positively type
produces false positives (observed: a Java CVE signature firing on APK members).

| Target | Type | exav |
|---|---|---|
| 0 | Any file | Supported |
| 1 | PE | Supported |
| 2 | OLE2 | Supported |
| 3 | HTML | Supported (restricted to HTML and RTF) |
| 4 | Mail | Supported |
| 5 | Graphics | **Not gated** — images are reached through a special case, not a target |
| 6 | ELF | Supported |
| 7 | ASCII text | Supported |
| 8 | *(unused)* | **Not implemented** — a reserved slot in ClamAV too |
| 9 | Mach-O | Supported |
| 10 | PDF | Supported |
| 11 | Flash / SWF | Supported (`FWS` uncompressed, `CWS`/`ZWS` compressed) |
| 12 | Java class | Supported (gated on the `cafebabe` magic) |
| 13 | Internal engine-generated data | **Not implemented** |
| 14 | Other | **Not implemented** |

### Signature-format coverage

**Every signature in every database tracked here loads** — 0 of 273,587 lines on
daily 28074, 0 across `main`+`daily`, and 0 across the `shelter`,
`malware.expert` and `twinclams` third-party feeds.

That number was 20 at the start of this release. Closing it was not one feature
but seven, and every one of them was a case where the format's documented
behaviour and its actual behaviour differ. Each was settled by loading the
offending line into clamscan with a crafted input, never by reading the spec:

| Was | What it actually is |
|---|---|
| **Alternations with an empty branch** — `(2d4120\|)` | "this run, or nothing". Variable-width, so the branch has to propagate the current position unchanged rather than search for a needle. |
| **Alternations with nibble wildcards** — `(5?\|b?)`, `(?4\|?c)`, `(130?\|0?)` | A branch is not a literal. Branches now compile to `(value, mask)` pairs; the all-literal case keeps its substring-search fast path. |
| **`SEn:` offsets** | "the match *starts* inside section n" — not that it ends there. A pattern beginning in section 0 and running into section 1 matches `SE0:`, and the upper bound is inclusive by one byte. exav reproduces both; being stricter would drop detections. |
| **`VI:` offsets** | Not a window over the version resource but an **anchor set**: the match must begin exactly at a `VS_VERSION_INFO` string key. One byte either side does not match. |
| **A literal `;` inside a PCRE** | Splits the line into extra fields. The format says to write `\x3B`; live signatures do not, and clamscan rejoins them. exav rejoins on unescaped-slash parity — and only across subsignature fields, since signature *names* contain `/` too. |
| **`0:0&(…)` in a logical expression** | A `:`-suffix on a subsignature reference, discarded. Three probes pinned it down: the reference is the number *before* the colon, and it stays live. The suffix is not always numeric — two `.lnk` signatures put the header bytes they match there. |
| **`(8==9)` and `0=2,&1&2`** | `==` for equality and a trailing comma with no second count. Neither is the documented spelling; both load. |

Two more came out of the same sweep and are TDB rather than syntax:
`HandlerType:CL_TYPE_GRAPHICS` needed a graphics type to re-type *to*, and
`Container:CL_TYPE_MHTML` needed MHTML told apart from mail — which turns on the
mail envelope, not the multipart subtype: a `multipart/related` document *with*
`From:`/`To:` is mail, a `multipart/mixed` one without them is MHTML.

**A recorded correction.** An earlier version of this list led with
"byte-compare subsignatures". That was wrong: the classifier guessed the cause
from punctuation and filed every *alternation* as a byte-compare, because both
contain a parenthesis. Byte-compare causes zero skips. Attribution is an
advertised property — "counted and attributable by cause" — so a wrong label
sends a reader to build a capability that already exists. A second entry on the
list, "malformed database line", was wrong the same way: the line loads
in clamscan, and the real cause was the `:`-suffix above.

### Engine options and parser toggles

ClamAV's engine exposes 37 tunables (`cl_engine_set_num`/`_str`) and 13
per-parser on/off bits (`CL_SCAN_PARSE_*`). exav implements the four headline
limits — scan size, file size, recursion depth, file count — and none of the
rest. Found by enumerating ClamAV's own option enum rather than by inspection of
exav, which is why they were missed before.

| Missing | ClamAV default | Why it matters |
|---|---|---|
| `MAX_SCANTIME` | 120 s | **exav has no in-engine wall-clock limit.** Its in-core budgets are size- or count-based; wall clock is bounded only by the kernel-level `--max-scan-secs` (default 120 s per job under the prefork daemon, opt-in on a one-shot run, absent in a library embedding) |
| `PCRE_MATCH_LIMIT` / `PCRE_RECMATCH_LIMIT` / `PCRE_MAX_FILESIZE` | 100000 / 2000 / 100 MB | no backtracking bound on the PCRE path |
| `CACHE_SIZE` / `DISABLE_CACHE` | 65536 entries | ClamAV caches clean-file hashes; exav has no equivalent, a straight performance cost on trees with repeated files |
| `MAX_EMBEDDEDPE`, `MAX_HTMLNORMALIZE`, `MAX_HTMLNOTAGS`, `MAX_SCRIPTNORMALIZE`, `MAX_ZIPTYPERCG`, `MAX_PARTITIONS`, `MAX_ICONSPE`, `MAX_RECHWP3` | various | per-subsystem caps exav applies globally or not at all |
| 13 `CL_SCAN_PARSE_*` toggles | all on | an operator can disable any single parser (`--scan-pe=no`, `--scan-ole2=no`, …); a migrating config that does so silently changes meaning under exav |
| `FORCETODISK`, `KEEPTMP`, `TMPDIR`, `AC_ONLY`, `AC_MINDEPTH`/`MAXDEPTH`, `BYTECODE_TIMEOUT`/`MODE`/`SECURITY`, `PUA_CATEGORIES`, `DISABLE_PE_CERTS` | — | I/O policy, matcher tuning, bytecode policy |

### Heuristic alerts

Heuristics are **engine-emitted, not database-driven**: across `main`+`daily`
only 5 signatures are literally named `Heuristics.*`, plus one in `bytecode.cvd`.
Everything else is hardcoded. ClamAV does not distinguish the two — it
prefix-tests `PUA.` / `Heuristics.` / `BC.Heuristics.` and routes any of them
down the same potentially-unwanted path.

exav emits 60-odd heuristic names, all from code. The parity picture:

| exav | ClamAV | Status |
|---|---|---|
| `Heuristics.PDF.ObfuscatedNameObject` | same | exact parity, on by default |
| `Heuristics.Zip.OverlappingFiles` | same | exact parity, on by default |
| `Heuristics.XZ.DicSizeLimit` | same | exact parity, always on (ClamAV has no flag for it either) |
| `Heuristics.Limits.Exceeded.{MaxScanSize,MaxFileSize,MaxFiles,MaxRecursion}` | same | parity, via `--not-scanned limits-exceeded=alert` |
| `Heuristics.GPTPartitionIntersection`, `…APMPartitionIntersection`, `…MBRPartitionnIntersect` | same | parity, via `--detect partition-intersection`. The doubled `n` is upstream's typo and is reproduced verbatim — the name is the API |
| `Heuristics.Broken.Executable` | same | parity, via `--detect broken` |
| `Heuristics.Phishing.Email.SSL-Spoof` | same | parity, via `--detect phishing` |
| `Heuristics.Structured.{CreditCardNumber,SSN}` | same | exact parity |
| `Heuristics.Encrypted.{Zip,RAR,7Zip,PDF}` | same | parity |
| `Heuristics.Encrypted.{Doc,Archive}` | ClamAV has `EGG`, no `.Doc`/`.Archive` | **exav-invented names** |
| `Heuristics.OLE2.ContainsMacros.{VBA,XLM}` | same | exact name parity, via `--detect macros` |
| `Heuristics.Phishing.Email.Cloaked.NumericIP` | same | exact name parity |
| `Heuristics.Phishing.Email.{Cloaked.Username,SpoofedDomain}` | same | name parity; ClamAV runs these **on by default**, exav does not |
| `Heuristics.Authenticode.HashMismatch`, `…PE.PackedWithInjectionImports`, `…Static.Suspect.<score>` | — | exav-exclusive |
| `Heuristics.Broken.Media.{GIF,PNG,TIFF,JPEG}.*` | same | parity, via `--detect broken-media`, validating all four container structures |

Still missing, and **on by default in ClamAV**: `Exploit.W32.MS05-002`,
`W32.Parite.B`, `W32.Kriz`, `W32.Magistr.{A,A.dam,B,B.dam}`, `W32.Polipos.A`,
`Trojan.Swizzor.Gen`, `Worm.Mydoom.M.log`, `Phishing.URL.Blocked`,
`Safebrowsing.Suspected-{malware,phishing}`, `BoundsCheck`. Nothing opt-in is missing: every ClamAV alert class that can be switched on has
an exav counterpart.

Most of the remaining default-on set is a different kind of thing from the rest:
`W32.Parite.B`, `W32.Kriz`, `W32.Magistr.*`, `W32.Polipos.A`,
`Trojan.Swizzor.Gen`, `Worm.Mydoom.M.log` and `Exploit.W32.MS05-002` are
**detection content for specific 2000s-era malware families expressed as engine
code** rather than structural checks. Reimplementing them means reproducing
per-family matching logic, which is signature content in C.

**exav will not implement these, and the reason is licensing rather than
effort.** A structural heuristic can be rebuilt from the file format it inspects
— the format is the specification, and exav's implementation is checked against
what ClamAV *outputs*. These are not that. The matching logic for a particular
2000s virus family exists only inside GPLv2 source; there is no specification
behind it to reimplement from, and observing the output of a detection tells you
that a file matched, not what the rule was. Reproducing them would mean reading
and translating that source, which is precisely what exav's clean-room rule
forbids. Their absence is therefore permanent, not a backlog item. It costs
detection of a handful of long-dead families, and every affected file is still
scanned against the full signature database.

`BoundsCheck` is raised by ClamAV's own yC unpacker. exav has no hand-written
unpacker for yC (Yoda's *Cryptor*) — it unpacks those files by running the stub
under the emulator, which recovers the image but does not reproduce the
bounds-check diagnostic the C unpacker emits along the way.

`Phishing.URL.Blocked` and both `Safebrowsing.*` names come from a URL-hash
blocklist database that is opt-in even in ClamAV (`SafeBrowsing yes`), and is a
different mechanism from the `.wdb`/`.pdb` allow-lists exav already loads. That
one is a distribution question — hosting and refreshing a URL blocklist — more
than an engine question, and is out of scope for now rather than declined.

**Heuristics are also how ClamAV expresses what exav models as verdicts.**
`Heuristics.Limits.Exceeded.*` is `LIMITS-EXCEEDED`; `Heuristics.Encrypted.*` is
`PASSWORD-PROTECTED`; `Heuristics.Broken.*` overlaps `UNSCANNABLE`. ClamAV's form
fits the three clamd reply shapes (it is a `FOUND`), where exav's needs the
`ERROR` line — and most clients read `ERROR` as *the scanner broke*, not *this
file is interesting*.

Two of the three bridges exist, and one flag reaches both:
`--not-scanned password-protected=alert` converts the password-protected
verdict into `Heuristics.Encrypted.*`, and `--not-scanned
limits-exceeded=alert` converts a budget stop into
`Heuristics.Limits.Exceeded.<which budget>`. The alert name comes from a typed
limit kind carried on the error, never from parsing the human-readable reason —
deriving a detection name from prose is how a reworded message silently becomes
a different alert. `UNSCANNABLE` has no bridge yet.

### ClamAV's feature surface, for scale

Context for reading every number above: how large the thing being subsetted
actually is.

| Surface | ClamAV |
|---|---|
| `CL_TYPE_*` file types | 88 in 1.4.3, 90 in 1.5.3 |
| — of those, unpacked into child files | 55 |
| — parsed (inspected, no children emitted) | 12 |
| — identified only | 23 |
| `Target:` values | 15 |
| TDB attributes | 19 |
| Bytecode host APIs | 107 |
| `clamd` protocol commands | 17 |
| Distinct `Heuristics.*` alert names | 82 |
| DCONF | Signature-controlled feature toggles |

The 55/12/23 split is the useful one: a file-type count is a weak measure of an
engine, because most of a type table is recognition rather than extraction.

### Non-capability differences

Two more differences that are not capability gaps but will show up in a
migration:

* **`.cdiff` incremental updates, DNS `TXT` version probing and GPG verification
  of databases** — exav does full reloads and does not verify signatures;
  `freshclam`/`cvdupdate` remain the supported updaters and exav reads what they
  produce.
* **Quarantine actions, `VirusEvent` and on-access scanning** are deliberately
  [out of scope](#out-of-scope-for-now).

### Correction: RAR multi-volume is not a gap

An earlier revision of this page listed RAR volume joining as a capability gap.
That was wrong, and the correction is recorded here because of how the error
happened. One verification pass tested it on a host whose ClamAV build ships
**no unrar library at all**, so every RAR returned `OK` — a result that says
nothing about volume joining. A second pass on 1.5.3 reported the opposite.

Settled directly, with a control: a single-volume RAR containing EICAR is
detected by ClamAV 1.5.3 (so RAR support is live), while a three-volume set whose
payload provably lives only in the last volume returns **`OK`** when volume 1 is
scanned with all siblings present. ClamAV does not join RAR volumes.

exav reports the split member rather than joining it, and — since a fix that
came out of this — hands over the part that *is* in the scanned volume while
saying the rest is missing. Before that fix a **stored** split member was emitted
with no reason attached, so its prefix read as a complete member and a
multi-volume archive scanned clean. That was a real silent truncation, now
closed for both RAR3 and RAR5.

### Things that look like gaps and are not

Each of these is listed as a shortfall somewhere in this page's history, and
each turned out to be a format ClamAV does not handle either:

| Format | ClamAV | exav |
|---|---|---|
| ACE, StuffIt, Inno Setup | No support | Recognised, reported |
| WIM (any compression) | No support at all | Decoded (XPRESS/LZX; LZMS reported) |
| ZIP method 10 (DCL Implode) | Enumerates the entry, cannot extract | Reported per member |
| PDF `DCTDecode` / `CCITTFax` / `JBIG2` / `JPXDecode` | Not decoded — falls back to the raw stream | Not decoded |
| KWAJ | **No support, not even type recognition** | Decoded |
| NTFS, FAT, VHD, VHDX, QCOW2, VMDK | No support | Decoded |
| UDF | Parser present but extracted nothing from 13 test images | Decoded |
| YARA modules | **None work — even `pe` fails to load** | 7 modules implemented |
| CAB Quantum | Decodes | Decodes |

Two behavioural differences in exav's favour change what a clean verdict means:

* An **encrypted archive** is reported `PASSWORD-PROTECTED` by default. ClamAV
  returns `OK` unless `--alert-encrypted-archive` is passed.
* **SZDD** is decoded regardless of layout; ClamAV accepts it only when the
  tenth byte is zero and reports "not supported" otherwise.

## Out of scope for now

exav prioritises **CLI and server invocations** — scanning files and directories,
and answering on a socket. Three ClamAV features are deliberately not
implemented, and are listed here rather than left for you to discover:

| Not implemented | What to do instead |
|---|---|
| **Quarantine actions** (`--move`, `--copy`, `--remove`) | Act on the exit code or the result line. exav reports; your script moves. Exit codes are clamscan-compatible (`0` clean, `1` infected, `2` error) and `--files-from` + `--log` give you the same batch plumbing. |
| **`VirusEvent`** (run a command on detection) | Same: drive it from the daemon's reply or the scan output. |
| **On-access scanning** (`OnAccess*`, fanotify) | Not supported at all. Keep ClamAV if you depend on real-time protection — this is the one gap where "partially works" would be dangerous, so exav does not pretend to offer it. |

**`clamd.conf` is not read.** exav is configured with **CLI flags and
environment variables** (see [Configuration](/reference/configuration/)); there
is no `--config-file`. Migrating means translating your config once, not editing
a file exav will silently half-honour. That is the deliberate trade: ignoring a
tuning directive costs performance, but silently ignoring `ExcludePath` or
`OnAccessPrevention` changes what an operator believes is running. The
[ClamAV flag matrix](/reference/clamav-flag-matrix/) lists every `clamd.conf`
directive against the exav flag or environment variable that does the same job.

The migration exav aims at is *"change the container, set env vars and startup
flags, read the docs, done"* — not a transparent binary swap. See
[Migrating from ClamAV](/guides/migrating-from-clamav/).

## Licensing & distribution

ClamAV is GPLv2 and its signature database is GPL-licensed. exav is **MIT**,
written clean-room from public specifications — it reuses the signature *formats*
(interoperability, not derivation) but **never bundles or redistributes** the GPL
signature database; you fetch that yourself (see [Signatures](/guides/signatures/)
and [Contributing](/project/contributing/)). exav ships as a single static binary
rather than a set of system packages and libraries.
