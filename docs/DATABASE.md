# Signatures and the compiled database: contents, how exav uses them, and memory

Two things are easy to conflate, so this doc keeps them distinct:

- **signatures**: the raw ClamAV-format files (`.cvd`/`.cld` containers and the
  loose `.ndb`/`.ldb`/`.hsb`/… inside them) that you fetch with
  `cvdupdate`/`freshclam`;
- **the database**: the single compiled `.exavdb` file exav builds from those
  signatures (`--build-db`), which loads far faster and lighter.

This documents what the signatures contain, how exav turns each part into a
runtime structure, and where the time and memory go when building and loading.

## What's in the signatures

A `.cvd`/`.cld` is a signed, gzip'd tar of typed signature files. Measured
contents of one `daily.cvd` (≈356k signatures total):

| File | Meaning | Count (daily.cvd) |
|---|---|---|
| `.ldb` | logical signatures (boolean expr over subsignatures) | **282,947** |
| `.hsb` | SHA file-hash signatures (`hash:size:name`) | 54,631 |
| `.mdb` | PE section-hash signatures (`size:md5:name`) | 11,575 |
| `.ndb` | literal/hex body signatures | 312 |
| `.msb` | PE section SHA hashes | 2 |
| `.hdb` | MD5 file-hash signatures | 22 |

`main.cvd` is much larger (≈3.2M signatures, mostly file hashes). Other types
exav understands: `.cdb` (container metadata), `.imp` (PE import-hash), `.cbc`
(bytecode), `.fp`/`.sfp` (allowlist), and YARA `.yar`/`.yara`.

## How each type is built and used

Different signature types compile to different runtime structures; there is no
one monolithic matcher:

| Source | Runtime structure | Matching |
|---|---|---|
| `.ndb` bodies **and** `.ldb` subsignatures | an **anchor index**: one literal *anchor* per body, indexed by the bytes of it the signature set shares least (the whole anchor at 1 to 3 bytes, 4 of them at 4 or 5, two overlapping 6-byte windows past that, looked up at every other position), behind filters small enough to stay in cache | the index is looked up at each position of the object; a hit fans out to every body sharing that anchor, and each candidate is verified (wildcards/gaps/nibbles/alternation, offset, nocase) |
| bodies whose offset (`n`, `EOF-n`, `EP+n`, `Sn+n`, `SL+n`, with an optional `,m` range of at most 4096) pins them to a window of starts | per-offset tables, kept out of the index | checked at the places each can start |
| `.ldb` `Trigger/PCRE/` subsignatures | `regex` objects, **compiled lazily** on first use, gated by the trigger expression | linear-time `regex` (DoS-safe); lookaround/backreferences run on a backtracking engine under a step bound |
| `.ldb` byte-compare subsignatures | small structs (`offset#options#comparisons`) | evaluated after the referenced subsig matches |
| `.hsb`/`.hdb` | size-keyed sorted **hash tables**, stored as flat blobs | whole-file digest lookup, computing only the digests some signature of that size needs |
| `.mdb`/`.msb` | a section-hash table | per-PE-section digest lookup, only for section sizes a signature names |
| `.cdb` | container-metadata matchers | matched on archive members (name/size/encryption/position) |
| `.imp` | size-constrained import-hash map | PE imphash lookup |
| `.cbc` | a sandboxed **bytecode interpreter** (no JIT) | trigger-gated programs; triggers are matched in the same sweep as every other signature |
| `.yar`/`.yara` | exav's **native YARA engine**, with an atom prefilter over the same anchor index (no JIT, no runtime codegen) | full-ish YARA |

So the engine is: *one anchor index (fed by ndb + ldb subsigs) + pinned-offset
tables + hash tables + lazy regex + an interpreter + YARA.*

## Build versus load

Measured on a 2026 `daily.cvd` alone, and on `main.cvd` + `daily.cvd` +
`bytecode.cvd`, with the 0.0.2 engine (peak RSS of the whole process):

| | daily | main + daily + bytecode |
|---|---|---|
| Parse the signatures and build (`--build-db`, or `-d` on the raw files) | 14 s, 1.3 GB | 23 s, 1.6 GB |
| Load the prebuilt `.exavdb` | 0.7 s, 0.55 GB | 1.3 s, 0.92 GB |
| `.exavdb` size | 140 MB | 352 MB |

The build holds the parsed signature text and its working tables next to the
structures it produces; a load allocates about the final size and reads the
index, hash tables and anchor groups back with a copy.

## The prebuilt database is the answer

`exav --build-db FILE -d <sigs>` serializes the built engine (flat arrays for
the index, the hash tables and the anchor groups; MessagePack through rmp-serde
for the rest) into a single `.exavdb`. Loading it skips parsing and the index
build. What can be computed once from the signatures is computed at build time
and stored, even when that makes the file larger: load time and scan speed come
first.

Recommended deployment: **build the database once on a capable machine (or in
CI), distribute the `.exavdb`, and load it cheaply everywhere.** Constrained
hosts never pay the build.

> Note: the environment matters too. RAM-backed `/tmp` (tmpfs) and a resident
> `clamd` can each consume 1 to 2 GB; account for those when sizing a build host.

**Updating a running database-based daemon** is recompile, then atomic swap:
the daemon mtime-polls the database file (like clamd's `SelfCheck`), so
swapping it in hot-reloads within a poll tick, with no explicit `RELOAD`. The
framing `MAGIC | VERSION | payload | CRC-32` lets the daemon reject a
torn/wrong-version database on reload and keep serving the current one. The
database is a trusted artifact: the CRC-32 catches damage, not tampering. See
[Updating a running deployment](https://exav.org/scanner/guides/prebuilt-database/#updating-a-running-deployment).

## Future ideas

- **`malloc_trim` after load** to return glibc-retained freed memory to the OS
  (shrinks steady RSS; does not affect the build peak).
- **A pre-decoded bytecode form**: operands resolved to frame offsets when a
  program is loaded, so the interpreter does not look them up at every step.
