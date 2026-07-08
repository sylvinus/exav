# Signature databases: contents, how exav uses them, and memory

This documents what a ClamAV-format signature database actually contains, how
exav turns each part into a runtime structure, and where the memory goes —
based on measurements against a real `daily.cvd` (ClamAV 1.4 era).

## What's in the database

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

The headline fact: **`.ldb` dominates the count and the cost.** Everything else
is comparatively cheap.

## How each type is built and used

Different signature types compile to different runtime structures — there is
**not** one monolithic engine:

| Source | Runtime structure | Matching |
|---|---|---|
| `.ndb` bodies **and** `.ldb` literal subsignatures | a shared **Aho-Corasick automaton** (one case-sensitive + one tiny case-insensitive), keyed on a literal *anchor* per body | an automaton hit fans out to every body sharing that anchor; each candidate body is then verified (wildcards/gaps/nibbles/alternation, offset, nocase) |
| `.ldb` `Trigger/PCRE/` subsignatures | `regex` objects, **compiled lazily** on first use, gated by the trigger expression | linear-time `regex` (DoS-safe); unsupported constructs (backref/lookaround) are skipped |
| `.ldb` byte-compare subsignatures | small structs (`offset#options#comparisons`) | evaluated after the referenced subsig matches |
| `.hsb`/`.hdb` | a size-keyed **hash table** | whole-file digest lookup |
| `.mdb`/`.msb` | a section-hash table | per-PE-section digest lookup |
| `.cdb` | container-metadata matchers | matched on archive members (name/size/encryption/position) |
| `.imp` | size-constrained import-hash map | PE imphash lookup |
| `.cbc` | a sandboxed **bytecode interpreter** (no JIT) | trigger-gated programs run on extracted buffers |
| `.yar`/`.yara` | compiled by **yara-x**, executed on the Pulley interpreter (no JIT) | full-ish YARA |

So the engine is really: *one Aho-Corasick automaton (fed by ndb + ldb literal
subsigs) + several cheap hash tables + lazy regex + an interpreter.*

## Where the memory goes

Measured peak RSS by signature type (each loaded alone, scanning a 1-byte file):

| Loaded | Peak RSS |
|---|---|
| 20,000 `.hsb` | ~2 MB |
| 11,575 `.mdb` | ~2 MB |
| 312 `.ndb` | ~2 MB |
| 5,000 `.ldb` | ~80 MB |
| 20,000 `.ldb` | ~284 MB |

`.ldb` costs ~14 KB/signature; hash tables are ~free. **All the memory is the
automaton**, and almost all of *that* is one specific thing — see below.

### Build peak vs steady state vs cache load

For the full `daily.cvd` (≈356k sigs, 961,830 anchor patterns, 1.36M bodies):

| Phase | Peak RSS |
|---|---|
| After parsing all signatures, **before** building the automaton | ~740 MB |
| **Building** the automaton (from raw signatures) | **~3.6 GB** |
| Final live structures (Body 148 MB + automaton 237 MB + groups 32 MB + …) | ~470 MB |
| **Loading the same DB from a prebuilt cache** | **~1.0 GB** |

The ~2.9 GB spike is the **daachorse double-array Aho-Corasick construction
transient** — a one-shot allocation burst while the automaton is built. It is
*not* steady-state storage (live data is ~470 MB) and it is *not* a leak: the
build frees its intermediates correctly (the dedup map is dropped before
construction, anchor buffers after, the two automatons build sequentially). The
transient simply can't be reduced by freeing things between steps — it's a
single construction event.

### The cache is the answer

`exav --build-cache FILE -d <db>` serializes the built engine (the daachorse
automaton via its own format, the rest via bincode). **Loading a cache skips the
construction transient entirely** — deserialization allocates ~the final size,
not the build peak. Measured: 62 MB (cache) vs 284 MB (build) for 20k ldb;
**1.0 GB (cache) vs 3.6 GB (build)** for full daily.cvd.

Recommended deployment: **build the cache once on a capable machine (or in CI),
distribute the `.exavcache`, and load it cheaply everywhere.** Constrained hosts
never pay the build peak.

> Note: the environment matters too. RAM-backed `/tmp` (tmpfs) and a resident
> `clamd` can each consume ~1–2 GB; account for those when sizing a build host.

## Future ideas

- **`--shard-anchors N` (build-time):** build N smaller automatons sequentially
  instead of one, dividing the build peak by ~N at the cost of N scan passes
  (×N Aho-Corasick time). Default N=1 (fastest matching); N>1 for building from
  raw signatures *on* a constrained machine without a prebuilt cache. The shard
  count would be baked into the cache, so one optimal N=1 build can still serve
  everyone.
- **`malloc_trim` after load** to return glibc-retained freed memory to the OS
  (shrinks steady RSS; does not affect the transient build peak).
- **More compact body/token representation** (a flat byte-code instead of
  `Vec<Elem>` enums) to shave the ~148 MB of `Body` structures.
