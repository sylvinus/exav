# Signatures and the compiled database: contents, how exav uses them, and memory

Two things are easy to conflate, so this doc keeps them distinct:

- **signatures** — the raw ClamAV-format files (`.cvd`/`.cld` containers and the
  loose `.ndb`/`.ldb`/`.hsb`/… inside them) that you fetch with
  `cvdupdate`/`freshclam`;
- **the database** — the single compiled `.exavdb` file exav builds from those
  signatures (`--build-db`), which loads far faster and lighter.

This documents what the signatures actually contain, how exav turns each part
into a runtime structure, where the memory goes, and why the compiled database is
the answer to the build-time memory spike — based on measurements against a real
`daily.cvd` (ClamAV 1.4 era).

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
| `.yar`/`.yara` | exav's **native YARA engine** — a tree-walking evaluator (no JIT, no runtime codegen) | full-ish YARA |

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

### Build peak vs steady state vs database load

For the full `daily.cvd` (≈356k sigs, 961,830 anchor patterns, 1.36M bodies):

| Phase | Peak RSS |
|---|---|
| After parsing all signatures, **before** building the automaton | ~740 MB |
| **Building** the automaton (from raw signatures) | **~3.6 GB** |
| Final live structures (Body 148 MB + automaton 237 MB + groups 32 MB + …) | ~470 MB |
| **Loading the same signatures from a prebuilt database** | **~1.0 GB** |

The ~2.9 GB spike is the **daachorse double-array Aho-Corasick construction
transient** — a one-shot allocation burst while the automaton is built. It is
*not* steady-state storage (live data is ~470 MB) and it is *not* a leak: the
build frees its intermediates correctly (the dedup map is dropped before
construction, anchor buffers after, the two automatons build sequentially). The
transient simply can't be reduced by freeing things between steps — it's a
single construction event.

### The prebuilt database is the answer

`exav --build-db FILE -d <sigs>` serializes the built engine (the daachorse
automaton via its own format, the rest via bincode) into a single `.exavdb`.
**Loading the database skips the construction transient entirely** —
deserialization allocates ~the final size, not the build peak. Measured: 62 MB
(database) vs 284 MB (build) for 20k ldb; **1.0 GB (database) vs 3.6 GB (build)**
for full daily.cvd.

Recommended deployment: **build the database once on a capable machine (or in
CI), distribute the `.exavdb`, and load it cheaply everywhere.** Constrained hosts
never pay the build peak. On a small *build* host, `--build-shard-bytes <SIZE>`
bounds the per-shard construction transient (e.g. `--build-shard-bytes 1G` keeps
the full main+daily build near 3.3 GB peak) at a small scan-speed cost.

> Note: the environment matters too. RAM-backed `/tmp` (tmpfs) and a resident
> `clamd` can each consume ~1–2 GB; account for those when sizing a build host.

**Updating a running database-based daemon** is just recompile → atomic-swap: the
daemon mtime-polls the database file (like clamd's `SelfCheck`), so swapping it in
hot-reloads within a poll tick — no explicit `RELOAD` needed. The framing
`MAGIC | VERSION | payload | SHA-256` lets the daemon reject a torn/wrong-version
database on reload and keep serving the current one. See
[Updating a running deployment](https://exav.org/guides/prebuilt-database/#updating-a-running-deployment).

## Future ideas

- **`malloc_trim` after load** to return glibc-retained freed memory to the OS
  (shrinks steady RSS; does not affect the transient build peak).
- **More compact body/token representation** (a flat byte-code instead of
  `Vec<Elem>` enums) to shave the ~148 MB of `Body` structures.
