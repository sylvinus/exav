# Fuzzing exav

Coverage-guided fuzzing is how we hold the line on exav's core promise: **the
scanner must never crash, hang, or corrupt memory on the files it scans** —
and those files are, by definition, hostile.

## Why fuzz a `#![forbid(unsafe_code)]` codebase?

`forbid(unsafe_code)` removes *undefined behaviour* (the memory-corruption class
— buffer overflows, use-after-free, type confusion that turn into RCE/info-leak).
It does **not** make the process unkillable. Safe Rust still terminates on:

- **Panics** — out-of-bounds indexing (`s[i]`), integer overflow (in debug /
  `-Cdebug-assertions` builds), `unwrap()`/`expect()`, `assert!`, division by
  zero, slice-range start > end. A panic that reaches the top of a thread with no
  catcher kills the process.
- **Aborts** — OOM (`Vec::with_capacity(attacker_huge)` → `handle_alloc_error`),
  stack overflow from unbounded recursion (guard-page `SIGSEGV`), double-panic,
  `panic = "abort"`.
- **Hangs** — infinite loops or super-linear algorithms (algorithmic DoS).

These are all **denial-of-service, not memory corruption** — far less severe (no
code execution, no out-of-bounds disclosure), but the scanner must still
contain them. That reframing is what memory safety buys: the *same* logic error
that is a silent out-of-bounds read in a C parser (potential RCE) is a
deterministic, safe `panic_bounds_check` here (at worst a DoS). Fuzzing finds
those panics/aborts/hangs so we can eliminate or contain them.

We still run under **AddressSanitizer** because our *dependencies* (`cab`,
`sevenz`, `pdf`, `delharc`, `lzxd`, compression shims, and under the image
hash `crc32fast` and `simd-adler32`) carry their own `unsafe`;
ASan catches genuine UB in them, distinct from the safe panics that surface on
their own.

## Tooling

`cargo-fuzz` + libFuzzer (in `fuzz/`). libFuzzer is **coverage-guided**: it
instruments every branch edge (SanitizerCoverage) and evolves inputs to maximise
new coverage, under ASan, with `-Cdebug-assertions` (so overflow/underflow
panic instead of wrapping). Targets in `fuzz/fuzz_targets/`:

| target          | entry point                       | covers                                   |
|-----------------|-----------------------------------|------------------------------------------|
| `analyze`       | `analyze()` — the whole scanner   | format detection → every extractor (recursively) → pattern/hash matching → PE/ML/fuzzy heuristics → bytecode, against the signature files of `fuzz/db/` (every signature kind, the YARA rules, a bytecode program), under options the input's last two bytes choose (`fuzz/options.rs`: the heuristics, every `alert_*`, the structured-data and phishing checks, tight or production bounds, an object read in memory or through the block cache). **Broadest; the primary target.** |
| `full_pipeline` | the scanner as a deployment builds it | up to eight database files (a kind byte, bit 7 official, and their text) go through `loader::Builder::add_named_bytes` as the CLI does, so every kind the loader reads is reached (signatures, hashes, container and file-type rules, YARA, bytecode, phishing and allow-lists, `.crb`, passwords); then the scan, held to what the entry points promise each other: the same bytes scanned twice agree, `analyze_all` is a superset of `analyze` and a clean scan lists nothing, a stream read in pieces answers what a buffer did, and a database written out and read back scans as the one it came from. **Widest single target.** |
| `seekable`      | `scan_seekable()` over a reader that returns a few bytes a call and fails part way | the block-cache read of an object over `deep_analysis_max`, which no other target reaches. Checked: a reader and a buffer give one answer, a reader that fails is an error unless a detection was already made, and an object read through the cache that found nothing is not `Clean`. |
| `yara`          | `yara::compile()` + `Scanner::scan()` | exav's native YARA engine: the rule text through the compiler, then the rules over fuzzed data (the `pe`, `elf`, `dotnet`, `math`, `hash` and `string` modules, which parse the scanned file; hex, regular-expression, `xor` and `base64` patterns). Checked: a scan twice agrees, every match lies in the data. |
| `pcre`          | `engine::compare_engines()`       | a PCRE subsignature rewritten for the two Rust engines (vendored fancy-regex and `regex`): neither panics or hangs, and where the translation is in the linear engine's subset the two answer the same. |
| `clamd`         | the daemon's command loop, over memory (`exav::fuzzing::clamd`) | the clamd protocol as any client of the socket speaks it: NUL or newline terminated lines, `IDSESSION`, and the `INSTREAM`, `EXINSTREAM` and `EXINSTREAM MULTI` framings, with lying chunk lengths and missing terminators. Paths are refused in this build. Checked: a plain `INSTREAM` or `EXINSTREAM` answers what `analyze` says of the same bytes. |
| `icap`          | the ICAP request loop, over memory (`exav::fuzzing::icap`) | RFC 3507 as a proxy sends it: the head, `Encapsulated` offsets, `Preview`, `Allow: 204`, the chunked body with its extensions, `ieof` and trailers. Checked: a plain `REQMOD` is blocked exactly when `analyze` calls the bytes anything but clean. |
| `volumes`       | `volume::Collector`, `join_rar_volumes` | multi-volume names, the collector that holds and joins the parts of a split archive (it loses nothing: every offered name comes out once, the bytes add up) and the RAR joiner with the extraction of what it joins. |
| `authenticode`  | `authenticode::analyze_pe()`      | the PE certificate table, the PKCS#7 `SignedData` and each certificate's DER. Checked: a `.crb` list naming a certificate's subject (with or without its serial) blocks it, and one naming another subject does not. |
| `database`      | `database::read()` / `write()`    | the prebuilt `.exavdb`: MessagePack whose lengths size allocations. Checked: what reads writes back to something that reads and scans the same. |
| `unpack`        | `unpack::extract()`               | every container format with tight budgets; every parser exercised on every input |
| `ndb_compile`   | `EngineBuilder::add_ndb/ldb`      | NDB/LDB signature compilation edge cases |
| `pe`            | PE parsing                        | section/import/resource parsing          |
| `filetype`      | magic/type detection              | type sniffing                            |
| `cvd`           | signature-DB container parsing, then the loader | `.cvd`/`.cld` header, gzip and tar under tight bounds, and each member through `loader::Builder::add_named_bytes` as a signed database's are |
| `sigs`          | signature compilation             | DB rule parsing                          |
| `bytecode`      | `.cbc` bytecode loader            | bytecode verification                    |
| `rar3_ppmd`     | RAR3 PPMd decompression          | PPMd/LZSS conversion path               |
| `pe_emulator`   | `exav_pe_emu::unpack()`               | the x86 emulator that runs packer stubs: instruction decode + semantics, the emulated Windows environment, SEH, and the dump path. **The only target where the input supplies control flow rather than data.** Its decoder, `exav-x86`, is hand-written and `forbid(unsafe_code)` like the emulator (`x86_decode` checks it against `iced-x86`); the target goes through the entry point the scanner uses. Asserts the invariant the scanner relies on: anything emitted parses as a PE. |
| `imagehash`     | `exav_imagehash::Hasher::hash()`, `exav_render::image::decode_any()`, `exav_render::pdf_image` | every image decoder behind `fuzzy_img#` (PNG, GIF, JPEG, TIFF, BMP, WebP, ICO, PNM, QOI, DDS, farbfeld, HDR, and JPEG 2000 and JBIG2 through hayro-jpeg2000 and hayro-jbig2), then the grey conversion, resize and DCT of both presets, with a 64 MiB decode budget. The scan reaches these only when a database has a `fuzzy_img#` signature, so `analyze` rarely does. Then the JPXDecode, JBIG2Decode and CCITTFaxDecode decoders `@exav/viewer` puts in place of pdf.js's, their parameters taken from the input's length. Those do not catch panics: in the browser a panic traps the wasm instance. |
| `drawing`       | `exav_render::dwg::Document::parse()` + `tessellate()` | DXF, ASCII and binary, and DWG (R13 to 2018), into the drawing model, then the tessellation of every layout on a light and a dark ground: what `@exav/viewer`'s DWG module runs on any file a user opens. The scanner does not read drawings, so no other target reaches it. A panic `parse` would catch counts: in the browser it traps the wasm instance. |
| `cad_dxf`       | `exav_render::cad::read_dxf_with()` + `to_json()`, `cad::preview()` | DXF, ASCII and binary, R12 to 2018, into the drawing model: the meaning of each group code in each record (hatch boundaries, multileader context data, R12 viewport extended data, subclass splits, proxy graphics streams), and the thumbnail found from the end of the file. `unpack` and `analyze` reach DXF's tokenizer and the payload extraction through exav-unpack's `dxf` format, but not this reading of it. |
| `ifc`           | `exav_render::ifc::read()` + `exav_render::stl::read()` | IFC (IFC2X3, IFC4, IFC4X3) and STL into triangle meshes, as `@exav/viewer`'s model module reads them: the STEP index and parameter parser, units, placements, profiles, curves, swept and tessellated solids, B-reps, booleans (BSP trees) and openings, within a 200,000-triangle budget; and binary and ASCII STL. No other target reaches them. |
| `cad_dwg`       | `exav_render::cad::read_dwg_with()` + `to_json()`, `cad::preview()` | DWG, R13 to R2018, into the drawing model: exav-unpack's `dwg` bit codes, the sections the file header locates (R2004 on: the encrypted file header, the page and section maps, page checksums and the LZ77 decompression; R2007: the Reed-Solomon coded file header, maps and pages, their CRCs and copies, and its own LZ77 variant), the classes, the object map and each object's common data and string stream, then the header variables, the tables and the blocks with their entities, each entity type's own data and the proxy graphics streams of the others, and the thumbnail read alone. `unpack` and `analyze` reach the file header, the preview images and, opening the drawing, the OLE2FRAME objects. |
| `parser_recursion` | nesting depth, constructed        | Builds deep nesting from a couple of input bytes rather than waiting for the mutator to find it — every extra level needs another well-formed delimiter pair, so byte mutation stalls at two or three while this reaches thousands. Targets the failure the panic boundary cannot contain: `catch_unwind` catches a bounds check, not a stack overflow, and `max_recursion` bounds containers-inside-containers rather than a grammar that nests into itself. A finding looks like a crash with **no panic message**. |
| `x86_decode`    | `exav_x86::decode()`                  | **differential against `iced-x86`**, which is compiled in as the oracle. Asserts six properties per input: never claim an encoding iced rejects; agree on length; agree on mnemonic; agree on the memory operand's base/index/scale/displacement and on every register operand's file, number and position; re-decoding from exactly the reported length gives the same answer; and no proper prefix of an instruction decodes. Declining is not a failure — `None` means "not an encoding this decoder claims", which the caller reports as unsupported. |

`x86_decode` earns its place beside the crate's own differential tests because
those sweep the opcode maps with a **fixed instruction body** — one ModRM byte
and a constant tail. The mistakes that survive a sweep live in the body: a SIB
byte that decides whether a displacement exists, a `mod` field that changes its
width, a prefix run that pushes the instruction past fifteen bytes. Mutation
reaches those combinations; enumeration does not. A wrong length is the failure
to watch, because it desynchronises every instruction after it rather than
staying local.

Run it with `ASAN_OPTIONS=detect_leaks=0`, as CI's `fuzz-smoke` does: iced-x86
builds its decoder tables in a `lazy_static` it never frees, and the newest
nightly's LeakSanitizer reports them at exit (552 bytes in 12 allocations,
whatever the input). It is the oracle's, not exav's, and every other target
keeps the check.

The fuzz crate builds `exav-core` with the default features off and then what
the scanner ships with that matters here: **`yara`** (the in-tree engine, which
has no wasmtime and does not slow the ASan build much), `all-formats`,
`decrypt`, `checksums` and `image-hash`. An earlier version left YARA out, and
with it the rule compiler, the evaluator and the `pe`/`elf`/`dotnet`/`math`/
`hash` modules that parse the scanned file: nothing fuzzed them.

All fuzz targets live in a single workspace (`fuzz/`). The `unpack` target
exercises every container format with tight budgets; `full_pipeline` exercises
the full scan path through the real loader and holds the entry points to each
other; `ndb_compile` exercises signature compilation edge cases. `analyze()`
reaches every extractor recursively, so there is no separate `exav-unpack` fuzz
workspace. `fuzz/support` (its own crate, no dependencies) holds the custom
mutator and the input framing, so that their tests run on their own:
`cargo test --manifest-path fuzz/Cargo.toml -p exav-fuzz-support`.

## The signature files, and what the input chooses

`analyze` and `full_pipeline` scan against `fuzz/db/`: one or more lines of
every kind the loader reads, written for exav (no ClamAV content), each the
shape of a feature (an anchor at `EP+0`, an alternative group, a PCRE
subsignature with a back-reference, a YARA `for` over a module's array). A line
the loader rejects is a line no input reaches, so `fuzz/db.rs` refuses to start
a target when one does not load or a YARA rule does not compile.
`EXAV_FUZZ_DB_SKIP=yar,ldb` leaves files out, to see what one costs a scan.

The options a scan runs under are the input's too (`fuzz/options.rs`): each
`alert_*` heuristic, the structured-data and phishing checks, bounds tight
(three inputs in four, so that a run is short) or production's, an object read
in memory or through the block cache. A seed of any length works unchanged:
`analyze` takes the selector from the input's last two bytes and does not scan
them, `full_pipeline` and `seekable` from a short header the seed script puts
in front.

`exav` ships no library, and a fuzz target can only call a library. So
`fuzz/exav-cli` is a crate whose `[lib]` points at `crates/exav/src/main.rs`:
the source of the binary, built as a library (`exav_cli`), so that the `clamd`
and `icap` targets drive the daemon's parsers over memory and what is fuzzed is
what ships. Its dependencies repeat `crates/exav/Cargo.toml`'s; one added there
and not here fails its build. Its `fuzzing` feature, which no shipped build has,
adds the entry points (`crates/exav/src/fuzzing.rs`) and makes the clamd verbs
that take a path answer an error instead of opening it.

## Seeding strategy (the multiplier)

Random bytes rarely form a valid `xar!` / `MSCF` / `Rar!` header, so a cold
fuzzer never reaches the deep parsers. We seed aggressively:

`scripts/fuzz-seeds.sh OUT` builds one seed directory per target from the
committed fixtures, which CI's `fuzz-smoke` job and `scripts/fuzz-campaign.sh`
pass as an extra, read-only corpus directory:

1. **Format fixtures**, for `analyze`, `full_pipeline`, `unpack` and
   `filetype`: every `crates/*/tests/fixtures/**` file of at most 64 KiB
   (`MAX_BYTES`), `.xor` ones unmasked, which is why `OUT` belongs outside the
   repository. The PE files among them seed `pe` and `pe_emulator`.
2. **Images**, for `imagehash`: exav-imagehash's committed test images
   (`crates/exav-imagehash/tests/fixtures/img`) and, for the three formats
   they lack, one tiny DDS, farbfeld and HDR file in `fuzz/seeds/imagehash`;
   exav-render's JPEG 2000, JBIG2 and CCITT fixtures
   (`crates/exav-render/tests/fixtures/images`) and the viewer's PDF image
   streams (`crates/exav-viewer/e2e/fixtures/pdf-images`).
3. **Drawings**, for `drawing`: exav-render's fuzz-finding fixtures and the
   viewer tests' `plan.dxf` and `plan.dwg`, which
   `crates/exav-viewer/e2e/fixtures/make-plan.py` writes with ezdxf and the
   ODA File Converter, and the proxy graphics drawings
   (`crates/exav-render/tests/fixtures/cad/proxy`: streams its `make.py`
   writes chunk by chunk, as DXF and the converter's DWG of each version).
   LibreDWG's test drawings are GPL and are not used.
4. **DXF**, for `cad_dxf`: the drawing model's fixtures
   (`crates/exav-render/tests/fixtures/cad`, ezdxf's drawings as the ODA File
   Converter saved them in each version, ASCII and binary) and exav-unpack's
   (`crates/exav-unpack/tests/fixtures/dxf`), unzipped, of at most 64 KiB;
   and the viewer demo's `plan.dxf`. The unzipped ones go to the format
   targets' seeds too.
5. **DWG**, for `cad_dwg`: the same drawings as the converter saved them as
   R13, R14, 2000, 2004, 2010, 2013 and 2018 DWG
   (`crates/exav-render/tests/fixtures/cad/dwg`), the proxy graphics
   drawings' DWGs (`cad/proxy/dwg`) and exav-unpack's
   (`crates/exav-unpack/tests/fixtures/dwg`), unzipped, of at most 64 KiB
   (which leaves the 2000 ones out: the converter's smallest is 94 KiB; from
   2004 the sections are compressed). They go to the format targets' seeds
   too.
6. **IFC and STL**, for `ifc`: exav-render's fixtures
   (`crates/exav-render/tests/fixtures/ifc` and `stl`, STEP text and STL
   written by their `make.py`, a file per kind of geometry) and the viewer
   tests' `house.ifc` and `house.stl` (`tests/fixtures/viewer`).

7. **Framed targets**, written by the script: `full_pipeline` and `seekable` get
   every fixture behind their header (and `full_pipeline` each file of
   `fuzz/db/` as its database, alone and eight together), `volumes` the RAR sets
   of exav-unpack's fixtures, `yara` the rules of `fuzz/db/fuzz.yar` and
   `fuzz/seeds/yara/` each over a PE, an ELF and some text, `pcre` the lines of
   `fuzz/seeds/pcre/patterns.txt`, `cvd` a container of `fuzz/db/` and `database`
   the prebuilt database `exav --build-db` makes of it (so the script builds
   `exav`, or uses `$EXAV`), `authenticode` the signed PEs.

`sigs`, `ndb_compile`, `bytecode`, `rar3_ppmd`, `parser_recursion`, `x86_decode`,
`clamd` and `icap` get no seeds: no committed file is in their input format, and
the last two decode any bytes into commands and requests.

`fuzz/dicts/` holds strings to splice in for the targets whose input is text or
a protocol (`yara`, `pcre`, `icap`, `clamd` and `signatures`, which
`full_pipeline`, `ndb_compile`, `sigs` and `cvd` use). The campaign script and
CI pass them.

Locally, small (≤ 64 KB) files sampled from the MalwareBazaar corpus can be
added to a target's work directory. They carry valid PE, archive and document
structure, so the mutator starts *inside* the parsers instead of rediscovering
magic.

Seeds and fuzzer-discovered inputs live in a **gitignored** work dir
(`tmp/data/fuzzwork_analyze`), never the committed corpus, so a run never bloats
the tree. The corpus accumulates across runs — coverage climbs monotonically.

> One pitfall: don't seed a deliberately-pathological input. The
> `ppmd_lzss_conversion.rar` fixture decodes ~241 MB (its real test is
> `#[ignore]`d); seeded, it just makes libFuzzer time out on it immediately and
> abort. Exclude known-slow fixtures from the seed set.

## Synthesized seeds

`scripts/fuzz-seeds-synth.py` (run by `scripts/fuzz-seeds.sh`) writes small
seeds from what each target's source reads: for each input format, the shapes
the code branches on. Measured, as the coverage (edges) libFuzzer reports right
after loading the seed corpus, before any mutation (`-runs=0`, ASan build, the
fixture seeds as "old"):

| target | no seeds | old seeds | old + synthesized | synthesized alone |
|---|---|---|---|---|
| `sigs` | 280 | 280 (none) | 575 | 575 |
| `ndb_compile` | 339 | 339 (none) | 3,362 | 3,356 |
| `bytecode` | 76 | 76 (none) | 643 | 643 |
| `parser_recursion` | 19 | 19 (none) | 540 | 543 |
| `rar3_ppmd` | 19 | 19 (none) | 329 | 329 |
| `x86_decode` | 1,855 | 1,855 (none) | 4,250 | 4,250 |
| `pe_emulator` | 65 | 1,385 | 1,721 | 1,586 |
| `cvd` | 40 | 20,086 | 20,179 | 20,038 |
| `authenticode` | 25 | 1,770 | 1,793 | 1,070 |
| `seekable` | 19 | 65,002 | 65,018 | 19,052 |
| `analyze` | 183 | 44,219 | 44,958 | 19,443 |
| `full_pipeline` | 25 | 76,707 | 77,120 | 36,647 |
| `pe` | 56 | 1,298 | 1,298 | 426 |

Where there were no seeds the gain is large (five to ten times); where the
fixtures already open the parser it is small, and the point is the inputs the
fixtures do not have: the option bits, a reader that fails, a PE of the shapes a
packer's stub takes. `database` has none of its own: its per-file databases are
in the old count, so it is not measured alone. A seed that breaks a check is
the best kind: one found the `--alert-exceeds-max` all-match bug in the table
below the moment `full_pipeline` first loaded it. `clamd` and `icap` are not
here: their input is `arbitrary`'s encoding, which no one writes by hand, and
they reach 17,000 edges within seconds without seeds.

## Running a campaign

CI's `fuzz-smoke` job runs every target for 60 seconds on each push, from the
seeds and from the corpus the last run left (`actions/cache`), and runs the
tests of `fuzz/support`. The `fuzz-nightly` workflow runs the campaign below
for three hours every night and fails if it finds a crash, a timeout or an OOM,
uploading `fuzz/artifacts`.

`scripts/fuzz-campaign.sh` splits a wall-clock budget across every target, in
fork mode, and reports what each one found:

```sh
scripts/fuzz-campaign.sh                          # one hour, split evenly
TOTAL=1800 scripts/fuzz-campaign.sh               # half an hour
TARGETS="analyze x86_decode" scripts/fuzz-campaign.sh
```

It builds every target **before** running any of them and refuses to start if
one fails. That gate is not ceremony: `cargo fuzz run` per target, with its
output piped away, turns a compile error into a target that "ran" and found
nothing — the same shape in the log as a clean run, which is the worst possible
way to be wrong about test coverage. It also reports only the artifacts *this*
campaign produced, so a stale directory does not read as new findings.

### Memory

Building `exav-core` under AddressSanitizer is the memory peak of the whole
repository: one rustc process, full instrumentation, and `codegen-units=1`,
which `cargo fuzz` sets by default. On a small host that combination is what the
OOM killer reaches for, and rustc dies with `signal: 9` rather than an error
message. The campaign script therefore passes `--codegen-units 16` and builds
one crate at a time; raise `CODEGEN_UNITS` on a larger machine for slightly
faster fuzzing.

## Run modes

- **Single-shot** (find the first crash fast): aborts on the first
  crash/timeout, writes the artifact.
  ```sh
  cargo +nightly fuzz run analyze tmp/data/fuzzwork_analyze -- \
    -max_total_time=600 -timeout=25 -rss_limit_mb=4096
  ```
- **Fork mode** (collect *many* distinct crashes without rebuilding between
  them): the parent keeps fuzzing after each child crash/timeout/OOM. This is
  the efficient campaign mode — one run yields a batch of distinct artifacts to
  triage, so we rebuild once per batch instead of once per bug.
  ```sh
  cargo +nightly fuzz run analyze tmp/data/fuzzwork_analyze -- \
    -fork=1 -ignore_crashes=1 -ignore_timeouts=1 -ignore_ooms=1 \
    -timeout=60 -rss_limit_mb=4096 -max_total_time=1500
  ```

`-timeout` is the DoS threshold (an input slower than this is a finding);
`-rss_limit_mb` catches runaway allocation as an OOM.

## Triage & fix workflow

For each artifact (`fuzz/artifacts/<target>/{crash,timeout,oom}-*`):

1. **Reproduce** with a backtrace:
   `RUST_BACKTRACE=1 ./fuzz/target/*/release/analyze <artifact>`.
2. **Classify by where the panic originates:**
   - **Our code** (e.g. `formats/cpio.rs`) → **fix the root cause**: bounds-check
     before slicing, `saturating_*` arithmetic, `.min(len)` clamps on
     attacker-controlled offsets/sizes. A parser must tolerate any byte string.
   - **A third-party decoder** (e.g. `cab`, which panics instead of returning
     `Err`) → contain it at the **`walk` `catch_unwind` boundary**, which
     turns any decoder panic into a clean `LimitHit`. (We can't easily fix the
     dep in place; the boundary makes hostile input a non-event for *every*
     decoder uniformly.)
   - **Timeout** → decide algorithmic-DoS vs budget-bound. RAR/PPMd decode is
     CPU-heavy but bounded by `max_buffer_bytes`/`max_extracted_bytes`; in production
     the daemon's `RLIMIT_CPU`/`SIGALRM` cap wall-clock. A *super-linear* loop on
     small input is a real bug to fix.
   - **OOM** → an allocation sized from an attacker length field escaped the
     budget; tighten the budget check.
3. **Lock it** with a regression test in `crates/exav-unpack/tests/
   panic_containment.rs` (or the relevant crate), embedding the minimal
   artifact as a committed fixture (these are tiny, malformed-but-benign inputs,
   safe to commit — unlike the malware corpus).
4. **Rebuild** the fuzz binary and resume; the prior corpus is reused, so the
   fuzzer doesn't re-discover fixed paths and pushes into new ones.

## Containment layers (defence in depth)

Even with every known panic fixed, new ones can hide in deps. The layers:

| layer | contains | mechanism |
|-------|----------|-----------|
| Root-cause fixes in our parsers | our own panics | bounds checks, saturating math |
| `walk` `catch_unwind` | third-party decoder panics | panic → `LimitHit` (never a silent Clean) |
| Daemon prefork pool | OOM, stack overflow, hangs | per-job `RLIMIT_AS` / `RLIMIT_CPU` / `SIGALRM` → worker `_exit`, recycled |
| Verdict taxonomy | "couldn't fully scan" | `LimitsExceeded`/`Unscannable` — a not-fully-scanned file is never reported Clean |

The `catch_unwind` boundary protects the **library/CLI** path (which has no
process-level backstop); the prefork pool protects the **daemon** path against
the aborts `catch_unwind` can't catch (OOM, stack overflow). Note that libFuzzer
installs its own abort-on-panic hook, so the fuzzer surfaces *every* reachable
panic even ones `catch_unwind` would contain — which is what we want: the
boundary is a backstop, not an excuse to leave our own parsers panicky.

## Findings log

| input            | site                              | root cause                                              | fix |
|------------------|-----------------------------------|---------------------------------------------------------|-----|
| `MSCF` cabinet   | `cab-0.6.0` `folder.rs:134`       | dep indexes an empty vector on a crafted cabinet (panics instead of `Err`) | `catch_unwind` boundary in `walk` → `Unscannable` |
| `0o070707` cpio  | `formats/cpio.rs` (bin/newc/odc)  | `data_start` from attacker `namesize`, unclamped → `data[start..end]` with start > len | clamp `data_start` to `data.len()` (all 3 variants) |
| ISO9660          | `formats/iso.rs:54/57`            | dir record's self-declared `rec_len < 33`, then `rec[2..32]` indexed | require `rec_len >= 33` before slicing |
| UPX (NRV2B/D/E)  | `formats/upx.rs` (4 gamma loops)  | corrupt bitstream doubles the gamma value until `usize` overflow (and downstream `(m-3)*256`) | cap gamma at `NRV_GAMMA_MAX` (`u32::MAX`) → `Unscannable` |
| `fuzzy_img#` sig | `engine.rs` `parse_fuzzy_subsig`  | multi-byte UTF-8 chars in hash field caused `&hash[i*2..]` to slice inside char boundary | `hash.is_ascii()` guard — reject non-ASCII hash fields |
| NDB anchor sig   | `engine.rs` `pick_anchor`         | `fixed += w` overflowed on crafted input | `fixed = fixed.saturating_add(w)` |
| truncated CAB (LZX) | `cab` → `lzxd` `bitstream.rs:37` | dep reads `buffer[1]` when buffer has 1 byte | `catch_unwind` boundary → `Unscannable` |
| LHA level 3      | `delharc` `header/parser.rs:265`  | dep adds `parser.len + first_header_len` which overflows u32 | `catch_unwind` boundary → `Unscannable` |
| ARC, 69 bytes (`full_pipeline`, OOM) | `formats/arc.rs` `lzw` | a code past the next free one was taken for KwKwK; it then became a code's own prefix, and expanding it never ended | refuse `code > next` |
| ZOO LZD (review of the above) | `formats/zoo.rs` `decode` | output was not capped at the declared size the budget checked, and LZW expands a few thousand times | a writer that stops at `org_size` |
| PE import directory at 4 GiB (`pe_emulator`) | `exav-pe-emu` `win.rs` `bind_imports` | `is_mapped` saturated, so a descriptor past the top passed, and reading its fields overflowed; API output pointers had the same `p + off` | `is_mapped` refuses a range past 4 GiB; guest pointer offsets wrap |
| `67 F3 0F AE /6` (`x86_decode`) | `exav-x86` | UMONITOR's register was sized by the operand size, not the address size | 16 bits under `67` |
| VSIB gathers and scatters (`x86_decode`) | `exav-x86` | claimed under `67` (no SIB in 16-bit addressing), and gathers whose destination, index and mask registers overlap, which are #UD | refused |
| DWG arc ending at -1.2e99 (`drawing`, timeout) | `exav-render` `dwg/curves.rs` `flatten_arc`, `flatten_ellipse` | the sweep was brought into (0, 2π] by adding 2π until positive, which a float that size never becomes | `rem_euclid`; a non-finite angle draws nothing (`tests/fixtures/fuzz/arc-end-angle-1e99.dwg`) |
| (review of the above) hatch dashes far from the origin | `dwg/hatch.rs` `apply_dashes` | the same pattern: adding a fine period to a cycle start of 1e20 left it unchanged, with nothing drawn to stop the loop | the cycles counted first; too many draw the span solid |
| (review of the above) a hatch or line a float's range wide | `dwg/hatch.rs` `pattern_segments`, `dwg/linetype.rs` | indices cast to `i64` and lengths to `usize` saturated, and their difference or product overflowed | `saturating_sub`; the dash count guard in `f64` |
| JPX decoded at a reduced size (`imagehash`, 7 panics) | hayro-jpeg2000 0.4.1 `j2c/decode.rs` `store`, through exav-render's `pdf_image::decode_jpx` | a reduced decode places its samples with full-resolution coordinates: an image area offset or a subsampled component in a second tile underflows a subtraction or slices past a row (or, offset, draws nothing), and a column of tiles empty at that size is a zero chunk size | `decode_jpx` refuses a reduced decode of those layouts (`Siz::reducible`), as pdf.js's decoder failing; full-size decodes unchanged (`a_reduced_jpx_decode_the_decoder_cannot_place_fails_cleanly`, files written by OpenJPEG in `tests/fixtures/images/make.py`) |
| JBIG2 stream of 418 bytes declaring a 16,504 by 65,359 region on a 120 by 64 page (`imagehash`, timeout) | exav-render `pdf_image/jbig2.rs` and `image/jbig2.rs`, through hayro-jbig2 0.3.1 `decode/generic.rs` | the budget counted the page bitmap only; hayro-jbig2 decodes each region at its declared size (up to 65,535 by 65,535) wherever it lies, so a region far off the page took 135 MB and minutes | the bitmaps the region segments declare count against the budget too, in both organisations of a file (`region_pixels`; `a_jbig2_region_larger_than_the_budget_is_refused`, segments written in the test). Symbol dictionaries, whose symbol sizes are coded in the data, are still bounded by hayro-jbig2's own limits only |
| TIFF LZW strip without a clear code (`imagehash`, panic in debug builds) | `weezl` 0.1.10 `decode.rs` (the vendored TIFF decoder's LZW) | a `debug_assert!` held that a TIFF table never reaches 4,095 codes; release builds decode the strip | weezl 0.1.12, whose only change is that assertion, corrected upstream (`a_tiff_lzw_strip_filling_its_table_without_a_clear_code_decodes`, a strip written in the test) |
| streamOptimized VMDK, grain-table marker counting 2^64 - 1 sectors (`analyze`, CI smoke run, overflow panic) | `formats/vmdk.rs` `read_markers` | the marker's skip saturated the walk position to `usize::MAX`, and the loop condition then added 512 to it | `pos.saturating_add(512)` (`a_metadata_marker_that_skips_past_the_end_of_the_file_ends_the_walk`) |
| ZIP Implode member whose Huffman table has 256 length bytes (`unpack`, 2 overflow panics) | `zip` 8.6.0 `legacy/implode.rs` `read_huffman_code`, through `formats/zip.rs` | the table's byte count was computed as `byte + 1` in `u8`, so 255 overflowed; containment turned it into a corrupt archive, losing the other members | `zip` 9.0.1, which counts in `usize` (`implode_tree_size_255_is_not_a_panic`, a ZIP written in the test) |
| JBIG2 stream of 227 bytes, generic region of hundreds of millions of pixels (`imagehash`, timeout and 2 slow units) | exav-render `pdf_image/jbig2.rs` and `image/jbig2.rs`, through hayro-jbig2 0.3.1 | regions were charged at a bit a pixel against the budget, a memory measure, but decoding costs time per pixel: ~5 s in a release build at a 64 MiB budget, and the viewer's 1 GiB budget allows 16 times as much | a region's declared pixels are also charged at a byte each (`a_region_declaring_more_pixels_than_the_budget_is_refused`, `tests/fixtures/images/jbig2_region_bomb.seg`) |
| JPEG of 206 by 64,540 pixels, 1.6 KB (`imagehash`, slow unit) | none | a real 13 MP decode and hash: 0.1 s in a release build, 9 s only under the fuzzer's sanitizer and coverage | not a bug; no change |
| 12.6 KB archive reaching the 100,000-member limit (`full_pipeline`, slow unit) | none | the member limit working as designed: ~1.1 s at `opt-level` 1 for 100,000 members, ~22 s per scan under the fuzzer, four scans per input | not a bug; no change |
| PCRE `\bword` on `1\x9aword` (`pcre`, the two engines disagreed) | vendored fancy-regex 0.19.2 `vm.rs`, `\b`, `\B` and their half forms | in `BytesMode::Ascii` the VM asked regex-automata's Unicode word boundary, which reads the bytes beside the position as UTF-8: a byte over 0x7F was taken with the byte before it for a letter, so no boundary was found where `regex` and PCRE2 find one. A signature using `\b` beside a high byte missed | the ASCII boundary functions in that mode (`a_word_boundary_beside_a_high_byte_reads_the_same_in_both_engines`; `fancy_regex/README.md` records the change) |
| PCRE `(\bb)x*` on `c\b\x9e` (`pcre`, the two engines disagreed) | vendored fancy-regex `compile.rs` `options_to_rabuilder` | the delegated engines kept regex-automata's default `utf8_empty(true)` in bytes mode: an empty match at a position before a byte over 0x7F was skipped as splitting a UTF-8 character, so a delegated repeat that can match nothing failed the whole pattern there | `utf8_empty` only in `BytesMode::Unicode` (same test) |
| safetensors sniff of an object whose first read failed (`seekable`, CI smoke run, index out of bounds) | `formats/aimodel.rs` `is_safetensors_in` | `Probe::head` is the start of the object and `len` its length; the sniff checked `len` and then indexed `head`, which a failed read leaves empty or short | the head's own length is checked, and the header is read as far as the head goes (`a_head_shorter_than_the_object_is_not_sniffed_past_its_end`) |
| bz2 bomb under `--alert-exceeds-max`, all-match mode (`full_pipeline`, found by a synthesized seed) | `lib.rs` `analyze_all_source` | the walk stopped by a budget ends as the alert (`limits_outcome`), and the match on its outcome had arms for `Limits`, `Unscannable` and `PasswordProtected` but not for that: the alert was dropped and the scan reported `Complete` with nothing found, which `--all-matches` printed as clean | the alert is a name in the list, as the unfinished-search arm already did (`all_matches_names_the_budget_that_stopped_the_walk`) |
| RAR volume numbered 65535 (RAR4) or 2^64 - 1 (RAR5) (`volumes`, overflow panic) | `formats/rar.rs` `join_rar4`, `join_rar5` | the refusal message added one to the number it had read, in its own width; release builds check overflow, so the panic was real and became `Unscannable` for the whole set instead of the volume being named | the sum in `usize` / saturating (`a_volume_numbered_65535_is_refused_by_name_not_by_a_panic`, `a_rar5_volume_numbered_2_pow_64_minus_1_is_refused_by_name_not_by_a_panic`) |
| `"secret" xor(1-255)` over 64 KB (`analyze`, 6 execs a second after the YARA rules were added; 3 s a scan) | `yara/matcher.rs` `PatternMatcher::search` | every position was compared with every key in the range, 255 times the work, and an `xor` pattern is never gated by an atom, so every scan paid it; a 16 MiB object took 9 s | the one key a position can match with is its first byte's (`a_wide_xor_range_does_not_cost_a_comparison_per_key_per_position`, `xor_finds_each_key_where_it_was_used`) |
| `/a.{0,32}b[^\x00-\x1f]+c\b/s` over 2 MiB of text (`full_pipeline`, timeout, all-match mode) | the YARA regex matcher | a start position's match runs to the end of the text, so the work is quadratic in it; yara's own engine has the same shape | not a bug in exav: the rule is the cost (`fuzz/db/fuzz.yar` bounds its repetition) |

Header numbers at the top of their range are what unchecked sums overflow on,
and libFuzzer's stock mutations seldom put one in a chosen field. Two things
cover that. The `unpack` and `analyze` targets share a custom mutator
(`fuzz/extreme.rs`) that sets one 2-, 4- or 8-byte field to such a value a
quarter of the time. And `crates/exav-unpack/tests/suites/extreme.rs` does it
exhaustively and deterministically for the disk-image formats: every field of a
valid container, one at a time, must not panic the decoder. `make test-wasm`
runs it on wasm32 too, where the production build wraps silently and a test
build aborts.

exav-render's `tests/fixtures/fuzz/` also holds damaged drawings from early
`drawing` runs (an over-long run of modular-number continuation words, an
entity declaring 2.3 GB of graphic data, a handle seed of `u64::MAX`, a
viewport with 2^31 frozen layers). They run against the DWG reader in
`the_fuzzers_findings_fail_quickly_and_cleanly` (`tests/dwg.rs`), which also
bounds the memory a finding may take; the modular-number reader refuses an
over-long run (`modular_numbers_read_as_the_spec_examples` in
`exav_unpack::dwg`'s `bits.rs`).

Verdict note: decoder panics and corrupt-stream errors map to **`Unscannable`**
(recognised format, undecodable bytes), distinguished from genuine resource
bounds (`LimitsExceeded`) via `LimitHit`'s `LimitKind`. An 8-hour fuzz campaign
across 10 targets found 2 engine bugs and 2 dep panics, deduplicated from 27
crash artifacts (25 ndb_compile = root causes #5/#6, 2 unpack = dep panics
contained by `catch_unwind`). All 4 dep panics (CAB×2, lzxd, delharc) are
caught by the same `catch_unwind` boundary.
