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
| `analyze`       | `analyze()` — the whole scanner   | format detection → every extractor (recursively) → pattern/hash matching → PE/ML/fuzzy heuristics → bytecode. **Broadest; the primary target.** |
| `full_pipeline` | all DB subsystems + scan API      | populates all DB subsystems (ndb/ldb/hdb/mdb/ldb/pdb/hsb/etc.) from fuzz text, then exercises `analyze()`, `analyze_all()`, `scan_seekable()`, and database round-trip. **Widest single target.** |
| `unpack`        | `unpack::extract()`               | every container format with tight budgets; every parser exercised on every input |
| `ndb_compile`   | `EngineBuilder::add_ndb/ldb`      | NDB/LDB signature compilation edge cases |
| `pe`            | PE parsing                        | section/import/resource parsing          |
| `filetype`      | magic/type detection              | type sniffing                            |
| `cvd`           | signature-DB container parsing    | `.cvd`/`.cld` loader                      |
| `sigs`          | signature compilation             | DB rule parsing                          |
| `bytecode`      | `.cbc` bytecode loader            | bytecode verification                    |
| `rar3_ppmd`     | RAR3 PPMd decompression          | PPMd/LZSS conversion path               |
| `pe_emulator`   | `exav_pe_emu::unpack()`               | the x86 emulator that runs packer stubs: instruction decode + semantics, the emulated Windows environment, SEH, and the dump path. **The only target where the input supplies control flow rather than data** — and the only path from a scanned file to a dependency containing `unsafe` (the instruction decoder), so it is fuzzed through the entry point the scanner uses. Asserts the invariant the scanner relies on: anything emitted parses as a PE. |
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

The fuzz crate builds `exav-core` with **`default-features = false`** (YARA off):
the YARA path isn't exercised by the builtin-DB harness, and dropping it keeps
ASan compile times down on a constrained host. Everything we touch — archive
parsers, decryption, PE, icon, the matcher — is reached without it.

All fuzz targets live in a single workspace (`fuzz/`). The `unpack` target
exercises every container format with tight budgets; `full_pipeline` exercises
the full scan path including all DB subsystems and database round-trip; `ndb_compile`
exercises signature compilation edge cases. A single `full_pipeline` target covers
all extractors — `analyze()` reaches them recursively — so there is no separate
`exav-unpack` fuzz workspace.

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

`sigs`, `ndb_compile`, `cvd`, `bytecode`, `rar3_ppmd`, `parser_recursion` and
`x86_decode` get no seeds: no committed file is in their input format.

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

## Running a campaign

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
