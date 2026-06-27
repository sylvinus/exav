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
code execution, no out-of-bounds disclosure), but a robust scanner must still
contain them. That reframing is the whole point of the rewrite: the *same* logic
error that is a silent out-of-bounds read in a C parser (potential RCE) is a
deterministic, safe `panic_bounds_check` here (at worst a DoS). Fuzzing finds
those panics/aborts/hangs so we can eliminate or contain them.

We still run under **AddressSanitizer** because our *dependencies* (`cab`,
`sevenz`, `pdf`, compression shims) carry their own `unsafe`; ASan catches
genuine UB in them, distinct from the safe panics that surface on their own.

## Tooling

`cargo-fuzz` + libFuzzer (in `fuzz/`). libFuzzer is **coverage-guided**: it
instruments every branch edge (SanitizerCoverage) and evolves inputs to maximise
new coverage, under ASan, with `-Cdebug-assertions` (so overflow/underflow
panic instead of wrapping). Targets in `fuzz/fuzz_targets/`:

| target     | entry point                       | covers                                   |
|------------|-----------------------------------|------------------------------------------|
| `analyze`  | `analyze()` — the whole scanner   | format detection → every extractor (recursively) → pattern/hash matching → PE/ML/fuzzy heuristics → bytecode. **Broadest; the primary target.** |
| `unpack`   | `unpack::extract()`               | the extractor library directly           |
| `pe`       | PE parsing                        | section/import/resource parsing          |
| `filetype` | magic/type detection              | type sniffing                            |
| `cvd`      | signature-DB container parsing    | `.cvd`/`.cld` loader                      |
| `sigs`     | signature compilation             | DB rule parsing                          |
| `bytecode` | `.cbc` bytecode loader            | bytecode verification                    |

The fuzz crate builds `exav-core` with **`default-features = false`** (no
`yara-x`): the yara path pulls the heavy wasmtime/cranelift tree, which is
pathological to compile under ASan on a constrained host and isn't exercised by
the builtin-DB harness anyway (yara-x has its own fuzz suite). Everything we
touch — archive parsers, decryption, PE, icon, the matcher — is reached without
it.

## Seeding strategy (the multiplier)

Random bytes rarely form a valid `xar!` / `MSCF` / `Rar!` header, so a cold
fuzzer never reaches the deep parsers. We seed aggressively:

1. **Format fixtures** — every `crates/*/tests/fixtures/**` file (real zip/rar/
   7z/cab/upx/ole/… plus the encrypted-archive fixtures).
2. **Real corpus samples** — small (≤ 64 KB) files sampled from the live
   MalwareBazaar corpus. These carry valid PE/archive/document structure, so the
   mutator starts *inside* the parsers instead of rediscovering magic.

Seeds and fuzzer-discovered inputs live in a **gitignored** work dir
(`tmp/data/fuzzwork_analyze`), never the committed corpus, so a run never bloats
the tree. The corpus accumulates across runs — coverage climbs monotonically.

> One pitfall worth noting: don't seed a deliberately-pathological input. The
> `ppmd_lzss_conversion.rar` fixture decodes ~241 MB (its real test is
> `#[ignore]`d); seeded, it just makes libFuzzer time out on it immediately and
> abort. Exclude known-slow fixtures from the seed set.

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
     `Err`) → contain it at the **`extract_each` `catch_unwind` boundary**, which
     turns any decoder panic into a clean `LimitHit`. (We can't easily fix the
     dep in place; the boundary makes hostile input a non-event for *every*
     decoder uniformly.)
   - **Timeout** → decide algorithmic-DoS vs budget-bound. RAR/PPMd decode is
     CPU-heavy but bounded by `max_entry_bytes`/`max_total_bytes`; in production
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
| `extract_each` `catch_unwind` | third-party decoder panics | panic → `LimitHit` (never a silent Clean) |
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
| `MSCF` cabinet   | `cab-0.6.0` `folder.rs:134`       | dep indexes an empty vector on a crafted cabinet (panics instead of `Err`) | `catch_unwind` boundary in `extract_each` → `Unscannable` |
| `0o070707` cpio  | `formats/cpio.rs` (bin/newc/odc)  | `data_start` from attacker `namesize`, unclamped → `data[start..end]` with start > len | clamp `data_start` to `data.len()` (all 3 variants) |
| ISO9660          | `formats/iso.rs:54/57`            | dir record's self-declared `rec_len < 33`, then `rec[2..32]` indexed | require `rec_len >= 33` before slicing |
| UPX (NRV2B/D/E)  | `formats/upx.rs` (4 gamma loops)  | corrupt bitstream doubles the gamma value until `usize` overflow (and downstream `(m-3)*256`) | cap gamma at `NRV_GAMMA_MAX` (`u32::MAX`) → `Unscannable` |

Verdict note: decoder panics and corrupt-stream errors map to **`Unscannable`**
(recognised format, undecodable bytes), distinguished from genuine resource
bounds (`LimitsExceeded`) via `LimitHit`'s `LimitKind`. A batch of 12 fork-mode
crashes deduplicated to these 4 root-cause sites (plus the already-contained CAB
dep panic).
