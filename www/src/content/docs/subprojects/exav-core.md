---
title: exav-core
description: The exav scanning engine as a Rust library, with signature-database parsing, pattern and hash matching, file typing and the verdict model, the scan API, and the bounds an embedding has to supply itself.
---

**The engine.** Everything that turns bytes into a verdict, with no CLI and no
daemon attached, to embed in your own service.

```bash
cargo add exav-core
```

It defaults to every format, decryption and YARA; see [Features](#features)
for a smaller build. For extraction alone, with no signature database and no
matching, use [exav-unpack](/unpack/rust/).

`exav`, the package `cargo install exav` installs, publishes no `[lib]`
target, so there is no `use exav::…`. Its job is orchestration: flag parsing,
output formatting, the daemon and ICAP listeners, the process-level limits.
Everything that decides a verdict lives in `exav-core` and `exav-unpack`. To
drive the CLI's behaviour from another program, run the binary or, better for
a long-lived caller, talk to the daemon over the `clamd` protocol or to the
[ICAP listener](/scanner/guides/icap/) instead of paying the database load per
scan.

## What it owns

- **Database parsing:** `.cvd`/`.cld` containers and the loose formats
  (`.ndb`/`.ldb`/`.hdb`/`.hsb`/`.mdb`/`.msb`/`.cdb`/`.imp`/`.cbc`, allowlists,
  phishing and password databases, `.yar` rules) and the prebuilt `.exavdb`. A
  signature exav cannot load is skipped and counted
  (`Scanner::unsupported_count`, shown in the CLI's `-v` summary).
- **Matching:** one index of literal anchors for body signatures plus size-keyed
  hash tables for whole-file and section hashes, over an object held in memory up
  to the deep-analysis limit and read through a bounded block cache beyond it:
  the same matching either way. Wildcard verification runs as a simulation
  over reachable position intervals, so it cannot backtrack or blow up on
  repetitive input. See [Streaming & memory](/scanner/concepts/streaming-memory/).
- **The native [YARA engine](/scanner/guides/yara/)** and a step-capped
  [bytecode interpreter](/scanner/concepts/bytecode-sandbox/) for `.cbc` programs, both
  without runtime code generation.
- **Content-based file typing**, PE parsing, fuzzy and similarity scoring, the
  prebuilt-`.exavdb` builder, and an HTTP range-reader backend (`http`
  feature) that scans a large remote file through the block cache instead of
  downloading it whole.

## Read this first: you supply the bounds

The CLI and the daemon wrap the engine in protections the library does not have.
The prefork daemon runs each scan in a worker with `RLIMIT_AS`, `RLIMIT_CPU`, a
wall-clock alarm and replacement on death. A one-shot CLI run sets kernel limits
when asked. **A library embedding gets none of that.**

What you do get is the in-core budget, and it is the layer that ends a scan with
a verdict rather than a killed process. Set it deliberately:

```rust
use exav_core::ScanOptions;

let mut opts = ScanOptions::default();
opts.limits.max_extracted_bytes = 256 * 1024 * 1024; // held at once, in total
opts.deep_analysis_max = 64 * 1024 * 1024;           // one object held whole
opts.limits.max_recursion = 8;
opts.limits.max_pe_emulation_steps = 200_000_000;
```

`deep_analysis_max` also caps `limits.max_buffer_bytes` for a scan. `Limits` and
`ScanOptions` are `#[non_exhaustive]`, so set fields on a default value; a struct
literal does not compile outside the crate, even with `..Default::default()`.
Each field, with the CLI flag that sets it and its default, is in
[Limits and tuning](/scanner/reference/limits/#the-in-core-budgets).

An object over `deep_analysis_max` is scanned through a block cache. Its text
views, and an archive member too large to hold, need somewhere to be written and
read back: give the scan a [`Spill`](#somewhere-to-spill), or those are reported
`LimitsExceeded` rather than scanned.

Two failure modes stay outside any in-process budget, and you should decide what
to do about them before you feed the library hostile input:

- **An allocation large enough to abort.** Rust aborts rather than unwinding, so
  the panic boundary inside `exav-unpack` cannot catch it.
- **Stack exhaustion** from a file whose own grammar nests into itself.
  `max_recursion` bounds containers inside containers, not recursive descent
  inside one parser.

If your process must survive arbitrary input, scan out of process, or run the
[WASM build](/scanner/guides/wasm-sandbox/), which is bounded by its runtime.

## A scan

```rust
use exav_core::{loader, ScanOptions, Scanner, Verdict};

// A directory of .cvd/.cld/.ndb/.yar files, or a .exavdb file.
let scanner = loader::load("/var/lib/exav".as_ref())?;
if scanner.signature_count() <= Scanner::builtin().signature_count() {
    return Err("no signatures loaded".into());
}
let mut opts = ScanOptions::default(); // set `opts.spill` here, see below

let report = exav_core::scan_path(&scanner, "suspicious.bin".as_ref(), &opts)?;

match report.verdict {
    Verdict::Infected { ref signature, .. } => println!("found {signature}"),
    Verdict::Clean => println!("scanned, nothing found"),
    _ => println!("NOT fully scanned: {}", report.verdict.status_tag()),
}
```

`loader::load` returns a `Scanner`. It fails on a path that does not exist, but
an empty directory loads as the built-in baseline, which detects only the EICAR
test file. The CLI refuses to run against it; a library caller has to check, as
above. `loader::load` skips the PUA databases and `loader::load_with_pua` loads
them; a `.exavdb` keeps the choice it was built with.

`scan_path` opens a file and hands it to `scan_seekable`, the one scan every
input goes through, which takes any `Read + Seek` and reads a large input
through a block cache rather than whole. The entry points:

| Function | Scans |
|---|---|
| `scan_path` | a file, with its path as YARA's `filepath`/`filename`/`extension` |
| `scan_seekable` | any `Read + Seek` of known length (`scan_seekable_located` also returns the member path of a hit) |
| `analyze` | bytes already in memory |
| `analyze_all_with_outcome`, `analyze_all_seekable` | every match, not just the first, with whether the scan finished (`analyze_all` drops that, so avoid it) |
| `warm_up` | nothing: builds the lazily-initialised structures, to call before forking workers |

Only `scan_path` knows a file name. Set `opts.filename` when calling the others
if your YARA rules test it. The YARA engine can also be used on its own, as
`exav_core::yara` (see [YARA rules](/scanner/guides/yara/#using-the-engine-directly)).

### Somewhere to spill

The library writes nothing to disk on its own. To let a scan spill, implement
`exav_core::spill::Spill`, for instance over temporary files (with the
`tempfile` crate):

```rust
use std::io::{Seek, SeekFrom, Write};
use exav_core::spill::{Spill, SpillReader, SpillWriter};

struct TempSpill(std::path::PathBuf);

impl Spill for TempSpill {
    fn create(&self) -> Result<Box<dyn SpillWriter>, String> {
        let file = tempfile::tempfile_in(&self.0).map_err(|e| e.to_string())?;
        Ok(Box::new(SpillFile(file)))
    }
}

struct SpillFile(std::fs::File);

impl SpillWriter for SpillFile {
    fn write(&mut self, bytes: &[u8]) -> Result<(), String> {
        self.0.write_all(bytes).map_err(|e| e.to_string())
    }
    fn finish(mut self: Box<Self>) -> Result<Box<dyn SpillReader>, String> {
        self.0.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
        Ok(Box::new(self.0))
    }
}

opts.spill = Some(std::sync::Arc::new(TempSpill(std::env::temp_dir())));
```

Bound what it may write yourself: `create` and `write` can refuse, and the scan
then reports what it could not keep.

## Reading a verdict

The API returns more than infected or clean, because "clean" is a safety claim:

| Verdict | Meaning | CLI and clamd word |
|---|---|---|
| `Clean` | Scanned in full, nothing matched | `OK` |
| `Infected` | A signature matched | `FOUND` |
| `LimitsExceeded` | A budget stopped the scan; raise a limit and retry | `PARTIAL` (`LIMITS-EXCEEDED`) |
| `Unscannable` | Content was present but could not be decoded; raising a limit changes nothing | `PARTIAL` (`UNSCANNABLE`) |
| `PasswordProtected` | Encrypted, and no password worked; set `opts.passwords` and retry | `PARTIAL` (`PASSWORD-PROTECTED`) |

`Ok` does not mean clean, and `Err` does not mean infected. The `io::Error` on
`scan_path` covers only reaching the file (it is the CLI's `ERROR`); every scan
outcome arrives as a `Verdict`.

**The last three are not errors and must not be treated as clean.** They exist
so that an incomplete scan is never reported as clean: a file exav could not
read is a better hiding place than one it read and cleared. If you collapse
them into a boolean, collapse them toward "suspicious", not away.

`Verdict` is `#[non_exhaustive]`, so match with a wildcard arm. See
[Verdicts & exit codes](/scanner/reference/verdicts/) for how the CLI reports
each one.

## Options behind the CLI flags

The `ScanOptions` fields each `exav` flag sets. The limit fields, with
defaults, are in [Limits](/scanner/reference/limits/#the-in-core-budgets); the
spill flags are not engine fields (see
[Buffering a stream](/scanner/reference/cli/#buffering-a-stream-spill)).

| CLI flag | ScanOptions field | Default |
|---|---|---|
| `--decode base64` / `--no-decode base64` | `decode_base64` | on |
| `--detect exav-heuristics` | `heuristics` | off |
| `--detect macros` / `phishing` / `broken` / `broken-media` / `packed` / `partition-intersection` | matching `alert_*` fields | off |
| `--detect pua` | PUA databases loaded, `PUA.*` kept | off |
| `--dlp-credit-cards` / `--dlp-ssns` | `structured_cc_count` / `structured_ssn_count` | off |
| `--passwords` / `--passwords-from` | `passwords` | none |
| `--partial-as …=found` | `alert_encrypted` / `alert_exceeds_max` | partial |
| `--clamav-compat` | `restrict_extractors` + `unofficial_suffix` + `clamav_compat`, plus the limits and decoders listed under [ClamAV compatibility](/scanner/reference/cli/#clamav-compatibility) | off (full reach) |
| none (always on) | `clamav_heuristics` (imphash + PDF obfuscation) | on |

The ClamAV-parity heuristics (`clamav_heuristics`) can only be turned off through
the library, so an out-of-the-box scan matches ClamAV's default detection surface.

Two `alert_*` fields are set by `--partial-as` rather than `--detect`, because
they answer a verdict question: `found` turns "could not fully examine this" into
a detection under ClamAV's own `Heuristics.Encrypted.*` / `Heuristics.Limits.*`
names.

## Features

| Feature | What it does |
|---|---|
| default | `yara`, `all-formats`, `decrypt`, `dlp`, `phishing`, `image-hash`: the `exav` binary's defaults minus its `icap` |
| `http` | The HTTP range-request reader (`dep:ureq`) |
| `checksums` | Lets `ScanOptions::verify_checksums` make a container checksum mismatch an error |
| `unstable-internals` | Makes the engine internals (`engine`, `bytecode`, `pe`, …) public, for tools; no stability promise |
| `wasi-bin` | The `exav-wasm` WASI command-line binary (see [WASM sandbox](/scanner/guides/wasm-sandbox/)) |

The format features and `decrypt` are forwarded to `exav-unpack`: every name in
[its list](/unpack/rust/#features) can be named here, after
`--no-default-features`. What each capability feature adds to the scanner is in
[Feature flags](/scanner/reference/feature-flags/#capability-features).

## Stability

exav is `0.0.x`: any release may break any API. Cargo treats every `0.0.x` as
incompatible with the last, so a dependency on one is pinned exactly whatever you
write.

Modules behind the `unstable-internals` feature (such as `engine`, `bytecode`,
`patterns` and `pe`) exist so the tests and diagnostic examples can reach inside.
They are not an API and will change without a note.
