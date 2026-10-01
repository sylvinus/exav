---
title: Using exav as a Rust library
description: Embedding exav-core or exav-unpack in your own Rust program, with the scan API, the verdict model, and the limits you have to supply yourself.
---

Everything else in this documentation addresses someone running the `exav`
command. This page is for embedding the engine.

```sh
cargo add exav-core      # scanning
cargo add exav-unpack    # extraction only
```

Both default to every format (and `exav-core` to YARA). For a smaller build,
turn default features off and pick what you need; see
[Feature flags](/reference/feature-flags/). The crate pages,
[exav-core](/subprojects/exav-core/) and
[exav-unpack](/subprojects/exav-unpack/), list what each one contains.

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
[WASM build](/guides/wasm-sandbox/), which is bounded by its runtime.

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

`loader::load` fails on a path that does not exist, but an empty directory loads
as the built-in baseline, which detects only the EICAR test file. The CLI refuses
to run against it; a library caller has to check, as above. `loader::load` skips
the PUA databases and `loader::load_with_pua` loads them; a `.exavdb` keeps the
choice it was built with.

Other entry points:

| Function | Scans |
|---|---|
| `scan_path` | a file, with its path as YARA's `filepath`/`filename`/`extension` |
| `scan_seekable` | any `Read + Seek` of known length (`scan_seekable_located` also returns the member path of a hit) |
| `analyze` | bytes already in memory |
| `analyze_all_with_outcome`, `analyze_all_seekable` | every match, not just the first, with whether the scan finished (`analyze_all` drops that, so avoid it) |
| `warm_up` | nothing: builds the lazily-initialised structures, to call before forking workers |

Only `scan_path` knows a file name. Set `opts.filename` when calling the others
if your YARA rules test it.

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

`Ok` does not mean clean, and `Err` does not mean infected. The `io::Error` on
`scan_path` covers only reaching the file; every scan outcome arrives as a
`Verdict`.

| Verdict | What it means for you |
|---|---|
| `Clean` | Scanned in full, nothing matched |
| `Infected` | A signature matched |
| `LimitsExceeded` | A budget stopped the scan; raise a limit and retry |
| `Unscannable` | The content could not be decoded; raising a limit changes nothing |
| `PasswordProtected` | Encrypted; set `opts.passwords` and retry |

**The last three are not errors and must not be treated as clean.** A file exav
could not read is a better hiding place than one it read and cleared. If you
collapse them into a boolean, collapse them toward "suspicious", not away.

`Verdict` is `#[non_exhaustive]`, so match with a wildcard arm. See
[Verdicts & exit codes](/reference/verdicts/) for how the CLI reports each one.

## Extraction without the scanner

`exav-unpack` stands alone: every container format in
[the supported list](/reference/formats/), `#![forbid(unsafe_code)]`, and no
signature database:

```rust
use exav_unpack::{extract, Budget, Format, Limits};

let mut budget = Budget::new(Limits::default());
let entries = extract(Format::Zip, &bytes, &mut budget)?;
for e in &entries {
    if let Some(reason) = &e.unsupported {
        // Recognised, not decoded. Do not treat this as an empty member.
        eprintln!("{}: {reason}", e.name);
        continue;
    }
    println!("{} ({} bytes)", e.name, e.data.len());
}
```

`Entry::unsupported` is how the crate says "this exists and I could not read
it". Skipping those entries silently reintroduces exactly the failure the
verdict model exists to prevent.

`extract` buffers every member. For anything large, use `walk`, which hands the
members over one at a time, a large one as a reader, and stops early when the
visitor returns `Some`:

```rust
use exav_unpack::{detect, walk, Budget, Limits, Member, MemberMeta};

let Some(format) = detect(&bytes) else { return Ok(()) };
let mut budget = Budget::new(Limits::default());
let mut visit = |meta: &MemberMeta, content: Option<Member<'_>>, budget: &mut Budget| {
    match content {
        None => eprintln!("{}: {}", meta.name, meta.unsupported.unwrap_or("no content")),
        Some(member) => match member.into_bytes(meta, budget) {
            Ok((data, _partial)) => println!("{} ({} bytes)", meta.name, data.len()),
            Err(e) => eprintln!("{}: {e}", meta.name),
        },
    }
    None::<()>
};
walk(format, &bytes, &mut budget, &mut visit)?;
```

`into_bytes` reads a streamed member whole under the buffer limit; read a
`Member::Stream` directly to keep it out of memory.

## Which crate

| Crate | Take it if you want |
|---|---|
| `exav-core` | Scanning: signatures, hashes, YARA, heuristics, verdicts |
| `exav-unpack` | Extraction only: no database, no matching |
| `exav-grep` | Searching inside archives |
| `exav-x86` | An x86-32 decoder with no dependencies |
| `exav-pe-emu` | Running a packer stub in a sandbox |
| `exav-update` | Fetching signature databases |
| `exav-unpack-wasm` | Extraction from JavaScript: an npm package, not a Rust dependency |
| `exav` | Nothing: it is the binary, not a library |

`exav` is the package `cargo install exav` installs, and it publishes no `[lib]`
target, so there is no `use exav::…`. Its
job is orchestration: flag parsing, output formatting, the daemon and ICAP
listeners, the process-level limits. Everything that decides a verdict lives in
`exav-core` and `exav-unpack`, which is what you embed. To drive the CLI's
behaviour from another program, run the binary or, better for a long-lived
caller, talk to the daemon over the `clamd` protocol or to the
[ICAP listener](/guides/icap/) instead of paying the database load per scan.

## Stability

exav is `0.0.x`: any release may break any API. Cargo treats every `0.0.x` as
incompatible with the last, so a dependency on one is pinned exactly whatever you
write.

Modules behind the `unstable-internals` feature (such as `engine`, `bytecode`,
`patterns` and `pe`) exist so the tests and diagnostic examples can reach inside.
They are not an API and will change without a note.
