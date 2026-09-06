---
title: Using exav as a Rust library
description: Embedding exav-core or exav-unpack in your own Rust program — the scan API, the verdict model, and the limits you have to supply yourself.
---

Everything else in this documentation addresses someone running the `exav`
command. This page is for embedding the engine.

## Read this first: you supply the bounds

The CLI and the daemon wrap the engine in protections the library does not have.
The prefork daemon runs each scan in a worker with `RLIMIT_AS`, `RLIMIT_CPU`, a
wall-clock alarm and replacement on death. A one-shot CLI run sets kernel limits
when asked. **A library embedding gets none of that.**

What you do get is the in-core budget, and it is the layer that produces a
verdict rather than a corpse. Set it deliberately:

```rust
use exav_core::ScanOptions;
use exav_unpack::Limits;

let mut opts = ScanOptions::default();
opts.limits = Limits {
    max_extracted_bytes: 256 * 1024 * 1024,
    max_buffer_bytes: 64 * 1024 * 1024,
    max_recursion: 8,
    ..Limits::default()
};
```

Two failure modes stay outside any in-process budget, and you should decide what
to do about them before you feed the library hostile input:

- **An allocation large enough to abort.** Rust aborts rather than unwinding, so
  the panic boundary inside `exav-unpack` cannot catch it.
- **Stack exhaustion** from a file whose own grammar nests into itself.
  `max_recursion` bounds containers inside containers, not recursive descent
  inside one parser.

If your process must survive arbitrary input, scan out of process — or run the
[WASM build](/guides/wasm-sandbox/), which is bounded by its runtime.

## A scan

```rust
use exav_core::{loader, ScanOptions, Verdict};

let scanner = loader::load("/var/lib/exav".as_ref())?;   // .cvd/.cld/.ndb/.yar, or a .exavdb
let opts = ScanOptions::default();

let report = exav_core::scan_path(&scanner, "suspicious.bin".as_ref(), &opts)?;

match report.verdict {
    Verdict::Infected { ref signature, .. } => println!("found {signature}"),
    Verdict::Clean => println!("scanned, nothing found"),
    _ => println!("NOT fully scanned: {}", report.verdict.status_tag()),
}
```

## The verdict model is the API

`Ok` does not mean clean, and `Err` does not mean infected. The `io::Error` on
`scan_path` covers only reaching the file; every scan outcome arrives as a
`Verdict`.

| Verdict | What it means for you |
|---|---|
| `Clean` | Scanned in full, nothing matched |
| `Infected` | A signature matched |
| `LimitsExceeded` | A budget stopped the walk — raise a limit and retry |
| `Unscannable` | The content could not be decoded; raising a limit changes nothing |
| `PasswordProtected` | Encrypted, and a password would fix it |

**The last three are not errors and must not be treated as clean.** A file exav
could not read is a better hiding place than one it read and cleared. If you
collapse them into a boolean, collapse them toward "suspicious", not away.

`Verdict` is `#[non_exhaustive]`, so match with a wildcard arm.

## Extraction without the scanner

`exav-unpack` stands alone — every container format in
[the supported list](/reference/formats/), `#![forbid(unsafe_code)]`, no
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

`extract` buffers every member. For anything large, use `extract_each`, which
streams member by member and can stop early.

## Which crate

| Crate | Take it if you want |
|---|---|
| `exav-core` | Scanning: signatures, hashes, YARA, heuristics, verdicts |
| `exav-unpack` | Extraction only — no database, no matching |
| `exav-grep` | Searching inside archives |
| `exav-x86` | An x86-32 decoder with no dependencies |
| `exav-pe-emu` | Running a packer stub in a sandbox |
| `exav-update` | Fetching signature databases |
| `exav` | Nothing — it is the binary, not a library |

`exav` is the package `cargo install exav` installs, and it publishes no `[lib]`
target, so there is no `use exav::…`. Its
job is orchestration: flag parsing, output formatting, the daemon and ICAP
listeners, the process-level limits. Everything that decides a verdict lives in
`exav-core` and `exav-unpack`, which is what you embed. To drive the CLI's
behaviour from another program, run the binary — or, better for a long-lived
caller, talk to the daemon over the `clamd` protocol or to the
[ICAP listener](/guides/icap/) instead of paying the database load per scan.

## Stability

exav is `0.0.x`: any release may break any API. Cargo treats every `0.0.x` as
incompatible with the last, so a dependency on one is pinned exactly whatever you
write.

Modules behind the `unstable-internals` feature (`engine`, `bytecode`,
`patterns`, `pe`) exist so the tests and diagnostic examples can reach inside.
They are not an API and will change without a note.
