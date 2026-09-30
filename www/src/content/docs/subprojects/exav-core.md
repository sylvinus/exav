---
title: exav-core
description: The exav scanning engine as a library, with signature-database parsing, pattern and hash matching, file typing, and the verdict model.
---

**The engine.** Everything that turns bytes into a verdict, with no CLI and no
daemon attached, to embed in your own service.

```bash
cargo add exav-core
```

## What it owns

- **Database parsing:** `.cvd`/`.cld` containers and the loose formats
  (`.ndb`/`.ldb`/`.hdb`/`.hsb`/`.mdb`/`.msb`/`.cdb`/`.imp`/`.cbc`, allowlists,
  phishing and password databases). A signature that fails to load is counted and
  attributed by cause rather than dropped.
- **Matching:** one Aho-Corasick automaton for body signatures plus size-keyed
  hash tables for whole-file and section hashes, over an object held in memory up
  to the deep-analysis limit and read through a bounded block cache beyond it:
  the same matching either way. Wildcard verification runs as a simulation
  over reachable position intervals, so it cannot backtrack or blow up on
  repetitive input. See [Streaming & memory](/concepts/streaming-memory/).
- **The native [YARA engine](/guides/yara/)** and a step-capped
  [bytecode interpreter](/concepts/bytecode-sandbox/) for `.cbc` programs, both
  without runtime code generation.
- **Content-based file typing**, PE parsing, fuzzy and similarity scoring, the
  prebuilt-`.exavdb` serializer, and an HTTP range-reader backend (`http`
  feature) that scans a remote ZIP by fetching only the members it needs.

The API is `0.0.x` and may break in any release.

## The verdict model

The API returns more than infected or clean, because "clean" is a safety claim:

| Verdict | Meaning | CLI and clamd word |
|---|---|---|
| `Clean` | Fully scanned, nothing matched | `OK` |
| `Infected` | A signature matched (`scan_seekable_located` also returns the member path when the hit was inside a container) | `FOUND` |
| `LimitsExceeded` | A limit stopped the scan before it finished | `PARTIAL` (`LIMITS-EXCEEDED`) |
| `Unscannable` | Content was present but could not be decoded | `PARTIAL` (`UNSCANNABLE`) |
| `PasswordProtected` | Content is encrypted and no password worked | `PARTIAL` (`PASSWORD-PROTECTED`) |

An `io::Error` from `scan_path` (the file could not be read) is the CLI's
`ERROR`. The last three verdicts exist so that an incomplete scan is never
reported as clean. See [Verdicts & exit codes](/reference/verdicts/) and
[Using exav as a library](/guides/library-usage/).

## Scanning a file

```rust
use exav_core::{loader, scan_path, ScanOptions, Verdict};

let db = loader::load(std::path::Path::new("/var/lib/exav"))?;
let report = scan_path(&db, std::path::Path::new("sample.bin"), &ScanOptions::default())?;

match report.verdict {
    Verdict::Infected { signature, .. } => println!("FOUND {signature}"),
    Verdict::Clean => println!("OK"),
    other => println!("not fully scanned: {other:?}"),
}
```

`scan_path` reads the file through a block cache, so a large one is not loaded
whole; `analyze` scans a buffer already in memory.
