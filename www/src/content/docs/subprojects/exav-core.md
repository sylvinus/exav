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
  hash tables for whole-file and section hashes, over a file held in memory up to
  the deep-analysis limit, and a constant-memory streaming pass (literal
  signatures and hashes) beyond it. Wildcard verification runs as a simulation
  over reachable position intervals, so it cannot backtrack or blow up on
  repetitive input. See [Streaming & memory](/concepts/streaming-memory/).
- **The native [YARA engine](/guides/yara/)** and a step-capped
  [bytecode interpreter](/concepts/bytecode-sandbox/) for `.cbc` programs, both
  without runtime code generation.
- **Content-based file typing**, PE parsing, fuzzy and similarity scoring, the
  prebuilt-`.exavdb` serializer, and an HTTP range-reader backend that scans a
  remote ZIP by fetching only the members it needs.

## The verdict model

The API returns more than infected or clean, because "clean" is a safety claim:

| Verdict | Meaning |
|---|---|
| `Clean` | Fully scanned, nothing matched |
| `Infected` | A signature matched, with the nested member path when the hit was inside a container |
| `LimitsExceeded` | A limit stopped the scan before it finished |
| `Unscannable` | Content was present but could not be decoded |
| `PasswordProtected` | Content is encrypted and no password worked |

The last three exist so that an incomplete scan is never reported as clean. See
[Verdicts & exit codes](/reference/verdicts/) and
[Using exav as a library](/guides/library-usage/).

## Scanning a buffer

```rust
use exav_core::{analyze, loader, ScanOptions, Verdict};

let db = loader::load(std::path::Path::new("/var/lib/exav"))?;
let data = std::fs::read("sample.bin")?;

match analyze(&db, &data, &ScanOptions::default()).verdict {
    Verdict::Infected { signature, .. } => println!("FOUND {signature}"),
    Verdict::Clean => println!("OK"),
    other => println!("not fully scanned: {other:?}"),
}
```
