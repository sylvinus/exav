# exav-core

The core scanning engine of [**exav**](https://github.com/sylvinus/exav), a
memory-safe ClamAV replacement written in Rust.

`exav-core` provides the library API for loading ClamAV signature databases and
scanning files or streams in constant memory: signature-database parsing
(`.ndb`/`.ldb`/`.hdb`/`.cvd`/…), pattern/hash/fuzzy matching, optional YARA
(via `yara-x`), a sandboxed `.cbc` bytecode interpreter, and PE/ELF/Mach-O
parsing. Archive/container extraction lives in the companion
[`exav-unpack`](https://crates.io/crates/exav-unpack) crate.

The stable public surface is the crate root (`Database`, `ScanOptions`,
`Verdict`, `ScanReport`, and the `scan_*`/`analyze*` functions) plus the `db`,
`cache`, `source`, `profile`, `filetype`, and `unpack` modules. Archive formats,
`yara`, `http`, `checksums`, and `decrypt` are Cargo features.

```rust
use exav_core::{db, scan_path, ScanOptions, Verdict};

let database = db::load(std::path::Path::new("/var/lib/clamav"))?;
let report = scan_path(&database, std::path::Path::new("sample.bin"), &ScanOptions::default())?;
assert!(matches!(report.verdict, Verdict::Clean));
```

For the CLI and daemon, see [`exav-cli`](https://crates.io/crates/exav-cli).
Licensed under MIT.
