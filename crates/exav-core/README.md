# exav-core

The core scanning engine of [**exav**](https://github.com/sylvinus/exav), a
memory-safe ClamAV replacement written in Rust.

`exav-core` provides the library API for loading ClamAV signature databases and
scanning files or streams in constant memory: signature-database parsing
(`.ndb`/`.ldb`/`.hdb`/`.cvd`/…), pattern/hash/fuzzy matching, optional YARA
(via the native engine in `exav_core::yara`), a sandboxed `.cbc` bytecode interpreter, and PE/ELF/Mach-O
parsing. Archive/container extraction lives in the companion
[`exav-unpack`](https://crates.io/crates/exav-unpack) crate.

The stable public surface is the crate root (`Scanner`, `ScanOptions`,
`Verdict`, `ScanReport`, and the `scan_*`/`analyze*` functions) plus the
`loader`, `database`, `source`, `profile`, `filetype`, and `unpack` modules.
Archive formats, `yara`, `http`, `checksums`, and `decrypt` are Cargo features.

```rust
use exav_core::{loader, scan_path, ScanOptions, Verdict};

let scanner = loader::load(std::path::Path::new("/var/lib/exav"))?;
let report = scan_path(&scanner, std::path::Path::new("sample.bin"), &ScanOptions::default())?;
assert!(matches!(report.verdict, Verdict::Clean));
```

For the CLI and daemon, see [`exav`](https://crates.io/crates/exav).
Licensed under MIT.
