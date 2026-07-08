# exav-unpack

**Bounded, memory-safe, pure-Rust archive & container extraction** — the
extraction layer of [**exav**](https://github.com/sylvinus/exav), usable on its
own.

The entire crate is `#![forbid(unsafe_code)]`. It extracts a wide range of
containers to memory under a shared [decompression-bomb `Budget`](https://docs.rs/exav-unpack)
(output-byte, ratio, file-count, recursion-depth, and cumulative-scan-byte
caps), with per-member panic containment so hostile input can never crash the
process — an unsupported codec or encrypted member is reported as unsupported,
never silently dropped.

**Formats:** zip, gzip, tar, xz, bzip2, zstd, lzip, cab, 7z, RAR (RAR3 LZ+PPMd,
RAR5 LZ), ARJ, LHA, ISO, ar, cpio, xar, OLE2, PDF, MIME email, Apple DMG
(UDIF + HFS+/APFS), and UPX.

Every format is a **Cargo feature**, so you can build only what you need
(`--no-default-features --features zip` for a ZIP-only extractor). Decryption
(`decrypt`, on by default) and checksum verification (`checksums`, off by
default) are also features.

```rust
use exav_unpack::{extract, detect, Budget, Limits};

let data = std::fs::read("archive.zip")?;
if let Some(fmt) = detect(&data) {
    let mut budget = Budget::new(Limits::default());
    for member in extract(fmt, &data, &mut budget)? {
        println!("{}: {} bytes", member.name, member.data.len());
    }
}
```

Licensed under MIT. See [`NOTICE`](https://github.com/sylvinus/exav/blob/main/NOTICE)
for third-party attributions.
