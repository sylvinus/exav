# exav-unpack

**Bounded, memory-safe, pure-Rust archive & container extraction**: the
extraction layer of [**exav**](https://github.com/sylvinus/exav), usable on its
own.

The entire crate is `#![forbid(unsafe_code)]`. It extracts a wide range of
containers to memory under a shared [decompression-bomb `Budget`](https://docs.rs/exav-unpack)
(output-byte, ratio, file-count, recursion-depth, and cumulative-scan-byte
caps), with panic containment per container walk, so a decoder panic becomes an
error for that container instead of a crash. An unsupported codec or encrypted
member is reported as unsupported, never silently dropped.

**Formats:** ZIP (every method in common use, including Deflate64, LZMA, bzip2,
zstd, XZ, PPMd and the PKZIP 1.x ones), gzip, tar, xz, bzip2, zstd, lzip, LZ4,
Unix `compress`, CAB, 7z, RAR (RAR3 LZ+PPMd, RAR5 LZ), ARJ, LHA, ZOO, ARC, EGG,
ALZ, ISO 9660 and UDF, ar, cpio, xar, WIM, OLE2, PDF, MIME email and TNEF, Apple
DMG (UDIF + HFS+/APFS), virtual disks (VHD, VHDX, QCOW2, VMDK) with the NTFS and
FAT filesystems inside them, UPX and other PE packers, and more. The full list
is at [exav.org](https://exav.org/reference/formats/).

Every format is a **Cargo feature**, so you can build only what you need
(`--no-default-features --features zip` for a ZIP-only extractor). Decryption
(`decrypt`, on by default) and making a checksum mismatch an error
(`checksums`, off by default) are also features.

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

`extract` holds every member; `walk` hands them over one at a time, a large one
as a reader, and reads its source through a `ByteSource` (a slice, or a
`source::BlockCache` over a file).

Licensed under MIT. Full documentation:
[exav.org](https://exav.org/subprojects/exav-unpack/). See [`NOTICE`](https://github.com/sylvinus/exav/blob/main/NOTICE)
for third-party attributions.
