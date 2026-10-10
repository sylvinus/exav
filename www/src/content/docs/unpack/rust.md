---
title: The exav-unpack crate
description: Bounded, memory-safe archive and container extraction in pure Rust with no unsafe code, member by member, with every format a Cargo feature.
---

**Bounded, memory-safe, pure-Rust archive and container extraction.** The
scanner's extraction layer, usable on its own.

The crate is `#![forbid(unsafe_code)]`. It extracts under one budget for the
whole tree, with panic containment per container walk;
[the safety model](/unpack/#the-safety-model) has the bounds, their
defaults and what stays outside them.

```bash
cargo add exav-unpack
```

The same crate ships the [`exav-unpack` command](/unpack/cli/), and
compiles to WebAssembly as [`@exav/unpack-wasm`](/unpack/wasm/).

## What makes it different from a bag of format crates

**It is never silently incomplete.** Content that is present but not decoded (an
unsupported codec, an encrypted member, damage part way) is reported, either as
a member with `unsupported` set and a reason, or as a `LimitHit` for the whole
container (a read error, a budget), never dropped. A stream that simply ends
early is different: the missing tail is absent, not hidden. Skipping the
`unsupported` members silently reintroduces exactly the failure this exists
to prevent.

**It opens containers most extractors decline.** Virtual disks (VHD, VHDX, QCOW2,
VMDK) are reconstructed to the guest disk, and the filesystems inside them (NTFS
through an MFT walk, FAT through the cluster chain, ext2/3/4) are walked for files with
their paths; UDF, WIM and Unix `compress` are handled natively. See
[Supported formats](/unpack/formats/).

**It survives adversarial archives.** ZIP members hidden from the central
directory, entries named with a trailing slash so tools discard them as folders,
members flagged encrypted that are not, an Android manifest given a compression
method that does not exist (Android reads it as stored): each is handled
because a live sample used it. See
[How it works](/unpack/how-it-works/).

**Decoders are validated against external implementations**, never against
themselves: a subtly wrong decoder produces plausible bytes rather than errors.
See [Validating a decoder](/unpack/how-it-works/#validating-a-decoder).

## Library

One call, `walk`, visits each member as it is produced, so nothing accumulates.
It reads its source by offset through a `ByteSource`: a slice in memory, or a
`source::BlockCache` over any `Read + Seek`, which holds a bounded amount of it.

```rust
use exav_unpack::{detect, walk, Budget, Limits, Member};

let data = std::fs::read("archive.zip")?;
let fmt = detect(&data).expect("recognised container");
let mut budget = Budget::new(Limits::default());

walk::<()>(fmt, &data, &mut budget, &mut |meta, content, _| {
    if let Some(reason) = meta.unsupported {
        // Content that is present but could not be decoded: surface it.
        eprintln!("{}: {reason}", meta.name);
    }
    match content {
        // Decoded whole.
        Some(Member::Bytes(bytes)) => println!("{}: {} bytes", meta.name, bytes.len()),
        // Decoded as it is read: read it, or leave it and the walk moves on.
        Some(Member::Stream(reader)) => match std::io::copy(reader, &mut std::io::sink()) {
            Ok(n) => println!("{}: {n} bytes", meta.name),
            Err(e) => eprintln!("{}: {e}", meta.name),
        },
        None => {}
    }
    None // return Some(_) to stop early
})?;
```

`Member::into_bytes` reads either kind whole, under the budget a member held in
memory has. `extract` is the collecting variant, returning a `Vec<Entry>`.

A file too large to read into memory is walked through a block cache:

```rust
let src = exav_unpack::source::BlockCache::new(std::fs::File::open("big.zip")?)?;
let fmt = detect(&src).expect("recognised container");
walk::<()>(fmt, &src, &mut budget, &mut |meta, _, _| {
    println!("{}", meta.name);
    None
})?;
```

A member's metadata comes before its content, and a visitor that does not read
a streamed member does not decode it. A ZIP is listed from its central directory,
and a tar from its headers with the data between them skipped. `MemberMeta::size`
is the decoded size the archive declares, where it declares one: declared, not
measured.

A ZIP's walk runs past its central directory: members with a local header and
no directory entry are visited too, after the directory's own.

With the `dxf` feature, `exav_unpack::dxf` is the low layer of a DXF reader:
`Tags` reads ASCII and binary DXF's group code and value pairs, `Records`
groups them by group code 0, `Parts` splits a record into its subclasses,
application groups and extended data, and `Decoder` decodes strings in the
drawing's code page. It interprets nothing; exav-render's drawing model is
built on it. As a container, a DXF's members are the files it embeds, such as
an OLE2FRAME's object.

With the `dwg` feature, `exav_unpack::dwg` is the low layer of a DWG reader,
R13 to 2018, following the Open Design Specification for .dwg
files: `Bits` reads the bit codes, `Dwg` the sections (located by the file
header to R2000; from 2004 found by name in a paged container whose maps it
decrypts and whose pages it checks and decompresses, within a byte limit;
2007's container is Reed-Solomon coded, with a compression of its own):
the header variables, left to the reader, the classes and the object map.
`Dwg::object` reads any object the map holds, with its extended data, its
common entity data and the streams its own data, strings and handles are
read from. As a container, a DWG's members are its preview images and the
object each OLE2FRAME embeds (`ole2frame-<handle>.ole`, the compound file);
a drawing whose objects cannot be read is reported as not fully examined,
and so is a drawing of a release before R13 (`pre_r13_version`), as one
unsupported `dwg-<version ID>` entry.

## Features

Every format is a Cargo feature, so you build only what you use:

```toml
# a ZIP-only extractor
exav-unpack = { version = "0.0.2", default-features = false, features = ["zip"] }
```

The defaults are `all-formats`, `decrypt` and `cli`.

| Feature | What it does |
|---|---|
| `all-formats` | Every extractor below, the PE packer emulator (`pe-emu`) included |
| `all-formats-no-emu` | Every extractor except `pe-emu`, for a deployment that will not follow control flow a file supplies. Not forwarded to `exav-core` or `exav` |
| `decrypt` | Decryption; pass passwords with `Budget::with_passwords(limits, passwords)` (see [Encryption support](/unpack/formats/#encryption-support)). Without it, encrypted content is reported, not decrypted |
| `checksums` | Lets a caller make a checksum mismatch an error (`Budget::set_verify_checksums`); by default the bytes are handed over regardless |
| `cli` | The [`exav-unpack` command](/unpack/cli/) |

The per-format features, which `all-formats` turns on:

```text
zip · gzip · tar · bzip2 · xz · zstd · lzip · lzw · lz4 · cab · chm · sevenz
rar · arj · arc · ace · lha · iso · ole · pdf · email · dmg · vhd · diskimage
fat · ext · ntfs · wim · upx · inno · nsis · ar · cpio · xar · uuencode · xdp · szdd
tnef · swf · binhex · lnk · partition · pyc · autoit · onenote · rtf
machofat · sfx · stuffit · alz · egg · hwp3 · zoo · ishieldz · pepack
javaclass · aimodel · screnc · base64scan · dxf · dwg · pe-emu
```

A ZIP member compressed with bzip2, LZMA, zstd or XZ also needs that codec's
feature (`bzip2`, `lzip`, `zstd`, `xz`); PPMd needs only `zip`. `diskimage`
covers the virtual disks that need reconstruction (VHDX, QCOW2, VMDK); `vhd` is
separate because the older format needs no decompressor. `pepack` is static
unpacking; `pe-emu` runs the stub, so it is its own switch (and turns `pepack`
on). `ace`, `stuffit` and `inno` only recognise their format and report it.
[Supported formats](/unpack/formats/) says what each covers.

Every name is forwarded through `exav-core` to the `exav` scanner, so each can
also be named on a `cargo build -p exav` line (see
[Feature flags](/scanner/reference/feature-flags/#smaller-builds)).
