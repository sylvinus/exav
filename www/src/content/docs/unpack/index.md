---
title: Archive extraction
description: exav-unpack opens archives, disk images, documents and packed executables in safe Rust, under one budget, and reports what it could not read. As a command, a Rust crate, and a WebAssembly package for browsers and Node.
---

**Bounded, memory-safe, pure-Rust archive and container extraction.**
`exav-unpack` is the scanner's extraction layer, usable on its own: it has no
dependency on the scanning engine, and the crate is `#![forbid(unsafe_code)]`.

It comes three ways, built from the same code:

| | Install | For |
|---|---|---|
| [The `exav-unpack` command](/unpack/cli/) | `cargo install exav-unpack`, or the release downloads | Extracting, listing and testing archives from a shell, with `unzip`'s options |
| [The Rust crate](/unpack/rust/) | `cargo add exav-unpack` | A program that walks an archive's members in memory, one at a time, under limits it sets |
| [`@exav/unpack-wasm`](/unpack/wasm/) | `npm install @exav/unpack-wasm` | A web page that opens user-supplied archives without sending them to a server, or a Node program |

## What it opens

The target is what real extractors open (7-Zip, WinRAR, WinZip, The
Unarchiver, Windows Explorer, macOS Archive Utility, libarchive), because an
attacker picks the delivery format: ZIP with every method in common use, 7z,
RAR3 and RAR5, tar, gzip, bzip2, xz, zstd, lzip, LZ4, Unix `compress`, CAB,
ARJ, LHA, ZOO, ARC, ALZ, EGG, ISO 9660 and UDF, `ar`, cpio, xar, WIM, Apple
DMG, virtual disks (VHD, VHDX, QCOW2, VMDK) reconstructed to the guest disk,
with the NTFS, FAT and ext2/3/4 filesystems inside them walked for their
files, OLE2 and PDF documents, MIME email and TNEF, installers, UPX and other
packed executables, and more.

[Supported formats](/unpack/formats/) has the full matrix: the codecs,
the encryption schemes and the built-in passwords, what is read as it goes and
what is read whole, and the list of what is still missing. Every format is a
Cargo feature, so a build can carry only the ones it needs.

## The safety model

**One budget for the whole tree.** Every extraction runs under one `Budget`,
built from `Limits`: the total bytes decoded, the largest object held in memory
at once, the expansion ratio of a compressed stream, the number of members,
the nesting depth, the cumulative bytes scanned, the steps of the PE unpacking emulator,
and optionally which formats may be opened. It is reserved before a member is
decoded, not checked after, so a member that claims 1 GB from 4 KB is refused
before anything is allocated.

**A bomb stops the walk, and says so.** A compression ratio past the cap (1000
by default), too many members or too much output ends the walk with a
`LimitHit` that names the limit. Nothing is cut short quietly: the caller can
tell a walk that finished from one that was stopped.

**Partial results are reported as partial.** Content that is present but was
not decoded (an unsupported codec, an encrypted member with no working
password, damage part way) is still visited, as a member with `unsupported`
set and the reason, never dropped. It is the scanner's rule,
[never a silent clean](/scanner/concepts/design-principles/#never-a-silent-clean),
applied to extraction: a container whose contents could not be read is not an
empty container.

**Hostile input is the normal case.** The crate forbids `unsafe`, and a
decoder panic is caught per container walk and becomes an error for that
container instead of a crash. An allocation large enough to abort, stack
exhaustion and a loop that neither allocates nor returns are outside that
boundary: the scanner's daemon bounds them with process limits, and an
embedding has to do the same.
On wasm32 a panic aborts the module, so `@exav/unpack-wasm` discards the
instance instead (see [how a trap is contained](/unpack/wasm/#how-a-file-is-read)).
The library never writes to disk; the command writes only under its
extraction directory.

The defaults differ by where the code runs:

| Limit | Rust crate | Command | `@exav/unpack-wasm` |
|---|---|---|---|
| Total bytes decoded | 1 GiB | 64 GiB (`--max-size`) | 128 MiB |
| Largest object held in memory | 256 MiB | 1 GiB (`--max-memory`) | 32 MiB |
| Members | 100,000 | 1,000,000 (`--max-members`) | 100,000 |

The command writes what it decodes to disk rather than holding it, so its
totals can be far higher; the compression-ratio cap still stops a bomb long
before them. A browser tab gets far less than wasm32's 4 GiB address space, and
running out aborts the module, so the WebAssembly package starts lower.

[How it works](/unpack/how-it-works/) covers the shape of the unpacker,
containers with two indexes, salvage, encryption and how each decoder is
validated; [Interesting quirks](/scanner/concepts/quirks/), under Malware
scanning, has the stories behind several of those behaviours.

## Which one to use

- **From a shell or a script**, the [command](/unpack/cli/). Its options are
  `unzip`'s, it reads every format the library reads, finds the parts of a
  split archive, and restores times, permissions and symbolic links where the
  archive records them.
- **In a Rust program**, the [crate](/unpack/rust/). `walk` hands over each
  member as it is produced, so nothing accumulates, and a member the visitor
  does not read is not decoded. Turn default features off to build only the
  formats you open.
- **In a browser**, [`@exav/unpack-wasm`](/unpack/wasm/). A `File` is read
  a piece at a time in a Web Worker, never held whole. In Node, bytes in memory
  and a synchronous reader work in-process.

Built on the same crate: the [`exav` scanner](/scanner/getting-started/introduction/),
which scans every member it yields; [exav-grep](/subprojects/exav-grep/), grep
for the inside of archives; and the [file viewer](/viewer/), which opens
archives in place through `@exav/unpack-wasm`.
