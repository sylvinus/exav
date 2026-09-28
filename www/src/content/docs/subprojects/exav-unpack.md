---
title: exav-unpack
description: Bounded, memory-safe archive and container extraction in pure Rust with no unsafe code, as a library, a CLI, or a WASM module.
---

**Bounded, memory-safe, pure-Rust archive and container extraction.** The
scanner's extraction layer, usable on its own.

The crate is `#![forbid(unsafe_code)]`. It extracts to memory under a shared
decompression-bomb budget (output bytes, expansion ratio, file count, recursion
depth, cumulative scanned bytes, emulation steps) with per-member panic
containment, so hostile input cannot crash the process.

```bash
cargo add exav-unpack
```

## What makes it different from a bag of format crates

**It is never silently incomplete.** An unsupported codec, an encrypted member, a
truncated stream or a read error is reported as an explicit `unsupported` entry
with a reason, never dropped. It is the scanner's rule
([never a silent clean](/concepts/design-principles/#never-a-silent-clean)), and
it is why extraction can be trusted as a coverage claim.

**It opens containers most extractors decline.** Virtual disks (VHD, VHDX, QCOW2,
VMDK) are reconstructed to the guest disk, and the filesystems inside them (NTFS
through an MFT walk, FAT through the cluster chain) are walked for files with
their paths; UDF, WIM and Unix `compress` are handled natively. See
[Supported formats](/reference/formats/).

**It survives adversarial archives.** ZIP members hidden from the central
directory, entries named with a trailing slash so tools discard them as folders,
members flagged encrypted that are not: each is handled because a live sample
used it. See [Archive extraction](/concepts/archive-extraction/).

**Decoders are validated against external implementations**, never against
themselves, and integrity-checked where the format carries a checksum (RAR
CRC-32, WIM SHA-1, UPX Adler-32). A subtly wrong decoder produces plausible bytes
rather than errors, so a checksum is the honest test.

## Library

The core call visits each member as it is produced, so nothing accumulates:

```rust
use exav_unpack::{extract_each, detect, Budget, Entry, Limits};

let data = std::fs::read("archive.zip")?;
let fmt = detect(&data).expect("recognised container");
let mut budget = Budget::new(Limits::default());

extract_each::<()>(fmt, &data, &mut budget, &mut |e: Entry, _b| {
    match e.unsupported {
        // Content that is present but could not be decoded: surface it.
        Some(reason) => eprintln!("{}: {reason}", e.name),
        None => println!("{}: {} bytes", e.name, e.data.len()),
    }
    None // return Some(_) to stop early
})?;
```

`extract` is the collecting variant, returning a `Vec<Entry>`, and
`stream_members` walks a seekable source without buffering the whole container.

`Archive<R>` is the random-access interface over a `Read + Seek` source: `open`
parses whatever index the format carries, `list()` reports it as
`&[MemberInfo]`, and `extract` takes one member by index without touching the
others.

**An empty `list()` means "this format has no directory", not "this archive has
no members".** ZIP and tar carry an index (a central directory, a block of
headers), so their members are known at `open` with nothing decompressed. Every
other format returns an empty slice: a gzip's single member has no name or size
until it is decompressed, and the other formats are read in full through this
API. Walk the archive when `list()` is empty rather than reporting nothing.

A ZIP's listing runs past its central directory: members with a local header and
no directory entry are listed too, at indices straight after the directory's own,
and `extract` takes those indices, so a listing and an extraction agree.

## CLI

The crate ships a standalone `exav-unpack` binary, a general extractor with the
same budgets (`cargo install exav-unpack`):

```bash
exav-unpack list archive.7z            # what's inside
exav-unpack extract archive.7z out/    # to disk
```

## In the browser

`exav-unpack-wasm` compiles the same code to WebAssembly, published on npm as
`@exav/unpack-wasm` with typed JavaScript bindings, so a web app can open
user-supplied archives in the browser without sending bytes to a server. The
sandbox is the browser's, and the crate has no `unsafe` of its own.

```js
import init, { Archive } from "@exav/unpack-wasm";

const archive = await Archive.open(file);   // a File from a drop or <input>
for (const m of await archive.list()) {
  const entry = await archive.extract(m.index);
  console.log(entry.name, entry.bytes.length);
}
await archive.close();
```

### How a `File` is read

The archive readers are synchronous (`Read + Seek`), the same code the CLI runs.
Reading a `Blob` synchronously needs `FileReaderSync`, which browsers provide
only in a Web Worker, so a `File`/`Blob` is opened there: the package spawns the
Worker itself (or takes one through `options.worker`, for bundlers that cannot
resolve `new URL("./worker.js", import.meta.url)`), the API stays a normal
`await`, and the file is read a piece at a time, never held whole.

Bytes already in memory need no Worker: a `Uint8Array`/`ArrayBuffer` runs
in-process, as does a caller-supplied `{ read(offset, length): Uint8Array, size }`
reader, whose `read` is synchronous because the readers beneath it are.

A decoder trap costs the archive, not the page. wasm32 is a `panic = "abort"`
target, so a panic traps the module instance for good. The instance is
discarded: in the Worker, pending requests are rejected with the reason and the
Worker is replaced; in-process, the instance is rebuilt on the next call.

### API

| Call | Does |
|---|---|
| `Archive.open(source, limits?, options?)` | Open a `File`/`Blob` (in the Worker), or a `Uint8Array`/`ArrayBuffer`/sync reader (in-process). |
| `archive.format()` | The detected format's name, known since `open`. |
| `archive.list(passwords?)` | Every member's metadata. Where the archive carries an index (a ZIP's central directory, a tar's headers) nothing is decompressed; an index-less single stream (gzip, xz) is walked once and the walk kept, so `list` plus `extractAll` is one walk. |
| `archive.extract(index, passwords?)` | One member, as an `Entry`. |
| `archive.extractAll(passwords?)` | Every member, under one budget for the whole archive. Where a limit stops the walk, the last entry says so. |
| `archive.close()` | Release the archive and its reader. Safe to call twice. |
| `unpack(bytes, passwords?, limits?)` | `open` + `extractAll` in one call, for bytes in memory. |
| `detectFormat(bytes)` | The format these magic bytes name, or `undefined`. |
| `isVolumePart(name)` | Whether a filename marks one part of a byte-split archive (`big.7z.001`). |
| `joinVolumes(files)` | Rejoin the split archives among files dropped together, into data `Archive.open` can take. |

An `Entry` is `{ name, bytes: Uint8Array, data: ReadableStream, encrypted,
unsupported }`. `unsupported` is empty when the member decoded, and otherwise says
why not (unsupported compression, a missing password, a limit), with the member
still reported. Member names come back verbatim; sanitize paths before writing
them anywhere.

The `Limits` object is `{ maxExtractedBytes, maxBufferBytes, maxMembers,
maxRecursion, maxCompressionRatio, allowedFormats }`; absent keys keep the browser
defaults, which set the byte budgets below the Rust library's (128 MiB total,
32 MiB per member), since wasm32 caps the address space at 4 GiB, a tab often
gets far less, and outgrowing it aborts the module. `allowedFormats` narrows what
one call may open; an excluded format is reported as `unsupported`.

## Features

Every format is a Cargo feature, so you build only what you use:

```toml
# a ZIP-only extractor
exav-unpack = { version = "*", default-features = false, features = ["zip"] }
```

`decrypt` (on by default) enables password handling; `checksums` enables
integrity verification. See [Feature flags](/reference/feature-flags/).
