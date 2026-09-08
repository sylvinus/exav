---
title: exav-unpack
description: Bounded, memory-safe archive and container extraction in pure Rust — no unsafe code, as a library, a CLI, or a WASM module.
---

**Bounded, memory-safe, pure-Rust archive and container extraction.** The
extraction layer of the scanner, usable entirely on its own.

The crate is `#![forbid(unsafe_code)]`. It extracts to memory under a shared
decompression-bomb budget — output bytes, expansion ratio, file count, recursion
depth, and cumulative scanned bytes — with per-member panic containment, so
hostile input cannot crash the process.

```bash
cargo add exav-unpack
```

## What makes it different from a bag of format crates

**It refuses to be silently incomplete.** An unsupported codec, an encrypted
member, a truncated stream — each is reported as an explicit `unsupported`
entry with a reason, never dropped. That is the same invariant the scanner is
built on ([never a silent clean](/concepts/design-principles/#never-a-silent-clean)),
and it is why extraction can be trusted as a *coverage* claim and not just a
convenience.

**It opens containers most extractors decline.** Virtual disks (VHD, VHDX,
QCOW2, VMDK) are reconstructed to the guest disk; filesystems inside them (NTFS
via an MFT walk, FAT via the cluster chain) are walked for files with their
paths; UDF, WIM, and Unix `compress` are handled natively. See
[Supported formats](/reference/formats/) for the full list.

**It survives adversarial archives.** ZIP members hidden from the central
directory, entries named with a trailing slash so tools discard them as folders,
members flagged encrypted that are not — all handled, each because a live sample
exploited it. See [Archive extraction](/concepts/archive-extraction/).

**Decoders are validated against external implementations**, never against
themselves, and integrity-checked where the format provides a checksum: RAR
CRC-32, WIM SHA-1, UPX Adler-32. A decoder that is subtly wrong produces
plausible bytes rather than errors, so a checksum is the only honest test.

## Library

The core call visits each member as it is produced, so nothing accumulates:

```rust
use exav_unpack::{extract_each, detect, Budget, Entry, Limits};

let data = std::fs::read("archive.zip")?;
let fmt = detect(&data).expect("recognised container");
let mut budget = Budget::new(Limits::default());

extract_each::<()>(fmt, &data, &mut budget, &mut |e: Entry, _b| {
    match e.unsupported {
        // Content that is present but could not be decoded — surface it.
        Some(reason) => eprintln!("{}: {reason}", e.name),
        None => println!("{}: {} bytes", e.name, e.data.len()),
    }
    None // return Some(_) to stop early
})?;
```

`extract` is the collecting variant when you want a `Vec<Entry>`, and
`stream_members` walks a seekable source without buffering the whole container.

`Archive<R>` is the random-access door over a `Read + Seek` source: `open` parses
whatever index the format carries, `list()` reports it as `&[MemberInfo]`, and
`extract` takes one member by index without touching the others.

**An empty `list()` means "this format has no directory", not "this archive has
no members."** ZIP and tar carry an index — a central directory, a block of
headers — so their members' names, sizes and offsets are known at `open` with
nothing decompressed. Every other format returns an empty slice: a gzip's single
member has no name or size until it is decompressed, and the buffered formats
(7z, RAR, CAB, ISO, OLE and the rest) are read through a different door. A caller
that reads the empty slice as an empty archive gets the wrong answer, so walk the
archive when `list()` is empty rather than reporting nothing.

A ZIP's listing runs past its central directory. Members that have a local header
and no directory entry are reported too, at indices straight after the
directory's own, and `extract` takes those same indices — so a listing and an
extraction agree about what the archive holds. See
[Archive extraction](/concepts/archive-extraction/).

## CLI

The crate ships a standalone `exav-unpack` binary alongside the library — a
universal extractor with the same budgets, and `cargo install exav-unpack` puts
it on your path:

```bash
exav-unpack list archive.7z            # what's inside
exav-unpack extract archive.7z out/    # to disk
```

## In the browser

`exav-unpack-wasm` compiles the same code to WebAssembly, published on npm with
typed JavaScript bindings, so a web app can open user-supplied archives
client-side without shipping bytes to a server — the sandbox is the browser's,
and the crate has no `unsafe` of its own.

```js
import init, { Archive } from "exav-unpack-wasm";

const archive = await Archive.open(file);   // a File from a drop or <input>
for (const m of await archive.list()) {
  const entry = await archive.extract(m.index);
  console.log(entry.name, entry.bytes.length);
}
await archive.close();
```

### How a `File` is read

exav's archive readers are synchronous (`Read + Seek`) — the same code the CLI
runs, not a second implementation written against async I/O. Reading a `Blob`
synchronously needs `FileReaderSync`, which browsers provide only inside a Web
Worker, so that is where a `File`/`Blob` is opened: the package spawns the
Worker itself (or takes one via `options.worker`, for bundlers that cannot
resolve `new URL("./worker.js", import.meta.url)`), the API stays a normal
`await`, and the file is read a piece at a time — never held in memory whole.

Bytes already in memory take no Worker: a `Uint8Array`/`ArrayBuffer` runs
in-process, as does a caller-supplied
`{ read(offset, length): Uint8Array, size }` reader — whose `read` is
**synchronous**, returning bytes rather than a Promise, because the archive
readers beneath it are.

A decoder trap costs the archive, not the page. wasm32 is a `panic = "abort"`
target, so the `catch_unwind` that turns a decoder panic into a returned limit
elsewhere in exav catches nothing there — a panic traps the module instance for
good. The poisoned instance is discarded: in the Worker, every pending request
is rejected with the reason and the Worker is replaced; in-process, the
instance is dropped and rebuilt on the next call.

### API

| Call | Does |
|---|---|
| `Archive.open(source, limits?, options?)` | Open a `File`/`Blob` (in the Worker), or a `Uint8Array`/`ArrayBuffer`/sync reader (in-process). |
| `archive.format()` | The detected format's name, known since `open`. |
| `archive.list(passwords?)` | Every member's metadata. Where the archive carries an index (a ZIP's central directory, a tar's headers) this decompresses nothing; an index-less single stream (gzip, xz) is walked once and the walk is kept, so `list` plus `extractAll` is not two walks. |
| `archive.extract(index, passwords?)` | One member, as an `Entry`. |
| `archive.extractAll(passwords?)` | Every member, under one budget for the whole archive. Where a limit stops the walk, the last entry says so rather than the list simply ending. |
| `archive.close()` | Release the archive and the reader behind it. Safe to call twice. |
| `unpack(bytes, passwords?, limits?)` | The one-line `open` + `extractAll` for bytes already in memory. |
| `detectFormat(bytes)` | The format these magic bytes name, or `undefined`. |
| `isVolumePart(name)` | Whether a filename marks one part of a byte-split archive (`big.7z.001`). |
| `joinVolumes(files)` | Rejoin the split archives among files dropped together, into data `Archive.open` can take. |

An `Entry` is `{ name, bytes: Uint8Array, data: ReadableStream, encrypted,
unsupported }`. `unsupported` is empty when the member decoded, and otherwise
says why it did not — unsupported compression, a missing password, a limit
reached — with the member still reported rather than dropped, the same
[never-silently-incomplete](/concepts/design-principles/#never-a-silent-clean)
contract as the Rust API. Member names come back verbatim; sanitize paths
before writing them anywhere.

The `Limits` object is `{ maxExtractedBytes, maxBufferBytes, maxMembers,
maxRecursion, maxCompressionRatio, allowedFormats }`; absent keys keep the
browser defaults, which set
the byte budgets below the Rust library's (128 MiB total, 32 MiB per member) —
wasm32 caps the address space at 4 GiB, a tab commonly gets far less, and
outgrowing it aborts the module rather than returning an error.
`allowedFormats` narrows what one call may open, per call rather than per
build; an excluded format is reported as `unsupported`, never silently
skipped.

## Features

Every format is a Cargo feature, so you build only what you use:

```toml
# a ZIP-only extractor
exav-unpack = { version = "*", default-features = false, features = ["zip"] }
```

`decrypt` (on by default) enables password handling; `checksums` enables
integrity verification. See [Feature flags](/reference/feature-flags/).
