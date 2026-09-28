---
title: Subprojects
description: The tools and libraries built alongside the exav scanner, from archive extraction and grep inside archives to the YARA engine, the updater and the WASM builds, each usable on its own.
---

exav is a workspace of focused pieces rather than one binary. Several are useful
without ever running a virus scan: the extractor opens more container formats
than most dedicated tools, the grep searches inside them, and the YARA engine
runs without a JIT.

[Architecture](/concepts/architecture/) covers
[how they compose](/concepts/architecture/#how-the-crates-compose) and how a scan
flows through them.

## Standalone tools

| Subproject | What it is |
|---|---|
| [exav-unpack](/subprojects/exav-unpack/) | Bounded, memory-safe extraction for the full [supported-format list](/reference/formats/), as a Rust library, a CLI, and a WASM module that runs in a browser |
| [exav-grep](/subprojects/exav-grep/) | grep for the inside of archives: search recursively through zip/rar/7z/tar/iso/OLE/PDF/email members |
| [exav-update](/subprojects/exav-update/) | A signature-database fetcher usable without the scanner |

## Libraries

| Subproject | What it is |
|---|---|
| [exav-core](/subprojects/exav-core/) | The scanning engine: database parsing, pattern and hash matching, file typing, and the verdict model |
| [exav-pe-emu](/subprojects/exav-pe-emu/) | A sandboxed x86-32 emulator that unpacks packed Windows executables by running their stub |
| [exav-x86](/subprojects/exav-x86/) | A decode-only x86-32 instruction decoder with no dependencies, checked against an independent decoder over real samples |

## Why they are separate

1. **Blast radius.** Extraction touches hostile bytes first and hardest, so it
   lives in its own `#![forbid(unsafe_code)]` crate with its own budget and panic
   containment.
2. **One piece can be used alone.** A build system that needs to look inside
   archives does not need a virus scanner, and a browser tool that unpacks
   uploads should not ship a signature database.
3. **Compile only what you use.** Every format is a
   [Cargo feature](/reference/feature-flags/), so a ZIP-only extractor is a real
   build target.
