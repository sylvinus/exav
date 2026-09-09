---
title: Subprojects
description: The tools and libraries built alongside the exav scanner — archive extraction, grep inside archives, the YARA engine, the updater, and the WASM builds — each usable on its own.
---

exav is a workspace of focused pieces rather than one binary. Several are useful
even if you never run a virus scan: the extractor opens more container formats
than most dedicated tools, the grep searches inside them, and the YARA engine
runs without a JIT.

Each is listed below with what it is and who it is for.
[Architecture](/concepts/architecture/) covers
[how they compose](/concepts/architecture/#how-the-crates-compose) and how a
scan flows through them.

## Standalone tools

| Subproject | What it is |
|---|---|
| [exav-unpack](/subprojects/exav-unpack/) | Bounded, memory-safe extraction for the full [supported-format list](/reference/formats/) — as a Rust library, a CLI, and a WASM module that runs in a browser |
| [exav-grep](/subprojects/exav-grep/) | grep for the *inside* of archives: search recursively through zip/rar/7z/tar/iso/OLE/PDF/email members |
| [exav-update](/subprojects/exav-update/) | Standalone signature-database fetcher, usable without the scanner |

## Libraries

| Subproject | What it is |
|---|---|
| [exav-core](/subprojects/exav-core/) | The scanning engine: database parsing, pattern/hash matching, file typing, and the verdict model |
| [exav-pe-emu](/subprojects/exav-pe-emu/) | A sandboxed x86-32 emulator that unpacks packed Windows executables by running their stub |
| [exav-x86](/subprojects/exav-x86/) | A decode-only x86-32 instruction decoder with no dependencies, checked against an independent decoder over 94 million real decode sites |

## Why they are separate

1. **Blast radius.** Extraction is the part that touches hostile bytes first and
   hardest. Keeping it in its own `#![forbid(unsafe_code)]` crate with its own
   budget and panic containment means a malformed archive cannot reach the
   engine, let alone the host.
2. **You can take one piece.** A build system that needs to look inside archives
   does not need a virus scanner, and a browser tool that unpacks uploads should
   not ship a signature database. Both are one crate, not a fork.
3. **Compile only what you use.** Every format is a
   [Cargo feature](/reference/feature-flags/), so a ZIP-only extractor is a real
   build target rather than a wish.
