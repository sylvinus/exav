---
title: exav-pe-emu
description: A sandboxed x86-32 emulator that unpacks runtime-packed Windows executables by running their stub and capturing the image it rebuilds.
---

**An x86-32 emulator that unpacks packed executables by running them.** Not a
decoder per packer — a machine the packer's own stub runs on, so whatever it
compresses or encrypts with, the original image is captured at the moment the
stub jumps to it.

```rust
let file = std::fs::read("packed.exe")?;
let report = exav_pe_emu::unpack(&file, &exav_pe_emu::EmuLimits::default());
match report.unpacked {
    Some(u) => std::fs::write("unpacked.exe", &u.data)?,
    // Nothing is ever invented — this says why the stub was not followed.
    None => eprintln!("{}", report.stop),
}
```

## Why run the stub

A packed executable is not the program that runs. Writing a decoder per packer
is a race against people who change their format every build, and it only ever
covers packers someone has already reverse-engineered. But every packer, without
exception, has to rebuild the original program in memory and transfer control to
it — otherwise it would not run. That moment is packer-independent, and it is
what this captures.

Measured against 276 samples from 23 real packers: 218 (79%) give back a complete
image, and 15 packers do so on every sample they were given. Four more unpack
most of theirs. Three defeat it (and are reported as unpacked-nothing, never as
clean), and one is a .NET packer whose payload comes back as the managed assembly
it loads. Five are packers ClamAV ships a hand-written unpacker for; most of the
rest have no decoder anywhere. See
[PE stub emulation](/concepts/pe-emulation/) for the mechanism and the full
table.

## What is emulated

Enough Windows that a stub cannot tell, and nothing more:

* **Sparse 32-bit address space** — pages appear when touched, so a hostile
  `SizeOfImage` is not a memory bomb; unmapped access faults; every page
  remembers whether it was written and whether it has executed.
* **The instruction set stubs use** — integers, flags, shifts, string
  primitives, the x87 subset (including the `fnstenv` program-counter trick),
  MMX/SSE data movement and shuffles, BCD, `crc32`, and the **trap flag**, so a
  stub that single-steps itself through its own exception handler runs as it
  would on hardware.
* **The loader's work** — TEB/PEB, the three module lists, synthetic
  `kernel32`/`ntdll`/`user32` with walkable export directories, and import
  binding, because a stub calls `LoadLibraryA` through the slot the loader
  filled in.
* **Structured exception handling** with `CONTEXT` resume, on-demand stack
  growth, and a read-only view of *the file being emulated*, so a
  self-extracting stub can read its own overlay.

## What is not

* **No host access of any kind.** No syscalls, no filesystem, no network, no
  processes. The only file that resolves is the one passed in, read-only.
  Malware here is *interpreted*, never executed.
* **No virtualizing protectors** (VMProtect, Themida, Enigma): they translate
  the protected code to a private bytecode at build time, so no original code
  exists in memory at any point. Nothing to capture, and the emulator does not
  pretend otherwise.
* **No `unsafe`.** `#![forbid(unsafe_code)]` — every access is bounds-checked
  and every stop is a value, never a panic. Decoding is
  [`exav-x86`](/subprojects/exav-x86/), which is itself dependency-free and
  `#![forbid(unsafe_code)]`: no assembler, no code generation, and nothing in
  the emulator's dependency tree that is not memory-safe Rust.

## Bounds

Instruction budget, resident-page cap, dump-size cap, and a progress check that
ends a stub spinning in an anti-emulation delay loop. All configurable through
`EmuLimits`; the defaults are what the scanner uses.
