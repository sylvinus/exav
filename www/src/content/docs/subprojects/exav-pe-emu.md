---
title: exav-pe-emu
description: A sandboxed x86-32 emulator that unpacks runtime-packed Windows executables by running their stub and capturing the image it rebuilds.
---

**An x86-32 emulator that unpacks packed executables by running them.** It runs
the packer's own stub and captures the original image when the stub jumps to it,
whatever the packer compresses or encrypts with.

```bash
cargo add exav-pe-emu
```

```rust
let file = std::fs::read("packed.exe")?;
let report = exav_pe_emu::unpack(&file, &exav_pe_emu::EmuLimits::default());
match report.unpacked {
    // `u.data` is the rebuilt image in memory layout, for scanning rather than
    // running; `u.reached_oep` says whether the stub jumped to it.
    Some(u) => std::fs::write("unpacked.bin", &u.data)?,
    // Nothing is invented: this says why the stub was not followed.
    None => eprintln!("{}", report.stop),
}
```

## Why run the stub

A packed executable is not the program that runs. A decoder per packer is a race
against authors who change their format every build, and only covers packers
someone has already reverse-engineered. But every packer has to rebuild the
original program in memory and transfer control to it, or it would not run. That
moment is packer-independent, and it is what this captures. Coverage measured on
real packers is on the [PE stub emulation](/concepts/pe-emulation/#measured-coverage)
page.

## What is emulated

Enough Windows that a stub cannot tell, and nothing more:

* **A sparse 32-bit address space:** pages appear when touched, so a hostile
  `SizeOfImage` is not a memory bomb; unmapped access faults; every page
  remembers whether it was written and whether it has executed.
* **The instructions stubs use:** integers, flags, shifts, string primitives, the
  x87 subset (including the `fnstenv` program-counter trick), MMX/SSE data
  movement and shuffles, BCD, `crc32`, and the trap flag, so a stub that
  single-steps itself through its own exception handler runs as on hardware.
* **The loader's work:** TEB/PEB, the three module lists, synthetic
  `kernel32`/`ntdll`/`user32` with walkable export directories, and import
  binding, because a stub calls `LoadLibraryA` through the slot the loader filled
  in.
* **Structured exception handling** with `CONTEXT` resume, on-demand stack
  growth, and a read-only view of the file being emulated, so a self-extracting
  stub can read its own overlay.

## What is not

* **No host access.** No syscalls, filesystem, network or processes; the only
  file that resolves is the one passed in, read-only. Malware here is
  interpreted, never executed.
* **No virtualizing protectors** (VMProtect, Themida, Enigma): they translate the
  protected code to a private bytecode at build time, so no original code exists
  in memory to capture.
* **No `unsafe`.** `#![forbid(unsafe_code)]`: every access is bounds-checked and
  every stop is a value, never a panic. Decoding is
  [`exav-x86`](/subprojects/exav-x86/), itself dependency-free and
  `#![forbid(unsafe_code)]`.

## Bounds

An instruction budget, a resident-page cap, a dump-size cap, and a progress check
that ends a stub spinning in an anti-emulation delay loop, all set through
`EmuLimits`. The defaults (200 million instructions, 192 MiB of pages, a 64 MiB
dump) suit one sample on its own; the scanner uses tighter per-stub budgets
(120 million, 64 MiB, 32 MiB) and also caps the total across every packed
executable in one file (`--max-pe-emulation-steps`).
