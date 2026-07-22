# exav-pe-emu

A sandboxed, bounded **x86-32 emulator for PE runtime-packer stubs**. It runs
the stub of a packed Windows executable and captures the image the stub rebuilds
in memory — the general answer to unpacking, as opposed to a decoder written per
packer, per version.

Part of [exav](https://github.com/sylvinus/exav), used by `exav-unpack`, and
usable on its own.

```rust
let file = std::fs::read("packed.exe")?;
let report = exav_pe_emu::unpack(&file, &exav_pe_emu::EmuLimits::default());
if let Some(u) = report.unpacked {
    // `u.data` is the reconstructed PE, in memory layout.
    // `u.reached_oep` says whether the stub actually transferred control to it.
    std::fs::write("unpacked.exe", &u.data)?;
} else {
    // Nothing is ever invented: this says why the stub was not followed.
    eprintln!("{}", report.stop);
}
```

## What it does

Whatever a packer compresses or encrypts with, its stub must reconstruct the
original program in memory and jump to it. This emulator follows that:

* **Sparse 32-bit address space** — pages exist once touched, so a hostile
  `SizeOfImage` is not a memory bomb. Unmapped access faults; every page
  remembers whether it was written and whether it has executed.
* **An x86-32 interpreter** — integer, flags, shifts, string primitives (`rep`
  charged per iteration), the x87 subset stubs use (including the `fnstenv`
  program-counter trick), MMX/SSE data movement and shuffles, BCD, `crc32`, and
  the trap flag, so a stub that single-steps itself through its own handler runs
  as it would on hardware. Decoding is [`exav-x86`](../exav-x86),
  **decode-only**: no assembler, no code generation, nothing is ever executed
  natively.
* **Enough Windows to be believed** — TEB/PEB, the loader's three module lists,
  synthetic `kernel32`/`ntdll`/`user32` with walkable export directories,
  loader-side import binding, ~200 implemented exports, structured exception
  handling with `CONTEXT` resume, on-demand stack growth, and a read-only view
  of *the file being emulated* so a self-extracting stub can read its own
  overlay.
* **Bounds on everything** — instruction budget, resident-page cap, dump size,
  and a progress check that ends a stub spinning in an anti-emulation loop.

## What it does not do

* **No host access of any kind.** No syscalls, no filesystem, no network, no
  process or thread creation. The only file that resolves is the one you passed
  in, read-only. Malware here is *interpreted*, never executed.
* **No virtualizing protectors.** VMProtect, Themida and Enigma translate the
  protected code to a private bytecode at build time; there is no original code
  in memory at any point, so there is nothing for an emulator to capture.
* **No `unsafe`.** `#![forbid(unsafe_code)]`: every access is bounds-checked and
  every stop is a value, not a panic.

## Licence

MIT.
