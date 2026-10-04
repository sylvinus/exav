---
title: PE stub emulation
description: How exav unpacks runtime-packed Windows executables by running their stubs in a sandboxed x86 interpreter, instead of writing a decoder per packer.
---

Most Windows malware ships packed. A runtime packer replaces the program's code
with a compressed or encrypted blob plus a small **stub** that rebuilds it in
memory at start-up. On disk there is nothing for a signature to match: the
original code is there, but not in a form anything can read.

The usual answer is a decoder per packer. exav has those for the common cases
(UPX, and the aPLib family: Petite, FSG, NsPack), and they are the fast path. But
a decoder per packer cannot keep up: the packer's author picks the format, and
the packers that matter vary it per build to break tools that assume a layout.

So exav also does the general thing. Whatever a packer compresses with, its stub
must rebuild the original image in memory and jump to it. exav runs the stub and
takes the picture at the jump.

## What runs

A bounded x86-32 interpreter, in-process, with:

* **A sparse address space.** Pages exist once touched, so a hostile
  `SizeOfImage` of 4 GB is not a memory bomb, and the page count is capped like
  any other buffer the scanner holds.
* **Instruction decoding by [`exav-x86`](/subprojects/exav-x86/):** decode-only,
  with no assembler and no code generation; exav supplies the semantics.
  Instruction boundaries are where a decoder goes quietly wrong, so the decoder
  lives in a crate that is checked instruction by instruction against an
  independent decoder over the sample corpus.
* **The Windows a stub looks for.** A TEB and PEB, the loader's three module
  lists, and synthetic `kernel32`/`ntdll`/`user32`/`advapi32`/`msvcrt` images
  with real export
  directories. Both ways a stub resolves imports work: calling
  `GetProcAddress`, and walking `fs:[0x30]` → PEB → loader list → export table
  by hand. The loader's own import binding is emulated too, because a packed
  file's stub calls `LoadLibraryA` through an IAT slot the loader filled in.
* **Structured exception handling.** A fault is delivered to the stub's own SEH
  chain, and execution resumes from the `CONTEXT` the handler leaves. Raising an
  exception at yourself and continuing from the handler is standard
  anti-emulation; an emulator that stops at the fault stops where the packer
  wanted.
* **The trap flag.** A stub that sets `TF` through `popfd` expects a single-step
  exception after the next instruction and drives its decryption loop from the
  handler (TELock does this). Ignoring the flag leaves it spinning.
* **Its own file, read-only.** Installers and self-extractors keep the payload as
  an overlay past the last section and read it back with `CreateFile`/`ReadFile`
  on their own path. That path, and only that one, resolves, served from the
  bytes already in memory.
* **The loader's quirks.** `PointerToRawData` is rounded down to 512 bytes, as
  Windows does, because packers rely on it. Stack pages commit on demand, as the
  guard page does.

Nothing escapes: no syscalls, no file or network access, no host memory beyond
the page table. The malware is interpreted, never executed; an emulated
`CreateFile` returns a handle that does nothing.

## When to take the picture

The tell is packer-independent:

> execution arrives at an address inside the image, on a page the stub itself
> wrote and has never executed, or in a different section from the one the stub
> started in, and enough of that section has been rewritten to be a rebuilt
> program rather than a patched jump.

Each clause is needed. "Different section" alone fires on a stub calling a
helper; "written page" alone fires on scratch data. Without the bulk test, an
obfuscated program that writes a jump table into another section looks like an
unpack. Without the never-executed clause, packers that unfold the program over
the section their stub lives in (MEW, RLPack) are never seen.

If the stub wiped its own `MZ` header on the way out (an anti-dump move), the
headers are taken from the file, which still has them.

The result is written as a memory-layout PE (sections at their virtual addresses,
`PointerToRawData == VirtualAddress`, entry point where the stub transferred
control), which the scanner parses like any other file, so resources, overlays
and nested content in the recovered image are reached too.

## When the stub wins

Some stubs will not run to completion. The run stops on an instruction outside
the implemented set, an export with no implementation, a fault nothing handled,
or a budget; the [`exav-pe-emu`](/subprojects/exav-pe-emu/) triage tool names
which.

* **Nothing is fabricated.** A dump is emitted only when it reads back as a
  valid PE; a wrong guess is discarded rather than handed to the matcher.
* **An identified packer is not called clean.** If exav named the packer and
  still could not unfold it, the file is `UNSCANNABLE`: the packed bytes were
  scanned, the image the stub would unpack was not. A file sent to the emulator
  only because of its shape, with no packer identified, is scanned as it is;
  flagging every unusual executable would be noise. `--detect packed` turns an
  identified packer exav could not unpack into a `Heuristics.Packed.*`
  detection.
* **Running out of budget is a limit.** The emulator has an instruction budget
  of 120 million per stub and a 32 MiB dump cap, and
  `--max-pe-emulation-steps` (1,000,000,000 by default) bounds the total across
  every packed executable in one file. A scan that reaches the total is
  `LIMITS-EXCEEDED`. A stub stopped by its own budget alone is treated like any
  other stub that would not finish: `UNSCANNABLE` if its packer was identified.

A run that stopped part-way with a substantial part of the image rebuilt is
reported as a partial reconstruction: worth scanning, but not named as the
original program.

## What it will never unpack

Virtualizing protectors (VMProtect, Themida/WinLicense, Enigma) translate the
protected functions into a private bytecode when the file is built, so the
original instructions never exist in memory, and no emulator can recover them.
exav does not spend the budget trying: it reports them `UNSCANNABLE`, and with
`--detect packed` as `Heuristics.Packed.VMProtect` and the like.

## Measured coverage

Against 276 samples from 23 real packers, 12 each (ordinary Windows utilities,
packed; fetched by `scripts/fetch-packed-pe.py` and checked by the corpus test in
`exav-unpack`; the names are the corpus's):

| | Packers |
|---|---|
| **Unpacked**: every sample yields an image at least as large as the packed file | ASPack, BeRoEXEPacker, EXpressor, FSG, MEW, MPRESS, Molebox, NSPack, Neolite, PECompact, Packman, RLPack, UPX, WinUpack, Yoda-Crypter |
| **Unpacked, but not on every sample** | Exe32pack (11/12), PEtite (11/12), JDPack (10/12), Eronana Packer (6/12) |
| **Payload recovered, image incomplete** | Amber (a .NET packer: the native stub hands the assembly to the runtime, and that assembly comes back, on 11 of 12 samples) |
| **Nothing recovered**: the stub defended itself | Alienyze, TELock, Yoda-Protector |

Apart from Amber, recovery is all-or-nothing per sample: every sample that
recovered anything recovered an image at least as large as the input. Seven of
the fully unpacked packers have a hand-written unpacker in ClamAV (ASPack, FSG,
MEW, NSPack, UPX, WinUpack, Yoda-Crypter), plus PEtite among the partial ones;
most of the rest have no decoder anywhere.

The measure is the size of what came back, not whether the run reached the
original entry point. Several packers hand control to the unpacked program in a
way the heuristic cannot tell from an ordinary jump, and the run then ends a
little later at `ExitProcess` with the whole image rebuilt; stopping late and
dumping everything beats stopping at the first plausible jump.

## Cost

The emulator runs only on files whose shape says a packer built them: an entry
point outside a read-only first section, a section reserving far more memory
than it occupies on disk, an import table with a handful of entries, a
high-entropy section under a name no linker emits. Every run is bounded by the
instruction budgets above, a 64 MiB address space, a dump cap, and a progress
check that ends a stub spinning in an anti-emulation delay loop.
