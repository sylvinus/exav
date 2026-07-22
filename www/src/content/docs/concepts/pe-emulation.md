---
title: PE stub emulation
description: How exav unpacks runtime-packed Windows executables by running their stubs in a sandboxed x86 interpreter, instead of writing a decoder per packer.
---

Most Windows malware ships packed. A runtime packer replaces the program's code
with a compressed or encrypted blob plus a small **stub** that rebuilds it in
memory at start-up. On disk there is nothing for a signature to match: the
original code is there, but not in a form anything can read.

The usual answer is a decoder per packer. exav has those for the common cases —
UPX, the aPLib family, MPRESS — and they are the fast path, because a decoder
that knows the format costs one decompression. But writing one per packer is a
race the scanner cannot win: the packer's author picks the format and is free to
change it, and the packers that matter vary it per build specifically to break
tools that assume a layout.

So exav also does the general thing. Whatever a packer compresses with, its stub
**must** reconstruct the original image in memory and jump to it — that is what
running the program means. exav runs the stub and takes the picture at the jump.

## What runs

A bounded x86-32 interpreter, in-process, with:

* **A sparse address space.** Pages exist once they are touched, so a hostile
  `SizeOfImage` of 4 GB is not a memory bomb, and the page count is capped by
  the same per-member ceiling as any other buffer the scanner materialises.
* **Instruction decoding by [`exav-x86`](/subprojects/exav-x86/)** — decode-only,
  no assembler and no code generation. exav supplies the semantics. Getting
  instruction *boundaries* right is where a decoder goes quietly wrong, so it
  lives in a crate whose whole job is to be checked instruction by instruction
  against an independent decoder — currently agreeing on all 94,245,255 decode
  sites in the sample corpus.
* **Enough Windows to be believed.** A TEB and PEB, the loader's three module
  lists, and synthetic `kernel32`/`ntdll`/`user32` images with real export
  directories. Both ways a stub resolves imports work: calling
  `GetProcAddress`, and walking `fs:[0x30]` → PEB → loader list → export table
  by hand. The loader's own import binding is emulated too, because a packed
  file's stub calls `LoadLibraryA` through an IAT slot the loader filled in.
* **Structured exception handling.** A fault is delivered to the stub's own SEH
  chain and execution resumes from the `CONTEXT` the handler leaves behind —
  throwing an exception at yourself and continuing from the handler is standard
  anti-emulation, and an emulator that stops at the fault stops exactly where
  the packer wanted it to.
* **The trap flag.** A stub that sets `TF` through `popfd` expects a
  single-step exception after the next instruction and drives its whole
  decryption loop from the handler. Ignore the flag and it spins forever; TELock
  does exactly this.
* **Its own file, read-only.** Installers and self-extractors keep the payload
  as an *overlay* past the last section and go back to disk for it with
  `CreateFile`/`ReadFile` on their own path. That path — and only that path —
  resolves, served from the bytes already in memory.
* **The loader's quirks.** `PointerToRawData` is rounded down to 512 bytes, as
  Windows does, because packers point a section a little past its real start and
  rely on the rounding. Stack pages commit on demand, as the guard page does.

Nothing escapes. There are no syscalls, no file or network access, and no host
memory beyond the page table. Malware being unpacked here is *interpreted*,
never executed: an emulated `CreateFile` returns a handle that does nothing.

## When to take the picture

The tell is packer-independent:

> execution arrives at an address **inside the image**, on a page **the stub
> itself wrote** and has **never executed** — or in a **different section** from
> the one the stub started in — and enough of that section has been rewritten to
> be a rebuilt program rather than a patched jump.

Each clause earns its place. "Different section" alone fires on a stub calling a
helper. "Written page" alone fires on its scratch data. Without the bulk test,
an *obfuscated* program — not packed at all — that writes a jump table into
another section and transfers through it looks identical to an unpack. And
without the never-executed clause, the packers that unfold the original program
*over the same section their stub lives in* (MEW, RLPack) can never be seen at
all, because no section-level rule applies to them.

If the stub wiped its own `MZ` header on the way out — an anti-dump move — the
headers are taken from the file, which still has them and which parsed. A
reconstructed image is not thrown away over four bytes the packer erased.

What comes out is written as a **memory-layout PE**: sections at their virtual
addresses, `PointerToRawData == VirtualAddress`, entry point set to where the
stub transferred control. That is a valid PE the scanner re-parses like any
other file, so resources, overlays and nested content inside the recovered image
are reached too.

## When the stub wins

Stubs defend themselves, and some will not run to completion. The run stops and
**says why**: an instruction outside the implemented set (named), an export with
no implementation (named), a fault nothing handled, a budget. Two things follow
from that:

* **Nothing is fabricated.** A dump is emitted only when it reads back as a
  valid PE. A wrong guess fails that check and is discarded rather than handed
  to the matcher as data.
* **The file is not called clean.** A packed executable exav could not unfold is
  reported `UNSCANNABLE`, which is the
  [never-silent-clean invariant](/concepts/design-principles/#never-a-silent-clean)
  doing its job — the packed bytes were scanned, the image the stub would have
  unpacked was not, and the report says so.

A run that stopped part-way having rebuilt a substantial part of the image
reports that separately, as a *partial* reconstruction. Half a decompressed
image is worth scanning; it is not the same claim as "this is the original
program", and it is not named as though it were.

## What it will never unpack

Virtualizing protectors — VMProtect, Themida/WinLicense, Enigma. These translate
the protected functions into a private bytecode when the file is *built*, so
there is no moment at runtime when the original instructions exist in memory.
No emulator recovers them, however good, because there is nothing to recover.
exav does not spend the budget trying; it reports them, in wording that says
what is actually true about them.

## Measured coverage

Against 276 samples produced by 23 real packers, 12 samples each (ordinary
Windows utilities, packed — fetched by `scripts/fetch-packed-pe.py`):

| | Packers |
|---|---|
| **Unpacked** — *every* sample yields an image at least as large as the packed file | ASPack, BeRoEXEPacker, EXpressor, FSG, MEW, MPRESS, Molebox, NSPack, Neolite, PECompact, Packman, RLPack, UPX, WinUpack, Yoda-Crypter |
| **Unpacked, but not on every sample** | Exe32pack (11/12), PEtite (11/12), JDPack (10/12), Eronana Packer (6/12) |
| **Payload recovered, image incomplete** | Amber (a .NET packer: the native stub hands the assembly to the runtime, and it is that assembly which comes back — on 11 of 12 samples) |
| **Nothing recovered** — the stub defended itself successfully | Alienyze, TELock, Yoda-Protector |

That is **218 of 276 samples** (79%) giving back a complete image, and **15 of 23
packers** doing so on every sample they were given. Where a stub wins, it costs
exav a verdict rather than a detection: the file is reported `UNSCANNABLE`,
never clean.

No sample came back with a partial image. Recovery is all-or-nothing per sample:
the 218 that recovered anything all recovered an image at least as large as the
input. A packer at 10/12 is one where two particular samples failed outright,
not one that half-unpacks.

Those 15 include four that ClamAV ships a hand-written unpacker for (ASPack, MEW,
NSPack, Yoda's Cryptor); PEtite, a fifth, unpacks on 11 of 12. Most of the rest
have no decoder anywhere, which is the point of running the stub instead of
writing one.

Note what the measure is: **the size of what came back**, not whether the run
reached the original entry point. Only 152 of 276 do the latter, and it is the
weaker signal — several packers hand control to the unpacked program in a way
the heuristic cannot distinguish from an ordinary jump, and the run then ends a
little later at `ExitProcess` with the whole image rebuilt. An entry-point rule
that fires sooner fires more often and produces *smaller* dumps; stopping late
and dumping everything beats stopping at the first plausible-looking jump.

## Cost

The emulator runs only on files whose *shape* says a packer built them — an
entry point outside a read-only first section, a section reserving far more
memory than it occupies on disk, an import table with a handful of entries, a
high-entropy section under a name no linker emits. On a corpus of 654 Windows
executables that gate routed 9%. Every run is bounded by an instruction budget,
a 64 MiB address space, a dump cap, and a progress check that ends a stub
spinning in an anti-emulation delay loop rather than paying for it to finish.
Median 0.4 s per emulated file, 5 s at the 90th percentile.
