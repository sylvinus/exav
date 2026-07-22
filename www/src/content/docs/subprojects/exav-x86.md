---
title: exav-x86
description: A decode-only x86-32 instruction decoder with no dependencies, checked against an independent decoder over 94 million real decode sites.
---

**A decode-only x86-32 instruction decoder, with nothing in `[dependencies]`.**
It turns bytes into instruction descriptions and declines anything it does not
claim. It does not assemble, does not generate code, and nothing it produces is
executed.

```rust
use exav_x86::{decode, Mn};

// 8b 45 08  =>  mov eax, [ebp+8]
let insn = decode(&[0x8b, 0x45, 0x08], 0x401000).expect("decodes");
assert_eq!(insn.mn, Mn::Mov);
assert_eq!(insn.len, 3);
```

`#![forbid(unsafe_code)]`, no build script, no code generated at build time.

## What `None` means

`decode` returns `None` for two situations it cannot tell apart:

* the bytes are not a valid instruction, and
* the bytes are a valid instruction outside this decoder's scope.

A caller must therefore report `None` as **unsupported**, never as an illegal
instruction. That distinction is not pedantry. Fabricating a CPU fault for code
a real processor runs is how an emulator gets fooled: a packer stub that
branches on its own exception handler takes the wrong path, and the wrong path
can produce a dump that looks clean.

## Why it exists

exav reaches x86 in two places — the packer emulator's fetch step, and the
bytecode `disasm_x86` host API, which is fed arbitrary bytes from a scanned
file. General-purpose decoders cover the whole instruction set and carry
hundreds of `unsafe` blocks to do it quickly: handler-table dispatch through raw
pointers, and integer-to-enum transmutes on table indices. None of that is
wrong, but it is the largest `unsafe` surface a scanner would link, sitting
directly on hostile input.

This crate is the trade taken the other way: safe Rust, no dependencies, and the
speed that costs.

## Scope

32-bit protected mode, in full — the integer and control-flow set, port I/O, far
transfers and segment-register loads, both address sizes, the whole x87 escape
map (`D8`–`DF`, memory and register forms, including the undocumented aliases),
the system-instruction space, SSE/MMX with the `0F 38`/`0F 3A` escapes, 3DNow!,
VEX (`C4`/`C5`), EVEX (`62`) and AMD's XOP (`8F`). No REX, no RIP-relative
addressing, no 64-bit forms.

Operands are modelled for the general-purpose and x87 encodings, and for the
SIMD maps each operand carries the register file it names (`Op::Xmm`, `Op::Mmx`,
general-purpose registers at their real width) and each memory operand its true
access width. Where a register file is not modelled at all — a vector index
register in a gather, for instance — no operand is reported, rather than one
that names the wrong file.

## How it is checked

A decoder cannot be checked against itself, and reading its tables proves
nothing: a wrong immediate width or a missed prefix rule looks exactly like a
right one on the page. So the tests are differential against `iced-x86`, which
is a dev-dependency and reaches no shipped binary. They compare instruction
length, mnemonic, memory base/index/scale/displacement, and every register
operand, over:

* every one-byte and `0F` opcode paired with every ModRM byte,
* those sweeps repeated under each prefix and prefix pair that changes how an
  encoding is read,
* pseudo-random and prefix-biased random bytes, from fixed seeds,
* truncation — no proper prefix of an instruction may decode,
* self-consistency — an instruction re-decoded from exactly its own reported
  length must give the same answer,
* and, behind `--ignored`, **every byte offset of 276 real packed samples**.

That last sweep is the gate: **94,245,255 sites where an independent decoder
decodes something, and agreement on every one** — no disagreements, and nothing
declined. The test asserts both, so a regression is a failure rather than a
number in a report.

Length is the property to watch. An instruction decoded one byte short or long
desynchronises every instruction after it, so a length error is not a local
mistake but a cascading one.

## The tables are generated, not transcribed

The SIMD, system and vector-prefix regions come from a checked-in
`src/generated.rs`, produced by `scripts/gen-x86-tables.sh`. It probes
`iced-x86` for every (prefix, opcode, `/digit`, `mod`) combination and records
what came back, because a hand-copied opcode table is wrong in ways review does
not catch.

Each cell holds only what a decoder cannot infer from the bytes: which
instruction an encoding names, how many immediate bytes follow, which register
file each operand belongs to, how wide a memory operand is, and — for EVEX — the
factor its compressed 8-bit displacement is scaled by. Never a displacement, so
a change to the addressing rules cannot be contradicted by a stale table.

`iced-x86` is MIT-licensed and the attribution is recorded in the project's
`NOTICE`.
