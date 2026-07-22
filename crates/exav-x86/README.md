# exav-x86

**A decode-only x86-32 instruction decoder with no dependencies.**

```rust
use exav_x86::{decode, Mn, Op};

// 8b 45 08  =>  mov eax, [ebp+8]
let insn = decode(&[0x8b, 0x45, 0x08], 0x401000).expect("decodes");
assert_eq!(insn.mn, Mn::Mov);
assert_eq!(insn.len, 3);
```

`#![forbid(unsafe_code)]`, no build script, no tables generated at build time,
and nothing in `[dependencies]`.

The SIMD and system regions of the opcode maps come from `src/generated.rs`,
which is checked in and produced by `scripts/gen-x86-tables.sh` — it reads each
cell off `iced-x86` (MIT; attributed in `NOTICE`) rather than transcribing a
manual, because a hand-copied table is wrong in ways review does not catch.

## What `None` means

`decode` returns `None` for two situations it cannot tell apart:

* the bytes are not a valid instruction, and
* the bytes are a valid instruction outside this decoder's scope.

A caller must therefore report `None` as **unsupported**, never as an illegal
instruction. Fabricating a CPU fault for code a real processor runs is how an
emulator gets fooled — a program that branches on its own exception handler will
take the wrong path, and the wrong path can look clean.

## Scope

32-bit protected mode, in full: the integer and control-flow set, port I/O, far
transfers and segment-register loads, both address sizes, the whole x87 escape
map (`D8`–`DF`, memory and register forms, including the undocumented aliases),
the system-instruction space, SSE/MMX with the `0F 38`/`0F 3A` escapes, 3DNow!,
VEX (`C4`/`C5`), EVEX (`62`) and AMD's XOP (`8F`). No REX, no RIP-relative
addressing, no 64-bit forms.

Operands are modelled for the general-purpose and x87 encodings. For the SIMD
maps the register *file* an operand names — MMX, XMM/YMM, mask — is not
modelled: a register number is reported as the encoding's own, and a vector
index register is not reported at all. Nothing in exav interprets those
operands; their identity and their length are what matter.

Coverage is measured, not asserted. The corpus sweep decodes every byte offset
of a set of real packed samples and compares each site where `iced-x86` decodes
something: it **asserts zero disagreements and zero declines**, and fails the
build otherwise, so a regression is a test failure rather than a number in a
README that nobody re-measures. Run it to see the counts for the corpus you
have. Every encoding exav's packer emulator actually executes is covered.

## Testing

A decoder cannot be checked against itself, so the tests are differential
against `iced-x86` (a dev-dependency — it reaches no shipped binary). They
compare instruction length and mnemonic, plus memory base/index/scale/
displacement, over:

* every one-byte and `0F` opcode paired with every ModRM byte,
* those sweeps repeated under each prefix and prefix pair that changes how an
  encoding is read (`66`, `67`, `F0`, `F2`, `F3`, segment overrides),
* pseudo-random and prefix-biased random bytes, from fixed seeds,
* truncation — no prefix of an instruction may decode,
* self-consistency — an instruction re-decoded from exactly its own reported
  length must give the same answer.

`fuzz/fuzz_targets/x86_decode.rs` asserts the same properties under
coverage-guided mutation, which reaches body shapes — a SIB byte that changes
whether a displacement is present, a prefix run that pushes past fifteen bytes —
that a fixed sweep does not.

```sh
cargo test -p exav-x86
cargo test -p exav-x86 --release -- --ignored   # + every byte of the sample corpus
```

Length is the property to watch: an instruction decoded one byte short or long
desynchronises every instruction after it, so a length error cascades rather
than staying local.

## License

MIT.
