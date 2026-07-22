# Known gaps

What exav does not do, recorded deliberately.

Every gap here is **reported, never a silent `Clean`**. A file exav cannot fully
process comes back `Unscannable`, `LimitsExceeded` or `PasswordProtected` — the
one failure mode that would matter is an unrecognised container scanning clean,
and that is what this list exists to prevent quietly happening.

## PE packers the emulator does not defeat

exav does not ship a hand-written unpacker per packer family. Anything whose
shape says a packer built it has its stub run under a bounded x86 interpreter,
and the image the stub rebuilds is captured. Coverage is therefore not a list of
families — but three packers in `corpus/packers` (23 packers, 276 samples)
defend themselves successfully, and nothing is recovered from them:

| Packer | What the stub does |
|---|---|
| **TELock** | Builds code on the stack and jumps to it. The stack-resident routine decodes to `EB FE` — a jump to itself — so an earlier instruction produced a wrong result. Needs a differential trace against a real x86 to find which. |
| **Yoda's Protector** | Spins without writing memory, and ends on the progress cutoff. The shape of an anti-emulation timing or exception construct. |
| **Alienyze** | Walks the loader module list, calls `MessageBoxW` with a module name as the caption, then dereferences null. It expects a module set the emulator does not present. |

Each is a separate investigation with no shared fix, which is why they are
recorded rather than scheduled.

Note the naming collision: **Yoda's *Cryptor* (`yC`) is a different product and
is unpacked** — it is in `MUST_UNPACK` in
`crates/exav-unpack/tests/suites/pe_emulation_corpus.rs`, so every one of its
samples must yield a complete image or the test fails. Yoda's *Protector* is the
one above. What exav does not implement is `BoundsCheck`, the heuristic ClamAV's
own yC unpacker emits.

To triage any of them:

```text
cargo run --release -p exav-unpack --example pepack_emu -- --trace FILE
```

which prints the API call log with string arguments, and the last 48
instructions before the stop.

## Virtualizing protectors

VMProtect, Themida/WinLicense and Enigma translate the protected functions into
a private bytecode when the file is *built*. There is no moment at runtime when
the original instructions exist in memory, so no emulator recovers them — there
is nothing to recover. exav does not spend the budget trying, and reports them
in wording that says what is true about them.

## Family-specific ClamAV heuristics

See [the ClamAV comparison](../www/src/content/docs/project/comparison-with-clamav.md)
for the list and the reasoning: they are per-family detection content expressed
as engine code rather than as signatures, so reproducing them means reproducing
logic that exists only in GPL source — which exav's clean-room rule forbids.
