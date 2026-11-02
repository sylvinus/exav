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
still defend themselves on most samples, and little or nothing is recovered from
them:

| Packer | What the stub does |
|---|---|
| **Yoda's Protector** | An `int3` + SEH + `call`/`ret` maze that never writes past a few stack pages. Verified instruction-for-instruction against a reference x86 (unicorn): the emulation is faithful, and even billions of instructions make no progress, so the maze's exit depends on exception-dispatch or timing state the synthetic environment does not reproduce. Nothing to fix in the interpreter. |
| **TELock** (11 of 12 samples) | After the rotate-flag fix below, TELock runs its whole loader and then CRC32s the image it rebuilt (`esi` over the unpacked `.text` at the image base, CRC poly `edb88320`) and `jne`-aborts to `MessageBox` + `ExitProcess` when the sum does not match the value it stored at pack time. The sum mismatches because a value this environment feeds the decryptor differs from a real machine's, so the decompressed bytes differ. The check reads the **image**, not `kernel32`/`user32` code, so presenting realistic system-DLL bytes does not satisfy it (and a packer could not embed a CRC of version-specific system code anyway). Pinning the divergent input needs a real-Windows reference trace, which is why it is recorded. The twelfth sample (`telock_ComIntRep`) has a payload large enough that the entry-point heuristic captures it before the self-check runs. |
| **Alienyze** (5 of 12 samples) | Resolves its imports by hashing export names, over `kernel32` and then `ntdll`. The synthetic DLLs advertise the real DLLs' documented export names (from Microsoft's API documentation, plus `ntdll!RtlDecompressBuffer`, added explicitly in `scripts/gen-exports.py` because the documentation lists it only under `NtosKrnl.exe`); an unimplemented one resolves to a trap that reports itself and returns failure. `GetFileAttributesExW` reports the program present with its size. With that, 7 of 12 samples unpack to real code. The other 5 are large inputs whose long read-heavy decompression pass writes few distinct pages, so the progress watchdog ends them before the payload is complete. |

**The TELock rotate-flag fix.** TELock's stack-resident routine used to decode
to `EB FE` (a jump to itself) because a 1-bit `rol`/`ror`/`rcl`/`rcr` set the
overflow flag wrong and a decryptor branched on it. A differential trace against
unicorn found the instruction; the fix is in `exav-pe-emu`'s interpreter
(`cpu.rs`, `shift`).

Each remaining gap is a separate investigation with no shared fix, which is
why they are recorded rather than scheduled.

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

See [the ClamAV comparison](../www/src/content/docs/scanner/reference/comparison-with-clamav.md)
for the list and the reasoning: they are per-family detection content expressed
as engine code rather than as signatures, so reproducing them means reproducing
logic that exists only in GPL source — which exav's clean-room rule forbids.
