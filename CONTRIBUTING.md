# Contributing to exav

Issues and PRs are welcome. Good first areas: additional archive formats, `.ndb`
wildcard matching, the S3 source backend, and fuzz targets.

The full guide — including the AI-assisted-contribution policy — lives at
**<https://exav.org/project/contributing/>**. The essentials:

## The clean-room rule (non-negotiable)

exav is **MIT**; ClamAV (`libclamav` / `libclamav_rust`) is **GPLv2**. All code in
this repository was, and must continue to be, written independently — without
reading, porting, translating, or otherwise consulting any ClamAV GPL source.
Deriving from GPL code (even C→Rust) would make this project a derivative work.

- Do **not** port from ClamAV, and do **not** cite any ClamAV source as the
  origin of any code.
- Implement only from **independent public sources**: the format's own published
  specification, reverse-engineered format docs, or **permissively-licensed**
  (MIT/BSD/Apache/public-domain) code, with attribution in `NOTICE`.
- Interoperating with ClamAV's *data* formats (signature databases, `CL_TYPE_*`
  ids) is fine — that's interoperability, not derivation.

The rule is GPL-specific. It does not apply to permissively-licensed sources such
as BSD-3-Clause YARA-X, which exav reuses with attribution.

This applies to AI-assisted contributions exactly as it does to hand-written
code, and the human author remains responsible for the correctness, security, and
provenance of every line they submit.

## Writing an extractor: classify every way you decline to scan

A scanner's worst outcome is not a crash, it is reporting a file clean that it
did not read. So for every path that can decline to scan bytes — each early
return, `continue`, `break`, `.ok()`, `unwrap_or_default`, `let … else`,
error-swallowing `match`, truncation and cap — decide which of these it is:

- **Nothing to scan.** An empty or directory entry, an absent optional field.
  Skipping hides nothing. Safe.
- **Content present, not examined.** It MUST surface: `Entry::unsupported`
  (→ `UNSCANNABLE`), a `LimitHit` (→ `LIMITS-EXCEEDED`), or an encrypted marker
  (→ `PASSWORD-PROTECTED`). **Anything here that does not surface is a bug.**
- **Content absent.** The container declares bytes the file does not contain — a
  truncated archive, an extent past EOF. Every byte that exists *was* scanned, so
  the missing tail is absent rather than hidden. **Reporting this is a bug in the
  other direction**, and it produces `UNSCANNABLE` on files that are merely
  damaged.

The distinction that matters is present-but-unread versus never-there. Getting it
backwards in either direction is a defect.

Nearly every bug of this class found so far had one signature: a bound or a
malformed-input check that was **correct to stop at** and **wrong to stop at
quietly**. The fix is never to remove the guard — it is to say so on the way out.

The exception is more instructive: a dispatch table with a missing row. Nothing
stopped at anything; a lookup simply had no entry, and "no entry" and "nothing to
find" are the same silence. Where a guard can be made to speak, a missing table
row can only be caught by asserting the table is total.

One trap when testing this: `extract()` discards already-emitted entries when it
returns `Err`, so a test using it cannot see members reported before a mid-way
failure, and will report a working fix as broken. Use `extract_each`, which is
what the scanner uses.

## Where documentation goes

There are two trees, and they are not interchangeable.

**`www/` is authoritative for anything a user or integrator relies on** —
supported formats, CLI flags, limits, verdicts, the wire protocol. If `www/` and
a note under `docs/` disagree about one of those, `www/` is right and the other
is stale. CI asserts this for format coverage and CLI flags.

**`docs/` is for engineering notes**: audits, investigations, design records,
and the reasoning behind a decision that would bury a user-facing page. It is
written for whoever maintains the code, and it may assume you have the source
open.

A rule of thumb that resolves most cases: if a reader would be *surprised* to
need it in order to use exav, it belongs in `www/`. If they would be surprised
to find it in a user manual, it belongs in `docs/`.

Anything with a number in it — a count, a measurement, a percentage — is worth
resisting in both. Numbers in prose go stale silently and nothing rebuilds them.
Prefer stating the claim without the digits, or move the number into a test that
asserts it.

## Before submitting

```sh
make test     # everything CI runs, bar diff-testing and fuzzing
make lint         # cargo clippy --all-targets -D warnings + cargo fmt --check
```

`make test` is the whole tree, not just `cargo test`. Each part also runs alone:

| target | what it covers | needs |
| --- | --- | --- |
| `make test-native` | the workspace under every feature pass: default, `http`, `checksums`, `--no-default-features`, `unstable-internals` | — |
| `make test-wasm` | the extractor + core unit tests on 32-bit `wasm32-wasip1` | `wasmtime` |
| `make test-js` | the WASM bindings' vitest units and playwright browser e2e | node, wasm-pack |
| `make test-www` | `astro check` + a full docs build (broken links, bad frontmatter) | node |

The two **differential** harnesses are not in `make test` and are not merge
gates: they measure exav against another engine, so they can go red because the
*other* engine changed. Run them when you touch the matching subsystem.

| harness | what it compares |
| --- | --- |
| `scripts/difftest.sh` | exav vs clamd over a corpus — compliance diff (needs docker + a corpus) |
| `make test-yara-diff` | exav's YARA engine vs `yara-x` on identical rules and inputs (pulls `yara-x`: +83 crates, 21 of them cranelift/wasmtime — nothing else in exav builds a JIT) |

`cargo test` is fine for the inner loop, but it is a **subset** and a misleading
one: a test file that opens `#![cfg(feature = "x")]` compiles to **zero tests**
without `x`, and the run reports green having checked nothing. Run `make test`
before you push.

CI additionally runs `cargo audit`, `cargo deny check`, and a `cargo-fuzz` smoke
pass.

**Run the wasm32 tests if you touch a decoder or byte-parsing path.** `usize` is
32-bit on the `wasm32` build exav ships, so integer- and capacity-overflow bugs on
parsed offsets/lengths are invisible on a 64-bit host but abort under
`make test-wasm`.

## Do not commit real malware

Tests use the harmless EICAR string and synthetic inputs only. **Never** commit
real malware to this repository.

## Security

Do not open a public issue for a vulnerability — see [`SECURITY.md`](SECURITY.md).
