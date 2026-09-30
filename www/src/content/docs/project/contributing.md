---
title: Contributing
description: How to contribute to exav, with the clean-room rule, the checks to run, and the 32-bit/WASM test requirement.
---

Issues and PRs are welcome. Good first areas: formats from the
[gap list](/reference/formats/#the-complete-gap-list), bytecode host APIs (see the
[comparison](/project/comparison-with-clamav/#bytecode-host-apis)), and fuzz
targets. For a vulnerability, do not open a public issue: see
[Security](/project/security/#reporting-a-vulnerability).

To start: clone the repository, `make test` to run everything CI runs, and
`scripts/difftest.sh` when you touch detection (it needs Docker and a corpus).

## The clean-room rule

:::danger[Never derive from ClamAV]
exav is MIT-licensed; ClamAV (`libclamav` / `libclamav_rust`) is GPLv2. All code
in this repository was, and must continue to be, written independently, without
reading, porting, translating or otherwise considering any ClamAV GPL source.
Deriving from GPL code (even C to Rust) would make this project a derivative work
and is a license violation.
:::

- Do not port from ClamAV, and do not cite any ClamAV source as the origin of any
  code.
- Implement only from independent public sources: the format's own published
  specification, reverse-engineered format documentation, or permissively
  licensed (MIT/BSD/Apache/public-domain) code with attribution in `NOTICE`.
- Interoperating with ClamAV's data formats (signature databases, `CL_TYPE_*`
  ids) is fine: that is interoperability, not derivation.

The rule is GPL-specific. It does not apply to permissively licensed sources such
as BSD-3-Clause YARA-X, which exav reuses with attribution.

## AI-assisted contributions

Using an assistant to write, refactor or review code is fine, but the human
author is responsible for every line they submit:

- **You review and stand behind it.** Treat AI output as a draft. You must
  understand what the code does and vouch for its correctness and security: a
  scanner parses hostile input, so a subtly wrong generated decoder is a
  vulnerability.
- **You are responsible for its licensing and provenance.** AI tools can emit
  code that reproduces GPL or otherwise incompatibly licensed sources. The
  clean-room rule applies to AI-assisted code exactly as to hand-written code. If
  you cannot establish that a suggested snippet is clean-room and permissively
  licensed, do not submit it.

## Writing an extractor: classify every way you decline to scan

A scanner's worst outcome is not a crash, it is reporting a file clean that it
did not read. So for every path that can decline to scan bytes (each early
return, `continue`, `break`, `.ok()`, `unwrap_or_default`, `let … else`,
error-swallowing `match`, truncation and cap), decide which of these it is:

- **Nothing to scan.** An empty or directory entry, an absent optional field.
  Skipping hides nothing.
- **Content present, not examined.** It must surface: `Entry::unsupported`
  (`UNSCANNABLE`), a `LimitHit` (`LIMITS-EXCEEDED`), or an encrypted marker
  (`PASSWORD-PROTECTED`). Anything here that does not surface is a bug.
- **Content absent.** The container declares bytes the file does not contain: a
  truncated archive, an extent past the end. Every byte that exists was scanned,
  so the missing tail is absent rather than hidden. Reporting this is a bug in
  the other direction, and produces `UNSCANNABLE` on files that are merely
  damaged.

Nearly every bug of this class found so far was a bound or a malformed-input
check that was right to stop and wrong to stop quietly. The fix is never to
remove the guard, it is to say so on the way out.

When testing this, use `walk`, which is what the scanner uses: `extract` discards
the members already emitted when it returns an error, so a test using it cannot
see members reported before a failure part way.

## Where documentation goes

`www/` (this site) is authoritative for anything a user or integrator relies on:
supported formats, CLI flags, limits, verdicts, the wire protocol. `docs/` in the
repository is for engineering notes: audits, investigations, design records. If
the two disagree about something a user relies on, `www/` is right. CI checks the
CLI flags the site documents against the binary.

## Before submitting

Run the same checks CI does:

```sh
make test    # everything CI runs, except differential testing and fuzzing
make lint    # clippy --all-targets -D warnings + cargo fmt --check
```

`make test` covers the whole tree; each part also runs alone:

| target | what it covers | needs |
| --- | --- | --- |
| `make test-native` | the workspace under every feature pass: default, `http`, `exav-unpack` with `checksums`, `--no-default-features`, `unstable-internals`, `testing-faults` | nothing extra |
| `make test-wasm` | the extractor and core unit tests on 32-bit `wasm32-wasip1` | `wasmtime` |
| `make test-js` | the WASM bindings' vitest units and Playwright browser tests | node, wasm-pack |
| `make test-www` | `astro check` and a full docs build (broken links, bad frontmatter) | node |

Not in `make test`:

| target | what it does | needs |
| --- | --- | --- |
| `scripts/difftest.sh` | exav against clamd over a corpus, a compliance diff | docker and a corpus |
| `make test-yara-diff` | exav's YARA engine against `yara-x` on identical rules and inputs | `yara-x-cli` |
| `make miri` | selected library tests under Miri, which checks the `unsafe` in dependencies along real code paths; slow | a nightly toolchain with the `miri` component |

The differential harnesses are not merge gates: they measure exav against another
engine, so they can go red because the other engine changed. Run them when you
touch the matching subsystem.

`cargo test` is fine for the inner loop, but it is a subset: a test file that
opens with `#![cfg(feature = "x")]` compiles to zero tests without `x`, and the run
reports green having checked nothing. Run `make test` before you push.

CI also runs `cargo audit`, `cargo deny check` and a `cargo-fuzz` smoke pass.

## 32-bit / WASM tests

`usize` is 32-bit on the `wasm32` build exav ships, so integer and capacity
overflows on parsed offsets and lengths that a 64-bit host hides abort there. If
you touch a decoder or byte-parsing path, run the extractor and core tests on
`wasm32-wasip1` under wasmtime:

```sh
make test-wasm          # or: scripts/test-wasm.sh   (needs `wasmtime` on PATH)
```

CI runs this on every pull request and push to `main`.

## Do not commit real malware

Tests use the harmless EICAR string and synthetic inputs only. Never commit real
malware to this repository.
