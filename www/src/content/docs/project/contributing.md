---
title: Contributing
description: How to contribute to exav — the non-negotiable clean-room rule, the checks to run, and the 32-bit/WASM test requirement.
---

Issues and PRs are welcome. Good first areas: additional archive formats, `.ndb`
wildcard matching, the S3 source backend, and fuzz targets.

## The clean-room rule (non-negotiable)

:::danger[Never derive from ClamAV]
exav is **MIT**; ClamAV (`libclamav` / `libclamav_rust`) is **GPLv2**. **All code
in this repository was, and must continue to be, written independently — without
reading, porting, translating, or otherwise considering any ClamAV GPL source
code.** Deriving from GPL code (even C→Rust) would make this project a derivative
work and is a license violation.
:::

- Do **not** port from ClamAV, and do **not** cite any ClamAV source as the origin
  of any code.
- Implement only from **independent public sources**: the format's own published
  specification, reverse-engineered format docs, or **permissively-licensed**
  (MIT/BSD/Apache/public-domain) code with attribution in `NOTICE`.
- Interoperating with ClamAV's *data* formats (signature databases, `CL_TYPE_*`
  ids) is fine — that's interoperability, not derivation.

This rule is GPL-specific. It does **not** apply to permissively-licensed sources
such as BSD-3-Clause YARA-X, which exav legitimately reuses with attribution.

## AI-assisted contributions

AI-assisted contributions are welcome — using an assistant to write, refactor, or
review code is fine. But the **human author remains fully responsible** for every
line they submit:

- **You review and stand behind it.** Treat AI output as a draft, not an
  authority. You must understand what the code does and vouch for its
  **correctness** and **security** — a scanner parses hostile input, so a subtly
  wrong AI-generated decoder is a real vulnerability, not a cosmetic bug.
- **You are responsible for its licensing and provenance.** AI tools can emit code
  that reproduces GPL or otherwise incompatibly licensed sources. The clean-room
  rule above is absolute and applies to AI-assisted code exactly as it does to
  hand-written code: exav is **MIT** and derives **nothing** from GPL sources
  (ClamAV included). Implement only from **public specifications** and
  **permissively-licensed** code. If you can't establish that an AI-suggested
  snippet is clean-room and permissively licensed, do not submit it.

In short: an assistant may help you write the code, but you own it.

## Before submitting

Run the same checks CI does:

```sh
make test    # everything CI runs, bar diff-testing and fuzzing
make lint    # clippy --all-targets -D warnings + cargo fmt --check
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
| `make test-yara-diff` | exav's YARA engine vs `yara-x` on identical rules and inputs (pulls `yara-x`, whose tree brings cranelift and wasmtime — nothing else in exav builds a JIT) |

`cargo test` is fine for the inner loop, but it is a **subset** and a misleading
one: a test file that opens `#![cfg(feature = "x")]` compiles to **zero tests**
without `x`, and the run reports green having checked nothing. Run `make test`
before you push.

CI additionally runs `cargo audit`, `cargo deny check`, and a `cargo-fuzz` smoke
pass.

## 32-bit / WASM tests

`usize` is 32-bit on the `wasm32` build exav ships (the sandboxed extractor), so
integer- and capacity-overflow bugs on parsed offsets/lengths are invisible on a
64-bit host but abort on wasm32. If you touch a decoder or byte-parsing path, run
the extractor and core tests on `wasm32-wasip1` under wasmtime:

```sh
make test-wasm          # or: scripts/test-wasm.sh   (needs `wasmtime` on PATH)
```

CI runs this on every push. An overflow that passes on x86-64 will fail here.

## Do not commit real malware

Tests use the harmless EICAR string and synthetic inputs only. **Never** commit
real malware to this repository.
