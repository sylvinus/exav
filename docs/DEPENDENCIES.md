# Dependency policy

exav aims to stay in control of its own codebase. Dependencies are where that
control is easiest to lose — to code we don't read, `unsafe` we don't audit,
supply-chain risk we don't track, and compile time / binary size we don't want.
So we are deliberate about what we pull in.

## Principles

1. **Favour leaf dependencies.** Prefer crates that are small and have few (ideally
   zero) transitive dependencies. A focused crate that does one thing over a
   bounded byte arena is worth more to us than a "batteries-included" crate that
   drags in a large tree. When two crates solve the same problem, the one with
   the smaller/shallower dependency graph wins, all else equal.

2. **Avoid pulling huge trees.** A dependency that expands into dozens or hundreds
   of transitive crates is a red flag: it inflates the `unsafe` surface we're
   trying to drive down (see [the `unsafe` posture in the README](../README.md)),
   the audit burden, the attack surface, cold compile time, and the binary/WASM
   size. We say no to such a dependency unless it earns its place and we've looked
   at what it actually pulls in (`cargo tree -e no-dev`).

3. **Gate optional capability behind features.** Anything not everyone needs is a
   Cargo feature, so a build only compiles the code and dependencies it uses:
   - **Archive/container formats** are per-format features on `exav-unpack`,
     forwarded through `exav-core`, `exav-cli`, and the WASM crates. A ZIP-only
     build is `--no-default-features --features zip`; it drops every non-ZIP
     extractor and its deps. (A recognised-but-not-compiled format is reported
     `UNSCANNABLE`, never silently clean.)
   - **YARA** (`yara`, on by default) — see the outlier note below.
   - **HTTP(S) range scanning** (`http`, off by default) — the only feature that
     links a TLS stack (`ureq → rustls → ring`).

4. **Prefer pure-Rust, and prune what we can.** The default build links no C and no
   native JIT. Concrete prunings we've made: dropping `tar`'s `xattr` feature
   (removed the `rustix`/`linux-raw-sys` syscall crates — the single largest
   `unsafe` source in the tree); keeping decryption cipher/KDF crates but never
   enabling RNG paths, so the tree stays `getrandom`-free; and disabling
   `yara-x`'s crypto-backed modules (pe/macho/dotnet/crx) to drop the `rsa` crate
   (RUSTSEC-2023-0071) entirely.

## The YARA outlier

`yara-x` is by far our largest dependency: on native targets it hard-requires
`wasmtime` **with Cranelift** to run compiled rules, which expands to ~140
transitive crates (the WASM runtime + a codegen backend). This is at odds with
principle 2, and we know it.

What we do about it today:

- It is **behind the `yara` feature (on by default)**. `--no-default-features`
  (optionally re-adding just the formats you want) drops `yara-x` and its entire
  tree — a much smaller, still-useful clamscan-compatible scanner.
- We run rules on the **Pulley interpreter** (`pulley` feature), so there is no
  runtime JIT / W^X page at scan time — but note this does **not** remove the
  Cranelift *dependency*: `yara-x` 1.x pins `wasmtime`'s `cranelift` feature
  unconditionally, so Cranelift is compiled in regardless.
- We disable `yara-x`'s default module set and re-enable only the non-crypto
  modules we need (see `crates/exav-core/Cargo.toml`).

**Still to look into** (tracked): whether `yara-x` can be driven with a
Pulley-only `wasmtime` (no Cranelift) via an upstream change or a `[patch]`, or
whether a lighter YARA matching path is viable for the common rule subset.
Cranelift is the one large tree we haven't yet been able to shed while keeping
YARA.

## Adding or bumping a dependency — checklist

- Is there a smaller/leaf alternative, or can we do it in-crate over our bounded
  byte arena? (Several parsers are vendored for exactly this reason — see
  `NOTICE`.)
- Run `cargo tree -e no-dev -i <crate>` and look at what it pulls in. Huge tree →
  justify or decline.
- Does it pull `getrandom`, a C/asm build, or a JIT? If so, it needs a strong
  reason and probably a feature gate.
- Gate it behind a feature if it's format- or capability-specific.
- CI must stay green: `cargo deny check` (advisories/bans/sources/licenses) and
  the license allowlist in `deny.toml`.

## Measuring WASM size honestly

A plain `cargo build --release` `.wasm` is **not** the shipped size — it still
carries the `__wasm_bindgen_unstable` metadata section and the `name` section,
which `wasm-bindgen`/`wasm-pack` and `wasm-opt` strip. Measure the real artifact:

```sh
wasm-pack build --release crates/exav-unpack-wasm -- --no-default-features --features zip
wasm-opt -Oz --all-features pkg/exav_unpack_wasm_bg.wasm -o out.wasm   # final size
```

For reference (release profile `opt-level="z"` + LTO, then `wasm-opt -Oz`): the
ZIP-only extractor is ~**323 KiB** vs ~**1.21 MiB** for the full all-formats
build — the per-format features earn their keep. Roughly a third of an
unoptimised `cargo build` `.wasm` is transient tooling data, so always strip +
`wasm-opt` before quoting a number.
