---
title: Feature flags
description: Cargo build features for exav — YARA, HTTP, decryption, DLP, and per-format extractors — so a build compiles only what it uses.
---

exav favors small leaf crates and feature-gates optional capability, so a build
compiles only what it uses — for control, auditability, `unsafe` surface, and
binary/WASM size. These are Cargo `--features` on `exav-cli` (they forward
through `exav-core` → `exav-unpack`).

## Default features

```toml
default = ["yara", "all-formats", "decrypt", "dlp", "icap"]
```

The default build is 100% pure-Rust and links **no TLS stack** — HTTP is opt-in.

## Capability features

| Feature | In default? | What it adds |
|---|---|---|
| `yara` | yes | Full YARA rule matching via the native engine. Disabling compiles away the YARA parser/evaluator subtree for a lighter binary. |
| `all-formats` | yes | Every archive/container extractor (see below). |
| `decrypt` | yes | Decryption of encrypted archives (ZIP ZipCrypto/AES, 7z AES, PDF, DMG). |
| `dlp` | yes | The structured-data leak heuristics (`--alert-credit-cards` / `--alert-ssns`). |
| `icap` | yes | The [ICAP (RFC 3507) server](/guides/icap/) and its `--icap*` flags. Pure-Rust and std-only, so it costs the default build nothing; it binds no port unless an `icap://` address on `--listen` asks it to. |
| `http` | **no** | HTTP(S) support. Enables both halves below; the only thing that links a TLS stack (`ureq → rustls → ring`). |
| `http-scan` | no | Scan an `http(s)://` argument + the daemon `SCANURL` command. |
| `http-update` | no | Signature auto-update over HTTP (`--sig-sources`, `--db-url`). |

The `http` split lets an updater-only daemon take `http-update` **without**
exposing the network-facing `SCANURL` verb (a client making the daemon fetch an
arbitrary URL) — take one, the other, or both.

## The test-only feature: `testing-faults`

`testing-faults` lets a **scanned file ask a decoder to fail**, so the tests can
check what exav reports when one does. It is declared in four crates and is in
the default set of none of them:

| Crate | Declaration |
|---|---|
| `exav-unpack` | the leaf — the marker is matched and the fault raised here |
| `exav-core` | forwards to `exav-unpack/testing-faults` |
| `exav-cli` | forwards to `exav-core/testing-faults` |
| `exav-unpack-wasm` | an independent leaf, keyed on the member *name* |

With it on, a reserved byte marker anywhere in the data reaching the format
dispatch raises the matching fault — `__exav_panic__` a panic,
`__exav_abort__` an abort, `__exav_stack__` unbounded recursion — from both the
buffered and the streaming dispatch, since a natively-streaming container never
goes through the buffered one. The WASM package keys the same idea on a member
name and offers `__exav_panic__`, `__exav_oom__` and `__exav_stack__`.

This exists because a crash a caller cannot tell apart from a clean scan is the
worst outcome exav has, and it is only observable from outside the process. A
panic must come back as a reported limit rather than a dead process; an abort and
a stack overflow are the two that no in-process boundary can contain, and the
tests pin which is which.

CI runs the containment suites with it — `make test-native` covers
`panic_containment` in `exav-unpack` and the `decoder_crash` suite in `exav-cli`,
each built with the feature so the tests have a decoder that can be asked to
fail. Without it those tests skip themselves and the question goes unasked. The
browser package has the parallel path in `npm run test:e2e`, which builds with
the feature before running Playwright.

**It is never in a shipped build.** The container image, the release binaries and
the published npm package are all built without it, and no default enables it, so
it is reachable only from a build that names it.

## Smaller builds

Turn off the defaults and pick only what you need:

```sh
# Pure-Rust scanner with no TLS stack (drop YARA + DLP + HTTP):
cargo build --release -p exav-cli --no-default-features --features all-formats,decrypt

# A ZIP-only scanner with YARA:
cargo build --release -p exav-cli --no-default-features --features yara,zip

# An updater-only daemon (no SCANURL):
cargo build --release -p exav-cli --features http-update
```

## Per-format features

`all-formats` is the umbrella; each extractor is also individually selectable
(e.g. `--no-default-features --features zip` yields a ZIP-only extractor). This
matters most for the WASM build, where size counts: a ZIP-only extractor is
~323 KiB vs ~1.2 MiB for the full build.

Available per-format features:

```text
zip · gzip · tar · bzip2 · xz · zstd · lzip · lzw · lz4 · cab · chm · sevenz
rar · arj · arc · ace · lha · iso · ole · pdf · email · dmg · vhd · diskimage
fat · ntfs · wim · upx · inno · nsis · ar · cpio · xar · uuencode · xdp · szdd
tnef · swf · binhex · lnk · partition · pyc · autoit · onenote · rtf
machofat · sfx
```

`diskimage` covers the virtual disks that need reconstruction (VHDX, QCOW2,
VMDK); `vhd` is separate because the older format needs no decompressor.

Some extractors are lower-level features that are not forwarded to `exav-cli`,
so they cannot be named on a `cargo build -p exav-cli` line (all of them are in
the default `all-formats` build): `stuffit`, `alz`, `egg`, `hwp3`, `ext`, `zoo`,
`ishieldz`, `pepack`, `javaclass`, `aimodel`, `screnc` and `base64scan`. Select
those when building `exav-unpack` (or the WASM package) directly.

See [Supported formats](/reference/formats/) for what each one covers.

## A lean dependency tree

exav's dependency tree is deliberately lean and pure-Rust. The native
[YARA engine](/guides/yara/) is a tree-walking evaluator with no WASM runtime or
JIT behind it — there is **no wasmtime and no Cranelift** anywhere in the build,
just a set of small leaf crates. Reviewing and driving down the residual
dependency `unsafe` is an explicit ongoing goal — see the
[roadmap](/project/roadmap/).
