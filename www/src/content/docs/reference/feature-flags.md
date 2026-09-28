---
title: Feature flags
description: Cargo build features for exav, covering YARA, HTTP, decryption, DLP, and per-format extractors, so a build compiles only what it uses.
---

exav feature-gates optional capability, so a build compiles only what it uses,
for auditability, `unsafe` surface and binary or WASM size. These are Cargo
`--features` on `exav`; they forward through `exav-core` to `exav-unpack`.

## Default features

```toml
default = ["yara", "all-formats", "decrypt", "dlp", "icap"]
```

The default build is pure Rust and links no TLS stack; HTTP is opt-in.

## Capability features

| Feature | In default? | What it adds |
|---|---|---|
| `yara` | yes | YARA rule matching through the native engine. Disabling it drops the YARA parser and evaluator. |
| `all-formats` | yes | Every archive and container extractor (see below). |
| `decrypt` | yes | Decryption of encrypted archives (ZIP ZipCrypto/AES, 7z AES, PDF, DMG). |
| `dlp` | yes | The structured-data leak heuristics (`--dlp-credit-cards` / `--dlp-ssns`). |
| `icap` | yes | The [ICAP (RFC 3507) server](/guides/icap/) and its `--icap-*` flags. Pure Rust and `std`-only, so it costs the default build nothing, and it binds no port unless an `icap://` address asks for one. |
| `http` | **no** | HTTP(S) support: both halves below, and the only thing that links a TLS stack (`ureq` → `rustls` → `ring`). In `exav-core`, `http` is only the range-request backend (`dep:ureq`); in `exav` it is `http = ["http-scan", "http-update"]`. |
| `http-scan` | no | Scanning an `http(s)://` argument, and the daemon's `SCANURL` command. |
| `http-update` | no | Signature auto-update over HTTP (`--sig-sources`, `--db-url`). |

The split lets an updater-only daemon take `http-update` without the
network-facing `SCANURL` command (a client making the daemon fetch an arbitrary
URL).

## Adding HTTP support

```sh
# From source: URL scanning (http-scan) plus signature auto-update (http-update)
cargo build --release -p exav --features http

# From crates.io
cargo install exav --features http
```

Or only the half you need:

```sh
# Scan http(s):// arguments, without the updater
cargo build --release -p exav --features http-scan

# Fetch signature updates, without SCANURL
cargo build --release -p exav --features http-update
```

The published container image is built with `http`.

## The test-only feature: `testing-faults`

`testing-faults` lets a scanned file ask a decoder to fail, so the tests can check
what exav reports when one does. It is declared in four crates and is in the
default set of none:

| Crate | Declaration |
|---|---|
| `exav-unpack` | the leaf: the marker is matched and the fault raised here |
| `exav-core` | forwards to `exav-unpack/testing-faults` |
| `exav` | forwards to `exav-core/testing-faults` |
| `exav-unpack-wasm` | an independent leaf, keyed on the member name |

With it on, a reserved byte marker in the data reaching the format dispatch
raises a fault (`__exav_panic__` a panic, `__exav_abort__` an abort,
`__exav_stack__` unbounded recursion) from both the buffered and the streaming
dispatch. The WASM package keys the same idea on a member name and offers
`__exav_panic__`, `__exav_oom__` and `__exav_stack__`.

A crash a caller cannot tell from a clean scan is the worst outcome exav has, and
it is only observable from outside the process. A panic must come back as a
reported result rather than a dead process; an abort and a stack overflow are the
two no in-process boundary can contain, and the tests pin which is which.
`make test-native` runs `panic_containment` in `exav-unpack` and the
`decoder_crash` suite in `exav` with the feature on; without it those tests skip.
The browser package runs the same checks in `npm run test:e2e`.

It is never in a shipped build: the container image, release binaries and npm
package are built without it, and no default enables it.

## Smaller builds

Turn off the defaults and pick what you need:

```sh
# Pure-Rust scanner with no TLS stack, no YARA, no DLP
cargo build --release -p exav --no-default-features --features all-formats,decrypt

# A ZIP-only scanner with YARA
cargo build --release -p exav --no-default-features --features yara,zip

# An updater-only daemon (no SCANURL)
cargo build --release -p exav --features http-update
```

## Per-format features

`all-formats` is the umbrella; each extractor can also be selected on its own
(`--no-default-features --features zip` builds a ZIP-only extractor), which
matters most for the WASM build, where size counts.

```text
zip · gzip · tar · bzip2 · xz · zstd · lzip · lzw · lz4 · cab · chm · sevenz
rar · arj · arc · ace · lha · iso · ole · pdf · email · dmg · vhd · diskimage
fat · ext · ntfs · wim · upx · inno · nsis · ar · cpio · xar · uuencode · xdp · szdd
tnef · swf · binhex · lnk · partition · pyc · autoit · onenote · rtf
machofat · sfx · stuffit · alz · egg · hwp3 · zoo · ishieldz · pepack
javaclass · aimodel · screnc · base64scan · pe-emu
```

`diskimage` covers the virtual disks that need reconstruction (VHDX, QCOW2,
VMDK); `vhd` is separate because the older format needs no decompressor.
`pepack` is static unpacking; `pe-emu` runs the stub, so it is its own switch.
Every name can be forwarded from `exav-unpack` through `exav-core` to `exav`, so
each can be named on a `cargo build -p exav` line. See
[Supported formats](/reference/formats/) for what each covers.

## A lean dependency tree

The native [YARA engine](/guides/yara/) is a tree-walking evaluator with no WASM
runtime or JIT behind it, so there is no wasmtime or Cranelift anywhere in the
build. Reducing the remaining dependency `unsafe` is on the
[roadmap](/project/roadmap/).
