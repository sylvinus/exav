---
title: Feature flags
description: Cargo build features for exav, covering YARA, HTTP, decryption, DLP, and per-format extractors, so a build compiles only what it uses.
---

exav feature-gates optional capability, so a build compiles only what it uses,
for auditability, `unsafe` surface and binary or WASM size. These are Cargo
`--features` on `exav`; the format and `decrypt` features forward through
`exav-core` to `exav-unpack`. The library crates' own features are
[at the end](#library-crate-features).

## Default features

```toml
default = ["yara", "all-formats", "decrypt", "dlp", "phishing", "icap"]
```

The default build is pure Rust and links no TLS stack; HTTP is opt-in.

## Capability features

| Feature | In default? | What it adds |
|---|---|---|
| `yara` | yes | YARA rule matching through the native engine. Disabling it drops the YARA parser and evaluator; rule files then still load but never match, with a warning at load. |
| `all-formats` | yes | Every archive and container extractor (see below). |
| `decrypt` | yes | Decryption of encrypted ZIP, 7z, PDF, DMG and Office content (see [Encryption support](/reference/formats/#encryption-support)). Without it that content is reported `PASSWORD-PROTECTED`. |
| `dlp` | yes | The structured-data leak heuristics (`--dlp-credit-cards` / `--dlp-ssns`). |
| `phishing` | yes | The phishing heuristic `--detect phishing` runs, and the `.pdb`/`.gdb`/`.wdb` URL lists it reads. |
| `icap` | yes | The [ICAP (RFC 3507) server](/guides/icap/) and its `--icap-*` flags. Pure Rust, no extra dependencies; binds nothing unless an `icap://` address is given. |
| `http` | **no** | HTTP(S) support: both halves below, and the only thing that links a TLS stack (`ureq` → `rustls` → `ring`). In `exav-core`, `http` is only the range-request backend (`dep:ureq`); in `exav` it is `http = ["http-scan", "http-update"]`. |
| `http-scan` | no | Scanning an `http(s)://` argument, and the daemon's `SCANURL` command. Both also need `--allow-http-scan` at run time. |
| `http-update` | no | Signature auto-update over HTTP (`--auto-update` with `--sig-sources` or `--db-url`), through the [`exav-update`](/subprojects/exav-update/) crate. |

The split lets an updater-only daemon take `http-update` without compiling in
the network-facing `SCANURL` command (a client making the daemon fetch an
arbitrary URL).

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

With it on, a reserved byte marker in a container's first bytes raises a fault
when `walk` dispatches it (`__exav_panic__` a panic, `__exav_abort__` an abort,
`__exav_stack__` unbounded recursion). The WASM package keys the same idea on a
member name and offers `__exav_panic__`, `__exav_oom__` and `__exav_stack__`.

A panic must come back as a reported result rather than a dead process. An abort
or a stack overflow cannot be contained inside the process; the tests check that
both are reported, not taken for clean. `make test-native` runs `panic_containment` in `exav-unpack` and the
`decoder_crash` suite in `exav` with the feature on; without it those tests skip.
The browser package runs the same checks in `npm run test:e2e`.

It is never in a shipped build: the container image, release binaries and npm
package are built without it, and no default enables it.

## Smaller builds

Turn off the defaults and pick what you need:

```sh
# Pure-Rust scanner: no TLS, YARA, DLP, phishing or ICAP
cargo build --release -p exav --no-default-features --features all-formats,decrypt

# A ZIP scanner with YARA
cargo build --release -p exav --no-default-features --features yara,zip
```

`exav` always has the gzip and tar extractors: a `.cvd` is a gzipped tar, so
loading signatures needs them. A ZIP member compressed with bzip2, LZMA, zstd,
XZ or PPMd also needs that codec's feature (`bzip2`, `lzip`, `zstd`, `xz`,
`sevenz`); without it the member is reported `UNSCANNABLE`.

## Per-format features

`all-formats` is the umbrella; each extractor can also be selected on its own.

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
`pepack` is static unpacking; `pe-emu` runs the stub, so it is its own switch
(and turns `pepack` on). `ace`, `stuffit` and `inno` only recognise their format
and report it `UNSCANNABLE`. Every name is forwarded from `exav-unpack` through
`exav-core` to `exav`, so each can be named on a `cargo build -p exav` line. See
[Supported formats](/reference/formats/) for what each covers.

## Library crate features

| Crate | Feature | What it does |
|---|---|---|
| `exav-core` | default | `yara`, `all-formats`, `decrypt`, `dlp`, `phishing` (no `icap`, which is the binary's) |
| `exav-core` | `http` | The HTTP range-request reader (`dep:ureq`) |
| `exav-core` | `checksums` | Lets `ScanOptions::verify_checksums` make a container checksum mismatch an error |
| `exav-core` | `unstable-internals` | Makes the engine internals (`engine`, `bytecode`, `pe`, …) public, for tools; no stability promise |
| `exav-core` | `wasi-bin` | The `exav-wasm` WASI command-line binary |
| `exav-unpack` | default | `all-formats`, `decrypt` |
| `exav-unpack` | `all-formats-no-emu` | Every format except `pe-emu`. Not forwarded to `exav-core` or `exav` |
| `exav-unpack` | `checksums` | Lets `Budget::set_verify_checksums` make a checksum mismatch an error |
| `exav-unpack-wasm` | `standard` (default) | Every format except `pe-emu`, plus `decrypt`: what the npm package ships |
| `exav-unpack-wasm` | `full` | Every format, emulator included |
| `exav-unpack-wasm` | `minimal` | ZIP, gzip and tar only |

`exav-unpack-wasm` lets only these formats be picked one by one: `zip`, `gzip`,
`tar`, `bzip2`, `xz`, `zstd`, `lzip`, `cab`, `sevenz`, `rar`, `arj`, `lha`,
`iso`, `ole`, `pdf`, `email`, `dmg`, `upx`, `ar`, `cpio`, `xar`. For the rest,
pick a preset.
