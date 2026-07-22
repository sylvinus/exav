---
title: Dependencies
description: Full transparency on exav's third-party dependencies — what the default binary links, each crate's purpose, license, and unsafe posture, and exav's memory-safety stance.
---

exav is a security tool, so what it links is part of its threat model. This page
lists the dependencies of the shipped binary (`exav-cli`, default features): the
**direct** ones first — what each is for, its license, and its `unsafe`
posture — then [every transitive crate](#every-transitive-dependency) with the
direct dependency that pulls it in, so the full supply chain is on one page. The
dependency *policy* behind these choices is in the repository's
`docs/DEPENDENCIES.md`.

## Memory-safety posture

- **Safe Rust by default.** exav's own scanning and extraction code is written in
  safe Rust — `exav-core` and `exav-unpack` are `#![forbid(unsafe_code)]`, so
  the crates that parse hostile input contain no `unsafe` of their own.
- **Pure Rust, no C, no JIT.** The default build links **no C libraries** and **no
  native code generator**. Compression (`flate2` uses the pure-Rust
  `miniz_oxide` backend, plus pure-Rust bzip2/xz/zstd/lzma crates) and crypto are
  all pure Rust. There is **no wasmtime, no Cranelift, no OpenSSL, and no `ring`**
  in the default binary.
- **A network server with no network crates.** The
  [ICAP server](/guides/icap/) adds no dependency at all: its request framing,
  chunked decoding and `Encapsulated` offset parsing are written against `std`,
  in a module that carries `#![deny(unsafe_code)]` — the parsers a hostile
  client reaches first are exav's own code, not a transitive one.
- **Minimal, contained `unsafe`.** exav is *not* zero-`unsafe` overall: a small
  number of dependencies use `unsafe` internally, almost entirely for **SIMD
  acceleration** (byte search, hashing) and **OS syscalls** (the daemon). None of
  it is in exav's own parsing logic, and driving the residual surface down is an
  explicit [roadmap](/project/roadmap/) goal.
- **Feature-gated capability.** Optional features (`http`, individual formats)
  only pull their dependencies when enabled — see [Feature flags](/reference/feature-flags/).
  The network stack is **opt-in**: it is the only thing that would link a
  non-pure-Rust crypto library (see [Opt-in dependencies](#opt-in-dependencies-not-in-the-default-binary)).

The default binary resolves to **151 third-party crates** in total: the 60 direct
dependencies exav explicitly chose (below) plus
[91 transitive ones](#every-transitive-dependency).

## CLI & runtime (`exav-cli`)

| Crate | Purpose | License | `unsafe` posture |
|---|---|---|---|
| [`clap`](https://crates.io/crates/clap) | Command-line argument parsing | MIT OR Apache-2.0 | safe |
| [`anyhow`](https://crates.io/crates/anyhow) | Error handling in the binary | MIT OR Apache-2.0 | safe |
| [`serde_json`](https://crates.io/crates/serde_json) | JSON scan-report output | MIT OR Apache-2.0 | safe |
| [`walkdir`](https://crates.io/crates/walkdir) | Recursive directory traversal | Unlicense OR MIT | safe |
| [`regex`](https://crates.io/crates/regex) | Linear-time regex (CLI filters) | MIT OR Apache-2.0 | safe (SIMD via `memchr`/`aho-corasick`) |
| [`libc`](https://crates.io/crates/libc) | Syscall bindings for the prefork daemon (signals, resource limits) | MIT OR Apache-2.0 | `unsafe` FFI declarations |

Spilling an oversized stream to a temp file is **not** a dependency: it is
`exav-cli/src/tmpfile.rs`, a page of `std::fs` with the properties that matter
(`O_CREAT|O_EXCL`, so a pre-planted symlink cannot be followed; `0600`; delete on
drop). The ready-made crates for it reach the filesystem through `rustix` and
`linux-raw-sys`, which would add more `unsafe` than the rest of the tree
combined — for a feature that never touches a scanned byte.

## Core engine (`exav-core`)

The engine crate is `#![forbid(unsafe_code)]`; the `unsafe` noted below lives
inside these dependencies, not in exav.

| Crate | Purpose | License | `unsafe` posture |
|---|---|---|---|
| [`daachorse`](https://crates.io/crates/daachorse) | Double-array Aho-Corasick automaton (the main pattern matcher) | MIT OR Apache-2.0 | perf-critical indexing |
| [`aho-corasick`](https://crates.io/crates/aho-corasick) | Multi-pattern search (YARA atoms, prefilters) | Unlicense OR MIT | SIMD |
| [`memchr`](https://crates.io/crates/memchr) | Vectorized byte search | Unlicense OR MIT | SIMD |
| [`regex-automata`](https://crates.io/crates/regex-automata) / [`regex-syntax`](https://crates.io/crates/regex-syntax) | Linear-time (DoS-safe) regex engine + parser | MIT OR Apache-2.0 | via `memchr` |
| [`fancy-regex`](https://crates.io/crates/fancy-regex) | Backtracking regex for wildcard-signature verification | MIT | safe |
| [`goblin`](https://crates.io/crates/goblin) | PE / ELF / Mach-O executable parsing | MIT | safe |
| [`iced-x86`](https://crates.io/crates/iced-x86) | **Not linked by any shipped binary.** A dev-dependency of [`exav-x86`](/subprojects/exav-x86/) only, where it is the oracle its differential tests, table generator and fuzz target check against | MIT | handler dispatch through raw pointers, and integer-to-enum transmutes on table indices |
| [`md-5`](https://crates.io/crates/md-5) / [`sha1`](https://crates.io/crates/sha1) / [`sha2`](https://crates.io/crates/sha2) | Hash signatures (whole-file / section digests) | MIT OR Apache-2.0 | minimal (CPU-feature detection) |
| [`crc32fast`](https://crates.io/crates/crc32fast) | CRC32 | MIT OR Apache-2.0 | SIMD |
| [`base64`](https://crates.io/crates/base64) | Base64 decode (embedded payloads, YARA) | MIT OR Apache-2.0 | safe |
| [`bstr`](https://crates.io/crates/bstr) | Byte-string utilities (YARA engine) | MIT OR Apache-2.0 | safe |
| [`yara-x-parser`](https://crates.io/crates/yara-x-parser) | YARA grammar/AST parser (the native engine's front end) | BSD-3-Clause | safe |
| [`image`](https://crates.io/crates/image) | Icon/image decoding for fuzzy image hashing | MIT OR Apache-2.0 | some, in codec paths |
| [`rustdct`](https://crates.io/crates/rustdct) / [`transpose`](https://crates.io/crates/transpose) | DCT for perceptual image hashing | MIT OR Apache-2.0 | safe |
| [`tlsh2`](https://crates.io/crates/tlsh2) | TLSH fuzzy hashing | Apache-2.0 OR BSD-3-Clause | safe |
| [`rmp-serde`](https://crates.io/crates/rmp-serde) / [`serde`](https://crates.io/crates/serde) | MessagePack (de)serialization of the prebuilt `.exavdb` | MIT / MIT OR Apache-2.0 | safe |
| [`thiserror`](https://crates.io/crates/thiserror) | Error-type derive | MIT OR Apache-2.0 | safe |

## Extraction & decompression (`exav-unpack`)

Also `#![forbid(unsafe_code)]`. The decoders are pure-Rust; there is no C
compression library in the tree.

| Crate | Purpose | License | `unsafe` posture |
|---|---|---|---|
| [`flate2`](https://crates.io/crates/flate2) | DEFLATE / gzip / zlib (pure-Rust `miniz_oxide` backend) | MIT OR Apache-2.0 | safe (no C zlib) |
| [`deflate64`](https://crates.io/crates/deflate64) | Deflate64 (ZIP method 9) | MIT | **none** — `forbid` |
| [`bzip2-rs`](https://crates.io/crates/bzip2-rs) | bzip2 (pure Rust) | MIT OR Apache-2.0 | safe |
| [`xz4rust`](https://crates.io/crates/xz4rust) | XZ / LZMA (pure Rust) | MIT | safe |
| [`lzma-rust2`](https://crates.io/crates/lzma-rust2) | LZMA / LZMA2 (7z) | Apache-2.0 | safe |
| [`ruzstd`](https://crates.io/crates/ruzstd) | Zstandard (pure Rust) | MIT | safe |
| [`lzxd`](https://crates.io/crates/lzxd) | LZX (CAB) | MIT OR Apache-2.0 | safe |
| [`lzfse_rust`](https://crates.io/crates/lzfse_rust) | LZFSE / LZVN (DMG) | MIT OR Apache-2.0 | safe |
| [`delharc`](https://crates.io/crates/delharc) | LHA / LZH | MIT OR Apache-2.0 | safe |
| [`bitstream-io`](https://crates.io/crates/bitstream-io) | Bit-level readers for decoders | MIT OR Apache-2.0 | safe |
| [`tar`](https://crates.io/crates/tar) | tar archives (`xattr` disabled — drops syscall `unsafe`) | MIT OR Apache-2.0 | safe |
| [`zip`](https://crates.io/crates/zip) | ZIP container parsing | MIT | safe |
| [`cfb`](https://crates.io/crates/cfb) | OLE2 / Compound File Binary (Office) | MIT | safe |
| [`quick-xml`](https://crates.io/crates/quick-xml) | OOXML / XML parsing | MIT | safe |
| [`mail-parser`](https://crates.io/crates/mail-parser) | MIME / email parsing | Apache-2.0 OR MIT | safe |
| [`apfs`](https://crates.io/crates/apfs) / [`hfsplus`](https://crates.io/crates/hfsplus) | DMG filesystem parsing | MIT | safe |
| [`ext4-view`](https://crates.io/crates/ext4-view) | ext2/3/4 filesystem walking (virtual disks) | MIT OR Apache-2.0 | **none** — `forbid` |
| [`fatfs`](https://crates.io/crates/fatfs) | FAT12/16/32 cluster-chain walking | MIT | 13 |
| [`lznt1`](https://crates.io/crates/lznt1) | LZNT1 (NTFS compressed streams) | MIT | **none** — `forbid` |
| [`salzweg`](https://crates.io/crates/salzweg) | LZW (ZOO, Unix `compress`) | MIT | **none** |
| [`unshield`](https://crates.io/crates/unshield) | InstallShield `.z` archives | MIT | **none** |
| [`byteorder`](https://crates.io/crates/byteorder) / [`bincode`](https://crates.io/crates/bincode) | Byte-order + binary (de)serialization | Unlicense OR MIT / MIT | safe |

### Cryptographic primitives (the `decrypt` feature)

Used only to decrypt encrypted archive members. These are [RustCrypto](https://github.com/RustCrypto)
crates; their residual `unsafe` is confined to SIMD/CPU-feature detection.

| Crate | Purpose | License | `unsafe` posture |
|---|---|---|---|
| [`aes`](https://crates.io/crates/aes) / [`cbc`](https://crates.io/crates/cbc) | AES block cipher + CBC (ZIP/7z/DMG) | MIT OR Apache-2.0 | minimal (CPU-feature detection) |
| [`des`](https://crates.io/crates/des) | DES (legacy archive encryption) | MIT OR Apache-2.0 | safe |
| [`hmac`](https://crates.io/crates/hmac) / [`pbkdf2`](https://crates.io/crates/pbkdf2) / [`digest`](https://crates.io/crates/digest) | Key derivation + MAC | MIT OR Apache-2.0 | safe |
| [`constant_time_eq`](https://crates.io/crates/constant_time_eq) | Constant-time comparison | CC0-1.0 OR MIT-0 OR Apache-2.0 | safe |
| [`stringprep`](https://crates.io/crates/stringprep) | Password normalization | MIT OR Apache-2.0 | safe |

## Opt-in dependencies (not in the default binary)

Enabled only by the `http` feature (URL scanning / signature auto-update),
handled by the separate `exav-update` crate:

| Crate | Purpose | License | Note |
|---|---|---|---|
| [`ureq`](https://crates.io/crates/ureq) | Minimal blocking HTTP(S) client | MIT OR Apache-2.0 | pulls `rustls` → [`ring`](https://crates.io/crates/ring) |

`ring` bundles C/assembly crypto — it is the one non-pure-Rust component exav can
pull, which is **exactly why HTTP is off by default**. Builds that don't need
network fetch never link it.

## Every transitive dependency

The tables above are the crates exav *chose*. Those crates pull in their own
dependencies, and a security tool's real supply chain is the whole closure — so
here it is: every remaining crate in the default `exav-cli` build, with the
direct dependency (or dependencies) that pulls it in.

The default `exav-cli` build resolves to **159 packages**, five of which are
exav's own workspace crates (`exav-cli`, `exav-core`, `exav-unpack`,
`exav-pe-emu`, `exav-x86`). `bitflags`, `hashbrown` and `rustc-hash` each resolve
at two major versions, so the count of distinct *projects* is lower still. Check
it against the current lockfile with:

```sh
cargo tree -e no-dev -p exav-cli --prefix none | sed 's/ (\*)$//' \
  | awk '{print $1}' | sort -u | wc -l
```

Nothing here is a C library, a TLS stack, or a code generator. `syn`, `quote` and
`proc-macro2` are build-time proc-macro machinery and contribute no runtime code
to the binary.

**35 of the 94 packages contain no `unsafe` at all**, 17 of those enforcing it with a
crate-root `#![forbid(unsafe_code)]`. The `unsafe` uses column counts occurrences
of the `unsafe` keyword in each crate's shipped `src/` (comments stripped; tests,
benches and examples excluded) at the exact version this build resolves. Read it
as *surface area to review*, not as risk: a count is not a defect, and the
concentration is unsurprising — `rustfft` (SIMD butterflies, reached only through
the perceptual image hash), `hashbrown` and `bytemuck` are 2,496 of the 3,490
occurrences in this table, and none of them sits on a path that parses scanned
bytes. There are no raw-syscall binding crates here at all — the two that would
otherwise dominate the count, `rustix` and `linux-raw-sys`, are kept out by
[writing the daemon's spill file in-tree](#cli--runtime-exav-cli) and by building
`tar` without `xattr`. Reproduce the count with `cargo geiger`, or per crate
with:

```sh
grep -rc '\bunsafe\b' ~/.cargo/registry/src/*/<crate>-<version>/src/
```

| Crate | License | `unsafe` uses | Pulled in by |
|---|---|---|---|
| [`adler2`](https://crates.io/crates/adler2) | 0BSD OR MIT OR Apache-2.0 | **none** — `forbid` | `flate2`, `image`, `zip` |
| [`anstream`](https://crates.io/crates/anstream) | MIT OR Apache-2.0 | 3 | `clap` |
| [`anstyle`](https://crates.io/crates/anstyle) | MIT OR Apache-2.0 | 1 | `clap` |
| [`anstyle-parse`](https://crates.io/crates/anstyle-parse) | MIT OR Apache-2.0 | 3 | `clap` |
| [`anstyle-query`](https://crates.io/crates/anstyle-query) | MIT OR Apache-2.0 | 1 | `clap` |
| [`arraydeque`](https://crates.io/crates/arraydeque) | MIT/Apache-2.0 | 77 | `explode` |
| [`ascii_tree`](https://crates.io/crates/ascii_tree) | MIT | **none** | `yara-x-parser` |
| [`beef`](https://crates.io/crates/beef) | MIT OR Apache-2.0 | 26 | `yara-x-parser` |
| [`bit-set`](https://crates.io/crates/bit-set) | Apache-2.0 OR MIT | 2 | `fancy-regex` |
| [`bit-vec`](https://crates.io/crates/bit-vec) | Apache-2.0 OR MIT | 4 | `fancy-regex` |
| [`bitflags`](https://crates.io/crates/bitflags) | MIT OR Apache-2.0 | 2 | `delharc`, `image`, `yara-x-parser` |
| [`block-buffer`](https://crates.io/crates/block-buffer) | MIT OR Apache-2.0 | 4 | `digest`, `hmac`, `md-5`, `pbkdf2`, `sha1`, `sha2` |
| [`block-padding`](https://crates.io/crates/block-padding) | MIT OR Apache-2.0 | 1 | `aes`, `cbc`, `des` |
| [`bytemuck`](https://crates.io/crates/bytemuck) | Zlib OR Apache-2.0 OR MIT | 318 | `image` |
| [`cfg-if`](https://crates.io/crates/cfg-if) | MIT OR Apache-2.0 | **none** | `aes`, `bzip2-rs`, `crc32fast`, `flate2`, `image`, `md-5`, `sha1`, `sha2`, `tar`, `zip` |
| [`chrono`](https://crates.io/crates/chrono) | MIT OR Apache-2.0 | 11 | `delharc` |
| [`cipher`](https://crates.io/crates/cipher) | MIT OR Apache-2.0 | 2 | `aes`, `cbc`, `des` |
| [`clap_builder`](https://crates.io/crates/clap_builder) | MIT OR Apache-2.0 | **none** — `forbid` | `clap` |
| [`clap_derive`](https://crates.io/crates/clap_derive) | MIT OR Apache-2.0 | **none** — `forbid` | `clap` |
| [`clap_lex`](https://crates.io/crates/clap_lex) | MIT OR Apache-2.0 | 6 | `clap` |
| [`color_quant`](https://crates.io/crates/color_quant) | MIT | **none** | `image` |
| [`colorchoice`](https://crates.io/crates/colorchoice) | MIT OR Apache-2.0 | **none** | `clap` |
| [`countme`](https://crates.io/crates/countme) | MIT OR Apache-2.0 | 1 | `yara-x-parser` |
| [`cpufeatures`](https://crates.io/crates/cpufeatures) | MIT OR Apache-2.0 | 9 | `aes`, `sha1`, `sha2` |
| [`crc`](https://crates.io/crates/crc) | MIT OR Apache-2.0 | **none** — `forbid` | `ext4-view` |
| [`crc-catalog`](https://crates.io/crates/crc-catalog) | MIT OR Apache-2.0 | **none** — `forbid` | `crc` |
| [`crypto-common`](https://crates.io/crates/crypto-common) | MIT OR Apache-2.0 | **none** — `forbid` | `aes`, `cbc`, `des`, `digest`, `hmac`, `md-5`, `pbkdf2`, `sha1`, `sha2` |
| [`either`](https://crates.io/crates/either) | MIT OR Apache-2.0 | 2 | `yara-x-parser` |
| [`equivalent`](https://crates.io/crates/equivalent) | Apache-2.0 OR MIT | **none** | `mail-parser`, `yara-x-parser`, `zip` |
| [`explode`](https://crates.io/crates/explode) | MIT | 6 | `unshield` |
| [`fdeflate`](https://crates.io/crates/fdeflate) | MIT OR Apache-2.0 | **none** — `forbid` | `image` |
| [`filetime`](https://crates.io/crates/filetime) | MIT/Apache-2.0 | 9 | `tar` |
| [`fnv`](https://crates.io/crates/fnv) | Apache-2.0 / MIT | **none** | `cfb`, `yara-x-parser` |
| [`generic-array`](https://crates.io/crates/generic-array) | MIT | 78 | `aes`, `cbc`, `des`, `digest`, `hmac`, `md-5`, `pbkdf2`, `sha1`, `sha2` |
| [`gif`](https://crates.io/crates/gif) | MIT OR Apache-2.0 | **none** — `forbid` | `image` |
| [`hashbrown`](https://crates.io/crates/hashbrown) | MIT OR Apache-2.0 | 759 (two versions resolve: 454 + 305) | `mail-parser`, `yara-x-parser`, `zip` |
| [`hashify`](https://crates.io/crates/hashify) | Apache-2.0 OR MIT | **none** | `mail-parser` |
| [`heck`](https://crates.io/crates/heck) | MIT OR Apache-2.0 | **none** — `forbid` | `clap` |
| [`iana-time-zone`](https://crates.io/crates/iana-time-zone) | MIT OR Apache-2.0 | 212 | `delharc` |
| [`indexmap`](https://crates.io/crates/indexmap) | Apache-2.0 OR MIT | 11 | `mail-parser`, `yara-x-parser`, `zip` |
| [`inout`](https://crates.io/crates/inout) | MIT OR Apache-2.0 | 22 | `aes`, `cbc`, `des` |
| [`is_terminal_polyfill`](https://crates.io/crates/is_terminal_polyfill) | MIT OR Apache-2.0 | **none** | `clap` |
| [`itertools`](https://crates.io/crates/itertools) | MIT OR Apache-2.0 | 10 | `yara-x-parser` |
| [`itoa`](https://crates.io/crates/itoa) | MIT OR Apache-2.0 | 13 | `serde_json` |
| [`jpeg-decoder`](https://crates.io/crates/jpeg-decoder) | MIT OR Apache-2.0 | 16 | `image` |
| [`lazy_static`](https://crates.io/crates/lazy_static) | MIT OR Apache-2.0 | 2 | `iced-x86`, `yara-x-parser` |
| [`log`](https://crates.io/crates/log) | MIT OR Apache-2.0 | 6 | `goblin` |
| [`logos`](https://crates.io/crates/logos) | MIT OR Apache-2.0 | 18 | `yara-x-parser` |
| [`logos-codegen`](https://crates.io/crates/logos-codegen) | MIT OR Apache-2.0 | 4 | `yara-x-parser` |
| [`logos-derive`](https://crates.io/crates/logos-derive) | MIT OR Apache-2.0 | **none** | `yara-x-parser` |
| [`miniz_oxide`](https://crates.io/crates/miniz_oxide) | MIT OR Zlib OR Apache-2.0 | **none** — `forbid` | `flate2`, `image`, `zip` |
| [`no_std_io2`](https://crates.io/crates/no_std_io2) | Apache-2.0 OR MIT | 11 | `bitstream-io` |
| [`num-complex`](https://crates.io/crates/num-complex) | MIT OR Apache-2.0 | 2 | `rustdct` |
| [`num-integer`](https://crates.io/crates/num-integer) | MIT OR Apache-2.0 | **none** | `rustdct`, `transpose` |
| [`num-traits`](https://crates.io/crates/num-traits) | MIT OR Apache-2.0 | 1 | `delharc`, `image`, `rmp-serde`, `rustdct`, `transpose`, `yara-x-parser` |
| [`plain`](https://crates.io/crates/plain) | MIT/Apache-2.0 | 23 | `goblin` |
| [`png`](https://crates.io/crates/png) | MIT OR Apache-2.0 | **none** — `forbid` | `image` |
| [`primal-check`](https://crates.io/crates/primal-check) | MIT OR Apache-2.0 | **none** | `rustdct` |
| [`proc-macro2`](https://crates.io/crates/proc-macro2) | MIT OR Apache-2.0 | 6 | `apfs`, `bincode`, `clap`, `goblin`, `hfsplus`, `mail-parser`, `rmp-serde`, `serde`, `thiserror`, `yara-x-parser` |
| [`quote`](https://crates.io/crates/quote) | MIT OR Apache-2.0 | **none** | `apfs`, `bincode`, `clap`, `goblin`, `hfsplus`, `mail-parser`, `rmp-serde`, `serde`, `thiserror`, `yara-x-parser` |
| [`rmp`](https://crates.io/crates/rmp) | MIT | 1 | `rmp-serde` |
| [`rowan`](https://crates.io/crates/rowan) | MIT OR Apache-2.0 | 55 | `yara-x-parser` |
| [`rustc-hash`](https://crates.io/crates/rustc-hash) | Apache-2.0 OR MIT | **none** | `yara-x-parser` |
| [`rustfft`](https://crates.io/crates/rustfft) | MIT OR Apache-2.0 | 1419 | `rustdct` |
| [`same-file`](https://crates.io/crates/same-file) | Unlicense/MIT | 3 | `walkdir` |
| [`scroll`](https://crates.io/crates/scroll) | MIT | 7 | `goblin` |
| [`scroll_derive`](https://crates.io/crates/scroll_derive) | MIT | 1 | `goblin` |
| [`serde_core`](https://crates.io/crates/serde_core) | MIT OR Apache-2.0 | 2 | `bincode`, `rmp-serde`, `serde`, `serde_json` |
| [`serde_derive`](https://crates.io/crates/serde_derive) | MIT OR Apache-2.0 | **none** | `bincode`, `rmp-serde`, `serde` |
| [`simd-adler32`](https://crates.io/crates/simd-adler32) | MIT | 36 | `flate2`, `image`, `zip` |
| [`strength_reduce`](https://crates.io/crates/strength_reduce) | MIT OR Apache-2.0 | **none** | `rustdct`, `transpose` |
| [`strsim`](https://crates.io/crates/strsim) | MIT | **none** — `forbid` | `clap` |
| [`subtle`](https://crates.io/crates/subtle) | BSD-3-Clause | 2 | `digest`, `hmac`, `md-5`, `pbkdf2`, `sha1`, `sha2` |
| [`syn`](https://crates.io/crates/syn) | MIT OR Apache-2.0 | 71 | `apfs`, `bincode`, `clap`, `goblin`, `hfsplus`, `mail-parser`, `rmp-serde`, `serde`, `thiserror`, `yara-x-parser` |
| [`text-size`](https://crates.io/crates/text-size) | MIT OR Apache-2.0 | **none** — `forbid` | `yara-x-parser` |
| [`thiserror-impl`](https://crates.io/crates/thiserror-impl) | MIT OR Apache-2.0 | 1 | `apfs`, `hfsplus`, `thiserror` |
| [`tiff`](https://crates.io/crates/tiff) | MIT | 2 | `image` |
| [`tinyvec`](https://crates.io/crates/tinyvec) | Zlib OR Apache-2.0 OR MIT | **none** — `forbid` | `bzip2-rs`, `stringprep` |
| [`tinyvec_macros`](https://crates.io/crates/tinyvec_macros) | MIT OR Apache-2.0 OR Zlib | **none** — `forbid` | `bzip2-rs`, `stringprep` |
| [`twox-hash`](https://crates.io/crates/twox-hash) | MIT | 72 | `ruzstd` |
| [`typed-path`](https://crates.io/crates/typed-path) | MIT OR Apache-2.0 | 32 | `zip` |
| [`typenum`](https://crates.io/crates/typenum) | MIT OR Apache-2.0 | **none** — `forbid` | `aes`, `cbc`, `des`, `digest`, `hmac`, `md-5`, `pbkdf2`, `sha1`, `sha2` |
| [`unicode-bidi`](https://crates.io/crates/unicode-bidi) | MIT OR Apache-2.0 | 1 | `stringprep` |
| [`unicode-ident`](https://crates.io/crates/unicode-ident) | (MIT OR Apache-2.0) AND Unicode-3.0 | 2 | `apfs`, `bincode`, `clap`, `goblin`, `hfsplus`, `mail-parser`, `rmp-serde`, `serde`, `thiserror`, `yara-x-parser` |
| [`unicode-normalization`](https://crates.io/crates/unicode-normalization) | MIT OR Apache-2.0 | 5 | `stringprep` |
| [`unicode-properties`](https://crates.io/crates/unicode-properties) | MIT/Apache-2.0 | **none** | `stringprep` |
| [`utf8parse`](https://crates.io/crates/utf8parse) | Apache-2.0 OR MIT | 1 | `clap` |
| [`uuid`](https://crates.io/crates/uuid) | Apache-2.0 OR MIT | 9 | `cfb` |
| [`web-time`](https://crates.io/crates/web-time) | MIT OR Apache-2.0 | **none** | `cfb` |
| [`weezl`](https://crates.io/crates/weezl) | MIT OR Apache-2.0 | **none** — `forbid` | `image` |
| [`zmij`](https://crates.io/crates/zmij) | MIT | 74 | `serde_json` |

## Verifying this yourself

Nothing here has to be taken on trust — regenerate the tables above and check
them:

```sh
# Direct + transitive dependencies of the default binary, with licenses.
# --no-dedupe (or --invert <crate>) is what shows every "pulled in by" edge:
cargo tree -p exav-cli -e normal --no-dedupe --format "{p} {l}"

# Audit advisories, bans, and the license allowlist (also run in CI):
cargo deny check
cargo audit
```
