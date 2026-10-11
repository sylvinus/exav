---
title: Dependencies
description: exav's third-party dependencies, with what the default binary links, each crate's purpose, license and unsafe posture, and exav's memory-safety stance.
---

exav is a security tool, so what it links is part of its threat model. This page
lists the dependencies of the shipped binary (`exav`, default features): the
direct ones first, with what each is for, its license and its `unsafe` posture,
then [every transitive crate](#every-transitive-dependency) with the direct
dependency that pulls it in. The published container image is built with
`http`, so it also carries the
[opt-in dependencies](#opt-in-dependencies-not-in-the-default-binary). The
dependency policy behind these choices is in the repository's
`docs/DEPENDENCIES.md`.

## Memory-safety posture

- **Safe Rust.** Every workspace crate except the `exav` binary is
  `#![forbid(unsafe_code)]`, so the crates that parse hostile input contain no
  `unsafe` of their own.
- **Pure Rust, no C, no JIT.** The default build links no C library and no native
  code generator. Compression (`flate2` with the pure-Rust `miniz_oxide` backend,
  and pure-Rust bzip2, xz, zstd and lzma crates) and crypto are pure Rust. There
  is no wasmtime, Cranelift, OpenSSL or `ring` in the default binary.
- **A network server with no network crates.** The [ICAP server](/scanner/guides/icap/)
  adds no dependency: its framing, chunked decoding and `Encapsulated` parsing
  are written against `std`, in a module that is `#![forbid(unsafe_code)]`, so
  the parsers a hostile client reaches first are exav's own.
- **`unsafe` in dependencies.** Many dependencies use `unsafe` internally: SIMD
  byte search and hashing, OS syscalls (the daemon), and buffer handling in some
  decoders that read scanned bytes (`lzfse_rust`, `ruzstd`, `zip`, `tar`,
  `delharc`, `goblin`). exav's own crates contain none outside the daemon's
  `libc` calls. The tables give a count per crate, and reducing it is on the
  [roadmap](/project/roadmap/).
- **Feature-gated capability.** Optional features (`http-scan`, `http-update`,
  individual formats)
  pull their dependencies only when enabled (see
  [Feature flags](/scanner/reference/feature-flags/)). The network stack is opt-in, and
  it is the only thing that would link a crypto library that is not pure Rust
  (see [Opt-in dependencies](#opt-in-dependencies-not-in-the-default-binary)).

## CLI & runtime (`exav`)

The `unsafe` column is counted the same way as in
[the transitive table](#every-transitive-dependency).

| Crate | Purpose | License | `unsafe` uses |
|---|---|---|---|
| [`clap`](https://crates.io/crates/clap) | Command-line argument parsing | MIT OR Apache-2.0 | **none** (`forbid`) |
| [`serde_json`](https://crates.io/crates/serde_json) | JSON scan-report output | MIT OR Apache-2.0 | 13 |
| [`walkdir`](https://crates.io/crates/walkdir) | Recursive directory traversal | Unlicense OR MIT | **none** |
| [`regex`](https://crates.io/crates/regex) | `--exclude` / `--include` path filters | MIT OR Apache-2.0 | 1 |
| [`libc`](https://crates.io/crates/libc) | Syscall bindings for the prefork daemon (signals, resource limits) | MIT OR Apache-2.0 | 668 (FFI declarations) |

Spilling an oversized object to a temp file is not a dependency: it is
`crates/exav/src/tmpfile.rs`, a page of `std::fs` with the properties that matter
(`O_CREAT|O_EXCL`, so a planted symlink cannot be followed; mode `0600`; delete
on drop). The ready-made crates reach the filesystem through `rustix` and
`linux-raw-sys`, which would add more `unsafe` than the rest of the tree.

## Core engine (`exav-core`)

The engine crate is `#![forbid(unsafe_code)]`; the `unsafe` noted below lives
inside these dependencies, not in exav. The index the signature engine finds
its anchors with, which also serves as YARA's atom prefilter, is exav's own
code, not a dependency.

| Crate | Purpose | License | `unsafe` uses |
|---|---|---|---|
| [`memchr`](https://crates.io/crates/memchr) | Vectorized byte search | Unlicense OR MIT | 333 (SIMD) |
| [`regex`](https://crates.io/crates/regex) | Linear-time regex (PCRE subsignatures, phishing allowlists) | MIT OR Apache-2.0 | 1 |
| [`regex-automata`](https://crates.io/crates/regex-automata) / [`regex-syntax`](https://crates.io/crates/regex-syntax) | Linear-time (DoS-safe) regex engine + parser (YARA regexes, the atom prefilter's required literals) | MIT OR Apache-2.0 | 55 / **none** (`forbid`) |
| [`bit-set`](https://crates.io/crates/bit-set) | For the backtracking regex engine vendored in exav-core (below) | Apache-2.0 OR MIT | 2 |
| [`goblin`](https://crates.io/crates/goblin) | PE / ELF / Mach-O executable parsing | MIT | 34 |
| [`md-5`](https://crates.io/crates/md-5) / [`sha1`](https://crates.io/crates/sha1) / [`sha2`](https://crates.io/crates/sha2) | Hash signatures (whole-file / section digests), and key derivation in `decrypt` | MIT OR Apache-2.0 | 1 / 7 / 50 (CPU-feature detection, SIMD) |
| [`crc32fast`](https://crates.io/crates/crc32fast) | CRC-32 (the `.exavdb` trailer, YARA's `hash` module, archive CRCs) | MIT OR Apache-2.0 | 15 (SIMD) |
| [`base64`](https://crates.io/crates/base64) | Base64 decode (YARA `base64` modifiers; uuencode, email, XDP and embedded payloads in `exav-unpack`) | MIT OR Apache-2.0 | **none** (`forbid`) |
| [`yara-x-parser`](https://crates.io/crates/yara-x-parser) | YARA grammar/AST parser (the native engine's front end) | BSD-3-Clause | 5 |
| [`image`](https://crates.io/crates/image) | Image decoding for `fuzzy_img` hashing, in [exav-imagehash](/subprojects/exav-imagehash/): PNG, GIF, BMP, WebP, ICO, PNM, QOI, DDS, farbfeld and HDR itself, JPEG and TIFF through its decoders vendored there (below) | MIT OR Apache-2.0 | 6, plus its codecs below |
| [`zune-jpeg`](https://crates.io/crates/zune-jpeg) / [`zune-core`](https://crates.io/crates/zune-core) | JPEG decoding for fuzzy image hashing (0.5.8, and 0.4.21 for JPEG-compressed TIFF), built without its SIMD features, which hold all of its `unsafe` | MIT OR Apache-2.0 OR Zlib | **none** (`forbid`) / **none** (two versions of each resolve) |
| [`png`](https://crates.io/crates/png) / [`gif`](https://crates.io/crates/gif) | `image`'s PNG and GIF decoders, required at the versions libclamav links (as are the JPEG and TIFF ones), which `cargo install` would not otherwise hold | MIT OR Apache-2.0 | **none** (`forbid`) / **none** (`forbid`) |
| [`hayro-jpeg2000`](https://crates.io/crates/hayro-jpeg2000) / [`hayro-jbig2`](https://crates.io/crates/hayro-jbig2) | JPEG 2000 and JBIG2 decoding for fuzzy image hashing, in [exav-render](/subprojects/exav-render/), built without their `simd` feature (fearless_simd); `hayro-ccitt`, below, is hayro-jbig2's | Apache-2.0 OR MIT | **none** (`forbid`) / **none** (`forbid`) |
| [`fax`](https://crates.io/crates/fax) / [`weezl`](https://crates.io/crates/weezl) / [`half`](https://crates.io/crates/half) / [`quick-error`](https://crates.io/crates/quick-error) / [`bytemuck`](https://crates.io/crates/bytemuck) | The vendored TIFF decoder's: CCITT fax, LZW, 16-bit floats, error types, byte casts | MIT / MIT OR Apache-2.0 / MIT OR Apache-2.0 / MIT OR Apache-2.0 / Zlib OR Apache-2.0 OR MIT | **none** / **none** (`forbid`) / 84 / **none** / 323 |
| [`tlsh2`](https://crates.io/crates/tlsh2) | TLSH fuzzy hashing | Apache-2.0 OR BSD-3-Clause | **none** |
| [`rmp-serde`](https://crates.io/crates/rmp-serde) / [`rmp`](https://crates.io/crates/rmp) / [`serde`](https://crates.io/crates/serde) | MessagePack encoding of the prebuilt `.exavdb` | MIT / MIT / MIT OR Apache-2.0 | **none** (`forbid`) / 1 / 2 |
| [`rustc-hash`](https://crates.io/crates/rustc-hash) | Fast hashing for internal maps (also in `exav-pe-emu`) | Apache-2.0 OR MIT | **none** |
| [`thiserror`](https://crates.io/crates/thiserror) | Error-type derive | MIT OR Apache-2.0 | **none** |

Some of exav is vendored source instead of dependencies, under its crates'
`forbid(unsafe_code)`, with what changed from upstream in a README beside it:

- exav-core's `src/fancy_regex/`: fancy-regex 0.19.2 (MIT) with two fixes
  merged upstream after it, the backtracking engine for the PCRE
  subsignatures with lookaround, backreferences or atomic groups, under a step
  bound. Without the fixes it matches a byte above `0x7F` as its UTF-8
  encoding.
- [exav-render](/subprojects/exav-render/)'s `src/image_codecs/`, which
  exav-imagehash decodes through: `image` 0.25.9's JPEG and TIFF decoders and
  the decoder of `tiff` 0.10.3 (MIT), so that zune-jpeg is built without its
  SIMD code, which `image` and `tiff` cannot turn off.
- exav-imagehash's `src/pillow.rs`: Pillow 12.3.0's resampler and grey
  conversions (MIT-CMU), ported for its imagehash preset.
- exav-imagehash's `src/dct.rs`: rustdct 0.7.1's DCT-II for power-of-two
  lengths (MIT), with bounds checks where upstream skips them with `unsafe`.
  Other lengths, which rustdct hands to rustfft and its SIMD code, go through
  a Bluestein FFT written there.

`iced-x86` is not linked by any shipped binary. It is a dev-dependency of
[`exav-x86`](/subprojects/exav-x86/) only, the oracle its differential tests,
table generator and fuzz target check against.

## Extraction & decompression (`exav-unpack`)

Also `#![forbid(unsafe_code)]`. The decoders are pure-Rust; there is no C
compression library in the tree. Most of these read scanned bytes. The bzip2
decoder is not a dependency: it is vendored from `bzip2-rs` into
`formats/bzip2_rs`, with a fix for incompressible blocks, and is as
`unsafe`-free as the rest of the crate.

| Crate | Purpose | License | `unsafe` uses |
|---|---|---|---|
| [`flate2`](https://crates.io/crates/flate2) | DEFLATE / gzip / zlib (pure-Rust `miniz_oxide` backend) | MIT OR Apache-2.0 | 36 (no C zlib) |
| [`deflate64`](https://crates.io/crates/deflate64) | Deflate64 (ZIP method 9) | MIT | **none** (`forbid`) |
| [`xz4rust`](https://crates.io/crates/xz4rust) | XZ (`.xz`, ZIP method 95, DMG) | MIT | 3 |
| [`lzma-rust2`](https://crates.io/crates/lzma-rust2) | LZMA / LZMA2 (7z, lzip, ZIP method 14, SWF, NSIS, UPX, EGG) | Apache-2.0 | 14 |
| [`ruzstd`](https://crates.io/crates/ruzstd) | Zstandard (pure Rust) | MIT | 39 |
| [`lzxd`](https://crates.io/crates/lzxd) | LZX (CAB) | MIT OR Apache-2.0 | **none** |
| [`lzfse_rust`](https://crates.io/crates/lzfse_rust) | LZFSE / LZVN (DMG) | MIT OR Apache-2.0 | 435 |
| [`delharc`](https://crates.io/crates/delharc) | LHA / LZH | MIT OR Apache-2.0 | 19 |
| [`bitstream-io`](https://crates.io/crates/bitstream-io) | Bit-level readers for decoders | MIT OR Apache-2.0 | **none** (`forbid`) |
| [`tar`](https://crates.io/crates/tar) | tar archives (`xattr` disabled, which drops its syscall crates) | MIT OR Apache-2.0 | 26 |
| [`zip`](https://crates.io/crates/zip) | ZIP container parsing | MIT | 32 |
| [`cfb`](https://crates.io/crates/cfb) | OLE2 / Compound File Binary (Office) | MIT | **none** |
| [`encoding_rs`](https://crates.io/crates/encoding_rs) | the code pages of DXF and DWG drawings before 2007, Asian double-byte ones included (features `dxf`, `dwg`), built without `simd-accel` | (Apache-2.0 OR MIT) AND BSD-3-Clause | 193 |
| [`quick-xml`](https://crates.io/crates/quick-xml) | OOXML / XML parsing | MIT | **none** (`forbid`) |
| [`mail-parser`](https://crates.io/crates/mail-parser) | MIME / email parsing | Apache-2.0 OR MIT | **none** (`forbid`) |
| [`apfs`](https://crates.io/crates/apfs) / [`hfsplus`](https://crates.io/crates/hfsplus) | DMG filesystem parsing | MIT | **none** |
| [`ext4-view`](https://crates.io/crates/ext4-view) | ext2/3/4 filesystem walking (virtual disks) | MIT OR Apache-2.0 | **none** (`forbid`) |
| [`fatfs`](https://crates.io/crates/fatfs) | FAT12/16/32 cluster-chain walking | MIT | 11 |
| [`lznt1`](https://crates.io/crates/lznt1) | LZNT1 (NTFS compressed streams) | MIT | **none** (`forbid`) |
| [`salzweg`](https://crates.io/crates/salzweg) | LZW (ZOO, Unix `compress`) | MIT | **none** |
| [`unshield`](https://crates.io/crates/unshield) | InstallShield `.z` archives | MIT | **none** |
| [`tinyvec`](https://crates.io/crates/tinyvec) | Inline vectors for the vendored bzip2 decoder | Zlib OR Apache-2.0 OR MIT | **none** (`forbid`) |
| [`byteorder`](https://crates.io/crates/byteorder) | Byte-order reads | Unlicense OR MIT | 40 |

### Cryptographic primitives (the `decrypt` feature)

Used only to decrypt encrypted members (see
[Encryption support](/unpack/formats/#encryption-support)). These are
[RustCrypto](https://github.com/RustCrypto) crates; their residual `unsafe` is
SIMD (AES-NI) and CPU-feature detection.

| Crate | Purpose | License | `unsafe` uses |
|---|---|---|---|
| [`aes`](https://crates.io/crates/aes) / [`cbc`](https://crates.io/crates/cbc) | AES block cipher + CBC (ZIP, 7z, PDF, DMG, Office) | MIT OR Apache-2.0 | 60 / **none** |
| [`des`](https://crates.io/crates/des) | Triple DES (encrypted DMG key unwrap) | MIT OR Apache-2.0 | **none** |
| [`hmac`](https://crates.io/crates/hmac) / [`pbkdf2`](https://crates.io/crates/pbkdf2) / [`digest`](https://crates.io/crates/digest) | Key derivation + MAC | MIT OR Apache-2.0 | **none** / **none** / **none** (`forbid`) |
| [`constant_time_eq`](https://crates.io/crates/constant_time_eq) | Constant-time comparison | CC0-1.0 OR MIT-0 OR Apache-2.0 | 2 |
| [`stringprep`](https://crates.io/crates/stringprep) | Password normalization | MIT OR Apache-2.0 | **none** |

## Opt-in dependencies (not in the default binary)

Enabled only by `http-scan` (URL scanning, through `exav-core`) or
`http-update` (signature auto-update, through the
[`exav-update`](/subprojects/exav-update/) crate); `http` enables both. The
published container image is built with `http`; the release binaries are not.

| Crate | Purpose | License | Note |
|---|---|---|---|
| [`ureq`](https://crates.io/crates/ureq) | Minimal blocking HTTP(S) client | MIT OR Apache-2.0 | pulls `ureq-proto`, `http`, `rustls` → [`ring`](https://crates.io/crates/ring) |

`exav-update` also uses `sha2` and `crc32fast`, which the default build already
links. `ring` bundles C and assembly crypto; it is the one component exav can
pull that is not pure Rust, which is why HTTP is off by default.

## Every transitive dependency

The tables above are the crates exav chose. The real supply chain is the whole
closure, so here is every remaining crate in the default `exav` build, with the
direct dependencies that pull it in. Count the packages against the current
lockfile with:

```sh
cargo tree -e no-dev -p exav --prefix none | sed 's/ (\*)$//' \
  | awk '{print $1}' | sort -u | wc -l
```

Seven of those are exav's own workspace crates (`exav`, `exav-core`,
`exav-unpack`, `exav-imagehash`, `exav-render`, `exav-pe-emu`, `exav-x86`), and a few crates resolve at two
versions. None is a C library, a TLS stack or a code generator; `syn`, `quote`
and `proc-macro2` are build-time proc-macro machinery, and `autocfg`,
`rustc_version` and `semver` run only in build scripts, so none of them has
runtime code in the binary.

The `unsafe` column counts occurrences of the `unsafe` keyword in each crate's
shipped `src/` (comments stripped; tests, benches and examples excluded) at the
version resolved when the table was written. Read it as surface to review, not as
risk. Most of it is in `hashbrown` and `bytemuck`, neither of which parses
scanned bytes, and in `zerocopy` (with its derive macro), which `half` pulls
in, and `moxcms`, which `image` does. There are
no raw-syscall binding crates: `rustix` and `linux-raw-sys` are kept out by
[writing the spill file in-tree](#cli--runtime-exav) and by building `tar`
without `xattr`. Reproduce the counts with `cargo geiger`, or per crate with:

```sh
find ~/.cargo/registry/src/*/<crate>-<version>/src -name '*.rs' -print0 \
  | xargs -0 sed 's://.*$::' | grep -cw unsafe
```

| Crate | License | `unsafe` uses | Pulled in by |
|---|---|---|---|
| [`adler2`](https://crates.io/crates/adler2) | 0BSD OR MIT OR Apache-2.0 | **none** (`forbid`) | `flate2`, `image`, `png`, `zip` |
| [`aho-corasick`](https://crates.io/crates/aho-corasick) | Unlicense OR MIT | 227 | `regex`, `regex-automata`, `yara-x-parser` |
| [`anstream`](https://crates.io/crates/anstream) | MIT OR Apache-2.0 | 3 | `clap` |
| [`anstyle`](https://crates.io/crates/anstyle) | MIT OR Apache-2.0 | 1 | `clap` |
| [`anstyle-parse`](https://crates.io/crates/anstyle-parse) | MIT OR Apache-2.0 | 3 | `clap` |
| [`anstyle-query`](https://crates.io/crates/anstyle-query) | MIT OR Apache-2.0 | 1 | `clap` |
| [`arraydeque`](https://crates.io/crates/arraydeque) | MIT/Apache-2.0 | 77 | `unshield` |
| [`ascii_tree`](https://crates.io/crates/ascii_tree) | MIT | **none** | `yara-x-parser` |
| [`beef`](https://crates.io/crates/beef) | MIT OR Apache-2.0 | 26 | `yara-x-parser` |
| [`bit-vec`](https://crates.io/crates/bit-vec) | Apache-2.0 OR MIT | 4 | `bit-set` |
| [`autocfg`](https://crates.io/crates/autocfg) | Apache-2.0 OR MIT | **none** | build-time: `num-traits` and its users |
| [`bitflags`](https://crates.io/crates/bitflags) | MIT OR Apache-2.0 | 21 (two versions resolve: 19 + 2) | `delharc`, `ext4-view`, `fatfs`, `image`, `png`, `yara-x-parser` |
| [`block-buffer`](https://crates.io/crates/block-buffer) | MIT OR Apache-2.0 | 21 | `digest`, `hmac`, `md-5`, `pbkdf2`, `sha1`, `sha2` |
| [`block-padding`](https://crates.io/crates/block-padding) | MIT OR Apache-2.0 | **none** | `aes`, `cbc`, `des` |
| [`bstr`](https://crates.io/crates/bstr) | MIT OR Apache-2.0 | 39 | `yara-x-parser` |
| [`byteorder-lite`](https://crates.io/crates/byteorder-lite) | Unlicense OR MIT | 1 | `image` |
| [`cfg-if`](https://crates.io/crates/cfg-if) | MIT OR Apache-2.0 | **none** | `crc32fast`, `flate2`, `half`, `image`, `md-5`, `png`, `sha1`, `sha2`, `tar`, `zip` |
| [`chrono`](https://crates.io/crates/chrono) | MIT OR Apache-2.0 | 11 | `delharc` |
| [`cipher`](https://crates.io/crates/cipher) | MIT OR Apache-2.0 | **none** (`forbid`) | `aes`, `cbc`, `des` |
| [`clap_builder`](https://crates.io/crates/clap_builder) | MIT OR Apache-2.0 | **none** (`forbid`) | `clap` |
| [`clap_derive`](https://crates.io/crates/clap_derive) | MIT OR Apache-2.0 | **none** (`forbid`) | `clap` |
| [`clap_lex`](https://crates.io/crates/clap_lex) | MIT OR Apache-2.0 | 6 | `clap` |
| [`cmov`](https://crates.io/crates/cmov) | Apache-2.0 OR MIT | 25 | `digest`, `hmac`, `md-5`, `pbkdf2`, `sha1`, `sha2` |
| [`color_quant`](https://crates.io/crates/color_quant) | MIT | **none** | `gif`, `image` |
| [`colorchoice`](https://crates.io/crates/colorchoice) | MIT OR Apache-2.0 | **none** | `clap` |
| [`const-oid`](https://crates.io/crates/const-oid) | Apache-2.0 OR MIT | 1 | `digest`, `hmac`, `md-5`, `pbkdf2`, `sha1`, `sha2` |
| [`countme`](https://crates.io/crates/countme) | MIT OR Apache-2.0 | 1 | `yara-x-parser` |
| [`cpubits`](https://crates.io/crates/cpubits) | MIT OR Apache-2.0 | **none** | `aes` |
| [`cpufeatures`](https://crates.io/crates/cpufeatures) | MIT OR Apache-2.0 | 11 | `aes`, `sha1`, `sha2` |
| [`crc`](https://crates.io/crates/crc) | MIT OR Apache-2.0 | **none** (`forbid`) | `ext4-view` |
| [`crc-catalog`](https://crates.io/crates/crc-catalog) | MIT OR Apache-2.0 | **none** (`forbid`) | `ext4-view` |
| [`crypto-common`](https://crates.io/crates/crypto-common) | MIT OR Apache-2.0 | **none** (`forbid`) | `aes`, `cbc`, `des`, `digest`, `hmac`, `md-5`, `pbkdf2`, `sha1`, `sha2` |
| [`ctutils`](https://crates.io/crates/ctutils) | Apache-2.0 OR MIT | **none** (`forbid`) | `digest`, `hmac`, `md-5`, `pbkdf2`, `sha1`, `sha2` |
| [`either`](https://crates.io/crates/either) | MIT OR Apache-2.0 | 2 | `yara-x-parser` |
| [`equivalent`](https://crates.io/crates/equivalent) | Apache-2.0 OR MIT | **none** | `mail-parser`, `yara-x-parser`, `zip` |
| [`explode`](https://crates.io/crates/explode) | MIT | 5 | `unshield` |
| [`fax_derive`](https://crates.io/crates/fax_derive) | MIT | **none** | `fax` |
| [`fdeflate`](https://crates.io/crates/fdeflate) | MIT OR Apache-2.0 | **none** (`forbid`) | `image`, `png` |
| [`filetime`](https://crates.io/crates/filetime) | MIT/Apache-2.0 | 9 | `tar` |
| [`fnv`](https://crates.io/crates/fnv) | Apache-2.0 / MIT | **none** | `cfb`, `yara-x-parser` |
| [`hashbrown`](https://crates.io/crates/hashbrown) | MIT OR Apache-2.0 | 751 (two versions resolve: 450 + 301) | `mail-parser`, `yara-x-parser`, `zip` |
| [`hashify`](https://crates.io/crates/hashify) | Apache-2.0 OR MIT | **none** | `mail-parser` |
| [`hayro-ccitt`](https://crates.io/crates/hayro-ccitt) | Apache-2.0 OR MIT | **none** (`forbid`) | `hayro-jbig2` |
| [`heck`](https://crates.io/crates/heck) | MIT OR Apache-2.0 | **none** (`forbid`) | `clap` |
| [`hybrid-array`](https://crates.io/crates/hybrid-array) | MIT OR Apache-2.0 | 37 | `aes`, `cbc`, `des`, `digest`, `hmac`, `md-5`, `pbkdf2`, `sha1`, `sha2` |
| [`iana-time-zone`](https://crates.io/crates/iana-time-zone) | MIT OR Apache-2.0 | 212 | `delharc` |
| [`image-webp`](https://crates.io/crates/image-webp) | MIT OR Apache-2.0 | **none** (`forbid`) | `image` |
| [`indexmap`](https://crates.io/crates/indexmap) | Apache-2.0 OR MIT | 12 | `mail-parser`, `yara-x-parser`, `zip` |
| [`inout`](https://crates.io/crates/inout) | MIT OR Apache-2.0 | 30 | `aes`, `cbc`, `des` |
| [`is_terminal_polyfill`](https://crates.io/crates/is_terminal_polyfill) | MIT OR Apache-2.0 | **none** | `clap` |
| [`itertools`](https://crates.io/crates/itertools) | MIT OR Apache-2.0 | 10 | `yara-x-parser` |
| [`itoa`](https://crates.io/crates/itoa) | MIT OR Apache-2.0 | 13 | `serde_json` |
| [`lazy_static`](https://crates.io/crates/lazy_static) | MIT OR Apache-2.0 | 2 | `yara-x-parser` |
| [`log`](https://crates.io/crates/log) | MIT OR Apache-2.0 | 6 | `fatfs`, `goblin` |
| [`logos`](https://crates.io/crates/logos) | MIT OR Apache-2.0 | 18 | `yara-x-parser` |
| [`logos-codegen`](https://crates.io/crates/logos-codegen) | MIT OR Apache-2.0 | 4 | `yara-x-parser` |
| [`logos-derive`](https://crates.io/crates/logos-derive) | MIT OR Apache-2.0 | **none** | `yara-x-parser` |
| [`miniz_oxide`](https://crates.io/crates/miniz_oxide) | MIT OR Zlib OR Apache-2.0 | **none** (`forbid`; two versions resolve) | `flate2`, `image`, `png`, `zip` |
| [`moxcms`](https://crates.io/crates/moxcms) | BSD-3-Clause OR Apache-2.0 | 344 | `image` |
| [`no_std_io2`](https://crates.io/crates/no_std_io2) | Apache-2.0 OR MIT | 11 | `bitstream-io`, `zip` |
| [`num-traits`](https://crates.io/crates/num-traits) | MIT OR Apache-2.0 | 1 | `delharc`, `image`, `rmp`, `rmp-serde`, `yara-x-parser` |
| [`plain`](https://crates.io/crates/plain) | MIT/Apache-2.0 | 23 | `goblin` |
| [`proc-macro2`](https://crates.io/crates/proc-macro2) | MIT OR Apache-2.0 | 6 | `apfs`, `clap`, `fax`, `goblin`, `half`, `hfsplus`, `lznt1`, `mail-parser`, `rmp-serde`, `serde`, `thiserror`, `yara-x-parser` |
| [`pxfm`](https://crates.io/crates/pxfm) | BSD-3-Clause OR Apache-2.0 | 224 | `image` |
| [`qoi`](https://crates.io/crates/qoi) | MIT/Apache-2.0 | **none** (`forbid`) | `image` |
| [`quote`](https://crates.io/crates/quote) | MIT OR Apache-2.0 | **none** | `apfs`, `clap`, `fax`, `goblin`, `half`, `hfsplus`, `lznt1`, `mail-parser`, `rmp-serde`, `serde`, `thiserror`, `yara-x-parser` |
| [`rowan`](https://crates.io/crates/rowan) | MIT OR Apache-2.0 | 55 | `yara-x-parser` |
| [`rustc-hash`](https://crates.io/crates/rustc-hash) | Apache-2.0 OR MIT | **none** | a second version (1.x) for `yara-x-parser` |
| [`rustc_version`](https://crates.io/crates/rustc_version) | MIT OR Apache-2.0 | **none** | build-time: `yara-x-parser` |
| [`same-file`](https://crates.io/crates/same-file) | Unlicense/MIT | 3 | `walkdir` |
| [`scroll`](https://crates.io/crates/scroll) | MIT | 7 | `goblin` |
| [`scroll_derive`](https://crates.io/crates/scroll_derive) | MIT | 1 | `goblin` |
| [`semver`](https://crates.io/crates/semver) | MIT OR Apache-2.0 | 47 | build-time: `yara-x-parser` |
| [`serde_core`](https://crates.io/crates/serde_core) | MIT OR Apache-2.0 | 2 | `rmp-serde`, `serde`, `serde_json` |
| [`serde_derive`](https://crates.io/crates/serde_derive) | MIT OR Apache-2.0 | **none** | `rmp-serde`, `serde` |
| [`simd-adler32`](https://crates.io/crates/simd-adler32) | MIT | 36 | `flate2`, `image`, `png`, `zip` |
| [`strsim`](https://crates.io/crates/strsim) | MIT | **none** (`forbid`) | `clap` |
| [`syn`](https://crates.io/crates/syn) | MIT OR Apache-2.0 | 152 (two versions resolve: 71 + 81) | `apfs`, `clap`, `fax`, `goblin`, `half`, `hfsplus`, `lznt1`, `mail-parser`, `rmp-serde`, `serde`, `thiserror`, `yara-x-parser` |
| [`text-size`](https://crates.io/crates/text-size) | MIT OR Apache-2.0 | **none** (`forbid`) | `yara-x-parser` |
| [`thiserror-impl`](https://crates.io/crates/thiserror-impl) | MIT OR Apache-2.0 | 1 | `apfs`, `hfsplus`, `lznt1`, `thiserror` |
| [`twox-hash`](https://crates.io/crates/twox-hash) | MIT | 72 | `ruzstd` |
| [`typed-path`](https://crates.io/crates/typed-path) | MIT OR Apache-2.0 | 32 | `zip` |
| [`typenum`](https://crates.io/crates/typenum) | MIT OR Apache-2.0 | **none** (`forbid`) | `aes`, `cbc`, `des`, `digest`, `hmac`, `md-5`, `pbkdf2`, `sha1`, `sha2` |
| [`unicode-bidi`](https://crates.io/crates/unicode-bidi) | MIT OR Apache-2.0 | 1 | `stringprep` |
| [`unicode-ident`](https://crates.io/crates/unicode-ident) | (MIT OR Apache-2.0) AND Unicode-3.0 | 2 | `apfs`, `clap`, `fax`, `goblin`, `half`, `hfsplus`, `lznt1`, `mail-parser`, `rmp-serde`, `serde`, `thiserror`, `yara-x-parser` |
| [`unicode-normalization`](https://crates.io/crates/unicode-normalization) | MIT OR Apache-2.0 | 5 | `stringprep` |
| [`unicode-properties`](https://crates.io/crates/unicode-properties) | MIT/Apache-2.0 | **none** | `stringprep` |
| [`utf8parse`](https://crates.io/crates/utf8parse) | Apache-2.0 OR MIT | 1 | `clap` |
| [`uuid`](https://crates.io/crates/uuid) | Apache-2.0 OR MIT | 15 | `cfb` |
| [`web-time`](https://crates.io/crates/web-time) | MIT OR Apache-2.0 | **none** | `cfb` |
| [`zerocopy`](https://crates.io/crates/zerocopy) | BSD-2-Clause OR Apache-2.0 OR MIT | 482 | `half` |
| [`zerocopy-derive`](https://crates.io/crates/zerocopy-derive) | BSD-2-Clause OR Apache-2.0 OR MIT | 807 | `half` |
| [`zmij`](https://crates.io/crates/zmij) | MIT | 70 | `serde_json` |

## Verifying this yourself

Regenerate the tables above and check them:

```sh
# Direct + transitive dependencies of the default binary, with licenses.
# --no-dedupe (or --invert <crate>) is what shows every "pulled in by" edge:
cargo tree -p exav -e normal --no-dedupe --format "{p} {l}"

# Audit advisories, bans, and the license allowlist (also run in CI):
cargo deny check
cargo audit
```
