# exav-unpack

A memory-safe, dependency-light **universal archive extractor** CLI, built on the
pure-Rust [`exav-unpack`](../exav-unpack) library (the same extractors the
[exav](../..) malware scanner uses). No native/C dependencies.

## What it does

Auto-detects the container format by magic bytes and **lists** or **extracts**
its members. Supported formats:

`zip` · `rar` (pure-Rust, independent of UnRAR) · `7z` · `cab` · `arj` · `lha/lzh` ·
`tar` · `gzip` · `xz` · `bzip2` · `iso9660` · `cpio` · `ar` · `xar` ·
`ole2` (Office/MSI streams) · `pdf` (stream objects) · `email` (MIME parts) ·
`upx` (decompressed original)

Notably this includes a **pure-Rust RAR and UPX** decompressor — uncommon among
memory-safe tools.

## Usage

```
exav-unpack list <archive>
exav-unpack extract <archive> [output-dir]    # default: current directory
```

Examples:

```console
$ exav-unpack list sample.docx
format: Ole
10 member(s):
         114  /CompObj
         244  /DocumentSummaryInformation
         ...

$ exav-unpack extract payload.rar ./out
format: Rar
./out/dropper.exe (262144 bytes)
```

## Notes

- **Bounded by design**: extraction is capped (recursion depth, total/per-member
  size, file count, compression ratio) to contain decompression bombs.
- **Path-traversal safe**: hostile member names (absolute paths, `..`) are
  reduced to safe relative paths under the output directory before writing.
- **Encrypted archives**: password-protected members can't be decrypted (no
  password) and are skipped — same as ClamAV's behavior.

## Build

```
cargo build --release -p exav-unpack-cli   # binary: target/release/exav-unpack
```
