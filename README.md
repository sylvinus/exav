# exav

**Memory-safe tools for untrusted files.** Scan them for malware, unpack them,
and view them in the browser.

exav is a set of tools for files you did not write and should not trust: an
attachment, an upload, a download. They are built on the same parsers,
written in safe Rust, and each bounds the work a hostile file can cause. Each
tool is usable on its own.

**Documentation: [exav.org](https://exav.org).**

## Malware scanning: `exav`

A scanner, daemon and ICAP server that reads ClamAV's signature databases and
answers the `clamd` and ICAP protocols, so it drops into an existing ClamAV
setup without changing what talks to it. A file it could not fully examine is
never reported clean: it gets status `PARTIAL` (exit 3) where ClamAV says `OK`.

```sh
cargo install exav
```

exav ships **no signatures** (the ClamAV database is GPL); with none loaded, it
refuses to run rather than report clean.
[Quick start](https://exav.org/scanner/getting-started/quick-start/) ·
[Migrating from ClamAV](https://exav.org/scanner/guides/migrating-from-clamav/) ·
[README](crates/exav/README.md)

## Archive extraction: `exav-unpack`

Bounded extraction of archives, disk images, documents and packed
executables: ZIP, 7z, RAR, tar, ISO, DMG, virtual disks and their
filesystems, and many more. A command with `unzip`'s options, a Rust crate,
and `@exav/unpack-wasm` for browsers and Node.

```sh
cargo install exav-unpack
```

[Overview](https://exav.org/unpack/) ·
[README](crates/exav-unpack/README.md) ·
[`@exav/unpack-wasm` README](crates/exav-unpack-wasm/README.md)

## File viewer: `@exav/viewer`

A file viewer for the browser: PDF, images, DWG and DXF drawings, Office
documents, IFC and STL models, media and archives. Each file can open in a
sandboxed frame of its own, and exav's own decoders run in WebAssembly.

```sh
npm install @exav/viewer
```

[Overview](https://exav.org/viewer/) ·
[Live demo](https://exav.org/viewer/demo/) ·
[README](crates/exav-viewer/README.md)

## Subprojects

| Crate | What it is |
|---|---|
| [`exav-grep`](crates/exav-grep/README.md) | `grep`, but it can see inside archives |
| [`exav-core`](crates/exav-core/README.md) | The scanning engine, as a Rust library |
| [`exav-render`](crates/exav-render/README.md) | The decoders behind the viewer: images, DWG, DXF, IFC, STL |
| [`exav-imagehash`](crates/exav-imagehash/README.md) | Perceptual image hashes, ClamAV's `fuzzy_img` among them |
| [`exav-pe-emu`](crates/exav-pe-emu/README.md) | A bounded x86-32 emulator that runs packer stubs to unpack them |
| [`exav-x86`](crates/exav-x86/README.md) | A decode-only x86-32 instruction decoder |
| [`exav-update`](crates/exav-update/README.md) | A standalone signature-database fetcher |

[Technical architecture](https://exav.org/project/architecture/) shows how
they depend on each other.

> **Status: beta.** Tested differentially against ClamAV and fuzzed, but young.
> The Rust APIs are `0.0.x` and may break in any release. Please report
> anything that looks wrong.

- **Contributing:** see [`CONTRIBUTING.md`](CONTRIBUTING.md) and the
  [guide](https://exav.org/project/contributing/). Clean-room rule: nothing
  derived from ClamAV's GPL sources.
- **Security:** see [`SECURITY.md`](SECURITY.md). **License:** [MIT](LICENSE).
