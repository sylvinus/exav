---
title: Subprojects
description: The smaller pieces built alongside the exav scanner, each usable on its own, from grep inside archives, perceptual image hashes and the x86 emulator to the scanning engine as a library, the renderer, the decoder and the updater library.
---

exav is a workspace of focused pieces rather than one binary. Besides the three
products ([malware scanning](/scanner/getting-started/introduction/),
[archive extraction](/unpack/) and the [file viewer](/viewer/)), these
are useful without ever running a virus scan.

## Tools

| Crate | What it is |
|---|---|
| [exav-grep](/subprojects/exav-grep/) | grep for the inside of archives: search recursively through zip/rar/7z/tar/iso/OLE/PDF/email members |
| [exav-imagehash](/subprojects/exav-imagehash/) | Perceptual image hashes with every step a parameter, reproducing ClamAV's `fuzzy_img` hash and Python imagehash's `phash` bit for bit, as a library and a CLI |
| [exav-pe-emu](/subprojects/exav-pe-emu/) | A sandboxed x86-32 emulator that unpacks packed Windows executables by running their stub, as a library and a CLI |

## Libraries

| Crate | What it is |
|---|---|
| [exav-core](/subprojects/exav-core/) | The scanning engine: database parsing, pattern and hash matching, file typing, and the verdict model, to embed in a program |
| [exav-render](/subprojects/exav-render/) | Memory-safe decoders that turn raster images, DWG and DXF drawings and IFC and STL models into something to draw, behind `@exav/viewer` and exav-imagehash |
| [exav-x86](/subprojects/exav-x86/) | A decode-only x86-32 instruction decoder with no dependencies, checked against an independent decoder over real samples |
| [exav-update](/subprojects/exav-update/) | The signature-fetching library behind `--auto-update` |

The products' own packages are documented with them:
[exav-unpack](/unpack/rust/) and
[`@exav/unpack-wasm`](/unpack/wasm/) under Archive extraction,
[`@exav/viewer`](/viewer/) under File viewer. `exav`, the scanner's
binary, publishes no library: embed `exav-core` instead.

[Technical architecture](/project/architecture/) shows how they depend on each
other, and why each is a crate of its own.
