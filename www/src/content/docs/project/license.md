---
title: License
description: exav is MIT-licensed, statically links permissively licensed dependencies, and never bundles the GPL ClamAV signature database.
---

exav is licensed under the MIT License (see
[`LICENSE`](https://github.com/sylvinus/exav/blob/main/LICENSE)): every crate,
and the `@exav/unpack-wasm` and `@exav/viewer` npm packages. What the viewer
bundles, and the engines installed beside it, keep their own licenses (see
[File viewer](/viewer/#license)).

## Third-party notices

The exav binary statically links third-party crates under permissive licenses,
whose required notices are reproduced in
[`NOTICE`](https://github.com/sylvinus/exav/blob/main/NOTICE). A build with the
`http` feature, such as the published image, also links the `ring` TLS
primitives and the `webpki-roots` certificate store. Among the rest:

- exav's [native YARA engine](/scanner/guides/yara/) reuses and adapts the YARA-X parser,
  source and test vectors under BSD-3-Clause, with attribution retained
  ([`crates/exav-core/LICENSE-YARA-X`](https://github.com/sylvinus/exav/blob/main/crates/exav-core/LICENSE-YARA-X)).
  It compiles rules to a native tree-walking evaluator, with no WASM runtime or
  JIT behind it.
- exav also contains code ported or derived from permissively licensed projects
  (RAR, AZO, CAB, DMG, PPMd and bzip2 decoders among them, the HWP3 layout, and
  `iced-x86`'s generated decoder tables), each attributed in `NOTICE`.
- The WASM sandbox runs exav under a WASI runtime you provide, under its own
  license; exav does not bundle it. See the [WASM sandbox guide](/scanner/guides/wasm-sandbox/).

## The GPL signature database

exav does not bundle or redistribute the GPL-licensed ClamAV signature database.
It can read the CVD format (reading a format is interoperability, not
redistribution), but the signatures are fetched by you, with `freshclam` or
`cvdupdate`, or with exav's `--auto-update` from a URL you supply.
See [Signatures](/scanner/guides/signatures/).

exav ships no signature database of its own, only a built-in EICAR test
signature; real detection comes from databases you supply.

## Clean-room provenance

All exav code was written independently from public specifications and
permissively licensed sources, and derives nothing from ClamAV's GPLv2 source.
See [Contributing](/project/contributing/) for the clean-room rule.
