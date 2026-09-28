---
title: License
description: exav is MIT-licensed, statically links permissively licensed dependencies, and never bundles the GPL ClamAV signature database.
---

exav is licensed under the MIT License (see `LICENSE` in the repository).

## Third-party notices

The exav binary statically links third-party crates under permissive licenses,
whose required notices are reproduced in `NOTICE`. Among them:

- exav's [native YARA engine](/guides/yara/) reuses and adapts the YARA-X parser,
  source and test vectors under BSD-3-Clause, with attribution retained
  (`LICENSE-YARA-X`). It compiles rules to a native tree-walking evaluator, with
  no WASM runtime or JIT behind it.
- The WASM sandbox runs exav under a WASI runtime you provide, under its own
  license; exav does not bundle it. See the [WASM sandbox guide](/guides/wasm-sandbox/).

## The GPL signature database

exav does not bundle or redistribute the GPL-licensed ClamAV signature database.
It can read the CVD format (reading a format is interoperability, not
redistribution), but the signatures are fetched by you with Cisco's own updater.
See [Signatures](/guides/signatures/).

exav ships no signature database of its own, only a built-in EICAR test
signature; real detection comes from databases you supply.

## Clean-room provenance

All exav code was written independently from public specifications and
permissively licensed sources, and derives nothing from ClamAV's GPLv2 source.
See [Contributing](/project/contributing/) for the clean-room rule.
