---
title: License
description: exav is MIT-licensed, statically links permissively-licensed dependencies, and never bundles the GPL ClamAV signature database.
---

exav is licensed under the **MIT License** — see `LICENSE` in the repository.

## Third-party notices

The exav binary statically links third-party crates under permissive licenses.
Their required notices are reproduced in `NOTICE`. Among them:

- exav's [native YARA engine](/guides/yara/) reuses and adapts the permissively
  licensed **YARA-X** parser, source, and test vectors under **BSD-3-Clause**,
  with attribution retained (`LICENSE-YARA-X`). It compiles rules to a native
  tree-walking evaluator, so the dependency tree stays lean and pure-Rust — no
  WASM runtime or JIT subtree.
- The optional WASM sandbox runs exav under a WASI runtime **you** provide (your
  own audited runtime, under its own license); exav does not bundle it. See the
  [WASM sandbox guide](/guides/wasm-sandbox/).

## The GPL signature database

exav **never bundles or redistributes** the GPL-licensed ClamAV signature
database. exav ships under MIT and can *read* the CVD format — reading a format is
interoperability, not redistribution — but the signatures themselves are fetched
by **you** at runtime with Cisco's own updater. See
[Signatures](/guides/signatures/).

exav ships with **no** signature database of its own — only a tiny built-in test
signature (EICAR). Real detection comes entirely from databases you supply.

## Clean-room provenance

All exav code was written independently from public specifications and
permissively-licensed sources — it derives nothing from ClamAV's GPLv2 source.
See [Contributing](/project/contributing/) for the clean-room rule.
