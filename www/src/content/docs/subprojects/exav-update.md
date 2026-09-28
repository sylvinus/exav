---
title: exav-update
description: A standalone signature-database updater that fetches ClamAV-format CVD containers and third-party feeds without running the scanner.
---

**A signature fetcher you can run on its own.** It pulls ClamAV-format
`.cvd`/`.cld` containers and loose signature files from any mirror or custom URL,
so a build pipeline or an image-bake step can populate a database directory
without the scanner.

```bash
cargo add exav-update   # or use the `exav` binary's own update paths
```

## What it does

- Fetches from a mirror, a private mirror, or explicit `DatabaseCustomURL`-style
  sources, including the source directives of an existing `freshclam.conf`.
- Writes a plain directory of signature files that
  [exav-core](/subprojects/exav-core/) loads directly.
- Composes with the [prebuilt database](/guides/prebuilt-database/): fetch once,
  compile once, ship one file.

## What it is not

It is not a `freshclam` replacement: no `.cdiff` patching, no DNS `TXT` version
probing, and no verification of a database's signature (`dsig`); updates are
full reloads. `freshclam` and `cvdupdate` remain the supported updaters, and exav
reads what they produce; this crate is for the cases where running either is
awkward.
