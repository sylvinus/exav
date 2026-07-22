---
title: exav-update
description: Standalone signature-database updater — fetch ClamAV-format CVD containers and third-party feeds without running the scanner.
---

**A signature fetcher you can run on its own.** Pulls ClamAV-format `.cvd`/`.cld`
containers and loose signature files from any mirror or custom URL, so a build
pipeline or an image-bake step can populate a database directory without the
scanner present.

```bash
cargo add exav-update   # or use the `exav` binary's own update paths
```

## What it does

- Fetches from a mirror, a private mirror, or explicit `DatabaseCustomURL`-style
  sources — including straight from an existing `freshclam.conf`, whose *source*
  directives it understands.
- Writes a plain directory of signature files that
  [exav-core](/subprojects/exav-core/) loads directly.
- Composes with the [prebuilt database](/guides/prebuilt-database/): fetch once,
  compile once, ship a single file that loads in seconds.

## What it is not

It is **not a freshclam replacement**. There is no `.cdiff` incremental
patching, no DNS `TXT` version probing, and no GPG verification — updates are
full reloads. `freshclam` and `cvdupdate` remain the supported updaters, and
exav reads what they produce; this crate exists for the cases where running
either is awkward.

That limitation is deliberate and documented rather than papered over — see the
[roadmap](/project/roadmap/).
