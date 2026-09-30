---
title: exav-update
description: The signature-fetching library behind exav's --auto-update, for a Rust build pipeline or image-bake step that needs ClamAV-format databases or a prebuilt .exavdb.
---

**A signature-fetching library**, for a build pipeline or image-bake step written
in Rust. It is what `exav --auto-update` fetches with, and it ships no binary of
its own: from the command line, use `exav --auto-update --sig-sources <URL>`.

```bash
cargo add exav-update
```

## What it does

- `fetch_signature_if_changed(url, sigdir, prev)` fetches one signature source
  (a `.cvd`/`.cld` container or a loose signature file) into
  `<sigdir>/env/<host>/…`, with a conditional GET that transfers nothing when the
  file has not changed. A `.cvd` must carry its `ClamAV-VDB:` header, and
  anything that looks like an HTML or JSON error page is refused.
- `fetch_db_if_changed(url, dest, prev)` pulls a
  [prebuilt `.exavdb`](/guides/prebuilt-database/), checks its length and
  trailing SHA-256, and installs it with an atomic rename.
- `prune_env_sources` removes files for sources no longer configured, and
  `sig_dest` / `url_basename` say where a URL will land.

```rust
use exav_update::fetch_signature_if_changed;

let sigdir = std::path::Path::new("/var/lib/exav");
let mut validator: Option<String> = None;
let f = fetch_signature_if_changed("https://mirror.internal/daily.cvd", sigdir, validator.as_deref())?;
validator = f.validator().map(String::from); // pass back next time
if f.is_updated() {
    println!("daily.cvd changed");
}
```

The directory it writes loads directly in [exav-core](/subprojects/exav-core/).
Reading a `freshclam.conf` for its source directives is done by the `exav`
binary, not by this crate.

## What it is not

It is not a `freshclam` replacement: no `.cdiff` patching, no DNS `TXT` version
probing, and no verification of a database's signature (`dsig`); updates are
full downloads. `freshclam` and `cvdupdate` remain the supported updaters, and
Cisco's CDN serves only them: point this crate at a mirror you run.
