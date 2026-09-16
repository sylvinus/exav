# exav

**A fast, memory-safe malware scanner written in Rust.**

exav scans files of any size in constant memory, reads ClamAV's signature
databases, and answers the `clamd` and ICAP wire protocols — so it drops into
an existing ClamAV setup without changing what talks to it. It prints
`clamscan`'s output format; its flags are its own.

One deliberate difference: a file exav could not fully examine is never
reported clean. It gets status `PARTIAL` (exit 3) instead of ClamAV's `OK`
(see [Verdicts & exit codes](https://exav.org/reference/verdicts/)).

```sh
cargo install exav
```

exav ships **no signatures** (the ClamAV database is GPL) — with none loaded,
it refuses to run rather than report clean.

**Full documentation: [exav.org](https://exav.org).** Start here:
[Install](https://exav.org/getting-started/installation/),
[Quick start](https://exav.org/getting-started/quick-start/),
[Migrating from ClamAV](https://exav.org/guides/migrating-from-clamav/),
[CLI reference](https://exav.org/reference/cli/).

> **Status: beta.** Tested hard — differentially against ClamAV, plus fuzzing —
> but young. Please report anything that looks wrong.

- **Library** — [using exav as a Rust library](https://exav.org/guides/library-usage/).
  The `exav-core` API is `0.0.x` and may break in any release.
- **Contributing** — see [`CONTRIBUTING.md`](CONTRIBUTING.md) and the
  [guide](https://exav.org/project/contributing/). Clean-room rule: nothing
  derived from ClamAV's GPL sources.
- **Security** — see [`SECURITY.md`](SECURITY.md). **License** — [MIT](LICENSE).
