# exav

**A fast, memory-safe malware scanner.** A scanning CLI and a `clamd`- and
ICAP-compatible daemon, loading ClamAV's own signature databases, with no
file-size limit.

This crate is the `exav` binary. It reads `.cvd`/`.cld`, `.ndb`/`.ldb`/`.hdb`/…
and YARA `.yar`/`.yara`, and answers the `clamd` wire protocol — so `clamdscan`,
milters and existing client libraries talk to it unchanged. It prints
`clamscan`'s output format; its flags are its own, and one `clamscan` has that
exav lacks stops the run rather than being ignored.

```sh
cargo install exav

exav file.bin                      # scan one file
exav /var/www                      # scan a directory, recursively
cat file.zip | exav -              # scan stdin (constant memory, any size)
exav -d /var/lib/clamav /data      # use an existing ClamAV signature directory
exav --listen 0.0.0.0:3310 -d /var/lib/exav       # serve the clamd protocol
```

Two things it does that ClamAV does not. **A file too large to scan is never
reported clean** — anything that stops a full scan comes back
`LIMITS-EXCEEDED`, `UNSCANNABLE` or `PASSWORD-PROTECTED`, and exits 2, where
`clamscan` reports `OK` and exits 0. And **one process serves both protocols**:
naming a `clamd://` and an `icap://` address on `--listen` replaces a
`c-icap` + `clamav` container pair over one loaded database.

exav ships **no signatures** — the ClamAV database is GPL. Fetch them with
`freshclam` or `cvd`, or let `--auto-update` keep a directory current.

Full documentation, including the ClamAV flag matrix and the migration guide, is
at **[exav.org](https://exav.org)**.

> **Status: young project.** The CLI, the `clamd` wire protocol and the exit
> codes are the stable surface; the Rust API is `0.0.x` and may break in any
> release. Validate coverage on your own corpus before you rely on it.

Licensed under MIT. The library crates it is built from are
[`exav-core`](https://crates.io/crates/exav-core),
[`exav-unpack`](https://crates.io/crates/exav-unpack),
[`exav-pe-emu`](https://crates.io/crates/exav-pe-emu),
[`exav-x86`](https://crates.io/crates/exav-x86) and
[`exav-update`](https://crates.io/crates/exav-update).
