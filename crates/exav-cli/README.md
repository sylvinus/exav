# exav

**A drop-in, memory-safe ClamAV replacement — written in Rust — with a
clamscan-compatible CLI, the same signature formats, and no file-size limit.**

This crate provides the `exav` command-line scanner and its `clamd`-compatible
scanning daemon. It loads ClamAV's own signature databases (`.cvd`/`.cld`,
`.ndb`/`.ldb`/`.hdb`/…, plus YARA `.yar`/`.yara`) and speaks the `clamd` wire
protocol, so you can point it at an existing ClamAV setup and it just works —
while closing ClamAV's silent large-file skip and running on a memory-safe
engine.

```sh
cargo install exav-cli        # installs the `exav` binary

exav file.bin                 # scan one file
exav -r /var/www              # recurse a directory
cat file.zip | exav -         # scan stdin (constant memory, any size)
exav -d /var/lib/clamav -r /data   # use an existing ClamAV signature dir
```

See the [project README](https://github.com/sylvinus/exav) for the full CLI,
daemon, signature, and migration documentation.

> ⚠️ **Status: experimental (alpha).** Not independently audited. Do not rely on
> it as your only malware scanner in production.

Licensed under MIT.
