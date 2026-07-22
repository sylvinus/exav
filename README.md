# exav

**A fast, memory-safe malware scanner written in Rust.**

exav is a malware scanner written in memory-safe Rust: a single static,
MIT-licensed binary that scans files of any size in constant memory and runs a
native YARA engine. It reads ClamAV's signature databases, answers the `clamd`
and ICAP wire protocols, and matches `clamscan`'s CLI flags, output and exit
codes — so it drops into an existing ClamAV setup without changing anything
around it.

> **Status: beta.** exav is young. It is tested hard — differentially against
> ClamAV on a large corpus, plus fuzzing — but a scanner earns trust from use,
> and there has not been much of that yet. Please report anything that looks
> wrong; fixes ship quickly.

## Design principles

exav is built around a handful of [design principles](https://exav.org/concepts/design-principles/):
memory safety, no runtime code generation, constant-memory streaming, minimal
dependencies, drop-in compatibility, bounded work, clean-room/permissive
licensing, and — the one the rest hangs on — **never a silent clean**: an
incompletely-scanned file never gets `OK`. Anything that stops the scan early (a
size/ratio/recursion limit, an unsupported codec, an encrypted member, or an
internal work budget) surfaces as a distinct verdict (`LIMITS-EXCEEDED` /
`UNSCANNABLE` / `PASSWORD-PROTECTED`, exit code 2), never swallowed into a silent
`OK` — closing the gap where a traditional engine reads a file over ~2 GB as
**zero bytes** and still reports it clean.

## Install

Build from source with a Rust toolchain. **exav needs 1.91 or newer**, which is
recent enough that a distribution-packaged Rust will often be too old — if the
build fails on syntax rather than on your code, check `rustc --version` first:

```sh
git clone https://github.com/sylvinus/exav && cd exav
cargo build --release -p exav-cli      # -> target/release/exav
```

## Quick start

exav ships **no** signatures (the ClamAV DB is GPL). Fetch them yourself, then
scan:

```sh
pip install cvdupdate && cvd update      # or `freshclam`
exav -d ~/.cvdupdate/database suspicious.bin
# suspicious.bin: Win.Trojan.Agent-1234 FOUND

cat backup-50gb.tar.gz | exav -d ~/.cvdupdate/database -   # streams, constant memory
```

## Full documentation: **[exav.org](https://exav.org)**

Install, usage, the daemon, the ICAP server, Docker, signatures, the prebuilt
`.exavdb`, YARA, migrating from ClamAV, the WASM sandbox, architecture, the CLI
reference, and more.

## API stability

exav is `0.1.x`, and 0.1 means what SemVer says it means: **any release may
break any API.** Pin an exact version if you depend on the library crates.

Within that, the intent is:

- **`exav-core`, `exav-unpack`, `exav-x86`, `exav-pe-emu`, `exav-grep`,
  `exav-update`** — the public surface is meant to be usable, and
  breaking changes will be described in [`CHANGELOG.md`](CHANGELOG.md) rather
  than left for you to discover.
- **Anything behind `unstable-internals`** (the `engine`, `bytecode`,
  `patterns` and `pe` modules of `exav-core`) is exempt. It exists so the tests
  and the diagnostic examples can reach inside; it is not an API, and it will
  change without a note.
- **The CLI, the `clamd` wire protocol and the exit codes are the stable
  surface.** They are what compatibility means for this project, so they get
  more care than the Rust API — a script or a `clamd` client is the thing most
  likely to break in a way you cannot see.

`Verdict`, `Method`, `FileType`, `Format` and `LimitKind` are
`#[non_exhaustive]`, so matching on them needs a wildcard arm. Without it, every
new format or outcome would be a breaking change, and this project adds formats.

Two deliberate exceptions:

- **`VerdictCategory` is exhaustive**, and stays that way. It exists so exit
  codes and output shape are decided in one place, and its value is the compiler
  refusing to build until every consumer has handled a new category. A wildcard
  there would quietly give a future outcome some existing exit code.
- **`Limits` and `ScanOptions` are plain structs.** Marking them would forbid
  `..Default::default()` construction entirely, which is how they are meant to
  be built. Construct them that way and a new field will not break you.

## Contributing, Security, License

- **Contributing** — see [`CONTRIBUTING`](CONTRIBUTING.md) and the docs
  [Contributing guide](https://exav.org/project/contributing/). Non-negotiable
  clean-room rule: exav is MIT and derives **nothing** from ClamAV's GPLv2
  source; implement only from public specifications and permissively-licensed
  code.
- **Security** — see [`SECURITY.md`](SECURITY.md) for the threat model and how to
  report vulnerabilities.
- **License** — [MIT](LICENSE). The binary statically links permissively-licensed
  crates (see [`NOTICE`](NOTICE)); exav never bundles the GPL ClamAV signature
  database.

The design-level docs also live on [exav.org](https://exav.org); deeper
implementation notes remain under [`docs/`](docs/).
