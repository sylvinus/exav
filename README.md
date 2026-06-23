# exav

**A drop-in, memory-safe ClamAV replacement — written in Rust — with a clamscan-compatible CLI, the same signature formats, and no file-size limit.**

exav loads ClamAV's own signature databases (`.cvd`/`.cld`, `.ndb`/`.ldb`/`.hdb`/`.hsb`/`.mdb`/`.msb`/`.cdb`/`.imp`/`.cbc`, plus YARA `.yar`/`.yara`) and speaks the `clamd` wire protocol, so you can point it at an existing ClamAV setup and it just works — while fixing ClamAV's silent large-file skip, running on a memory-safe engine, and shipping under MIT.

> ⚠️ **Status: experimental (alpha).** exav is young and has not been independently audited. Do not rely on it as your only malware scanner in production. It's useful today for large-file scanning, CI gating, and as a fast clamscan-compatible front-end — but treat detections (and especially *non*-detections) with appropriate caution.

ClamAV has a long-standing large-file limitation: files over ~2 GB are read but scanned as **zero bytes** and still reported **`OK` / clean** (as of ClamAV 1.5, Dec 2025) — a *silent* clean verdict on a file that wasn't actually inspected. exav exists to close that gap.

exav's core invariant: **never report a file clean unless it was actually scanned.** If a limit prevents a full scan, it says so (`LIMITS-EXCEEDED`) — it never silently returns `OK`.

```console
# Built in: only the EICAR test signature. Load a real database for real coverage.
$ printf 'X5O!P%%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > eicar.txt
$ exav eicar.txt
eicar.txt: Exav.Test.EICAR FOUND

# With a ClamAV database loaded (see "Signatures"):
$ exav -d ~/.cvdupdate/database suspicious.bin
suspicious.bin: Win.Trojan.Agent-1234 FOUND

$ aws s3 cp s3://bucket/backup-50gb.tar.gz - | exav -      # streams, no download
stdin: OK
```

> Demonstrated: a **6 GiB file on a 4.8 GiB-RAM machine** (3× ClamAV's silent-skip limit), with the signature at the very end → **detected.** The file-scanning working set stays **flat (~2 MiB) regardless of file size** — that's the constant-memory streaming core. (The signature database is a separate, one-time load; this 2 MiB figure is the per-scan working set on top of it, measured here with the built-in test DB. See [`docs/DATABASE.md`](docs/DATABASE.md) for DB memory.)

---

## exav vs ClamAV

exav is designed as a drop-in replacement: same signature formats, same `clamd`
protocol, clamscan-compatible flags and output. Where it differs, it's on
purpose.

**What exav does better**

| | ClamAV | exav |
|---|---|---|
| Files > 2 GB | reads them, scans **zero bytes**, reports `OK` | scanned in constant memory, any size |
| Can't fully scan a file | silently `OK` | explicit `LIMITS-EXCEEDED` — **never** a false `OK` |
| Engine safety | C (the 32-bit-overflow / parser-CVE class) | Rust — memory-safe by construction, audited `unsafe` only at the OS boundary |
| YARA rules | restricted subset (no modules, ≤64 strings/rule) | near-full YARA via yara-x, **on by default** |
| YARA execution | n/a | bytecode **interpreter** (Pulley) — no runtime JIT / no W^X pages |
| Scanning S3 / streams | download to a temp file first | stream from stdin / pipe / HTTP range — no temp file |
| `.cbc` bytecode sigs | bundled JIT/interpreter | from-scratch sandboxed interpreter, no `unsafe`, step-capped |
| License | GPLv2 | MIT |
| Distribution | system packages | single static binary |

**Where ClamAV still leads (today)**

| | |
|---|---|
| Signature coverage | ClamAV's curated DB is mature and enormous; exav *runs* those signatures but adds none of its own |
| Large-DB memory | loading the full `main.cvd` is currently far more memory-hungry in exav — being worked on |
| Archive breadth | exav unpacks zip/gzip/tar/bz2/xz/7z/cab/iso/lha/ole/pdf/email + UPX (NRV2B + stored only — the **default NRV2E**, plus NRV2D/LZMA, aren't decompressed yet); **RAR is not done** |
| Maturity | ClamAV is 20+ years battle-tested; exav is alpha |

exav re-uses ClamAV's signature *formats* (so the ecosystem's signatures work)
but ships under MIT and never bundles the GPL-licensed signature database — you
fetch that yourself (see [Signatures](#signatures)).

## Install

Cross-platform (Linux, macOS, Windows). No prebuilt binaries or `cargo install` release yet — build from source with a Rust toolchain (1.85+):

```sh
git clone https://github.com/sylvinus/exav
cd exav
cargo build --release
./target/release/exav --help
```

## Usage

```sh
exav file.bin                     # scan one file
exav -r /var/www                  # recurse a directory
exav -i -r /data                  # only print infected files
cat file.zip | exav -             # scan stdin (Stream mode)
exav https://bucket.s3.amazonaws.com/obj.zip   # scan over HTTP range requests, no download
exav --heuristics -v sample.exe   # enable structural/ML/fuzzy analysis
exav -d ./mydb -r /data           # use a signature database (file or dir)
exav --datadir ./sigs -r /data    # auto-load a signatures dir when -d is omitted

# Get ClamAV signatures with Cisco's own updater, then point exav at them:
cvdupdate download                    # (or freshclam)
exav -d ~/.cvdupdate/database -r /data

# Prebuild a cache once (on a host with enough RAM), then load it instantly:
exav -d ~/.cvdupdate/database --build-cache exav.cache   # heavy, run daily in CI
exav -d exav.cache -r /data                              # ~sub-second cold start

# Daemon mode: load the DB once, scan with zero per-call cost (clamd-compatible):
exav --daemon -d exav.cache                  # load once, listen on /tmp/exav.sock
exav --socket /tmp/exav.sock -r /data        # client: scans pay no load cost
clamdscan --stream file.bin                  # the official ClamAV client works too
```

### Daemon mode

`--daemon` loads the database once and serves scans over a socket, so callers
pay **no per-scan cold-start cost**. The wire protocol is a subset of ClamAV's
`clamd` protocol, so existing tooling — `clamdscan` (incl. its default
fd-passing mode), milters, `clamd` client libraries — talks to exav unchanged
(validated against `clamdscan` `--fdpass`/`--stream`/`--multiscan`, the Python
`clamd` library, and raw `socat`). Commands: `PING`, `VERSION`, `STATS`,
`SCAN`/`CONTSCAN`/`MULTISCAN <path>`, `INSTREAM`, `FILDES` (fd passing),
`IDSESSION`/`END`, plus the exav extension `SCANURL <url>` (scan an `http(s)://`
object via range requests, no download). Unix socket by default (`--socket`), or
`--tcp host:port`.

Crucially, **the protocol imposes no size limit**: `SCAN <path>` sends only the
path (the daemon scans the file directly, any size), and `INSTREAM` chunks feed
straight into the constant-memory scanner — a 4 GiB stream adds only a **flat
~3 MiB to the daemon's working set** regardless of size (on top of the
already-loaded signature database). A limit that prevents a full scan is reported as
`ERROR`/`LIMITS-EXCEEDED`, never a silent `OK`.

### Prebuilt cache

Loading a raw ClamAV database means building a large in-memory automaton — tens
of seconds and gigabytes of RAM. `--build-cache FILE` does that work once and
writes a self-contained, portable file; pointing `-d` at that file loads it
directly (the automaton is restored, not rebuilt). For the **full
`main.cvd`+`daily.cvd` (3.7M signatures)** this turns a **75 s / 5.6 GiB** raw
load into a **3.5 s / 1.2 GiB** cache load. The intended workflow: build the
cache daily on a capable host (CI; the full build needs ~6–8 GiB RAM),
distribute the file, and have every CLI instance load it. The cache is a trusted
artifact — build and fetch it over a channel you trust (it is not meant for
arbitrary untrusted
input).

**clamscan-compatible** where it counts: exit codes `0` (clean) / `1` (found) / `2` (error), the `PATH: Signature FOUND` / `PATH: OK` output format, and the common flags (`-r -i --bell -d --datadir --max-filesize --max-scansize --allmatch --exclude --exclude-dir --include --quiet --no-summary`). `--datadir` (default `exav-db`) is the directory exav auto-loads signatures from when `-d` is omitted. It diverges only by *adding* — notably the never-silent-skip behavior, `http(s)://` URL targets, the prebuilt cache, the daemon, and informational findings under `-v`.

## What works today

- **Constant-memory streaming core** — Aho-Corasick multi-pattern matching + MD5/SHA1/SHA256 hashing in a single forward pass, matching across buffer boundaries, on inputs larger than RAM.
- **ClamAV signature formats**: `.ndb` byte signatures **including wildcards** (`??`, nibble `a?`/`?a`, `*`, `{n}`/`{n-m}` gaps, `(aa|bb)` alternation, `!(...)` negation), `.ldb` **logical signatures** (full boolean expressions incl. grouped match-counts `(0|1|2)>2,3`, plus `i`/`w`/`a` subsig modifiers and offset prefixes), `.hdb`/`.hsb` whole-file hashes, `.mdb`/`.mdu` **PE section hashes**, `.cdb` **container-metadata signatures**, `.fdb`/`.imp` fuzzy/imphash sets, **`EP`/section-relative offsets**, `.fp`/`.ign` allowlists, and `.cvd`/`.cld` containers. On a live ClamAV `daily.cvd` exav loads and matches **~99.8% of its signatures** (355,407 of 356,208); the rest — PCRE subsignatures (~640) and bytecode — are skipped (see Limitations) and counted, never silently ignored.
- **YARA rule support** via [yara-x](https://github.com/VirusTotal/yara-x) (on by default — `yara-x` is a hard dependency of the core engine): `.yar`/`.yara` rule files load alongside ClamAV signatures and match in the same scan.
- **Recursive unpacking** (the separate `exav-unpack` crate) of zip / gzip / tar / **xz / bzip2 / cab / 7z / ISO (CD001) / LHA** archives **and structured documents — OLE2 (legacy Office/MSI streams), PDF (object streams, FlateDecode), and MIME email (decoded attachments/parts)** — all pure-Rust, with **decompression-bomb defenses** (output-byte, ratio, file-count, recursion-depth budgets) — a bomb is `LIMITS-EXCEEDED`, never `OK`. **UPX-packed executables** are also walked (NRV2B + stored methods only — see Limitations).
- **Structural heuristics** (`--heuristics`): PE section entropy, packer detection, suspicious-import flags, **imphash**, **TLSH** fuzzy matching, and a static **ML feature pipeline** with a transparent baseline scorer.
- **Content-based file typing** (magic bytes, never extension-trust).
- **HTTP(S) range-request backend** (`http` feature, on in the CLI): scan an `http(s)://` object — including a public/presigned S3 URL — by fetching only the byte ranges touched. For a ZIP that means the central directory plus the members actually scanned, stopping at the first detection, so a 50 GB archive isn't downloaded.
- Reads ClamAV `.cvd`/`.cld` containers directly — populate them with Cisco's own `cvdupdate`/`freshclam` (exav never bundles the GPL DB).
- **Prebuilt cache** (`--build-cache`): serialize a fully-built database to a portable file and load it directly with `-d`, restoring the matcher instead of rebuilding it — a ~19× faster, ~5× lighter cold start (see [Prebuilt cache](#prebuilt-cache)).

## Signatures

The ClamAV signature database (`main.cvd`/`daily.cvd`) is **GPL-licensed**; using it inside another engine is considered a derivative work. exav therefore **never bundles or redistributes it**. Instead:

- exav ships under **MIT** and can *read* the CVD format (reading a format is interoperability, not redistribution).
- To get the signatures, **you** run Cisco's own updater — [`cvdupdate`](https://github.com/Cisco-Talos/cvdupdate) (Apache-2.0) or `freshclam` — onto your own machine, then point exav at the directory with `-d`. GPL governs distribution, not use. exav deliberately does *not* re-implement the downloader: `cvdupdate`/`freshclam` are the supported path and avoid hammering Cisco's CDN.
- For signatures exav *can* ship, use permissively-licensed sets — e.g. [Neo23x0 signature-base](https://github.com/Neo23x0/signature-base) (DRL-1.1) or [abuse.ch](https://abuse.ch).

## Architecture

Two input modes:

- **Stream** (`Read`: stdin, pipes) — `scan_stream` runs the constant-memory pattern + hash core. Unlimited size.
- **Seekable** (`Read + Seek`: local files, or `source::HttpRangeReader` over HTTP range GETs) — `scan_seekable` additionally drives ZIP extraction through the reader, fetching only the directory and members it scans.

| crate | role |
|---|---|
| `exav-unpack` | bounded, in-memory archive/document extraction (zip/gzip/tar/xz/bzip2/cab/7z/ISO/LHA, OLE2/PDF/MIME, UPX), with the decompression-bomb budget |
| `exav-core` | engine: streaming + seekable scan, signatures (`patterns`/`hashes`/`cvd`/`db`), YARA (`yara`, via yara-x), bytecode (`bytecode`), `cache` (prebuilt DB serialization), `pe`, `fuzzy`, `ml`, `filetype`, `source` (HTTP range backend) |
| `exav-cli`  | the `exav` binary, clamscan-compatible front-end + daemon |

## Limitations

This is early. Known gaps, none of which silently affect a verdict:

- **Pure stream mode (a pipe) does pattern+hash only** — structural unpacking needs a seekable source. Local files and HTTP(S) URLs are seekable and get full structural analysis; only forward-only pipes are limited.
- **HTTP backend reads public/presigned URLs** — for private S3 objects, presign the URL (or front with a proxy).
- **Files larger than the deep-analysis limit (256 MiB) are not structurally unpacked** — their raw bytes are still pattern+hash scanned, and the skip is reported as a finding. (This limit is a fixed library setting, not a CLI flag.) A large *archive* hiding a payload is the gap to close.
- **~0.2% of a live ClamAV DB is not yet matched** (counted in the summary): PCRE subsignatures (~640) and a few exotic offset/anchor forms.
- **Bytecode (`.cbc`) programs run in a memory-safe sandbox, but coverage is partial.** exav parses 100% of the live bytecode DB (85 programs) and **executes** them in the live scan path — trigger-gated (a program runs only when its logical-signature trigger matches), producing real `Method::Bytecode` detections. The caveat is coverage, not gating: programs that depend on not-yet-implemented host APIs (`disasm_x86`, the PDF/JSON object APIs, the inflate/lzma/bzip2 codecs) are skipped rather than executed, and the disasm/codec-dependent detections that do run are not yet detection-validated against `clamscan`. Crucially, exav's sandbox avoids the remote-code-execution class that has affected ClamAV's bytecode VM (e.g. CVE-2020-37167) — see [`docs/BYTECODE.md`](docs/BYTECODE.md).
- **Building a full database from raw signatures is memory-hungry.** The matcher is a double-array Aho-Corasick (daachorse) over the de-duplicated anchor set — its *result* is compact (~5× smaller than a classic NFA, so a loaded cache is light), but *constructing* it from raw signatures needs several GB of transient RAM (the full `main.cvd`+`daily.cvd` build wants a host with ~6 GB+). The intended workflow sidesteps this: build the cache once on a capable host with `--build-cache`, then every CLI instance loads that file cheaply. A modest host that has only the raw DB and can't build it should be given a prebuilt cache.
- **Scan throughput on large inputs against the full DB.** Much improved (longest-literal anchors cut spurious verification; logical-sig expressions are parsed once at load; clean files skip the logical pass), but scanning very large binaries against the full signature set can still be slower than ClamAV; further matcher tuning is ongoing.
- The ML scorer is a **transparent heuristic baseline**, not a trained classifier (the `Model` trait is ready for a real EMBER-trained model).
- imphash skips ordinal-only imports (minor VirusTotal-interop nuance).
- Unpacks zip/gzip/tar/xz/bzip2/cab/7z/ISO/LHA + OLE2/PDF/MIME-email; **RAR is pending**, as is **VBA-macro decompression** (OLE2 streams are extracted raw, so the compressed macro source isn't yet exposed to signatures) and PDF filters beyond FlateDecode.
- **UPX unpacking currently supports the NRV2B and stored methods only.** NRV2E (the UPX default), NRV2D, and LZMA are detected but **not yet decompressed** — for those, the UPX walk stops and the packed payload is still pattern/hash scanned in place (never silently cleared).
- Parsers are memory-safe (Rust), panic-isolated per file, and fuzzed (`cargo-fuzz`, see `fuzz/`). Continuous fuzzing (e.g. OSS-Fuzz) is still recommended before high-assurance production use.

## Security

exav parses hostile input. See [`SECURITY.md`](SECURITY.md) for the threat model and the hardening: bounded (budget-before-allocation) extraction, in-memory-only unpacking, the never-report-clean-unless-scanned invariant, `overflow-checks` in release, per-file panic isolation, fuzz targets for every parser, and `cargo audit` / `cargo deny` in CI.

## Roadmap

- **Now → next**: signature-matching performance · **broader bytecode coverage** (trigger-gated execution is live — see [`docs/BYTECODE.md`](docs/BYTECODE.md); remaining work is the `disasm_x86`/PDF/codec host APIs and differential validation vs `clamscan`) · PCRE subsigs · extended/continuous fuzzing and the >10 GB no-silent-skip CI suite.
- **v2**: trained static-ML model, broader fuzzy/similarity, more file-type parsers (LNK, OneNote), RAR and VBA-macro decompression.
- **v3 (optional)**: QEMU/KVM dynamic detonation — a separate, heavyweight feature, only if demand warrants.

## Contributing

Issues and PRs welcome. Please run `cargo test`, `cargo clippy --all-targets`, and `cargo fmt --check` before submitting (CI also runs `cargo audit`, `cargo deny check`, and a `cargo-fuzz` smoke pass). Good first areas: additional archive formats, `.ndb` wildcard matching, the S3 source backend, and fuzz targets.

**Do not commit real malware to this repository.** Tests use the harmless EICAR string and synthetic inputs only.

## License

MIT — see [`LICENSE`](LICENSE). The exav binary statically links third-party crates under permissive licenses (notably yara-x under BSD-3-Clause and the wasmtime/cranelift stack under Apache-2.0 WITH LLVM-exception); their required notices are reproduced in [`NOTICE`](NOTICE). exav never bundles or redistributes the GPL-licensed ClamAV signature database; those signatures may be fetched by the user at runtime (see [Signatures](#signatures)). exav ships only with permissively-licensed signatures.
