# exav

**A drop-in, memory-safe ClamAV replacement — written in Rust — with a clamscan-compatible CLI, the same signature formats, and no file-size limit.**

exav loads ClamAV's own signature databases (`.cvd`/`.cld`, `.ndb`/`.ldb`/`.hdb`/`.hsb`/`.mdb`/`.msb`/`.cdb`/`.imp`/`.cbc`, plus YARA `.yar`/`.yara`) and speaks the `clamd` wire protocol, so you can point it at an existing ClamAV setup and it just works — while fixing ClamAV's silent large-file skip, running on a memory-safe engine, and shipping under MIT.

> ⚠️ **Status: experimental (alpha).** exav is young and has not been independently audited. Do not rely on it as your only malware scanner in production. It's useful today for large-file scanning, CI gating, and as a fast clamscan-compatible front-end — but treat detections (and especially *non*-detections) with appropriate caution.

ClamAV has a long-standing large-file limitation: files over ~2 GB are read but scanned as **zero bytes** and still reported **`OK` / clean** (as of ClamAV 1.5, Dec 2025) — a *silent* clean verdict on a file that wasn't actually inspected. exav exists to close that gap.

exav's core invariant: **never report a file clean unless it was actually scanned.** A scanner's limits are an attack surface — anything that makes it *stop looking* is a bypass an adversary will reach for — so exav treats them as load-bearing security properties:

1. **A detection always beats a limit.** A signature match is reported `FOUND`, never downgraded because some *other* part of the input tripped a budget.
2. **Never refuse by size without scanning.** A file over `--max-scan-size` isn't skipped wholesale — the flat pattern/hash core still runs over the in-budget bytes, so a payload in the scanned prefix is still caught (otherwise `cat malware huge.pad > evil` would be a one-line bypass).
3. **Not-fully-scanned is never clean.** Anything exav couldn't fully examine gets a distinct non-clean verdict, never a silent `OK`:
   - **`LIMITS-EXCEEDED`** — a resource limit (size/ratio/recursion/scan-bytes) stopped the scan.
   - **`UNSCANNABLE`** — a container was recognised but couldn't be decoded (unsupported codec, e.g. a RAR solid/multi-volume stream).
   - **`PASSWORD-PROTECTED`** — an encrypted member; *actionable* — re-scan with a password supplied.

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
| Engine safety | C (the 32-bit-overflow / parser-CVE class) | Rust — safe-Rust engine + parsers; residual `unsafe` only in audited compression/crypto/SIMD deps and syscalls (being driven down) |
| YARA rules | restricted subset (no modules, ≤64 strings/rule) | near-full YARA via yara-x, **on by default** |
| YARA execution | n/a | bytecode **interpreter** (Pulley) — no runtime JIT / no W^X pages |
| Scanning S3 / streams | download to a temp file first | stream from stdin / pipe / HTTP range — no temp file |
| `.cbc` bytecode sigs | bundled JIT/interpreter | from-scratch safe-Rust interpreter — no native codegen (W^X), step-capped |
| License | GPLv2 | MIT |
| Distribution | system packages | single static binary |

**Where ClamAV still leads (today)**

| | |
|---|---|
| Signature coverage | ClamAV's curated DB is mature and enormous; exav *runs* those signatures but adds none of its own |
| Large-DB memory | loading the full `main.cvd` is currently far more memory-hungry in exav — being worked on |
| Archive breadth | exav unpacks zip/gzip/tar/bz2/xz/7z/cab/iso/lha/ole/pdf/email/DMG + UPX (all UCL methods + LZMA + DEFLATE); RAR3 (LZ + PPMd) + RAR5 (LZ) |
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

For all the ways to deploy — direct executable (`cargo install` / prebuilt
binaries / `.deb` / systemd), the WASM sandbox, a single container, or a
dual-container setup with a shared database volume — see the
**[deployment guide](docs/DEPLOYMENT.md)**.

## Usage

```sh
exav file.bin                     # scan one file
exav -r /var/www                  # recurse a directory
exav -i -r /data                  # only print infected files
cat file.zip | exav -             # scan stdin (Stream mode)
exav https://bucket.s3.amazonaws.com/obj.zip   # scan over HTTP range requests, no download (needs --features http)
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
`clamd` library, and raw `socat`). Commands: `PING`, `VERSION`,
`VERSIONCOMMANDS`, `STATS`, `RELOAD`, `SCAN`/`CONTSCAN`/`MULTISCAN`/`ALLMATCHSCAN
<path>`, `INSTREAM`, `FILDES` (fd passing), `IDSESSION`/`SESSION`/`END`, plus the
exav extension `SCANURL <url>` (scan an `http(s)://` object via range requests,
no download). Unix socket by default (`--socket`), or `--tcp host:port`. The
deprecated `STREAM` (separate-port) command is intentionally not implemented —
`INSTREAM` supersedes it — and `SHUTDOWN` is omitted so a client can't stop the
daemon (send the process a signal instead). `RELOAD` re-reads the database and,
in the prefork pool, re-forks the workers with the new signatures — the hook a
sidecar `freshclam`'s `NotifyClamd` drives (see Docker below).

Crucially, **the protocol imposes no size limit**: `SCAN <path>` sends only the
path (the daemon scans the file directly, any size), and `INSTREAM` chunks feed
straight into the constant-memory scanner — a 4 GiB stream adds only a **flat
~3 MiB to the daemon's working set** regardless of size (on top of the
already-loaded signature database). A limit that prevents a full scan is reported as
`ERROR`/`LIMITS-EXCEEDED` (or `UNSCANNABLE`/`PASSWORD-PROTECTED`), never a silent `OK`.

**Worker pool & per-scan kill (`--workers N`, Unix).** By default the daemon runs
a **prefork pool of one worker process per CPU core** (`--workers 0` forces the
older in-process thread model). Workers are forked *after* the DB loads, so they
share the signature database copy-on-write (no re-load); each handles one scan at
a time under **kernel-enforced per-job limits** — `--max-scan-time` (wall-clock,
default 120 s), `--max-scan-memory` (RLIMIT_AS, default 2 G), and CPU time — and
is recycled every `--max-jobs-per-worker` scans (default 1000) to bound leaks.
This is the only way to *safely* hard-kill a scan that gets stuck inside a
dependency: a runaway worker is `SIGKILL`ed and respawned without touching the
rest of the pool (a thread model fundamentally can't do this). It's the last line
of a layered defense — deterministic in-core caps (scan-byte/ratio/recursion)
fire first, in milliseconds; the pool is the backstop for the residual tail.

### Docker

The published image (`ghcr.io/sylvinus/exav`) is **drop-in compatible with the
[ClamAV Docker image](https://docs.clamav.net/manual/Installing/Docker.html)**:
same `/var/lib/clamav` database volume, same clamd port **3310**, and the same
`CLAMAV_NO_CLAMD` / `CLAMAV_NO_FRESHCLAMD` / `CLAMD_STARTUP_TIMEOUT` /
`FRESHCLAM_CHECKS` environment variables. It runs the clamd-compatible daemon by
default, so a host `clamdscan` (or any clamd client) pointed at the container's
TCP 3310 just works.

It's **distroless and rootless**: a static-musl binary on `distroless/static`
(no shell, no package manager, minimal attack surface) running as the `nonroot`
user (uid 65532). Bind-mounted database volumes must be writable by that uid.

```sh
# Start the daemon; persist signatures in a named volume.
docker run -d -p 3310:3310 -v exav-db:/var/lib/clamav ghcr.io/sylvinus/exav
clamdscan --stream file.bin                       # host clamdscan over TCP

# One-shot scan (overrides the default daemon):
docker run --rm -v "$PWD:/scan" ghcr.io/sylvinus/exav -r /scan
```

**Signatures are never bundled** (exav ships no GPL database and no CDN URL).
Populate `/var/lib/clamav` one of three ways — the daemon **hot-reloads** it
whenever it changes on disk, no restart needed:

| Env var | Default | Meaning |
| --- | --- | --- |
| `CLAMAV_NO_CLAMD` | `false` | Don't run the scanner (updater-only container). |
| `CLAMAV_NO_FRESHCLAMD` | `false` | Don't run the built-in updater. |
| `CLAMD_STARTUP_TIMEOUT` | `1800` | Seconds to wait for a database before falling back to the built-in baseline (`0` = don't wait). |
| `FRESHCLAM_CHECKS` | `1` | Update checks per day. |
| `EXAV_DB_MIRROR` | *(unset)* | **exav extension.** Base URL of a CVD mirror to auto-download `main`/`daily`/`bytecode.cvd` from. Unset = no auto-download. |
| `EXAV_DATADIR` | `/var/lib/clamav` | Database directory. |
| `EXAV_LISTEN` | `0.0.0.0:3310` | clamd listen address. |

1. **Managed volume** — mount a `/var/lib/clamav` you keep current with
   `cvdupdate`/`freshclam` yourself.
2. **Built-in updater** — set `EXAV_DB_MIRROR` to a mirror you trust; the
   container fetches on start and every `FRESHCLAM_CHECKS`/day. This needs the
   image's `--features http` build (the default image); it's a plain HTTPS fetch
   with **no signature verification**, so trust the mirror.
3. **Sidecar** — a second container writes the shared volume and the scanner
   reloads it. Run exav in updater-only mode (`CLAMAV_NO_CLAMD=true`) or the
   official `clamav/clamav` freshclam container (its `NotifyClamd` `RELOAD` is
   protocol-compatible). See [`docker-compose.yml`](docker-compose.yml).

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

**clamscan-compatible** where it counts: exit codes `0` (clean) / `1` (found) / `2` (error), the `PATH: Signature FOUND` / `PATH: OK` output format, and the common flags (`-r -i --bell -d --datadir --max-filesize --max-scansize --max-recursion --max-files --allmatch --exclude --exclude-dir --include --quiet --no-summary`). `--datadir` (default `exav-db`) is the directory exav auto-loads signatures from when `-d` is omitted. It diverges only by *adding* — notably the never-silent-skip behavior, `http(s)://` URL targets (opt-in `--features http`), the prebuilt cache, the daemon, and informational findings under `-v`. One deliberate compatibility caveat a migrating clamscan user should know: a file exav couldn't fully scan (`LIMITS-EXCEEDED`/`UNSCANNABLE`/`PASSWORD-PROTECTED`) exits `2`, where clamscan would report `OK` and exit `0`. For exact-parity differential testing, [`--clamav-compat`](#clamav-compatibility---clamav-compat) presets exav to ClamAV's documented defaults.

### ClamAV compatibility (`--clamav-compat`)

exav runs at **full capability by default** (no file-size limit, all extractors,
raw signature names). `--clamav-compat` is a **shortcut** that dials exav back to
a stock ClamAV build's documented defaults, for apples-to-apples differential
testing against `clamscan`. It is exactly the row-by-row combination below —
**every knob is also an individual flag**, and an explicit flag always wins over
the preset:

| Flag | exav default | `--clamav-compat` | Effect |
|---|---|---|---|
| `--max-filesize` | *unlimited* | `100M` | Per top-level file cap. Over it → `LIMITS-EXCEEDED` (ClamAV: silent `OK`). |
| `--max-scansize` | `256M` | `400M` | Total data-scanned budget: deep/structural-analysis size + summed extracted bytes. |
| `--max-recursion` | `16` | `17` | Max nesting depth for recursive unpacking. |
| `--max-files` | `10000` | `10000` | Max files extracted per archive (same value — exposed for parity/overriding). |
| `--clamav-formats` | off | on | Skip `ar` (`.deb`/`.a`) extraction — see below. **Functional.** |
| `--unofficial-names` | off | on | Append `.UNOFFICIAL` / `YARA.` to unofficial-DB signature names. **Cosmetic** — never changes whether a detection fires. |

So `--clamav-compat` ≡ `--max-filesize 100M --max-scansize 400M --max-recursion
17 --max-files 10000 --clamav-formats --unofficial-names`. The four limit values
are ClamAV's own documented engine defaults (ClamAV 1.6.0).

**Functional differences from stock ClamAV** (what changes *whether/what* gets
detected, verified against ClamAV 1.6.0 behavior — not cosmetics):

- **Never a silent skip.** This is the headline difference and is *not* undone by
  `--clamav-compat`. When a file exceeds a limit (or a nested/encrypted member
  can't be read), stock ClamAV returns `CL_SUCCESS` = **clean** by default
  (its `alert-exceeds-max`/`alert-encrypted` heuristics are off) — a silent `OK`
  on data it never inspected. exav instead reports `LIMITS-EXCEEDED` /
  `UNSCANNABLE` / `PASSWORD-PROTECTED` and exits `2`. `--clamav-compat` matches
  ClamAV's *limits*, but exav still surfaces the outcome rather than hiding it.
- **Extractor coverage — only `ar` differs.** exav and ClamAV both natively
  extract **cpio** and **xar**, and unpack **UPX** (inside PE scanning). The
  *only* archive exav extracts that
  stock ClamAV does not is **`ar`** (Unix archive / `.deb` / `.a`) — it has no
  `CL_TYPE_AR`. `--clamav-formats` (and thus `--clamav-compat`) skips exactly
  that one so a differential run doesn't count exav's `ar` reach as a
  disagreement; cpio/xar/UPX stay on in every mode.

Everything else is an exav *addition* (never-silent-skip, URL targets, the
prebuilt cache, the daemon), so it doesn't create a false disagreement in a
detection differential.

### WASM sandbox (untrusted signatures)

If you're loading **untrusted signature databases** — third-party `.ndb` sets,
community YARA rules, anything you didn't build yourself — run the scanner
inside a **WASM sandbox**. The same `exav-core` engine compiles to
`wasm32-wasip1` and runs under [wasmtime](https://wasmtime.dev/) with **no
custom host binary**: you bring your own audited runtime.

```sh
# Build the WASM module
cargo build --release --target wasm32-wasip1 -p exav-wasm
wasm-tools strip -a target/wasm32-wasip1/release/exav_wasm.wasm -o exav.wasm

# Scan a file (sigs mounted at /db, CWD mounted at /)
wasmtime \
  --dir /path/to/sigs::/db \
  --dir .::. \
  exav.wasm \
  /db malware.exe

# Multiple files
wasmtime --dir ./sigs::/db --dir .::. exav.wasm /db *.exe
```

JSON results go to stdout (pipe to `jq`), progress/errors to stderr:

```json
{"verdict":{"Infected":{"signature":"Win.Trojan.Agent-1234","offset":0,"method":"Pattern"}},"findings":[]}
```

**Why this matters:**

| | Native `exav` | WASM sandbox |
|---|---|---|
| Signature trust | full host access | memory-limited WASM instance |
| Runtime | your code | wasmtime (ByteCode Alliance, audited) |
| Blast radius | entire host | isolated WASM module, fuel-limited |
| Custom host code | N/A | **none** — users bring their own wasmtime |
| Overhead | native speed | ~10-20% (JIT compilation) |

The module is a standard WASI command — no `unsafe` ABI, no custom wire
protocol, no embed-by-importing-a-crate. Any WASM runtime that supports
`wasm32-wasip1` works. See [`docs/WASM.md`](docs/WASM.md) for the full
architecture and threat model.

## What works today

- **Constant-memory streaming core** — Aho-Corasick multi-pattern matching + MD5/SHA1/SHA256 hashing in a single forward pass, matching across buffer boundaries, on inputs larger than RAM.
- **ClamAV signature formats**: `.ndb` byte signatures **including wildcards** (`??`, nibble `a?`/`?a`, `*`, `{n}`/`{n-m}` gaps, `(aa|bb)` alternation, `!(...)` negation), `.ldb` **logical signatures** (full boolean expressions incl. grouped match-counts `(0|1|2)>2,3`, plus `i`/`w`/`a` subsig modifiers and offset prefixes), `.hdb`/`.hsb` whole-file hashes, `.mdb`/`.mdu` **PE section hashes**, `.cdb` **container-metadata signatures**, `.fdb`/`.imp` fuzzy/imphash sets, **`EP`/section-relative offsets**, `.fp`/`.ign` allowlists, `.pdb`/`.wdb`/`.gdb` **phishing databases** (protected-brand domain-list + legitimate-pair allow-list, consulted by `--alert-phishing`), and `.cvd`/`.cld` containers. On a live ClamAV `daily.cvd` exav loads and matches **~99.8% of its signatures** (355,407 of 356,208); the rest — PCRE subsignatures (~640) and bytecode — are skipped (see Limitations) and counted, never silently ignored.
- **YARA rule support** via [yara-x](https://github.com/VirusTotal/yara-x) (the `yara` feature, **on by default** but off-able with `--no-default-features`): `.yar`/`.yara` rule files load alongside ClamAV signatures and match in the same scan. `yara-x` is by far the heaviest dependency (it pulls a WASM runtime + Cranelift); disabling the feature drops that whole tree — see the [dependency policy](docs/DEPENDENCIES.md).
- **Recursive unpacking** (the separate `exav-unpack` crate) of zip / gzip / tar / **xz / bzip2 / cab / 7z / ISO (CD001) / LHA / ARJ / RAR (RAR3 LZ+PPMd, RAR5 LZ) / ar (.deb) / cpio (RPM) / xar (.pkg)** archives **and structured documents — OLE2 (legacy Office/MSI streams, with VBA-macro decompression and Excel 4.0 (XLM) macro-sheet surfacing), PDF (object streams; FlateDecode + LZW/ASCII85/ASCIIHex/RunLength filters and filter chains, plus **JavaScript / URI / launch-action** harvesting), RTF (embedded hex objects), and MIME email (decoded attachments/parts)** — all pure-Rust, with **decompression-bomb defenses** (output-byte, ratio, file-count, recursion-depth, and cumulative scan-byte budgets) — a bomb is `LIMITS-EXCEEDED`, never `OK`; a member with an unsupported codec or encryption is `UNSCANNABLE`/`PASSWORD-PROTECTED`, never silently dropped. Also unpacked: **CHM** (ITSF + LZX help files), **NSIS** and **SFX** installers, **AutoIt** (EA05) compiled scripts, **OneNote** embedded files, **TNEF** (`winmail.dat`), **SWF** (CWS/ZWS), **MS-SZDD/KWAJ**, **BinHex**, **uuencode**, **Adobe XDP**, **LNK** command-line strings, Python **`.pyc`**, **GPT/APM/MBR partition maps**, **Java `.class`** constant-pool strings, **AI models** (Python **pickle** import/opcode surfacing + **safetensors** header), and the **Microsoft Script Encoder** (`#@~^` VBScript/JScript.Encode). **Apple DMG** disk images (UDIF, including encrypted DMGs with password) are decompressed and their HFS+/APFS filesystems extracted. **UPX-packed executables** are walked with **all UCL methods + LZMA + DEFLATE** (NRV2B/NRV2D/NRV2E/LZMA/DEFLATE), and other **PE runtime packers** are handled — the **aPLib-based families (Petite 2.x / FSG 2.0 / NsPack)** are decompressed back to the original PE (verified by an in-tree clean-room aPLib codec, round-trip byte-exact), while **Aspack / MEW / Upack / wwpack32 / PeSpin / Yoda's Cryptor** are detected. **Embedded executables** appended/carved inside other files are detected too — **PE, ELF, and Mach-O** images at non-zero offsets are located and re-scanned in their own type context, and **Mach-O universal ("fat")** binaries are split per-architecture.
- **Structural heuristics** (`--heuristics`): PE section entropy, packer detection, suspicious-import flags, **imphash**, **TLSH** fuzzy matching, and a static **ML feature pipeline** with a transparent baseline scorer.
- **Content-based file typing** (magic bytes, never extension-trust).
- **HTTP(S) range-request backend** (`http` feature — **off by default**; build with `cargo build --release --features http`): scan an `http(s)://` object — including a public/presigned S3 URL — by fetching only the byte ranges touched. For a ZIP that means the central directory plus the members actually scanned, stopping at the first detection, so a 50 GB archive isn't downloaded. It is off by default so the standard build is 100% pure-Rust and links no TLS stack (`ureq → rustls → ring`); without it, an `http(s)://` argument errors out telling you to rebuild with the feature.
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
| `exav-unpack` | bounded, in-memory archive/document extraction (zip/gzip/tar/xz/bzip2/cab/7z/ISO/LHA/DMG, OLE2/PDF/MIME, UPX), with the decompression-bomb budget |
| `exav-core` | engine: streaming + seekable scan, signatures (`patterns`/`hashes`/`cvd`/`db`), YARA (`yara`, via yara-x), bytecode (`bytecode`), `cache` (prebuilt DB serialization), `pe`, `fuzzy`, `ml`, `filetype`, `source` (HTTP range backend) |
| `exav-cli`  | the `exav` binary, clamscan-compatible front-end + daemon |
| `exav-wasm` | WASI command: same scanner compiled to `wasm32-wasip1`, runs inside any WASM runtime (wasmtime, wasmer) with zero custom host code |

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
- Unpacks the full set above (zip/gzip/tar/xz/bzip2/cab/chm/7z/ISO/LHA/ARJ/ar/cpio/xar/DMG/NSIS/SFX/AutoIt/OneNote/TNEF/SWF/SZDD/BinHex/uuencode/XDP/LNK/pyc/partitions + RAR + OLE2-with-VBA/PDF-with-filters-and-JS/RTF/MIME-email), plus **Java `.class`** (constant-pool strings), **AI models** (Python pickle import/opcode surfacing + safetensors header), and **Microsoft Script Encoder** (`#@~^`). **RAR3 LZ + PPMd and RAR5 LZ are decoded** (PPMd byte-exact validated; RAR5 has no PPMd — it was removed from the format). Still not decoded (reported `UNSCANNABLE`, never silently cleared): **RAR solid / multi-volume / RAR7 big-dictionary**, **NSIS's modified-bzip2 blocks**, **CHM multi-frame LZX intervals**, and **AutoIt EA06**. **PE runtime packers** beyond UPX: the **aPLib-based families (Petite 2.x / FSG 2.0 / NsPack)** are now decompressed — the original PE is recovered and re-scanned, gated on it reconstructing a valid `MZ`/`PE` image so a mis-located stream is discarded, never fed to the matcher as bogus data; the emulation-required protectors (**Aspack / MEW / Upack / wwpack32 / PeSpin / Yoda's Cryptor**) are *detected* but not unpacked (the raw file is still scanned, so packer signatures match). An opt-in **phishing** heuristic (`--alert-phishing`) flags HTML/email link-spoofing (display-vs-href domain mismatch, userinfo cloak, IP-literal-under-brand), and — when ClamAV `.pdb`/`.wdb` **phishing databases** are loaded — scopes the check to monitored brands and suppresses the curated legitimate mismatches. **Excel 4.0 (XLM)** macro sheets are detected and surfaced so `--alert-macros` fires for them the same as for VBA. The **Authenticode** signature-verification engine is not implemented.
- **Encrypted archives/documents** are detected and reported `PASSWORD-PROTECTED`, never a silent clean. **Decryption is implemented** for **ZIP** (WinZip **AES-128/192/256** and legacy **ZipCrypto**), **7z AES-256** (SHA-256 KDF + AES-256-CBC, CRC-verified so a wrong passphrase is rejected, not emitted as garbage), **PDF** (RC4/AES standard security handler), and **DMG** — decrypted and scanned when the password is supplied via `--password` (repeatable) or a ClamAV **`.pwdb`** database; without the right password they stay `PASSWORD-PROTECTED`. All decryption is pure-Rust (no `getrandom`). **Still detect-only** (flagged, not yet decrypted): **RAR AES** and **Office** (OLE2/OOXML) native encryption — the password pool is threaded but those decryptors are pending.
- Parsers are memory-safe (Rust), panic-isolated per file, and fuzzed (`cargo-fuzz`, see `fuzz/`). Continuous fuzzing (e.g. OSS-Fuzz) is still recommended before high-assurance production use.

## Security

exav parses hostile input. See [`SECURITY.md`](SECURITY.md) for the threat model and the hardening: bounded (budget-before-allocation) extraction, in-memory-only unpacking, the never-report-clean-unless-scanned invariant, `overflow-checks` in release, per-file panic isolation, fuzz targets for every parser, and `cargo audit` / `cargo deny` in CI.

**On `unsafe`.** exav's own scanning and extraction code is safe Rust — both `exav-core` and `exav-unpack` are `#![forbid(unsafe_code)]` — and it runs **no C, no UnRAR, and no native JIT** — the historical AV remote-code-execution classes. It is **not** zero-`unsafe`, though: the residual lives in audited, widely-used dependency *primitives* (compression and crypto SIMD code, and OS syscalls), not in attacker-driven parsing logic. The posture is: **minimize** it (drop deps we don't need — e.g. `tar`'s `xattr`, which removed the largest syscall-`unsafe` source), **contain** it (per-file panic isolation; a prefork worker-process pool that `SIGKILL`s a corrupted worker; the WASM build sandboxes the extractor entirely), and **detect** bugs in it (fuzzing + Miri). Reviewing and driving down dependency `unsafe` is an explicit ongoing goal (see the roadmap).

**On dependencies.** We favour small **leaf** crates and avoid pulling large transitive trees — for control, auditability, `unsafe` surface, and binary/WASM size. Optional capability is feature-gated so a build compiles only what it uses: **per-format** features on `exav-unpack` (forwarded through `exav-core`/`exav-cli`/WASM) mean a ZIP-only WASM extractor is `--no-default-features --features zip` (~323 KiB vs ~1.2 MiB for the full build, release + `wasm-opt -Oz`), and the heavyweight `yara`/`http` features are independently off-able. The one large tree we haven't yet shed is `yara-x`'s Cranelift backend. See the [**dependency policy**](docs/DEPENDENCIES.md).

## Roadmap

- **Now → next**: signature-matching performance · **broader bytecode coverage** (trigger-gated execution is live — see [`docs/BYTECODE.md`](docs/BYTECODE.md); remaining work is the `disasm_x86`/PDF/codec host APIs and differential validation vs `clamscan`) · PCRE subsigs · extended/continuous fuzzing and the >10 GB no-silent-skip CI suite.
- **v2**: trained static-ML model, broader fuzzy/similarity, the emulation-required PE protectors (Aspack/MEW/Upack/wwpack32/PeSpin/Yoda), the Authenticode signature-verification engine, RAR AES / Office decryption, and RAR solid/multi-volume decoding. (LNK/OneNote/CHM/NSIS/AutoIt file-type parsers, VBA-macro decompression **and Excel 4.0 XLM macro-sheet surfacing**, PDF filters + JS/URI extraction, Java `.class` / AI-model / Script-Encoder parsers, DLP structured-data, JS normalization, the aPLib-family PE packers (Petite/FSG2/NsPack), 7z-AES decryption, and the `--alert-encrypted`/`--alert-macros`/`--alert-phishing` heuristics (the last now backed by `.pdb`/`.wdb` phishing DBs) all landed.)
- **v3 (optional)**: QEMU/KVM dynamic detonation — a separate, heavyweight feature, only if demand warrants.

### Hardening TODO: review & drive down dependency `unsafe`

Our own code is safe Rust, but dependencies still carry `unsafe`. Goal: review **all** of it and shrink the reachable surface.
- **Audit** every production dependency's `unsafe` (e.g. `cargo geiger`), categorising by kind (syscall/FFI · SIMD/perf · decode tables · containers · parsers/decompressors) and by whether it's reachable from a scan path with hostile input.
- **Drop** deps we don't need (done: `tar` `xattr` → removed `rustix`/`linux-raw-sys`; candidates: `iced-x86` disasm, the `rustfft`/`rustdct` DCT, `sevenz-rust2` PPMd — feature-gate each behind its capability).
- **Make safe** what we can: prefer portable/no-SIMD builds of compression/crypto where the speed cost is acceptable, and vendor-then-make-safe (our RAR PPMd decoder is zero-`unsafe`, and `exav-unpack` carries `#![forbid(unsafe_code)]`); apply the same forbid to every crate that can hold it.
- **Reuse our own safe code** instead of an `unsafe` dependency where we already have an equivalent: **7z PPMd** decodes through `sevenz-rust2`'s `ppmd-rust` (146 `unsafe` ops), but our own RAR `ppmd7` is the same PPMd var.H and is zero-`unsafe` — wire 7z's PPMd through it (or upstream the safe decoder to `sevenz-rust2`) to drop `ppmd-rust`.
- **Verify** the residual: `cargo-fuzz` + Miri over every reachable parser/decompressor, and document containment (panic isolation, the prefork process boundary, the WASM-sandboxed extractor) for the `unsafe` that must stay.

## Contributing

> ### ⚠️ Clean-room rule (non-negotiable)
> exav is **MIT**; ClamAV (`libclamav` / `libclamav_rust`) is **GPLv2**. **All
> code in this repository was, and must continue to be, written independently —
> without reading, porting, translating, or otherwise considering any ClamAV GPL
> source code.** Deriving from GPL code (even C→Rust) would make this project a
> derivative work and is a license violation. Do **not** port from ClamAV, and do
> **not** cite any ClamAV source as the origin of any code. Implement only from
> **independent public sources**: the format's own published specification,
> reverse-engineered format docs, or **permissively-licensed** (MIT/BSD/Apache/
> public-domain) code with attribution in [`NOTICE`](NOTICE). Interoperating with
> ClamAV's *data* formats (signature databases, `CL_TYPE_*` ids) is fine — that's
> interoperability, not derivation.

Issues and PRs welcome. Please run `cargo test`, `cargo clippy --all-targets`, and `cargo fmt --check` before submitting (CI also runs `cargo audit`, `cargo deny check`, and a `cargo-fuzz` smoke pass). Good first areas: additional archive formats, `.ndb` wildcard matching, the S3 source backend, and fuzz targets.

**32-bit / WASM tests.** `usize` is 32-bit on the `wasm32` build exav ships (the sandboxed extractor), so integer- and capacity-overflow bugs on parsed offsets/lengths are invisible on a 64-bit host but abort on wasm32. Run the `exav-unpack` (extractor) and `exav-core` (scanning core, minus `yara`) unit tests — including the hostile-input regressions — on `wasm32-wasip1` under [wasmtime](https://wasmtime.dev):

```
make test-wasm          # or: scripts/test-wasm.sh   (needs `wasmtime` on PATH)
```

CI runs this on every push (the `wasm` job). If you touch a decoder or a byte-parsing path, run it — an overflow that passes on x86-64 will fail here. A handful of core tests that need a host filesystem/tempdir are `#[cfg_attr(target_family = "wasm", ignore)]` (they run natively via `make test`).

**Do not commit real malware to this repository.** Tests use the harmless EICAR string and synthetic inputs only.

## License

MIT — see [`LICENSE`](LICENSE). The exav binary statically links third-party crates under permissive licenses (notably yara-x under BSD-3-Clause and the wasmtime/cranelift stack under Apache-2.0 WITH LLVM-exception); their required notices are reproduced in [`NOTICE`](NOTICE). exav never bundles or redistributes the GPL-licensed ClamAV signature database; those signatures may be fetched by the user at runtime (see [Signatures](#signatures)). exav ships only with permissively-licensed signatures.
