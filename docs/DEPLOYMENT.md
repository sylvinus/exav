# Deploying exav

How to install and run exav, from a single binary to a two-container setup.
Pick the row that matches your environment:

| Deployment | Best for | Signatures | Section |
|---|---|---|---|
| **Direct executable** | servers, cron, CI, an existing ClamAV host | you fetch them | [1](#1-direct-executable) |
| **WASM host** | scanning with *untrusted* signature databases, sandboxed | mounted read-only | [2](#2-wasm-sandbox) |
| **Single container** | one host, self-contained scanner service | volume + optional built-in updater | [3](#3-single-container) |
| **Dual container** | production, updater isolated from the scanner | sidecar writes a shared volume | [4](#4-dual-container-shared-volume) |

> **exav bundles no signature database and no download URL.** ClamAV's databases
> are GPL; exav ships under MIT and *reads* them but never redistributes them or
> their CDN endpoint. Every option below therefore includes how signatures get
> in. Without a database, exav still runs on a tiny **built-in baseline** (enough
> to detect the EICAR test file) and loads real signatures when you provide them.

---

## 1. Direct executable

A single static binary, no runtime dependencies. The CLI is `clamscan`-compatible
and the daemon speaks the `clamd` wire protocol — see [MIGRATION.md](MIGRATION.md).

### Install

Build from source (Rust 1.85+) — the primary method today:

```sh
git clone https://github.com/sylvinus/exav && cd exav
cargo build --release -p exav-cli            # -> target/release/exav
```

Release artifacts (produced by CI on each `v*` tag):

```sh
# Prebuilt binaries attached to the GitHub Release (static-musl Linux runs on any
# distro): https://github.com/sylvinus/exav/releases
# targets: {x86_64,aarch64}-linux-musl, {x86_64,aarch64}-apple-darwin, x86_64-windows

# Or build a Debian/Ubuntu package (binary + optional systemd unit):
cargo install cargo-deb
cargo build --release -p exav-cli && cargo deb -p exav-cli --no-build

# Once published to crates.io: cargo install exav-cli
```

The default build includes YARA and every archive format. For a smaller,
100%-pure-Rust binary (no wasmtime/Cranelift, no TLS): `cargo build --release -p
exav-cli --no-default-features --features all-formats,decrypt`. Add `--features
http` to enable URL scanning and the built-in mirror updater (this is the only
thing that links a TLS stack).

### Get the signatures

exav does not download databases. Use Cisco's own updater onto your host, then
point exav at the directory:

```sh
pip install cvdupdate && cvdupdate download   # or `freshclam`
exav -d ~/.cvdupdate/database -r /data         # scan using those signatures
```

See [DATABASE.md](DATABASE.md) for the supported formats and an optional prebuilt
cache for near-instant startup.

### Scan

```sh
exav file.bin                     # one file
exav -r /var/www                  # recurse a directory
cat file.zip | exav -             # stdin (constant memory, any size)
exav --allmatch -r /data          # report every matching signature per file
```

### Run as a daemon (clamd-compatible)

Load the DB once and serve scans over a socket, so callers pay no startup cost.
The included systemd unit is a drop-in for `clamav-daemon` on the same socket:

```sh
sudo systemctl stop clamav-daemon && sudo systemctl disable clamav-daemon
sudo systemctl enable --now exav-clamd        # from packaging/exav-clamd.service
clamdscan --ping 1                            # the official client talks to exav
```

Or run it directly:

```sh
exav --daemon --socket /run/clamav/clamd.ctl -d /var/lib/clamav
exav --daemon --tcp 0.0.0.0:3310 -d /var/lib/clamav      # TCP instead
```

By default the daemon uses a **prefork worker pool** (one process per CPU core),
so a runaway scan is isolated and hard-killed under kernel-enforced per-job
wall-clock/memory/CPU limits (`--max-scan-time`, `--max-scan-memory`,
`--max-jobs-per-worker`). See [Reloading & notification](#reloading--notification)
to pick up database updates without a restart.

---

## 2. WASM sandbox

Run the whole engine inside a WebAssembly sandbox so an **untrusted** signature
database can't touch your host. The scanner compiles to `wasm32-wasip1` and runs
under any WASI runtime (wasmtime, wasmer, wazero) with zero custom host code:

```sh
rustup target add wasm32-wasip1
cargo build --release --target wasm32-wasip1 -p exav-wasm
wasmtime --dir /path/to/sigs::/db --dir .::. \
  target/wasm32-wasip1/release/exav_wasm.wasm /db malware.exe
```

Full details, capability model, and runtime options are in [WASM.md](WASM.md).

---

## 3. Single container

The image is **drop-in compatible with the
[ClamAV Docker image](https://docs.clamav.net/manual/Installing/Docker.html)**:
same `/var/lib/clamav` database volume, same clamd port **3310**, and the same
`CLAMAV_NO_CLAMD` / `CLAMAV_NO_FRESHCLAMD` / `CLAMD_STARTUP_TIMEOUT` /
`FRESHCLAM_CHECKS` environment variables. It is **distroless and rootless**: a
static-musl binary on `distroless/static` (no shell, no package manager) running
as an unprivileged user.

```sh
# Start the daemon (default). Mount a volume so signatures persist across restarts.
docker run -d --name exav -p 3310:3310 -v exav-db:/var/lib/clamav \
  ghcr.io/sylvinus/exav

# Scan from the host over TCP with the official client:
clamdscan --stream file.bin

# One-shot scan instead of the daemon (override the default command):
docker run --rm -v "$PWD:/scan" ghcr.io/sylvinus/exav -r /scan
```

The daemon **hot-reloads** `/var/lib/clamav` whenever it changes, so populate it
any of three ways:

1. **Managed volume** — mount a `/var/lib/clamav` you keep current yourself with
   `cvdupdate`/`freshclam`. No updater in the container.
2. **Built-in updater** — set `EXAV_DB_MIRROR` to a CVD mirror **you trust**; the
   container fetches `main`/`daily`/`bytecode.cvd` on start and every
   `FRESHCLAM_CHECKS`/day. (Needs an image built with `--features http`, which
   the published image is.)
3. **Sidecar** — a second container writes the shared volume — see
   [Section 4](#4-dual-container-shared-volume).

### Environment variables

| Variable | Default | Meaning |
|---|---|---|
| `CLAMAV_NO_CLAMD` | `false` | Don't run the scanner (updater-only container). |
| `CLAMAV_NO_FRESHCLAMD` | `false` | Don't run the built-in updater. |
| `CLAMD_STARTUP_TIMEOUT` | `1800` | Seconds to wait for a database before serving the built-in baseline. |
| `FRESHCLAM_CHECKS` | `1` | Update checks per day. |
| `EXAV_DB_MIRROR` | *(unset)* | **exav extension.** Base URL of a CVD mirror to auto-download from. Unset = no auto-download. |
| `EXAV_DATADIR` | `/var/lib/clamav` | Database directory. |
| `EXAV_LISTEN` | `0.0.0.0:3310` | clamd listen address. |
| `EXAV_NO_SHUTDOWN_COMMAND` | `false` | Refuse the clamd `SHUTDOWN` command (see [Security](#security-notes)). |

### Rootless

The image already runs as the unprivileged `nonroot` user (uid 65532) and binds
3310 (>1024), so nothing extra is needed. When you bind-mount a host directory
(instead of a named volume), make it writable by uid 65532 so the daemon can
write databases and temp files:

```sh
mkdir -p ./exav-db && sudo chown 65532:65532 ./exav-db
docker run -d -p 3310:3310 -v "$PWD/exav-db:/var/lib/clamav" ghcr.io/sylvinus/exav
```

---

## 4. Dual container (shared volume)

Separate the updater from the scanner: an **updater-only** container refreshes a
shared volume and the **scanner** container hot-reloads it. This is the setup in
[`docker-compose.yml`](../docker-compose.yml):

```sh
EXAV_DB_MIRROR=https://your-mirror/ docker compose up -d
```

```yaml
services:
  exav:                       # scanner
    image: ghcr.io/sylvinus/exav:latest
    ports: ["3310:3310"]
    volumes: [exav-db:/var/lib/clamav]

  updater:                    # writes the shared volume, doesn't scan
    image: ghcr.io/sylvinus/exav:latest
    environment:
      CLAMAV_NO_CLAMD: "true"
      EXAV_DB_MIRROR: "${EXAV_DB_MIRROR}"
      FRESHCLAM_CHECKS: "2"
    volumes: [exav-db:/var/lib/clamav]

volumes:
  exav-db:
```

The scanner notices the updated files on the shared mount (a database-directory
watch, like clamd's `SelfCheck`) and re-forks its worker pool with the new
signatures — no restart, no cross-container signalling needed.

### Using the official ClamAV updater as the sidecar

Because the notification is protocol-compatible, you can instead run Cisco's own
`clamav/clamav` freshclam container as the updater. Point its `NotifyClamd` at
the exav scanner's clamd port; the `RELOAD` it sends is exactly what exav's
daemon honours. Either way the two containers only need to share the
`/var/lib/clamav` volume.

---

## Reloading & notification

The daemon refreshes its signatures, without a restart, on any of:

- the clamd **`RELOAD`** command over the socket/port (what `freshclam`'s
  `NotifyClamd` sends — strictly protocol-compatible);
- a change on disk in the database directory (the sidecar / `freshclam` case);
- a successful fetch by the built-in updater.

On each, the prefork supervisor reloads the database and re-forks the worker
pool, so the per-job hard-kill isolation is preserved across reloads. (In the
non-default single-thread model, `--workers 0`, `RELOAD` is accepted but does not
re-fork.)

The updater performs a **plain HTTPS fetch** with an HTTP-range version check —
it does **not** verify the container's digital signature. Point `EXAV_DB_MIRROR`
only at a mirror you trust; for cryptographically verified, bandwidth-efficient
updates use `freshclam`/`cvdupdate` (Section 4) and let exav hot-reload the volume.

---

## Security notes

- **`SHUTDOWN` command.** Like clamd, exav honours the `SHUTDOWN` command, which
  stops the daemon. If the socket or TCP port is reachable by untrusted clients,
  disable it with `--no-shutdown-command` (or `EXAV_NO_SHUTDOWN_COMMAND=true` in
  `--serve` mode); the daemon then answers `SHUTDOWN` with an error instead. Note
  a client that can reach the daemon can already request scans, so restrict the
  port regardless (bind to localhost, a private network, or the Unix socket).
- **Rootless by default** in the container (uid 65532); the systemd unit runs as
  the `clamav` user with a hardened sandbox.
- **Untrusted databases** — if you load signature databases you don't fully
  trust, run under the [WASM sandbox](#2-wasm-sandbox); the native engine treats
  the database as trusted input.

## See also

- [MIGRATION.md](MIGRATION.md) — moving from ClamAV (`clamscan`/`clamd` parity)
- [DATABASE.md](DATABASE.md) — signature formats, `cvdupdate`, prebuilt caches
- [WASM.md](WASM.md) — the sandboxed runtime in depth
- [`docker-compose.yml`](../docker-compose.yml) — the dual-container example
