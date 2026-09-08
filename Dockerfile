# Distroless, rootless, ClamAV-Docker-compatible image for exav.
#
# The runtime is `distroless/static` (built for static binaries — no OS, no
# shell, no package manager, minimal attack surface) running as the `nonroot`
# user (uid 65532). The `exav` binary is a static musl build that does all work
# in memory, so nothing else is needed at runtime.
#
# Default (`docker run`) starts the clamd-compatible daemon on TCP 3310 with a
# data dir of /var/lib/exav (wire-compatible with the ClamAV image):
#
#   docker run -d -p 3310:3310 -v exav-db:/var/lib/exav ghcr.io/sylvinus/exav
#   clamdscan --stream file.bin           # host clamdscan over TCP works
#
# Signatures are NOT bundled (exav ships no GPL DB and no CDN URL). Provide them
# by mounting a populated volume, running a sidecar that writes it (see
# docker-compose.yml), or setting EXAV_SIG_SOURCES to auto-download from a mirror
# you trust. See https://exav.org/guides/docker/ for the env vars.
#
# One-shot scan. `EXAV_LISTEN` below is set for the daemon this image defaults
# to; clear it to scan paths instead, or exav refuses rather than guessing which
# of the two jobs was meant:
#   docker run --rm -e EXAV_LISTEN= -v "$PWD:/scan" ghcr.io/sylvinus/exav /scan

# ---- build: static musl binary, updater (http feature) enabled ---------------
# rust:alpine targets *-unknown-linux-musl and links statically. `build-base`
# provides the C toolchain the TLS stack (ring, via the `http` feature's ureq →
# rustls) needs to compile under musl. Pinned to 1.91, the current MSRV floor
# imposed by the yara-x/wasmtime/cranelift tree (see the workspace `rust-version`);
# bump both together when that stack raises its MSRV again.
FROM rust:1.91-alpine AS build
RUN apk add --no-cache musl-dev build-base
WORKDIR /src
COPY . .
# `--features http` pulls in the standalone exav-update crate so `--auto-update`
# can fetch from EXAV_SIG_SOURCES. For a smaller, pure-Rust image without the
# updater, drop it (and set up signatures via a volume/sidecar instead).
RUN cargo build --release -p exav --features http \
    && strip target/release/exav

# ---- dirs: an empty, nonroot-owned data dir to COPY in -----------------------
# distroless has no shell to `mkdir`/`chown`, so stage the mount point here.
# 65532 is distroless's `nonroot` uid/gid.
FROM alpine AS dirs
RUN mkdir -p /data && chown 65532:65532 /data

# ---- runtime: distroless static, nonroot -------------------------------------
FROM gcr.io/distroless/static-debian13:nonroot
COPY --from=build /src/target/release/exav /exav
COPY --from=dirs --chown=65532:65532 /data /var/lib/exav
# Persist signatures across restarts. To reuse an existing ClamAV database
# volume, mount it here (or set EXAV_SIGS_DIR=/var/lib/clamav and mount there).
VOLUME ["/var/lib/exav"]
# The image's own configuration, in the form every other setting takes: an
# environment variable a flag on the command line can override. Listening on all
# interfaces is what makes a published port reachable.
ENV EXAV_LISTEN=clamd://0.0.0.0:3310
# clamd-compatible service port (publish with -p 3310:3310).
EXPOSE 3310
# ICAP (RFC 3507) service port, for replacing a c-icap container at a proxy's
# adaptation hook. Nothing binds it unless an `icap://` address is listed, and
# listing one ADDS the listener — both protocols are then served from the one
# process, over the one loaded database:
#
#   docker run -d -p 3310:3310 -p 1344:1344 \
#     -e EXAV_LISTEN=clamd://0.0.0.0:3310,icap://0.0.0.0:1344 \
#     -v exav-db:/var/lib/exav ghcr.io/sylvinus/exav
#
# For ICAP and nothing else, name the listener instead of the default command:
#
#   docker run -d -p 1344:1344 -v exav-db:/var/lib/exav \
#     ghcr.io/sylvinus/exav --listen icap://0.0.0.0:1344 --auto-update
#
# EXPOSE is documentation, not a listener — see the ICAP guide for the env vars.
EXPOSE 1344

# `--ping` reads the same `EXAV_LISTEN` the daemon did — the health check
# inherits the container's environment — so it follows the configuration instead
# of assuming it. A check pinned to `clamd://…:3310` calls a healthy daemon dead
# the moment that variable moves the port or asks for ICAP instead, and an
# orchestrator restarts the container for it.
#
# It is one exchange in whatever protocol the listener speaks (`PING` on clamd,
# `OPTIONS` on ICAP), not a bare TCP connect: a daemon that accepts and then
# answers nothing is exactly what this is for.
#
# `/exav` is the probe because the image is distroless — no shell, no curl.
#
# Unhealthy while the daemon is still waiting for signatures, deliberately: it
# is not serving then, and saying otherwise sends traffic somewhere that cannot
# answer. Raise --start-period when signatures come from a slow sidecar.
#
# It answers for the daemon this image defaults to, so a container given a
# different job — `--build-db`, a `--connect` client, a one-shot scan — reports
# unhealthy for its lifetime while working perfectly: nothing is listening, and
# the check cannot tell that from a daemon that died. Those runs are short and
# exit on their own, so this is cosmetic under `docker run`; pass
# `--no-healthcheck` if a supervisor would act on it.
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
  CMD ["/exav", "--ping"]

ENTRYPOINT ["/exav"]
# Serve whatever EXAV_LISTEN names, and keep the signature volume current:
# bootstrap it, wait for a sidecar to fill it if that is where signatures come
# from, refresh the configured sources on a schedule, and hot-reload on change.
CMD ["--auto-update"]
