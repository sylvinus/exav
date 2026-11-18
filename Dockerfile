# syntax=docker/dockerfile:1
# Global build args (must be declared before the first FROM to be usable in
# FROM lines): BIN_SOURCE selects how the runtime stage gets its binary:
# `build` compiles it in-image (default; local builds, CI smoke test),
# `prebuilt` copies bins/exav-$TARGETARCH (release publishing; see below).
ARG BIN_SOURCE=build
# Distroless, rootless, ClamAV-Docker-compatible image for exav.
#
# The runtime is `distroless/static` (built for static binaries: no OS, no
# shell, no package manager, minimal attack surface) running as the `nonroot`
# user, uid and gid 65532. The `exav` binary is a static musl build, so nothing
# else is needed at runtime. It needs no capability and no root at any point.
#
# The only paths it writes, besides a file a flag names (--log, --build-db), so
# a `--read-only` root filesystem works once they are volumes or tmpfs:
#   /var/lib/exav  signatures, a pulled .exavdb, the updater's temp files
#   /tmp           objects too large to hold in RAM while scanned (spill)
#   /run/exav      the Unix socket, when EXAV_LISTEN names one there
# The first and last are owned by 65532 in the image, so a new named volume
# mounted there starts with that owner. A bind mount keeps the host's owner.
#
# Default (`docker run`) starts the clamd-compatible daemon on TCP 3310 with a
# data dir of /var/lib/exav (wire-compatible with the ClamAV image):
#
#   docker run -d -p 127.0.0.1:3310:3310 -v exav-db:/var/lib/exav ghcr.io/sylvinus/exav
#   clamdscan --stream file.bin           # host clamdscan over TCP works
#
# Signatures are NOT bundled (exav ships no GPL DB and no CDN URL). Provide them
# by mounting a populated volume, running a sidecar that writes it (see
# docker-compose.yml), or setting EXAV_SIG_SOURCES to auto-download from a mirror
# you trust. See https://exav.org/scanner/guides/docker/ for the env vars.
#
# One-shot scan. Paths on the command line win over the `EXAV_LISTEN` set below
# for the default daemon; the scan needs the signature volume too:
#   docker run --rm -v exav-db:/var/lib/exav -v "$PWD:/scan" ghcr.io/sylvinus/exav /scan

# ---- binary: compile in-image, or copy a runner-built one --------------------
# Selected by BIN_SOURCE. Only the selected branch is built; the other is
# skipped entirely.
#
#   * `build` (default): compile the static musl binary here. Used for local
#     builds and the CI smoke test (`docker build -t exav:ci .`).
#   * `prebuilt`: copy `bins/exav-$TARGETARCH`, cross-compiled on the runner by
#     the `binaries` CI job with the same flags as below. Release publishing
#     uses this: compiling the Rust+ring tree under QEMU for arm64 is an order
#     of magnitude slower than cross-compiling it.
# rust:alpine targets *-unknown-linux-musl and links statically. `build-base`
# provides the C toolchain the TLS stack (ring, via the `http` feature's ureq →
# rustls) needs to compile under musl. Pinned to 1.95, the MSRV floor (see the
# workspace `rust-version`, which says what sets it); bump both together. The
# Alpine branch is pinned too, so the packages below come from one branch; their
# versions are not, because a branch keeps only the latest revision of each and
# a pinned one fails the build at its next security fix.
FROM rust:1.95-alpine3.23 AS build
# hadolint ignore=DL3018
RUN apk add --no-cache musl-dev build-base
WORKDIR /src
COPY . .
# `--features http` pulls in the standalone exav-update crate so `--auto-update`
# can fetch from EXAV_SIG_SOURCES. For a smaller, pure-Rust image without the
# updater, drop it (and set up signatures via a volume/sidecar instead).
# The `cp` normalises the output path with the `prebuilt` branch below, so the
# runtime stage copies one location whatever the source was. The release profile
# (fat LTO, one codegen unit) needs about 3 GiB of memory at its peak.
RUN cargo build --release -p exav --features http \
    && strip target/release/exav \
    && cp target/release/exav /exav

FROM scratch AS prebuilt
ARG TARGETARCH
# Executable whatever mode the file arrives with: a binary that went through
# `upload-artifact` and `download-artifact` has lost its permission bits, and an
# image whose /exav is not executable fails to start (`crun: open executable:
# Permission denied`), `latest` included.
COPY --chmod=755 bins/exav-${TARGETARCH} /exav

FROM ${BIN_SOURCE} AS binsrc

# ---- dirs: an empty, nonroot-owned directory to COPY in ----------------------
# distroless has no shell to `mkdir`/`chown`, so stage the mount points here.
# 65532 is distroless's `nonroot` uid/gid.
# Pinned to the build machine: this stage only makes a directory, so emulating
# it under QEMU on a multi-arch build would be pure overhead.
FROM --platform=$BUILDPLATFORM alpine:3.23 AS dirs
RUN mkdir -m 0755 /data && chown 65532:65532 /data

# ---- runtime: distroless static, nonroot -------------------------------------
FROM gcr.io/distroless/static-debian13:nonroot
COPY --from=binsrc /exav /exav
COPY --from=dirs --chown=65532:65532 /data /var/lib/exav
# Not writable by anyone else: whoever can write the socket's directory can
# replace the socket.
COPY --from=dirs --chown=65532:65532 /data /run/exav
# Numeric, so that Kubernetes can check `runAsNonRoot` against the image without
# a runAsUser. The base image sets the same user; this keeps it if the base
# changes.
USER 65532:65532
# Persist signatures across restarts. To reuse an existing ClamAV database
# volume, mount it here (or set EXAV_SIG_DIR=/var/lib/clamav and mount there):
# its files must be readable by 65532, and writable too for --auto-update.
VOLUME ["/var/lib/exav"]
# The image's own configuration, in the form every other setting takes: an
# environment variable a flag on the command line can override. Listening on all
# interfaces is what makes a published port reachable.
ENV EXAV_LISTEN=clamd://0.0.0.0:3310
# clamd-compatible service port (publish with -p 127.0.0.1:3310:3310: the clamd
# protocol has no authentication).
EXPOSE 3310
# ICAP (RFC 3507) service port, for replacing a c-icap container at a proxy's
# adaptation hook. Nothing binds it unless an `icap://` address is listed, and
# listing one ADDS the listener: both protocols are then served from the one
# process, over the one loaded database:
#
#   docker run -d -p 127.0.0.1:3310:3310 -p 127.0.0.1:1344:1344 \
#     -e EXAV_LISTEN=clamd://0.0.0.0:3310,icap://0.0.0.0:1344 \
#     -v exav-db:/var/lib/exav ghcr.io/sylvinus/exav
#
# For ICAP and nothing else, name it in EXAV_LISTEN rather than with --listen,
# so the HEALTHCHECK below, which reads only the environment, probes it:
#
#   docker run -d -p 127.0.0.1:1344:1344 -v exav-db:/var/lib/exav \
#     -e EXAV_LISTEN=icap://0.0.0.0:1344 ghcr.io/sylvinus/exav
#
# EXPOSE is documentation, not a listener: see the ICAP guide for the env vars.
EXPOSE 1344

# `--ping` reads the same `EXAV_LISTEN` the daemon did (the health check
# inherits the container's environment, not its command line), so it follows the
# configuration instead of assuming it. A check pinned to `clamd://…:3310` calls
# a healthy daemon dead the moment that variable moves the port or asks for ICAP
# instead, and an orchestrator restarts the container for it.
#
# It is one exchange in whatever protocol the listener speaks (`PING` on clamd,
# `OPTIONS` on ICAP), not a bare TCP connect: a daemon that accepts and then
# answers nothing is exactly what this is for.
#
# `/exav` is the probe because the image is distroless: no shell, no curl.
#
# Unhealthy while the daemon is still waiting for signatures, deliberately: it
# is not serving then, and saying otherwise sends traffic somewhere that cannot
# answer. Raise --start-period when signatures come from a slow sidecar.
#
# It answers for the daemon this image defaults to, so a container given a
# different job (`--build-db`, a `--connect` client, a one-shot scan) reports
# unhealthy for its lifetime while working perfectly: nothing is listening, and
# the check cannot tell that from a daemon that died. Those runs are short and
# exit on their own, so this is cosmetic under `docker run`; pass
# `--no-healthcheck` if a supervisor would act on it.
#
# HEALTHCHECK is a Docker extension of the image config, not part of the OCI
# spec. The field survives in an OCI image, and Docker reads it, but podman
# reads it only from an image published with Docker mediatypes, which the
# publish workflow asserts. Kubernetes ignores it whatever the format. An
# orchestrator that matters should say it itself, with the same command
# (docker-compose.yml, and the Health section of the Docker guide).
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
  CMD ["/exav", "--ping"]

ENTRYPOINT ["/exav"]
# Serve whatever EXAV_LISTEN names, and keep the signature volume current:
# bootstrap it, wait for a sidecar to fill it if that is where signatures come
# from, refresh the configured sources on a schedule, and hot-reload on change.
CMD ["--auto-update"]
