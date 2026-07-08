# Distroless, rootless, ClamAV-Docker-compatible image for exav.
#
# The runtime is `distroless/static` (built for static binaries — no OS, no
# shell, no package manager, minimal attack surface) running as the `nonroot`
# user (uid 65532). The `exav` binary is a static musl build that does all work
# in memory, so nothing else is needed at runtime.
#
# Default (`docker run`) starts the clamd-compatible daemon on TCP 3310 with a
# data dir of /var/lib/clamav, drop-in compatible with the ClamAV image:
#
#   docker run -d -p 3310:3310 -v exav-db:/var/lib/clamav ghcr.io/sylvinus/exav
#   clamdscan --stream file.bin           # host clamdscan over TCP works
#
# Signatures are NOT bundled (exav ships no GPL DB and no CDN URL). Provide them
# by mounting a populated volume, running a sidecar that writes it (see
# docker-compose.yml), or setting EXAV_DB_MIRROR to auto-download from a mirror
# you trust. See README "Docker" for the env vars.
#
# One-shot scan (overrides the default daemon CMD):
#   docker run --rm -v "$PWD:/scan" ghcr.io/sylvinus/exav -r /scan

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
# `--features http` pulls in the standalone exav-update crate so `--serve` can
# fetch from EXAV_DB_MIRROR. For a smaller, pure-Rust image without the updater,
# drop it (and set up signatures via a volume/sidecar instead).
RUN cargo build --release -p exav-cli --features http \
    && strip target/release/exav

# ---- dirs: an empty, nonroot-owned data dir to COPY in -----------------------
# distroless has no shell to `mkdir`/`chown`, so stage the mount point here.
# 65532 is distroless's `nonroot` uid/gid.
FROM alpine AS dirs
RUN mkdir -p /data && chown 65532:65532 /data

# ---- runtime: distroless static, nonroot -------------------------------------
FROM gcr.io/distroless/static-debian13:nonroot
COPY --from=build /src/target/release/exav /exav
COPY --from=dirs --chown=65532:65532 /data /var/lib/clamav
# Persist signatures across restarts (mirrors ClamAV's /var/lib/clamav volume).
VOLUME ["/var/lib/clamav"]
# clamd-compatible service port (publish with -p 3310:3310).
EXPOSE 3310
ENTRYPOINT ["/exav"]
CMD ["--serve"]
