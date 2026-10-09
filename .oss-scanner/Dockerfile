# Build environment for Anthropic's OSS Scanner (https://red.anthropic.com/oss-scanner/).
# The checkout is at /src, the build context is the repository, and nothing
# after the build has network access: every dependency is fetched here.
#
# Build it the way the scanner does, from the repository root:
#   docker build -f .oss-scanner/Dockerfile -t exav-oss-scanner .
FROM rust:1.92-bookworm

# Frame pointers and line tables for a debugger, without the full debug info
# that makes the build several times larger.
ENV DEBIAN_FRONTEND=noninteractive \
    CARGO_TERM_COLOR=never \
    CARGO_PROFILE_DEV_DEBUG=line-tables-only \
    RUSTFLAGS="-C force-frame-pointers=yes"

# gdb and valgrind are for the agent that reproduces a finding; clang is what a
# C dependency's build script may look for.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates build-essential clang pkg-config git python3 gdb valgrind \
    && rm -rf /var/lib/apt/lists/*

COPY . /src
WORKDIR /src

# Every dependency of every crate, test-only ones included, so that nothing
# is fetched after this step. `--locked` uses exactly Cargo.lock.
RUN cargo fetch --locked

# Every crate of the workspace, in the dev profile (overflow checks on, as in
# the release profile). `exav` is built with the optional network-facing half
# (`SCANURL`, `--sig-sources`), which pulls the TLS stack.
RUN cargo build --workspace --locked \
    && cargo build -p exav --locked --features http

# The tools, on PATH. They read a file given on the command line; `exav` needs
# a signature database to scan, which `threat_model.md` says how to make.
RUN for t in exav exav-unpack exav-grep exav-imagehash; do \
        ln -s "/src/target/debug/$t" "/usr/local/bin/$t"; \
    done

# A cheap check that the image works: the unit tests of the extractor. A
# failure is reported and does not fail the image.
RUN (cargo test -p exav-unpack --lib --locked 2>&1 | tail -n 5) \
    || echo "WARNING: the exav-unpack unit tests reported failures"
