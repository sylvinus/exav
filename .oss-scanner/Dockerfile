# Build environment for Anthropic's OSS Scanner (https://red.anthropic.com/oss-scanner/).
# The checkout is at /src, the build context is the repository, and nothing
# after the build has network access: every dependency is fetched here.
#
# Build it the way the scanner does, from the repository root:
#   docker build -f .oss-scanner/Dockerfile -t exav-oss-scanner .
FROM rust:1.92-bookworm

ENV DEBIAN_FRONTEND=noninteractive \
    CARGO_TERM_COLOR=never \
    RUSTFLAGS="-C force-frame-pointers=yes"

# gdb and valgrind are for the agent that reproduces a finding; clang is what a
# C dependency's build script may look for.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates build-essential clang pkg-config git python3 gdb valgrind \
    && rm -rf /var/lib/apt/lists/*

COPY . /src
WORKDIR /src

# Every crate of the workspace, with the debug info and the overflow checks of
# the dev profile (the release profile keeps overflow checks too). `--locked`
# builds exactly the dependencies of Cargo.lock.
RUN cargo build --workspace --locked

# The optional network-facing half of the CLI (`SCANURL`, `--sig-sources`),
# which pulls the TLS stack: built so that its dependencies are fetched too.
RUN cargo build -p exav --locked --features http

# The test binaries and their dependencies, built and not run: a test run takes
# a long time and a failing test must not fail the image.
RUN cargo test --workspace --locked --no-run

# The tools, on PATH. They read a file given on the command line; `exav` needs
# a signature database to scan, which `threat_model.md` says how to make.
RUN for t in exav exav-unpack exav-grep exav-imagehash; do \
        ln -s "/src/target/debug/$t" "/usr/local/bin/$t"; \
    done

# A cheap check that the image works, whose failure is only reported.
RUN (cargo test -p exav-unpack --lib --locked 2>&1 | tail -n 5) \
    || echo "WARNING: the exav-unpack unit tests reported failures"
