# exav — build, test, and the daily signature-cache pipeline.
#
# The cache pipeline (`make cache`) is the intended production flow: fetch the
# ClamAV signatures with Cisco's own updater, then compile a prebuilt cache that
# CLI instances load directly (a near-instant, low-memory cold start). Run it on
# a host with enough RAM — building the full main+daily set needs ~8 GB.

CARGO   ?= cargo
EXAV    ?= ./target/release/exav
DBDIR   ?= exav-db
CACHE   ?= exav.cache

.DEFAULT_GOAL := build
.PHONY: build release test test-native test-all test-wasm wasm-sizes lint fmt fuzz db cache daily clean help

## build: compile the release binary
build release:
	$(CARGO) build --release

## test: quick default-feature workspace tests (subset — see test-all)
test:
	$(CARGO) test --workspace

## test-native: the FULL native test matrix (every feature pass CI runs, no wasm).
##              Mirrors the `test` job in .github/workflows/ci.yml — keep in sync.
test-native:
	$(CARGO) test --workspace
	$(CARGO) test -p exav-core --features http
	$(CARGO) test -p exav-unpack --features checksums
	$(CARGO) test -p exav-unpack --no-default-features --features all-formats
	$(CARGO) test -p exav-core --features unstable-internals

## test-all: EVERY test (native matrix + wasm); excludes only diff-testing & fuzz.
##           The one command to run before pushing. Needs `wasmtime` for the wasm
##           pass (see test-wasm).
test-all: test-native test-wasm

## test-wasm: run the extractor unit tests on 32-bit wasm32-wasip1 under wasmtime
##            (catches integer/capacity-overflow bugs a 64-bit host hides).
##            Needs `wasmtime` on PATH (or $$WASMTIME). See scripts/test-wasm.sh.
test-wasm:
	./scripts/test-wasm.sh

## wasm-sizes: per-format exav-unpack WASM size table (how big is a min extractor)
wasm-sizes:
	./scripts/wasm-format-sizes.sh

## lint: clippy + rustfmt check
lint:
	$(CARGO) clippy --all-targets -- -D warnings
	$(CARGO) fmt --check

## fmt: format the code
fmt:
	$(CARGO) fmt

## fuzz: smoke-build the fuzz targets
fuzz:
	cd fuzz && $(CARGO) build

## db: download the ClamAV signature DB into $(DBDIR) with Cisco's cvdupdate
db:
	@command -v cvd >/dev/null 2>&1 || pip3 install --user cvdupdate || \
		pip3 install --user --break-system-packages cvdupdate
	cvd config set --dbdir $(DBDIR)
	cvd update

## cache: download fresh signatures and compile the prebuilt cache ($(CACHE))
cache: build db
	$(EXAV) -d $(DBDIR) --build-cache $(CACHE)

## daily: alias for `make cache` — run from cron to refresh the distributed cache
daily: cache

## clean: remove build artifacts (keeps $(DBDIR) and $(CACHE))
clean:
	$(CARGO) clean

## help: list targets
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/^## /  /'
