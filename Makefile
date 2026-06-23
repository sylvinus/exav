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
.PHONY: build release test lint fmt fuzz db cache daily clean help

## build: compile the release binary
build release:
	$(CARGO) build --release

## test: run the workspace test suite
test:
	$(CARGO) test --workspace

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
