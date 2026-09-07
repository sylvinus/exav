# exav — build, test, and the daily prebuilt-database pipeline.
#
# `make exavdb` is the intended production flow: fetch the ClamAV signatures with
# Cisco's own updater, then compile a prebuilt `.exavdb` that CLI instances load
# directly (a near-instant, low-memory cold start). Run it on a host with enough
# RAM — building the full main+daily set needs ~8 GB.

CARGO   ?= cargo
EXAV    ?= ./target/release/exav
DBDIR   ?= exav-db
EXAVDB  ?= exav.exavdb

.DEFAULT_GOAL := build
.PHONY: build release test test-native test-yara-diff test-wasm test-js test-www wasm-sizes lint fmt msrv release-check fuzz db exavdb cache daily clean www-dev www-build help

## build: compile the release binary
build release:
	$(CARGO) build --release

## test: EVERY test exav owns — native feature matrix, wasm32, the WASM bindings'
##       JS suites and the docs build. The one command to run before pushing.
##       Needs `wasmtime` (test-wasm) and node (test-js, test-www); the
##       sub-targets below run each part alone.
##
##       Excludes fuzzing and the two DIFFERENTIAL harnesses, which check exav
##       against another engine rather than against its own contract:
##       `scripts/difftest.sh` and `make test-yara-diff`.
##
##       For the fast inner loop use `cargo test` directly — but note it is a
##       SUBSET: feature-gated test files compile to zero tests without their
##       feature and report green having checked nothing.
test:
	$(MAKE) test-native
	$(MAKE) test-wasm
	$(MAKE) test-js
	$(MAKE) test-www

## test-native: the full native test matrix (every feature pass CI runs, no wasm).
##              Mirrors the `test` job in .github/workflows/ci.yml — keep in sync.
test-native:
	$(CARGO) test --workspace
	$(CARGO) test -p exav-core --features http
	$(CARGO) test -p exav-unpack --features checksums
	$(CARGO) test -p exav-unpack --no-default-features --features all-formats
	$(CARGO) test -p exav-core --features unstable-internals
	# Minimal build: compiles the `cfg(not(feature = ...))` fallbacks every other
	# pass hides — the paths that must report unsupported rather than clean.
	$(CARGO) test -p exav-core --no-default-features
	$(CARGO) test -p exav-unpack --no-default-features
	# Crash containment, which only runs when a decoder can be asked to fail.
	# Without this pass the tests that check it skip themselves and the whole
	# question goes unasked — a scanner that dies on crafted input and exits 0
	# is indistinguishable, to a pipeline reading `$$?`, from a clean scan.
	$(CARGO) test -p exav-unpack --features testing-faults panic_containment
	$(CARGO) test -p exav --features testing-faults --test decoder_crash

## test-yara-diff: the yara-x A/B differential harness — compiles the SAME rules
##                 with both engines and asserts equal matching-rule sets. NOT
##                 part of `make test`, for the same reason the clamav harness
##                 (scripts/difftest.sh) isn't: a differential test
##                 measures exav against another engine, so it can go red because
##                 the OTHER engine changed. That is a research signal, not a
##                 merge gate, and it does not belong on the path a contributor
##                 runs before pushing.
##
##                 yara-x is invoked as the `yr` BINARY, not linked as a crate.
##                 As a dependency it drags in ~83 extra crates, 21 of them
##                 cranelift/wasmtime — exav's own build contains no JIT backend
##                 at all, and a crate in the graph can reach a shipped artifact
##                 in a way a program on PATH cannot.
##
##                 Install the oracle with `cargo install yara-x-cli`, or point
##                 EXAV_YR_BIN at a build. WITHOUT it the tests SKIP and report
##                 green having checked nothing — so read the output, not just
##                 the exit code. Run it when you touch the YARA engine.
test-yara-diff:
	$(CARGO) test -p exav-core --test yara_difftest --test yara_coverage_difftest -- --nocapture

## test-js: the exav-unpack-wasm JavaScript suites — vitest units plus the
##          playwright browser e2e against a freshly built pkg/. This is the
##          published npm package's public API; no cargo test reaches it.
test-js:
	./scripts/test-js.sh

## test-www: type-check and build the exav.org docs site (broken links, bad
##           frontmatter, sidebar entries pointing at deleted pages).
test-www:
	./scripts/test-www.sh

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

## msrv: build the workspace on the `rust-version` floor declared in Cargo.toml.
##       Nothing else checks it, and a version nobody verifies drifts upward the
##       first time someone uses a newer feature — silently breaking anyone who
##       pinned the toolchain we promised.
msrv:
	@v=$$(sed -n 's/^rust-version = "\(.*\)"/\1/p' Cargo.toml | head -1); \
	  rustup toolchain install $$v --profile minimal >/dev/null 2>&1 || true; \
	  echo "checking MSRV $$v"; $(CARGO) +$$v check --workspace --all-targets

## release: the pre-publish gate, then crates.io in dependency order. Stops for
##          a human between the two. `scripts/release.sh --gate-only` runs just
##          the checks; `--dry-run` adds `cargo publish --dry-run`.
release-check:
	./scripts/release.sh --gate-only

## fuzz: smoke-build the fuzz targets
fuzz:
	cd fuzz && $(CARGO) build

## db: download the ClamAV signature DB into $(DBDIR) with Cisco's cvdupdate
db:
	@command -v cvd >/dev/null 2>&1 || pip3 install --user cvdupdate || \
		pip3 install --user --break-system-packages cvdupdate
	cvd config set --dbdir $(DBDIR)
	cvd update

## exavdb: download fresh signatures and compile the prebuilt database ($(EXAVDB))
exavdb: build db
	$(EXAV) -d $(DBDIR) --build-db $(EXAVDB)

## cache: deprecated alias for `make exavdb`
cache: exavdb

## daily: alias for `make exavdb` — run from cron to refresh the distributed database
daily: exavdb

## clean: remove build artifacts (keeps $(DBDIR) and $(EXAVDB))
clean:
	$(CARGO) clean

## www-dev: run the exav.org docs site (Astro Starlight) dev server (www/)
www-dev:
	cd www && ([ -d node_modules ] || npm install) && npm run dev

## www-build: build the static exav.org docs site into www/dist
www-build:
	cd www && ([ -d node_modules ] || npm install) && npm run build

# The order is the crate graph, leaves first. It is not a preference: a crate
# cannot be published before the crates it depends on exist on the registry,
# because cargo resolves the `version` alongside each path dependency from
# there. Publishing out of order fails partway and leaves some crates at the new
# version and some not — and a published version can be yanked but never
# replaced or reused, so a botched run burns that version number permanently.
PUBLISH_ORDER := exav-x86 exav-pe-emu exav-unpack exav-core exav-update exav-grep exav-cli

## publish-check: dry-run every crate in dependency order, publishing nothing
publish-check:
	@for c in $(PUBLISH_ORDER); do \
		echo "=== $$c"; \
		$(CARGO) publish --dry-run -p $$c || exit 1; \
	done
	@echo "All crates package cleanly. Review the file lists above before publishing."

## publish: publish every crate in dependency order (asks once, then commits)
publish:
	@echo "About to publish to crates.io, in this order:"
	@echo "  $(PUBLISH_ORDER)"
	@echo "This cannot be undone: a version can be yanked but never reused."
	@read -p "Type the version to confirm: " v; \
	 test "$$v" = "$$($(CARGO) metadata --no-deps --format-version 1 | \
	   sed -n 's/.*"name":"exav-core","version":"\([^"]*\)".*/\1/p')" || \
	   { echo "Version mismatch; nothing published."; exit 1; }
	@for c in $(PUBLISH_ORDER); do \
		echo "=== publishing $$c"; \
		$(CARGO) publish -p $$c || exit 1; \
	done

# The npm package is published from the CRATE directory, never from `pkg/`.
# `wasm-pack` writes its own `package.json` into `pkg/`, so running `npm publish`
# in there ships that one instead — different `files`, different `main`, and none
# of the metadata. Only the tracked manifest describes what should go out, and
# this target is what pins the choice.
## npm-publish-check: pack the npm bindings without publishing, and list contents
npm-publish-check:
	cd crates/exav-unpack-wasm && npm pack --dry-run

## npm-publish: build and publish the WASM bindings to npm
npm-publish:
	cd crates/exav-unpack-wasm && npm publish

## help: list targets
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/^## /  /'
