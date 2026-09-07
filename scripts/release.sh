#!/usr/bin/env bash
# Gate, review, then publish the workspace to crates.io.
#
# WHY: publishing is irreversible. A crates.io version can be yanked but never
# replaced, and the crates go up one at a time — so a manifest error found on
# crate five leaves four already published against a version that no longer
# builds. Everything that can be checked is therefore checked BEFORE the first
# `cargo publish`, and the run stops for a human in between.
#
# The gate is deliberately wider than CI. CI answers "does this branch work";
# this answers "is this the artifact we mean to ship", which also covers what
# goes INTO the tarballs (`cargo package`), the version floor we promise
# (`rust-version`), and the property that the release does not set off other
# scanners (the self-scan).
#
# USAGE:
#   scripts/release.sh                # gate, review, publish
#   scripts/release.sh --gate-only    # run the checks and stop (safe anywhere)
#   scripts/release.sh --dry-run      # gate + `cargo publish --dry-run`, no upload
#   scripts/release.sh --yes          # skip the interactive pause (CI/automation)
#
# REQUIREMENTS:
#   - a crates.io token (`cargo login`) for a real publish
#   - the MSRV toolchain, installed on demand below
#   - wasmtime + node if you want the full `make test` rather than the native set
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"

CARGO="${CARGO:-cargo}"
GATE_ONLY=0
DRY_RUN=0
ASSUME_YES=0
for arg in "$@"; do
  case "$arg" in
    --gate-only) GATE_ONLY=1 ;;
    --dry-run)   DRY_RUN=1 ;;
    --yes|-y)    ASSUME_YES=1 ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done

# Publish order. Each crate needs the ones before it already on crates.io, so
# this list is a dependency topological sort, not an alphabetical one.
CRATES=(exav-x86 exav-update exav-pe-emu exav-unpack exav-core exav-grep exav)

step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
fail() { printf '\033[31mFAILED: %s\033[0m\n' "$*" >&2; exit 1; }

VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)"
MSRV="$(sed -n 's/^rust-version = "\(.*\)"/\1/p' Cargo.toml | head -1)"
[ -n "$VERSION" ] || fail "could not read version from Cargo.toml"
[ -n "$MSRV" ] || fail "could not read rust-version from Cargo.toml"

# ─── Gate ──────────────────────────────────────────────────────────────────

step "Clean tree"
# Publishing from a dirty tree ships bytes that are in nobody's git history.
[ -z "$(git status --porcelain)" ] || fail "working tree is dirty — commit or stash first"

step "Version $VERSION is not already published"
# crates.io answers 403 to a request with no User-Agent, so one is set here:
# without it every probe looks like "already published" and the gate blocks a
# perfectly good release. Only 404 means free; only 200 means taken; anything
# else is an unknown answer and must not be read as either.
for c in "${CRATES[@]}"; do
  code="$(curl -sS -A "exav-release-check/$VERSION" -o /dev/null \
            -w '%{http_code}' "https://crates.io/api/v1/crates/$c/$VERSION" || echo 000)"
  case "$code" in
    404) ;;
    200) fail "$c $VERSION already exists on crates.io — bump the version" ;;
    *)   fail "crates.io returned HTTP $code for $c $VERSION — cannot tell whether it is published" ;;
  esac
done

step "Format and lint"
$CARGO fmt --all --check || fail "cargo fmt"
$CARGO clippy --all-targets --features exav-core/http -- -D warnings || fail "clippy"
$CARGO clippy -p exav-core --all-targets --features unstable-internals -- -D warnings || fail "clippy (unstable-internals)"

step "Tests"
# The native matrix; `make test` additionally needs wasmtime and node.
make test-native || fail "make test-native"

step "MSRV $MSRV actually builds"
# `rust-version` is a promise to anyone pinning an older toolchain, and nothing
# else in the build checks it. A number no one verifies drifts upward silently.
#
# Driven through `rustup run` rather than `cargo +$MSRV`: the `+toolchain`
# prefix is understood by the rustup *shim*, so it fails with "no such command"
# whenever `$CARGO` is a real cargo binary instead — which is what a toolchain
# path in `CARGO`, or a non-rustup install, gives you.
if command -v rustup >/dev/null 2>&1; then
  rustup toolchain install "$MSRV" --profile minimal >/dev/null 2>&1 || true
  rustup run "$MSRV" cargo check --workspace --all-targets \
    || fail "workspace does not build on its declared MSRV $MSRV"
else
  echo "  SKIPPED: needs rustup to install and select the $MSRV toolchain"
fi

step "Package contents"
# What actually lands in the tarballs, which is not what `cargo build` sees:
# `exclude` keys, missing files, and anything accidentally swept in.
$CARGO package --workspace --no-verify || fail "cargo package"

step "The published tarballs build on their own"
# The check `cargo publish --dry-run` cannot do on a first release.
#
# A dry run builds each crate as crates.io would, resolving its dependencies
# FROM crates.io — so on a first release every dependent fails with "no matching
# package named exav-…" and goes unverified. That is exactly when the risk is
# highest: an `exclude` key that drops a file the library needs compiles fine
# here, where the file is still on disk, and fails for the first person to run
# `cargo install`.
#
# So the registry is reconstructed from the tarballs themselves and the binary
# is built from those alone — the same thing `cargo install exav` does. Building
# `exav` covers exav-core, exav-unpack, exav-pe-emu and exav-x86 transitively;
# `exav-grep` is the other dependent. exav-x86 and exav-update have no internal
# dependencies, so their own dry runs verify them completely.
tb="$(mktemp -d)"
trap 'rm -rf "$tb"' EXIT
for c in "${CRATES[@]}"; do
  tar xzf "target/package/$c-$VERSION.crate" -C "$tb" || fail "extracting $c-$VERSION.crate"
done
cat > "$tb/Cargo.toml" <<EOF
[workspace]
members = ["exav-$VERSION", "exav-grep-$VERSION"]
resolver = "2"

[patch.crates-io]
exav-x86 = { path = "exav-x86-$VERSION" }
exav-pe-emu = { path = "exav-pe-emu-$VERSION" }
exav-unpack = { path = "exav-unpack-$VERSION" }
exav-core = { path = "exav-core-$VERSION" }
exav-update = { path = "exav-update-$VERSION" }
exav-grep = { path = "exav-grep-$VERSION" }
EOF
( cd "$tb" && $CARGO build --release ) \
  || fail "the packaged crates do not build on their own — a published file is missing (check the \`exclude\` keys)"
[ -x "$tb/target/release/exav" ] || fail "the packaged build produced no exav binary"
# It has to answer, not just link: a binary that cannot start is not installable.
"$tb/target/release/exav" --version >/dev/null || fail "the packaged exav binary does not run"
echo "  built and ran exav $VERSION from the tarballs alone"

step "No EICAR literal in any published tarball"
# The self-scan test covers the source tree; this covers the artifacts, which is
# what other people's scanners actually download. Kept separate because a bad
# `exclude` key can put a fixture back into a tarball without touching a source
# file, and that is exactly the mistake this catches.
needle="$(printf '*H+H$!ELIF-TSET-SURIVITNA-DRADNATS-RACIE$}7)CC7)^P(45XZP\\4[PA@%%P!O5X' | rev)"
for c in "${CRATES[@]}"; do
  crate_file="target/package/$c-$VERSION.crate"
  [ -f "$crate_file" ] || fail "missing $crate_file"
  if tar xzOf "$crate_file" 2>/dev/null | grep -qF "$needle"; then
    fail "$c-$VERSION.crate carries the EICAR test string — every scanner that sees this download will quarantine it"
  fi
done

step "Nothing in the tracked tree trips a real scanner"
# The literal check above is exact-match on one string; this asks a real engine
# with a real signature set, which is the question that actually matters — a
# committed fixture any scanner detects gets the repository quarantined on clone
# and deleted by an AV-scanned CI runner. Fixtures are masked (see
# `exav_unpack::unmask_fixture`) precisely so this stays quiet.
#
# Skipped rather than failed when no database is present: a signature set is a
# ~110 MB download, so this cannot be a precondition for every release, and
# silently passing without one would be worse than saying it was not checked.
if command -v clamscan >/dev/null 2>&1 && [ -d "${DBDIR:-exav-db}" ]; then
  hits="$(git ls-files -z | xargs -0 clamscan -d "${DBDIR:-exav-db}" --no-summary 2>/dev/null \
            | grep -v ': OK$' || true)"
  if [ -n "$hits" ]; then
    printf '%s\n' "$hits" >&2
    fail "a tracked file is detected by clamscan — mask it (unmask_fixture) or drop it"
  fi
  echo "  clamscan: no detections across $(git ls-files | wc -l | tr -d ' ') tracked files"
else
  echo "  SKIPPED: needs clamscan and a signature directory (\`make db\`)"
fi

step "Gate passed"
printf 'version   %s\n' "$VERSION"
printf 'MSRV      %s\n' "$MSRV"
printf 'crates    %s\n' "${CRATES[*]}"
ls -lh target/package/*.crate | awk '{printf "  %-8s %s\n", $5, $9}'

if [ "$GATE_ONLY" = 1 ]; then
  echo
  echo "--gate-only: stopping before publish."
  exit 0
fi

# ─── Review ────────────────────────────────────────────────────────────────

step "Review before publishing"
cat <<EOF
Publishing is irreversible: a version can be yanked, never replaced or reused.
The crates go up one at a time, in dependency order, and each is live the moment
it lands — so a failure partway leaves the earlier ones published for good.

Read before continuing:
  * git log --oneline \$(git describe --tags --abbrev=0 2>/dev/null || echo HEAD~10)..HEAD
  * tar tzf target/package/exav-$VERSION.crate | head -40
  * the CHANGELOG entry for $VERSION, if there is one

Order: ${CRATES[*]}
EOF

if [ "$DRY_RUN" = 1 ]; then
  step "Dry run"
  # A dry run builds each crate as crates.io would, which means resolving its
  # dependencies FROM crates.io. On a first release the workspace siblings are
  # not there yet, so every dependent fails with "no matching package named
  # exav-…" — a fact about publication order, not a defect in the crate. It is
  # reported rather than treated as a pass, because after the first release
  # those same crates should resolve and a real failure must not hide here.
  skipped=()
  for c in "${CRATES[@]}"; do
    log="$(mktemp)"
    if $CARGO publish -p "$c" --dry-run --allow-dirty >"$log" 2>&1; then
      echo "  $c: ok"
    elif grep -q "no matching package named \`exav" "$log"; then
      skipped+=("$c")
      echo "  $c: not verifiable yet (a workspace dependency is not on crates.io)"
    else
      cat "$log" >&2
      rm -f "$log"
      fail "dry-run publish of $c"
    fi
    rm -f "$log"
  done
  if [ ${#skipped[@]} -gt 0 ]; then
    echo
    echo "Not verified by this dry run: ${skipped[*]}"
    echo "They can only be checked once their dependencies are published."
  fi
  echo "Dry run complete; nothing was uploaded."
  exit 0
fi

if [ "$ASSUME_YES" != 1 ]; then
  if [ ! -t 0 ]; then
    fail "not a terminal and --yes was not given — refusing to publish unattended"
  fi
  printf '\nType the version (%s) to publish, anything else to abort: ' "$VERSION"
  read -r reply
  [ "$reply" = "$VERSION" ] || { echo "Aborted."; exit 1; }
fi

# ─── Publish ───────────────────────────────────────────────────────────────

for c in "${CRATES[@]}"; do
  step "Publishing $c $VERSION"
  $CARGO publish -p "$c" || fail "publish of $c — the crates before it are already live; fix, bump the version, and resume from here"
  # crates.io indexes asynchronously; the next crate's dependency resolution
  # fails if it runs before this one is queryable.
  echo "waiting for the index to catch up..."
  for _ in $(seq 1 60); do
    code="$(curl -sS -o /dev/null -w '%{http_code}' "https://crates.io/api/v1/crates/$c/$VERSION" || echo 000)"
    [ "$code" = "200" ] && break
    sleep 5
  done
done

step "Published $VERSION"
echo "Tag the release to trigger the container build:"
echo "  git tag -a v$VERSION -m 'exav $VERSION' && git push origin v$VERSION"
