#!/usr/bin/env bash
# Print the RUSTFLAGS of a build whose output is released: the checkout, the
# cargo home and the rustup home are mapped to fixed names, so that no panic
# location or other path in a binary or a wasm module names the machine that
# built it. scripts/check-build-paths.py checks the result.
#
# USAGE:
#   RUSTFLAGS="$(scripts/build-flags.sh)" cargo build --release ...
#   scripts/build-flags.sh DIR       # DIR is the tree built, when it is not this checkout
#
# The flags a caller already set in RUSTFLAGS come first. They replace the
# `rustflags` of .cargo/config.toml, as any RUSTFLAGS does (the linker setup of
# scripts/setup-lld.sh included).
#
# Cargo's `trim-paths` is not used: it is stable in no Cargo up to 1.99 (the
# MSRV is 1.95).
#
#   checkout        -> /exav
#   $CARGO_HOME     -> /cargo     (registry sources, git checkouts)
#   $RUSTUP_HOME    -> /rustup
#   /project        -> /exav      (where `cross` mounts the checkout)
#
# The standard library's own sources are already /rustc/<hash>.
set -euo pipefail

if [ -n "${CARGO_ENCODED_RUSTFLAGS:-}" ]; then
  echo "build-flags: CARGO_ENCODED_RUSTFLAGS is set and would replace these flags" >&2
  exit 1
fi

# rustc compares paths in the native form: C:/Users/x on Windows.
native() {
  if command -v cygpath >/dev/null 2>&1; then cygpath -m "$1"; else printf '%s\n' "$1"; fi
}

# Cargo names a directory by its real path (/private/var, not /var, on macOS).
dir="${1:-$(dirname "${BASH_SOURCE[0]}")/..}"
checkout="$(native "$(cd "$dir" && pwd -P)")"
logical="$(native "$(cd "$dir" && pwd)")"
cargo_home="$(native "${CARGO_HOME:-$HOME/.cargo}")"
rustup_home="$(native "${RUSTUP_HOME:-$HOME/.rustup}")"

pairs=("$checkout=/exav")
[ "$logical" = "$checkout" ] || pairs+=("$logical=/exav")
pairs+=("$cargo_home=/cargo" "$rustup_home=/rustup" "/project=/exav")

flags="${RUSTFLAGS:-}"
for pair in "${pairs[@]}"; do
  case "$pair" in
    *[[:space:]]*) echo "build-flags: a path with a space cannot go in RUSTFLAGS: $pair" >&2; exit 1 ;;
  esac
  # Already there (RUSTFLAGS from an earlier run of this script): not repeated.
  case " $flags " in *" --remap-path-prefix=$pair "*) continue ;; esac
  flags="${flags:+$flags }--remap-path-prefix=$pair"
done
printf '%s\n' "$flags"
