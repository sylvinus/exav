#!/usr/bin/env bash
# Regenerate crates/exav-x86/src/generated.rs.
#
# The generator reads the tables off `iced-x86` (MIT; attributed in NOTICE)
# rather than transcribing them from a manual, because a hand-copied opcode
# table is wrong in ways no review catches — a missing immediate byte gives a
# wrong length, and a wrong length desynchronises every instruction after it.
#
# The generator is its own workspace, outside this one: it has to be runnable
# when exav-x86 does not compile, which is exactly the state a change to the
# table layout leaves the crate in until this script has run.
#
# After running this, `cargo test -p exav-x86` re-checks every generated cell
# against the same oracle, and `--ignored` extends that to the sample corpus.
set -euo pipefail

cd "$(dirname "$0")/.."
out=crates/exav-x86/src/generated.rs

cargo run --release --manifest-path crates/exav-x86/tools/gen-tables/Cargo.toml >"$out.new"
mv "$out.new" "$out"
cargo fmt -p exav-x86

echo "wrote $out ($(wc -l <"$out") lines)"
