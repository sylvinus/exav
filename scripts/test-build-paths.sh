#!/usr/bin/env bash
# Test scripts/check-build-paths.py and scripts/build-flags.sh on fixtures made
# in a temporary directory.
#
# USAGE: scripts/test-build-paths.sh
# REQUIREMENTS: python3, tar.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CHECK="$REPO/scripts/check-build-paths.py"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
cd "$tmp"

failures=0
# expect STATUS DESCRIPTION [ARGS...]: run the check, compare its exit status.
expect() {
  local want="$1" what="$2" got=0
  shift 2
  python3 -I "$CHECK" "$@" >out.txt 2>&1 || got=$?
  if [ "$got" != "$want" ]; then
    echo "FAIL: $what: status $got, wanted $want" >&2
    cat out.txt >&2
    failures=$((failures + 1))
  else
    echo "ok: $what"
  fi
}
# said TEXT DESCRIPTION: the last run printed TEXT.
said() {
  grep -qF -- "$1" out.txt || { echo "FAIL: $2: output lacks '$1'" >&2; cat out.txt >&2; failures=$((failures + 1)); }
}

printf 'panicked at /home/someone/x/src/lib.rs:1\n' >dirty.bin
printf 'panicked at /cargo/registry/src/index/foo-1.0.0/src/lib.rs and /exav/crates/a.rs\n' >clean.bin
printf 'at C:\\Users\\bob\\.cargo\\registry\n' >windows.bin
printf 'at c:/users/bob/x\n' >windows-lower.bin

expect 1 "a file with /home/ fails" dirty.bin
said "dirty.bin: /home/someone/x/src/lib.rs:1" "the path and the file are named"
expect 0 "a file with the fixed names passes" clean.bin
expect 1 "C:\\Users\\ fails" windows.bin
expect 1 "c:/users/ fails" windows-lower.bin
expect 2 "a missing file is an error" does-not-exist.bin

# Archives, and archives in archives.
mkdir -p in/pkg
cp dirty.bin in/pkg/
tar czf dirty.tgz -C in pkg
expect 1 "a tarball with a dirty member fails" dirty.tgz
said "dirty.tgz!pkg/dirty.bin" "the member is named"
mkdir -p in2/pkg
cp clean.bin in2/pkg/
tar czf clean.tgz -C in2 pkg
expect 0 "a tarball with a clean member passes" clean.tgz
python3 -I - <<'PY'
import zipfile
with zipfile.ZipFile("dirty.zip", "w") as z:
    z.writestr("a/b.exe", b"x /Users/bob/work/y")
with zipfile.ZipFile("nested.zip", "w") as z:
    z.write("dirty.tgz")
PY
expect 1 "a zip with a dirty member fails" dirty.zip
expect 1 "a tarball inside a zip is opened" nested.zip
said "nested.zip!dirty.tgz!pkg/dirty.bin" "the nested member is named"
mkdir dir
cp clean.bin dir/
expect 0 "a clean directory passes" dir
cp dirty.bin dir/
expect 1 "a directory with a dirty file fails" dir

# --source and --also.
expect 0 "--source ignores an example path" --source dirty.bin
printf 'at %s/crates/x.rs\n' "$REPO" >checkout.bin
expect 1 "--source finds the checkout" --source checkout.bin
printf 'at /srv/ci/work/x.rs\n' >also.bin
expect 0 "an unknown path passes" also.bin
expect 1 "--also names another path" --also /srv/ci/work also.bin

expect 0 "--except skips a file by the end of its name" --except dirty.bin dirty.bin
expect 0 "--except skips a member" --except !pkg/dirty.bin dirty.tgz
expect 1 "--except does not skip another file" --except other.bin dirty.bin

# The flags map the checkout, and a caller's flags stay.
flags="$(RUSTFLAGS='-C opt-level=3' "$REPO/scripts/build-flags.sh")"
case "$flags" in
  "-C opt-level=3 --remap-path-prefix=$REPO=/exav "*"=/cargo "*) echo "ok: build-flags maps the checkout and keeps RUSTFLAGS" ;;
  *) echo "FAIL: build-flags printed: $flags" >&2; failures=$((failures + 1)) ;;
esac
again="$(RUSTFLAGS="$flags" "$REPO/scripts/build-flags.sh")"
[ "$again" = "$flags" ] || { echo "FAIL: build-flags repeats itself: $again" >&2; failures=$((failures + 1)); }

[ "$failures" = 0 ] || { echo "$failures failed" >&2; exit 1; }
echo "all passed"
