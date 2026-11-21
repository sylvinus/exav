#!/usr/bin/env bash
# Fetches the installers listed in installers.txt into DIR and checks each
# against its SHA-256. A file that does not match is deleted and the script
# fails; a file already there is checked again.
#
#   tests/inno/fetch.sh DIR
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
DIR="${1:?usage: fetch.sh DIR}"
mkdir -p "$DIR"

sha256() {
  if command -v sha256sum >/dev/null; then
    sha256sum "$1" | cut -d' ' -f1
  else
    shasum -a 256 "$1" | cut -d' ' -f1
  fi
}

status=0
while read -r version url want; do
  case "$version" in '' | '#'*) continue ;; esac
  file="$DIR/$(basename "$url")"
  if [ ! -f "$file" ]; then
    curl -fsSL "$url" -o "$file.part"
    mv "$file.part" "$file"
  fi
  got="$(sha256 "$file")"
  if [ "$got" != "$want" ]; then
    echo "refused: $file has SHA-256 $got, installers.txt says $want" >&2
    rm -f "$file"
    status=1
  else
    echo "ok: $file ($version)"
  fi
done <"$HERE/installers.txt"
exit "$status"
