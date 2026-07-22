#!/bin/sh
# Diff exav's `dotnet` YARA module against yara-x, rule by rule.
#
# The module was built this way rather than checked afterwards, and it mattered:
# four fields were wrong on the first pass and every one of them was a semantic
# trap rather than a coding slip —
#
#   number_of_classes  excludes the `<Module>` pseudo-type at TypeDef row 0
#   constants          is only the *string* rows of the Constant table (95 of 568)
#   field_offsets      comes from FieldRVA, not the similar FieldLayout table
#   user_strings       skips one-byte `#US` entries, which are a lone flag byte
#
# None would have failed a self-consistent implementation. Committed so the
# comparison can be re-run against a bigger assembly than the repository keeps.
#
# Usage: scripts/yara-dotnet-difftest.sh <rules.yar> <assembly.dll>
#
# Needs the yara-x CLI (`yr`, https://github.com/VirusTotal/yara-x/releases) on
# PATH, and a built exav (EXAV, default target/debug/exav).
set -eu

RULES="${1:?usage: $0 <rules.yar> <assembly.dll>}"
SAMPLE="${2:?usage: $0 <rules.yar> <assembly.dll>}"
EXAV="${EXAV:-target/debug/exav}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

agree=0
differ=0
# One rule at a time: exav reports the first match per file, so a combined run
# cannot tell which of several rules fired.
grep '^rule ' "$RULES" | while read -r line; do
    name=$(echo "$line" | awk '{print $2}')
    printf 'import "dotnet"\n%s\n' "$line" > "$WORK/one.yar"
    y=$(yr scan --disable-console-logs "$WORK/one.yar" "$SAMPLE" 2>/dev/null | grep -c "$name" || true)
    e=$("$EXAV" --database "$WORK/one.yar" "$SAMPLE" 2>&1 | grep -c "YARA.$name" || true)
    if [ "$y" = "$e" ]; then
        agree=$((agree + 1))
        printf '  %-24s agree (%s)\n' "$name" "$y"
    else
        differ=$((differ + 1))
        printf '  %-24s DIFFER yara-x=%s exav=%s\n' "$name" "$y" "$e"
    fi
done
