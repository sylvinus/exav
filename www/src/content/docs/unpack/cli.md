---
title: The exav-unpack command
description: exav-unpack extracts, lists and tests archives of every format the library reads, with a command line that is a subset of unzip's, under bounds of its own.
---

`exav-unpack` is a general extractor with the library's budgets. Its command
line is a subset of Info-ZIP `unzip` 6.00's: every option it takes means what
it means to `unzip`, and an `unzip` option it does not take is refused (exit
10) rather than ignored. It reads every format the [library](/unpack/rust/)
reads, not only ZIP.

```sh
cargo install exav-unpack
```

It is also in each [release](https://github.com/sylvinus/exav/releases), as
`exav-unpack-<tag>-<target>`, for the same targets as the scanner (see
[its prebuilt binaries](/scanner/getting-started/installation/#prebuilt-binaries)).
The command is the crate's `cli` feature, on by default; a library consumer
that turns default features off never builds it.

## Examples

```bash
exav-unpack archive.7z                    # extract here
exav-unpack archive.rar -d out/           # into out/
exav-unpack archive.zip 'docs/*' -x '*.tmp'  # some members only
exav-unpack -l archive.tar.gz             # list
exav-unpack -t archive.zip                # test: decode everything, write nothing
exav-unpack -p archive.zip notes.txt      # to stdout
exav-unpack '*.zip' -d out/               # several archives: a quoted wildcard
exav-unpack set.part1.rar                 # a volume set, from its first part
exav-unpack set.zip --volume /mnt/b/set.z01  # parts elsewhere, given one by one
```

## Usage

`exav-unpack --help` prints:

```text
usage: exav-unpack [-opts[modifiers]] archive [list] [-x xlist] [-d exdir]

Extracts the members in list (all by default), except those in xlist, into
exdir (the current directory by default). The options are a subset of
unzip's and mean what they mean to unzip; archive may be a wildcard, and of
any format exav-unpack reads.

  -l  list members                           -t  test members
  -p  extract members to stdout, no messages -c  as -p, with messages
  -Z1 list member names only                 -x  exclude the members that follow
  -d  extract into exdir
modifiers:
  -o  overwrite files without prompting      -n  never overwrite files
  -q  quiet (-qq quieter)                    -P  password to decrypt members
  -j  junk paths (no directories)            -C  match names case-insensitively
  -D  do not restore directory times (-DD: no times at all)

exav-unpack only:
  --volume FILE      another part of a split archive (repeat for each part)
  --max-size SIZE    stop past SIZE decoded bytes in all (default 64G)
  --max-memory SIZE  largest member or container held in memory whole (1G)
  --max-members N    stop past N members (default 1000000)
  --help, --version
SIZE takes a K, M, G or T suffix (powers of 1024).
```

| `unzip` option | |
|---|---|
| `-l`, `-t`, `-p`, `-c`, `-Z1` | list, test, to stdout, to stdout with names, names only; one at most |
| `-d DIR` | extract into `DIR` |
| `-x PATTERN...` | leave out the members that match |
| `-o`, `-n` | overwrite, never overwrite (default: ask, as `unzip` does) |
| `-P PASS` | a password; repeat for several |
| `-j`, `-C`, `-q`, `-qq` | no directories, case-insensitive patterns, quiet, quieter |
| `-D`, `-DD` | leave directory times, all times, unrestored |
| `-v` alone, `-h` | the version, the usage |

Arguments follow `unzip`'s rules: options before the archive; after it, member
patterns, `-x` and `-d`; `unzip a.zip b.zip` means member `b.zip` of `a.zip`, so
several archives are named with a quoted wildcard. A pattern's `*` matches any
run of characters, `/` included, `?` any one, and `[...]` one of a set
(`[!...]` one outside it). An archive named without its extension is also
looked for with `.zip` and `.ZIP` added.

`-v` with an archive (`unzip`'s verbose listing), `-Z` other than `-Z1`, and
the `unzip` options for other platforms and conversions (`-a`, `-f`, `-u`,
`-z`, `-L`, `-X` and the rest) are refused with exit 10, each named in the
message.

## Exit status

The statuses are `unzip`'s, as far as they apply. Over several archives, the
worst one is returned.

| Status | Meaning |
|---|---|
| 0 | Everything asked for came out |
| 1 | A warning: a member skipped for an unsafe name, a link not made, or a wrong password for some members while others came out |
| 2 | A member damaged or not fully decoded, or a limit reached |
| 5 | An encrypted member and no password |
| 9 | No archive found, or not a format `exav-unpack` reads |
| 10 | A bad or unsupported option |
| 11 | A member pattern nothing matched |
| 50 | A member could not be written (a full disk, for one) |
| 81 | A member compressed with a method that is not supported |
| 82 | A wrong password for every encrypted member |

## What it adds

Long options `unzip` does not have:

- `--volume FILE`: another part of a split archive, for parts not next to the
  archive or not named as a set. A set named as one is found on its own: `.001`,
  `.002` parts; `.z01`, ..., `.zip`; `.part1.rar`, `.part2.rar`; `.rar`, `.r00`.
  `unzip` reads none of these. Parts are found by name and read in order until
  one is missing; a RAR set is joined in memory, so only up to `--max-memory`.
- `--max-size`, `--max-memory`, `--max-members`: the bounds of the extraction
  (64 GiB decoded, 1 GiB held in memory at once, a million members by default).
  They are higher than the library's, since what is decoded goes to disk rather
  than staying in memory; the compression-ratio cap still stops a bomb long
  before them. See [the safety model](/unpack/#the-safety-model).

## Where it differs from `unzip`

On purpose:

- It does not ask for a password yet. An encrypted member with no `-P` is
  skipped as `unzip` skips one with no terminal, after the
  [built-in passwords](/unpack/formats/#encryption-support) are tried, and
  the exit status is 5. With `-P`, a password that opens none of the encrypted
  members exits 82; when other members came out, the run exits 1 and each
  member left behind is reported `skipping: NAME  incorrect password`. `-t`
  checks without writing anything.
- A symbolic link whose target leaves the extraction directory is not made, and
  nothing is written through a link already there. A member name's `..` and
  root (`/`, a drive letter) are dropped, so every file lands under the
  extraction directory. Links are made last, once every member is out.
- Every member is `extracting:`, whatever its compression.
- A split archive is read from any of its parts.

It restores what the archive records: modification times, the permission bits
(without setuid, setgid or sticky, as `unzip` without `-K`) and symbolic links,
for ZIP and tar. Other formats record less.

Members are written as they are decoded and the archive is read from disk as
needed, so neither is held in memory whole, except where a format's decoder
needs it (a 7z solid block, a RAR archive, a CAB folder). A packed executable
(UPX, or a PE the emulator unpacks) is read whole, up to `--max-memory`.
