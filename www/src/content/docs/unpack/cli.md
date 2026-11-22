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

`--profile fast-build` is a shorter build that needs less memory, for a larger
and slower binary (see [Installation](/scanner/getting-started/installation/#from-cratesio)).

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
exav-unpack -r backup.tar.gz -d out/      # archives inside archives too
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
  -r, --recursive    also open the archives found inside the archive: a member
                     that is one is replaced by its own members, named
                     archive!member in listings and nested as directories
  --volume FILE      another part of a split archive (repeat for each part)
  --max-extracted-bytes SIZE|off
                     stop past SIZE decoded bytes in all (default 64G);
                     --max-size is the older name
  --max-hole-bytes SIZE|off
                     stop past SIZE bytes of holes in all, the unwritten
                     stretches of the sparse files of a disk image, which do
                     not count in --max-extracted-bytes (default 64G)
  --max-object-bytes SIZE|off
                     largest member or container held in memory whole (1G);
                     --max-memory is the older name. With -r, a member that is
                     decoded as it is read is held whole, whatever this is,
                     when it ends or fails within 4 MiB + 1 KiB: the start
                     that is read to tell what it is
  --max-members N|off
                     stop past N members (default 1000000)
  --max-compression-ratio N|off
                     leave out a member that decodes to more than N times its
                     size, once it is past --max-object-bytes (default 1000);
                     the other members are still read, and the run ends with
                     the limit
  --max-unpack-depth N
                     deepest nesting -r opens (default 16); 0 opens no
                     archive, and -r takes the one named as one file
  --spill-dir DIR|off
                     with -r, the directory of the anonymous temporary file a
                     container inside a member over --max-object-bytes is
                     written to so that it can be opened (default: the system
                     temporary directory); off writes nothing, and such a
                     container is reported unreadable
  --max-total-spill-bytes SIZE|off
                     most the spill files open at once may hold (default 2G);
                     a container that would pass it is reported unreadable
  --object-cache-bytes SIZE
                     memory of the cache over the archive on disk, shared by
                     the parts of a split archive; an archive that fits in it
                     and in --max-object-bytes is read whole (default 32M)
  --object-cache-block-bytes SIZE
                     what that cache reads at a time (default 1M)
  --help, --version
SIZE takes a K, M, G or T suffix (powers of 1024). A limit that takes off takes
0 as off too. The two cache sizes also take off, which is 0: a cache never
holds less than two blocks. Each limit above is also read from the environment,
as EXAV_ and its name in capitals with underscores (EXAV_MAX_OBJECT_BYTES,
EXAV_SPILL_DIR); the option wins over the variable.
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

A member that was not decoded exits by the kind of reason its format's reader
gives: 81 when it says the method or format is one it does not decode, 5 or 82
for a password, 2 for any other (damage, a limit).

## What it adds

`-r` and long options `unzip` does not have:

- `-r`, `--recursive`: also open the archives found inside the archive, down to
  `--max-unpack-depth` levels (16 by default). A member that is an archive is
  replaced by its own members, which are listed, tested, piped or extracted as
  the archive's are. Listings name them from the archive down, with `!`
  between the names (`outer.zip!inner/a.txt`, which the member patterns match),
  and extraction puts them in a directory named for each archive on the way
  (`inner.zip/a.txt`). A member that is an archive and has no members, or is
  too deep to open, is one more file, and the second is an error (exit 2).
  A member larger than `--max-object-bytes` that is not an archive is written
  as it is decoded; one that is an archive is written to an anonymous
  temporary file (`--spill-dir`) and opened from there, and the file is deleted
  when the archive has been handled. With `--spill-dir off`, or past
  `--max-total-spill-bytes`, it cannot be opened with nowhere to put it, and is
  reported, exit 2. A member that is decoded as it is read is held whole,
  whatever `--max-object-bytes` is, when it ends or fails within 4 MiB + 1 KiB:
  the start that is read to tell what it is. An executable larger than the
  limit is not checked for being packed, which is said (exit 1).
- `--volume FILE`: another part of a split archive, for parts not next to the
  archive or not named as a set. A set named as one is found on its own: `.001`,
  `.002` parts; `.z01`, ..., `.zip`; `.part1.rar`, `.part2.rar`; `.rar`, `.r00`.
  `unzip` reads none of these. Parts are found by name and read in order until
  one is missing; a RAR set is read across its volumes like a ZIP set. Parts
  are known by their file names, so two with one
  name are refused.
- `--max-extracted-bytes`, `--max-object-bytes`, `--max-members`,
  `--max-unpack-depth`: the bounds of the extraction (64 GiB decoded, 1 GiB held
  in memory at once, a million members, 16 levels by default). They are higher
  than the library's, since what is decoded goes to disk rather than staying in
  memory. They are named as the scanner's are, and take `off` or `0` for no
  limit as its flags do (the depth has none); `--max-size` and `--max-memory` are the
  older names of the first two and still work. See
  [the safety model](/unpack/#the-safety-model).
- `--max-hole-bytes`: the holes of the sparse files of a disk image, the
  stretches the volume never wrote, written out as zeros, 64 GiB of them in
  all by default. They count here rather than in `--max-extracted-bytes`, so a
  large sparse file does not end the extraction of the rest of the volume.
- `--max-compression-ratio`: a member that decodes to more than this many times
  its size in the archive (1000 by default) is left out once it is past
  `--max-object-bytes`, and the other members are still read. The limit is
  reported once they are, and the status is 2. Below `--max-object-bytes` a
  member is held in memory and the memory limits bound it, so with
  `--max-object-bytes off` the ratio never acts. `off` for no limit.
- `--spill-dir`, `--max-total-spill-bytes`: with `-r`, where a container inside a
  member over `--max-object-bytes` is written so that it can be opened (the
  system temporary directory), and the most the spill files open at once may
  hold (2 GiB). `off` for the directory writes nothing; for the size, no
  ceiling.
- Each of these limits is also read from the environment, named as the
  scanner names it: `EXAV_MAX_EXTRACTED_BYTES`, `EXAV_MAX_OBJECT_BYTES`,
  `EXAV_MAX_MEMBERS`, `EXAV_MAX_COMPRESSION_RATIO`, `EXAV_MAX_UNPACK_DEPTH`,
  `EXAV_OBJECT_CACHE_BYTES`,
  `EXAV_OBJECT_CACHE_BLOCK_BYTES`, `EXAV_SPILL_DIR`, `EXAV_MAX_TOTAL_SPILL_BYTES`. The
  option wins over the variable.
- `--object-cache-bytes`, `--object-cache-block-bytes`: the memory of the cache
  over the archive on disk, shared by the parts of a split archive (32 MiB), and
  what it reads at a time (1 MiB). An archive that fits in the cache and in
  `--max-object-bytes` is read whole.

## Where it differs from `unzip`

On purpose:

- It does not ask for a password yet. An encrypted member with no `-P` is
  skipped as `unzip` skips one with no terminal, after the
  [built-in passwords](/unpack/formats/#encryption-support) are tried, and
  the exit status is 5. With `-P`, a password that opens none of the encrypted
  members exits 82; when other members came out, the run exits 1 and each
  member left behind is reported `skipping: NAME  incorrect password`. `-t`
  checks without writing anything.
- A symbolic link whose target leaves the extraction directory is not made,
  the target being followed through the links already made, and nothing is
  written through a link already there. A member name's `..` and
  root (`/`, a drive letter) are dropped, so every file lands under the
  extraction directory. Links are made last, once every member is out. A tar
  hard link is made a hard link to the file its target member was written
  to, as GNU tar makes it; one whose target is no file in the extraction
  directory is an error.
- Every member is `extracting:`, whatever its compression.
- A split archive is read from any of its parts.
- A name that could end a line, move the cursor or reorder text (a control
  character, a bidirectional mark, U+2028 or U+2029) is printed with each of
  them as `_`, and a name past 200 characters is cut, in a listing and in the
  reasons it is quoted in. The patterns are matched against the name as
  written, and the file is written with its name cleaned of control
  characters, as before.

It restores what the archive records: modification times, the permission bits
(without setuid, setgid or sticky, as `unzip` without `-K`) and symbolic links,
for ZIP and tar. Other formats record less.

Members are written as they are decoded, and an archive longer than the object
cache or `--max-object-bytes` is read from disk as needed (a shorter one is
read whole), so neither is
held in memory whole, except for the formats
[read whole](/unpack/formats/#size-what-is-read-as-it-goes-and-what-is-read-whole)
(PDF, ARJ and others), up to `--max-object-bytes`. So is a packed
executable (UPX, or a PE the emulator unpacks): one larger than that is not
checked for being packed, and the run says so (exit 9). With `-r`, a member
that is an archive is held in memory to be opened, up to the same limit, and
past it is written to a spill file.
