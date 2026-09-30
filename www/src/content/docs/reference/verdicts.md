---
title: Verdicts & exit codes
description: The complete mapping from exav verdict to clamscan/clamd status tag to process exit code.
---

Every scanned file resolves to exactly one verdict. Each maps to a
`clamscan`/`clamd`-style status and contributes to the process exit code. This is
the contract behind [never a silent clean](/concepts/design-principles/#never-a-silent-clean).

## Exit code 3 means "look at this"

`3` means a file could not be fully examined: it was encrypted, hit a limit, or
used a codec with no decoder. It is not a scanner failure; that is `2` (an
unreadable path, a database that would not load), as in ClamAV. A file exav
could not fully read is a good hiding place, so route `3` to a person.

## The mapping

Every result line ends in its status, and each status is one exit code:

| Verdict | Line | Status | Exit |
|---|---|---|---|
| Clean | `path: OK` | `OK` | `0` |
| Infected | `path: <Signature> FOUND` | `FOUND` | `1` |
| *(exav itself failed)* | `path: <message> ERROR` | `ERROR` | `2` |
| Limits exceeded | `path: <reason> LIMITS-EXCEEDED PARTIAL` | `PARTIAL` | `3` |
| Unscannable | `path: <reason> UNSCANNABLE PARTIAL` | `PARTIAL` | `3` |
| Password protected | `path: <reason> PASSWORD-PROTECTED PARTIAL` | `PARTIAL` | `3` |

The grammar is `path: [reason ][CATEGORY ]STATUS`, with the status last, where
`clamscan` puts `OK` and `FOUND`. The three categories sub-classify a `PARTIAL`.
`ERROR` lines go to stderr, the rest to stdout; all of them are written to
`--log`, and `--quiet` drops only the `OK` lines and the summary.

## What each `PARTIAL` category means

- **`LIMITS-EXCEEDED`**: a limit stopped the scan before it completed. Raise it
  and scan again. The limits are `--max-input-bytes`, `--max-object-bytes` (an
  object too large for the checks that parse it whole, or a member too large to
  hold with spilling off), the extraction and matcher budgets, the ratio,
  recursion and member caps, `--max-pe-emulation-steps`, a stream past the spill
  budgets, a daemon job past `--max-scan-secs`, the YARA step and match budgets,
  a bytecode signature that ran out of steps, and the engine's internal step
  budgets.
- **`UNSCANNABLE`**: something was recognised but could not be decoded (an
  unsupported codec, a RAR member continuing in another volume, a read error).
  Raising a limit changes nothing. The container's own bytes are still scanned;
  only what it holds could not be reached.
- **`PASSWORD-PROTECTED`**: an encrypted member. Scan again with `--passwords`
  (repeatable) or a `.pwdb` database to decrypt it.

A ZIP member using a compression method exav cannot decode is `UNSCANNABLE`,
however large the archive.

## Process exit code

Across all inputs, the exit code follows this precedence:

1. **`1`**: any file was `FOUND`. A detection stays true even if a limit was also
   hit or another file failed to open.
2. **`2`**: otherwise, any file produced an error. An error casts doubt on the
   whole run, where a partial is a fact about one object.
3. **`3`**: otherwise, any file came back `PARTIAL`.
4. **`0`**: otherwise; everything fully scanned and clean.

`0`, `1` and `2` mean what they mean in `clamscan`. `clamscan` returns `OK` and
exit `0` for a file it could not fully scan;
[`--partial-as`](/reference/cli/#what-an-unscannable-object-becomes) maps `3` to
any of the other codes, and `--clamav-compat` installs `--partial-as ok`. See
[Migrating from ClamAV](/guides/migrating-from-clamav/).

## On the clamd wire

`clamd`'s vocabulary is `OK`, `FOUND` and `ERROR`. `clamdscan` 1.4.3 rewrites a
status it does not recognise to `OK` and exits `0`, so `PARTIAL` on that wire
would turn a fail-closed answer into a fail-open one. A `PARTIAL` therefore
travels as `ERROR`, with the same `path: <reason> <CATEGORY> ERROR` grammar; the
category is what distinguishes it from a real failure, which has none:

```text
big.bin: file size 3145728 exceeds max-input-bytes 1048576; scanned first 1048576 bytes only LIMITS-EXCEEDED ERROR
gone.bin: cannot open file ERROR
```

An exav client (`--connect`) reads the category back and reproduces the local
exit code, so a daemon scan and a one-shot scan agree. `clamdscan` sees both as
`ERROR` and exits `2`, stricter than `clamscan`'s `0` and the closest the protocol
allows.

`--partial-as error` drops the category, so every client, exav's included, reads
the reply as an operational failure.

A stream over `--max-input-bytes`, or one larger than the daemon can hold, is
scanned as far as it was held and answered as a file over the limit is, so
`--partial-as` decides it the same way. A stream that ends before its
terminator is a plain `ERROR` whatever the policy: the object never fully
arrived, and `--partial-as ok` would otherwise answer `OK` to any client that
hangs up after a harmless first chunk.

## In JSON

`--json` and the daemon's `EXINSTREAM` use the same field names:

- **`status`**: `OK`, `FOUND`, `ERROR` or `PARTIAL`, the word the line ends with.
- **`category`**: `LIMITS-EXCEEDED`, `UNSCANNABLE` or `PASSWORD-PROTECTED`, only on
  a `PARTIAL`.
- **`reason`**: the explanation (`signature` instead, on a `FOUND`).
