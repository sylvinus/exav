---
title: Verdicts & exit codes
description: The complete mapping from exav verdict to clamscan/clamd status tag to process exit code.
---

Every scanned file resolves to exactly one verdict. Each maps to a `clamscan`/
`clamd`-style status tag and contributes to the process exit code. This table is
the contract behind the
[never-silent-clean invariant](/concepts/design-principles/#never-a-silent-clean).

## Read exit code 3 as "look at this", not "the scanner broke"

This is the first thing to know, and the thing most likely to be got wrong by a
script migrating from `clamscan`.

Exit code **3 does not mean exav failed.** It means exav declined to call a file
clean because it could not fully examine it — the file was encrypted, or hit a
budget, or used a codec with no decoder. The scan worked; the answer is "I could
not see inside this."

That is exactly why it is not `2`. **`2` is the code that means exav failed** —
an unreadable path, a database that would not load — and it means the same thing
in ClamAV. Sharing one code between "the scanner is broken" and "this object
needs a decision" left an operator unable to tell them apart, which is how the
second gets retried, logged as noise, and eventually silenced. That is precisely
backwards: **a file exav could not read is a better hiding place than one it read
and cleared**, so `3` is the code that most deserves a human. Route it somewhere
a person looks.

## `UNSCANNABLE` and `LIMITS-EXCEEDED` answer different questions

Both are `PARTIAL`, so it is tempting to treat them alike. They point somewhere
different:

* **`LIMITS-EXCEEDED`** — *raise a limit and try again.* The content is
  decodable; a budget stopped the walk before it finished.
* **`UNSCANNABLE`** — *this cannot be decoded at all.* Raising a limit changes
  nothing. A ZIP member using a compression method exav has no decoder for is
  this, not the former, however large the archive.

## The mapping

Every result line ends in its **status**, and each status is one exit code:

| Verdict | Line | Status | Exit |
|---|---|---|---|
| Clean | `path: OK` | `OK` | `0` |
| Infected | `path: <Signature> FOUND` | `FOUND` | `1` |
| *(exav itself failed)* | `path: <message> ERROR` | `ERROR` | `2` |
| Limits exceeded | `path: <reason> LIMITS-EXCEEDED PARTIAL` | `PARTIAL` | `3` |
| Unscannable | `path: <reason> UNSCANNABLE PARTIAL` | `PARTIAL` | `3` |
| Password protected | `path: <reason> PASSWORD-PROTECTED PARTIAL` | `PARTIAL` | `3` |

One grammar throughout — `path: [reason ][CATEGORY ]STATUS` — with the status
last, which is where `clamscan` puts `OK` and `FOUND` and therefore where
anything reading these lines looks. The three **categories** sub-classify a
`PARTIAL`; the other statuses have nothing to sub-classify.

## Process exit code

The overall exit code across all scanned inputs follows this precedence:

1. **`1`** — any file was `FOUND`. A detection is conclusive: that a limit was
   also hit, or another file failed to open, does not make the match less true.
2. **`2`** — otherwise, any file produced an error. An error casts doubt on the
   whole run, where a partial is a fact about one object.
3. **`3`** — otherwise, any file came back `PARTIAL`.
4. **`0`** — otherwise: everything fully scanned and clean.

`0`/`1`/`2` mean what they mean in `clamscan`. `3` is the addition, and it is the
one deliberate difference: `clamscan` returns `OK` / exit `0` for a file it could
not fully scan. [`--partial-as`](/reference/cli/#what-an-unscannable-object-becomes)
folds `3` into any of the other three when a caller wants that — including
`--partial-as ok`, which is what `--clamav-compat` installs. See
[Migrating from ClamAV](/guides/migrating-from-clamav/).

## What each `PARTIAL` category means

- **`LIMITS-EXCEEDED`** — a resource or internal-work limit stopped the scan
  before it completed: `--max-input-bytes`, the extracted-bytes / scan-reach
  budget, a ratio or recursion cap, a member-count cap, or an internal matcher step/time
  budget. Not a failure — a bound that prevented a *complete* scan, surfaced
  rather than hidden.
- **`UNSCANNABLE`** — a container was recognised but couldn't be decoded (an
  unsupported codec, e.g. a RAR member continuing in another volume). The raw bytes are
  still pattern+hash scanned; only the *contained* data couldn't be reached.
- **`PASSWORD-PROTECTED`** — an encrypted member. This one is **actionable**:
  re-scan with `--passwords` (repeatable) or a `.pwdb` database to decrypt and
  scan inside.

## On the clamd wire

`clamd`'s vocabulary is closed: `OK`, `FOUND`, `ERROR`, and nothing else. A
fourth word is not an extension — `clamdscan` 1.4.3 rewrites a status it does not
recognise to `OK` and exits `0`, so putting `PARTIAL` on that wire would turn
exav's fail-closed answer into a fail-open one at every existing client.

So a `PARTIAL` travels as `ERROR`, keeping the same
`path: <reason> <CATEGORY> ERROR` grammar as stdout. **The category is what tells
it apart from a scan that actually failed**, which has none:

```text
big.bin: file size 3145728 exceeds max-scan-size 1048576; scanned first 1048576 bytes only LIMITS-EXCEEDED ERROR
gone.bin: cannot open file ERROR
```

An exav client (`--connect`) reads the category back and reproduces the local
exit code, so a daemon scan and a one-shot scan of the same file agree. A
`clamdscan` client sees both as `ERROR` and exits `2` — a stricter answer than
`clamscan`'s `0`, and the closest the protocol allows.

`--partial-as error` drops the category, which is what makes it mean something
here: the reply becomes an uncategorised `ERROR` and every client, exav's
included, reads it as an operational failure.

## In JSON

Both `--json` and the daemon's `EXINSTREAM` emit the same three names:

- **`status`** — `OK` / `FOUND` / `ERROR` / `PARTIAL`, the word the line ends with.
- **`category`** — `LIMITS-EXCEEDED` / `UNSCANNABLE` / `PASSWORD-PROTECTED`, present
  only on a `PARTIAL`, because the other statuses have nothing to sub-classify.
- **`reason`** — the explanatory string (`signature` instead, on a `FOUND`).
