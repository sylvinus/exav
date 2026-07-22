---
title: Verdicts & exit codes
description: The complete mapping from exav verdict to clamscan/clamd status tag to process exit code.
---

Every scanned file resolves to exactly one verdict. Each maps to a `clamscan`/
`clamd`-style status tag and contributes to the process exit code. This table is
the contract behind the
[never-silent-clean invariant](/concepts/design-principles/#never-a-silent-clean).

## Read exit code 2 as "look at this", not "the scanner broke"

This is the first thing to know, and the thing most likely to be got wrong by a
script migrating from `clamscan`.

Exit code **2 does not mean exav failed.** It means exav declined to call a file
clean because it could not fully scan it — the file was encrypted, or hit a
budget, or used a codec with no decoder. The scan worked; the answer is "I could
not see inside this."

A pipeline that treats 2 as an infrastructure error will retry it, log it as
noise, and eventually silence it. That is precisely backwards: **a file exav
could not read is a better hiding place than one it read and cleared**, so 2 is
the code that most deserves a human. Route it somewhere a person looks.

`0` means scanned and clean. `1` means a detection. Everything else that could
happen to a file lands on 2, with the verdict naming which.

## `UNSCANNABLE` and `LIMITS-EXCEEDED` answer different questions

Both exit 2, so it is tempting to treat them alike. They point somewhere
different:

* **`LIMITS-EXCEEDED`** — *raise a limit and try again.* The content is
  decodable; a budget stopped the walk before it finished.
* **`UNSCANNABLE`** — *this cannot be decoded at all.* Raising a limit changes
  nothing. A ZIP member using a compression method exav has no decoder for is
  this, not the former, however large the archive.

## The mapping

| Verdict | Status tag | Category | Exit code contribution |
|---|---|---|---|
| Clean | `OK` | Clean | `0` |
| Infected | `<Signature> FOUND` | Infected | `1` |
| Limits exceeded | `LIMITS-EXCEEDED` | Not scanned | `2` |
| Unscannable | `UNSCANNABLE` | Not scanned | `2` |
| Password protected | `PASSWORD-PROTECTED` | Not scanned | `2` |

For an `Infected` verdict the status tag is the signature name followed by
`FOUND` (e.g. `Win.Trojan.Agent-1234 FOUND`).

## Process exit code

The overall exit code across all scanned inputs follows this precedence:

1. **`1`** — if any file was `FOUND` (a detection dominates).
2. **`2`** — otherwise, if any file hit an error **or** a "not scanned" verdict
   (`LIMITS-EXCEEDED` / `UNSCANNABLE` / `PASSWORD-PROTECTED`).
3. **`0`** — otherwise (everything fully scanned and clean).

This matches `clamscan`'s `0`/`1`/`2` scheme, with one deliberate difference:
`clamscan` returns `OK` / exit `0` for a file it couldn't fully scan, where exav
returns a "not scanned" verdict and exit `2`. See
[Migrating from ClamAV](/guides/migrating-from-clamav/).

## What each "not scanned" verdict means

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

## In the daemon and JSON output

- The **daemon** renders a not-scanned verdict as `<TAG> (<reason>) ERROR` over
  the wire; the exav client re-classifies those tags as "limits" (not hard
  errors), so a daemon scan's summary and exit code match a local one-shot scan.
- **`--json`** emits a `category` field (`clean` / `infected` / `limits` /
  `unscannable` / `password-protected` / `error`) and the `status` tag per file.
