# exav quirks & notable behaviors

The stories behind some of exav's less-obvious behaviors — collected partly for
the record, partly because they make good talk material. Everything here is
either exav's own design decision or a **public** fact (a published Microsoft/RFC
spec, a documented ClamAV default). Nothing in this file is derived from reading
ClamAV's (GPL) source; where exav matches a ClamAV behavior it does so from the
public spec, and that is noted.

---

## `VelvetSweatshop`: the password that isn't a secret

If you build a malware corpus and scan the spreadsheets, a striking number report
as **encrypted / password-protected** — yet they open in Excel with no password
prompt at all. The trick is a single hard-coded string: **`VelvetSweatshop`**.

`VelvetSweatshop` is the *default* password Microsoft Excel uses when a workbook
is encrypted with the default settings. Excel tries it automatically on open, so
a document "encrypted" with it opens **silently** — no prompt, no friction. That
combination is exactly what a malware author wants:

- To a scanner that stops at "encrypted", the payload is **opaque** — it can't
  see the macros or the embedded objects, so it reports clean (or, in exav's
  case, `PASSWORD-PROTECTED`).
- To the victim, the file opens **normally** and the macros run.

So `VelvetSweatshop` is a real-world evasion primitive: encrypt-to-hide while
staying zero-click to the target. It applies both to legacy `.xls` (BIFF, RC4 /
RC4-CryptoAPI encryption) and to OOXML `.xlsx`/`.docx` (AES). The mechanism is
fully public — Microsoft's **[MS-OFFCRYPTO]** documents the key derivation and
ciphers, and **[MS-XLS] §2.4.117** documents the legacy `FilePass` record that
marks a workbook stream encrypted.

**How the decryption works** (from [MS-OFFCRYPTO], so exav can implement it
clean-room):

- *Legacy XLS (BIFF8)* — the `Workbook`/`Book` stream begins `BOF` then a
  `FilePass` record; encryption type 1 is RC4 (basic) or RC4-CryptoAPI. The key
  is derived from the UTF-16LE password + a salt (MD5 for basic RC4; SHA-1 for
  CryptoAPI), a verifier block confirms the password, then the stream is RC4
  block-decrypted in 1024-byte blocks (re-keyed per block) with a handful of
  records left in plaintext.
- *OOXML standard encryption* — an OLE2/CFB wrapper holds `EncryptionInfo` +
  `EncryptedPackage`; the key is `SHA-1(salt ‖ UTF-16LE(password))` spun **50000**
  times, an AES-128-**ECB** verifier confirms it, and the package is AES-128-ECB
  decrypted back into the real `.xlsx` ZIP.
- *OOXML agile encryption* (modern default) — AES-256-CBC with a per-blob KDF;
  more involved, same idea.

**exav's implementation:** exav now auto-decrypts the legacy XLS **RC4-basic**
and **RC4-CryptoAPI** schemes (`crates/exav-unpack/src/formats/ole_crypto.rs`),
trying `VelvetSweatshop` and the empty password by default (plus any
`--password`), then scanning the recovered `Workbook` content — so the hidden
macros/strings become visible. It was implemented clean-room from [MS-OFFCRYPTO]
§2.3.6 / §2.3.5 and [MS-XLS] §2.4.117, verified **byte-exact against an
independent oracle** on real samples (RC4-basic) and cross-checked against the
reference verifier (CryptoAPI). On a live malware corpus, ~240 XLS that were
opaque `PASSWORD-PROTECTED` now decrypt — 180 surfacing
`Heuristics.OLE2.ContainsMacros`, the rest scanned clean; only the handful using
a *non-default* password stay `PASSWORD-PROTECTED` (correctly — we don't know
it). The XOR obfuscation scheme and OOXML standard/agile AES are still reported
`PASSWORD-PROTECTED` (never a silent clean); closing those is the remaining
follow-up.

> Talk aside: the string `VelvetSweatshop` has been the Excel default since the
> late 1990s. It is, as far as anyone can tell, an inside joke that shipped — and
> two decades later it's load-bearing malware infrastructure.

---

## "Never a silent OK": what exav does when it *can't* fully scan

exav's headline safety property is that it **never returns a clean verdict for a
file it could not fully scan**. If a member is encrypted, truncated, corrupt,
oversized, or hits a limit, exav says so — `PASSWORD-PROTECTED`,
`UNSCANNABLE`, or `LIMITS-EXCEEDED` (exit code 2) — rather than `OK`.

This is a deliberate divergence from ClamAV. ClamAV's default triage collapses
*every* limit/parse/decrypt failure to **clean/OK**; the only knob that surfaces
them (`--alert-exceeds-max`) is off by default, and there is no knob at all for
the "unsupported codec / unpack failed" case. So out of the box ClamAV silently
reports OK for a broad class of not-fully-scanned files. exav treats that class
as *not a pass*.

A 10-minute differential run over a live-malware corpus (daily.cvd only) put real
numbers on the categories exav flags where ClamAV stayed silent:

| exav verdict | Real cause seen in the corpus | Legit vs actionable |
|---|---|---|
| `PASSWORD-PROTECTED` | Encrypted OLE2/OOXML Office docs (the `VelvetSweatshop` set); genuinely encrypted ZIP members inside APKs | Legit flag; decryption is the coverage gap |
| `UNSCANNABLE` | Truncated gzip (recoverable content — now salvaged, see below); >256 MB decompressed members (pattern-scanned, structural analysis skipped) | Mixed — one was a real gap, now fixed |
| `LIMITS-EXCEEDED` | Corrupt PDF deflate streams; malformed OLE2 directory ordering; truncated ZIP extra fields; compression ratio > 1000 (bomb guard); CAB folder over the buffer cap | Some legit guards, some over-strict (see gaps) |

Crucially, in that run the "clam found but exav flagged not-fully-scanned"
bucket was **empty** — exav's carefulness never turned a real ClamAV detection
into a miss. It only ever flagged files ClamAV also called clean.

### The ClamAV-compat default limits (public facts)

For drop-in behavior exav matches ClamAV's documented default limits, while
*reporting* rather than *silently passing* when one is hit:

| Limit | Default | On exceed |
|---|---|---|
| max file size | 100 MB | ClamAV: whole file clean · exav: `LIMITS-EXCEEDED` |
| max scan size (cumulative) | 400 MB | ClamAV: skip rest, clean · exav: flag |
| max recursion | 17 | ClamAV: skip deeper, clean · exav: flag |
| max files per archive | 10000 | ClamAV: skip rest, clean · exav: flag |
| max scan time | 120 s | ClamAV: abort, clean · exav: flag |
| files ≤ 5 bytes | ignored | both skip |

---

## Truncated-stream salvage: keep what you decompressed

A gzip whose stream is cut short (an "unexpected end of file" mid-DEFLATE) is
common in the wild — half-downloaded droppers, deliberately mangled tails. `zcat`
happily recovers everything before the cut; a lot of real malware lives in that
recoverable part (one corpus sample was a `gzip(tar(...))` of a Linux cron/shell
dropper).

exav originally treated the decode error as fatal for that member: it discarded
the bytes decoded so far and reported `UNSCANNABLE`. That's a genuine miss — the
payload was right there in the recovered prefix.

exav now **salvages** the prefix: on a decode error in the streaming member path,
the bytes decoded before the error (which `Read::read_to_end` already collected)
are scanned. The salvage nests — a truncated `gzip(tar(...))` decompresses the
gzip, walks the tar entries that are intact, and scans each. If a signature
matches, it's `FOUND`.

And if nothing matches, the verdict is **`OK`** — not "not fully scanned." This
is a deliberate refinement of the invariant: **exav scans for malware; it is not
a file-integrity validator.** When a *sequential* stream simply runs out of input
(truncation), exav has scanned every byte that *exists* — the missing tail is
*absent*, not *hidden* — so a clean result is a real clean. The
not-fully-scanned flag is reserved for content that is **present but unscanned**:
an encrypted member exav can't decrypt, a member in an unsupported codec, or a
member skipped to stay under a resource limit. Those are the cases where "there's
stuff here I didn't look at" is true and worth telling the user; a merely damaged
file is not. (Checksum-verify mode, `--verify-checksums`, opts back into strict
integrity.)

> Nuance for indexed formats: a truncated *zip* is subtler than a truncated
> gzip/tar — a cut central directory can leave *present* member data that a
> naive reader never enumerates. Calling that "clean" is only honest once exav
> also scans orphan local-file-header members (the ClamAV "dual-indexing"
> behaviour); until then a damaged zip whose index we couldn't fully read is a
> coverage gap, not a clean verdict.

(Interesting footnote from studying the ecosystem: ClamAV salvages a *truncated*
deflate stream but **discards** the recovered prefix on a hard mid-stream data
error — so on that specific case exav is now the more thorough of the two.)

---

## How these were found

All of the above came out of **differential testing** — running exav and a
reference `clamd` over the same live-malware corpus with the same signature set
and diffing every verdict (`scripts/test-clamav-diff.sh`, see
[DIFF_TESTING.md](DIFF_TESTING.md)). Disagreements and exav's "not fully scanned"
bucket are where the interesting behavior hides; reviewing them is how the gzip
salvage gap and the `VelvetSweatshop` coverage gap surfaced.
