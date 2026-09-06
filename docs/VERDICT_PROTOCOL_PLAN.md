# Verdicts on the wire: a plan

How exav should report *"I could not look at this"* — to a human, to a clamd
client, and to a new integration — and what that costs in ClamAV compatibility.

Written to be decided on, not merged as-is. Every claim below that could have
been asserted was measured instead; the commands are given.

---

## 1. The question that motivates it

> If ClamAV is run with full heuristics and `--all-matches`, does it actually
> have the same capabilities as exav — no silent misses?

**No.** Not close, and not for want of flags.

Method (the rigorous one, not a signature-database comparison): extract each
container's members with exav, hash every member into an `.hdb`, then scan the
**untouched** container with `clamscan` and every alert flag it has. If clamscan
reports `OK`, it never reached the member. Flags used:

```
--allmatch --heuristic-alerts=yes --alert-broken=yes --alert-broken-media=yes
--alert-encrypted=yes --alert-encrypted-archive=yes --alert-encrypted-doc=yes
--alert-macros=yes --alert-exceeds-max=yes --alert-phishing-ssl=yes
--alert-phishing-cloak=yes --alert-partition-intersection=yes
```

Result — every row is a plain `OK` from clamscan on a file whose payload exav
reads:

| Container | Members exav reaches | ClamAV reaches |
|---|---|---|
| LZW `.Z` (10 fixtures, 12- and 16-bit) | 1 each | **0** |
| WIM — LZX, LZMS, XPRESS, uncompressed (5 images) | 1–3 each | **0** |
| UDF-only ISO (no ISO 9660 descriptor) | 3 | **0** |
| VHDX, dynamic | 1 | **0** |
| QCOW2 with deflate clusters (2 fixtures) | 1 each | **0** |
| VMDK sparse, and streamOptimized (the shape inside an OVA) | 1 each | **0** |
| **EGG with LZMA members** | 2 | **0** |
| **EGG solid archive** | 1 | **0** |

For contrast, ClamAV *does* reach: EGG store/deflate members, ALZ, ISO 9660
(including the ISO side of a bridge image), and anything behind gzip.

Two things this shows that a format list would not:

- **The last two rows are inside a format ClamAV claims.** Its EGG submodule is
  on by default, and it still returns `OK` on an EGG whose members are LZMA or
  solid. Format-level support is not member-level reach, so "does it support
  EGG?" is the wrong question to audit with.
- **No flag changes any of it.** These are not heuristics that are off by
  default; there is no name for "a container I have no code for". ClamAV's own
  `--help` says the quiet part for the limit cases — `--max-filesize`: *"Files
  larger than this will be skipped and **assumed clean**"*, `--max-scantime`:
  same wording. `--alert-exceeds-max` covers filesize/scansize/recursion; there
  is no `--alert-exceeds-scantime`.

Add the documented >2 GB behaviour (read, scanned as zero bytes, reported `OK`)
and the shape is clear: **ClamAV's `OK` means "nothing matched in what I
examined". exav's `OK` is intended to mean "I examined it".** Those are different
claims, and no combination of flags converts the first into the second.

This is the whole reason the vocabulary problem below exists. If ClamAV had a
verdict for "not examined", exav would just use it.

---

## 2. Where exav is today

**Verdicts** (`exav_core::Verdict`), collapsing to three categories:

| Verdict | Category | Exit |
|---|---|---|
| `Clean` | Clean | 0 |
| `Infected { signature, offset, method }` | Infected | 1 |
| `LimitsExceeded { reason }` | NotScanned | 2 |
| `Unscannable { reason }` | NotScanned | 2 |
| `PasswordProtected { reason }` | NotScanned | 2 |

The three-way split inside `NotScanned` is real and worth keeping:

- `LimitsExceeded` — **the operator can fix this.** Raise a limit, rescan.
- `PasswordProtected` — **the user can fix this.** Supply a password, rescan.
- `Unscannable` — **nobody can fix this today.** exav has no decoder.

Each points at a different person, which is the only justification a verdict
distinction ever needs.

**On the clamd wire** (`crates/exav/src/daemon.rs`), all three become:

```
<path>: <TAG> (<reason>) ERROR
```

and `EXINSTREAM`, exav's own command, returns one line of JSON:

```json
{"v":1,"verdict":"unscannable","tag":"LIMITS-EXCEEDED","message":"…"}
```

---

## 3. The problem with `ERROR`

The clamd protocol has exactly three reply shapes: `OK`, `<sig> FOUND`,
`<msg> ERROR`. exav maps "not scanned" to `ERROR` because it is the only reply
that is not a lie.

But `ERROR` already means something to every existing client, and it is not
this. In clamd, `ERROR` is an *infrastructure* failure — file vanished, socket
died, out of memory. Clients act accordingly:

- **Mail gateways** (amavisd, MailScanner, rspamd) typically **temp-fail** the
  message: a 4xx and a retry. A password-protected ZIP arriving as `ERROR`
  therefore gets retried forever and never delivered or quarantined — the worst
  outcome for a condition where the right answer is "quarantine and tell the
  user to send the password".
- **Storage/backup scanners** log and move on, so the finding is invisible.
- **`clamdscan`** prints it and sets exit 2, which most wrappers treat as "the
  scanner is broken", not "this file needs attention".

So the honest reply produces, in practice, the same operational outcome as
silence — sometimes worse. **The invariant is preserved on the wire and lost in
the client.** That is the actual bug, and it is a UX bug rather than a protocol
one.

Meanwhile ClamAV expresses the *same* conditions as ordinary detections:
`Heuristics.Encrypted.Zip`, `Heuristics.Limits.Exceeded`,
`Heuristics.Broken.Executable` arrive as `FOUND`, and every client already knows
what to do with `FOUND`.

---

## 4. The plan

### 4.1 Keep the model, change only the projection

The internal model (three NotScanned verdicts, each with a reason) is right and
should not move. What is wrong is that there is one lossy projection of it onto
the wire, chosen for us. Make the projection a policy.

**`--compat=<mode>`**, on both the CLI and the daemon:

| Mode | `OK`/`FOUND`/`ERROR` mapping | For |
|---|---|---|
| `clamav` | Not-scanned → `Heuristics.* FOUND`, gated by the same `--alert-*` flags ClamAV uses, **including staying silent when the flag is off** | Drop-in replacement behind existing clients |
| `strict` *(recommended default)* | Not-scanned → `Heuristics.* FOUND` always, no flag needed | Anyone who wants the invariant to survive contact with a real client |
| `exav` | Current behaviour: `<TAG> (<reason>) ERROR` | Operators who have already built on it |

`strict` differs from `clamav` in exactly one way — it does not let a flag turn
a known gap into an `OK`. That is the difference the whole project is about, and
making it one axis rather than a rewrite is the point.

### 4.2 The names

Reuse ClamAV's name wherever the condition is the same, so existing allowlists,
dashboards and alert rules keep working:

| exav condition | Name emitted |
|---|---|
| Encrypted archive member | `Heuristics.Encrypted.Zip` / `.7Zip` / `.RAR` / `.EGG` … |
| Encrypted document | `Heuristics.Encrypted.PDF` / `.Doc` |
| Any limit hit | `Heuristics.Limits.Exceeded.<MaxFileSize\|MaxScanSize\|MaxFiles\|MaxRecursion>` |
| Broken PE/ELF | `Heuristics.Broken.Executable` |
| Broken media | `Heuristics.Broken.Media.<Gif\|Png\|Tiff\|Jpeg>` |
| Overlapping partitions | `Heuristics.MBRPartitionnIntersect` (the doubled `n` is upstream's, reproduced deliberately) |

For the categories ClamAV has **no name for** — §1's eight rows — exav needs its
own, and they must not collide with anything Talos may ship:

```
Heuristics.Exav.Unopened.<FORMAT>     container recognised, no decoder
Heuristics.Exav.Unopened.<FORMAT>.<CODEC>   member codec not implemented
```

e.g. `Heuristics.Exav.Unopened.Ace`, `Heuristics.Exav.Unopened.Egg.Azo`. The
`Exav.` infix is the namespace; `Unopened` states the fact without claiming
maliciousness, which matters because these fire on entirely benign files.

**Open question for you:** whether `Heuristics.Exav.*` should be on in `clamav`
mode. Emitting a name ClamAV never emits is a compatibility divergence; *not*
emitting it reintroduces the exact silent miss the project exists to remove. My
recommendation is on-by-default with `--no-alert-unopened` to suppress, because
a name a client does not recognise still surfaces, whereas silence does not.

### 4.3 Structured detail is the real answer — via `EXINSTREAM`

Squeezing "why" into a signature name is a workaround for a protocol with three
reply shapes. New integrations should not have to.

`EXINSTREAM` already returns JSON and already carries `tag` + `message`. Extend
it rather than the string protocol — this is where the earlier
"shouldn't we return structured metadata?" question lands:

```json
{"v":1,"verdict":"unscannable",
 "tag":"UNSCANNABLE",
 "reasons":[
   {"format":"Egg","codec":"AZO","member":"a.zip/inner.egg/x.bin",
    "why":"no-decoder","recoverable":false}],
 "examined_bytes":12345,"total_bytes":99999}
```

Three properties worth having, none expressible in a name:

- **`member`** — the nesting path, so an operator can find the thing.
- **`recoverable`** — machine-readable version of the "who can fix this" split
  in §2. A gateway can route `recoverable:true` to a user-facing bounce and
  `false` to quarantine.
- **`examined_bytes` / `total_bytes`** — turns "not fully scanned" into a
  proportion. A 4 GiB archive with one 12-byte undecodable member is not the
  same risk as one where nothing was read, and today both report identically.

Add `--format=json` to the CLI with the same schema, so the daemon and the CLI
answer the same question the same way.

### 4.4 The invariant must not be defeasible

Whatever the wire says, the **process exit code and the scan summary keep
telling the truth**. In `clamav` mode a suppressed heuristic may produce `OK` on
the socket, but:

- the run still exits `2` if anything went unexamined;
- the summary still prints the count and the reasons;
- `--fail-on-unscanned=no` is the single explicit opt-out, and it is loud in
  `--help`.

This is what keeps `clamav` mode from being a hole: the compatibility surface is
the reply line, not the truth.

### 4.5 Sequencing

1. `Heuristics.*` emission behind `--compat`, reusing ClamAV's names — no new
   vocabulary, immediate interop win. Diff-testable against clamscan directly.
2. `Heuristics.Exav.Unopened.*` for the eight categories in §1, with the
   `docs/` gap list generated from the same table so they cannot drift.
3. `EXINSTREAM` structured reasons + CLI `--format=json`.
4. Revisit `--compat` default once (1)–(3) have run against a real corpus.

Steps 1 and 2 are what make exav's advantage *visible to an existing client*.
Today that advantage is real — §1 measures it — and largely invisible, because
`ERROR` is the one thing clients are trained to ignore.

---

## 5. Multi-file archives: the one-buffer assumption

Everything above concerns *what a verdict says*. This section is about a case
where exav cannot reach the content at all, and the cause is an API shape rather
than a missing decoder.

### 5.0 The governing principle: a scan unit is a *set*, not a file

Everything in this section is one gap wearing several hats, and it is worth
stating generally before the special cases.

**At every recursion level, the members produced by the level above are a
cohort — and exav's API hands them over one at a time.** `Sink` receives one
`Entry` with no view of its siblings, so no extractor and no recursion step can
observe a relationship *between* files:

| Relationship | Invisible today because |
|---|---|
| Multi-volume set (`x.part1.rar` …) | the member's stream continues in a sibling |
| Multi-cabinet CAB | the folder continues in the cabinet the header names |
| `x.exe` + `x.dat` sidecar | the relationship is in code, but both files are right there |
| Split archive inside a ZIP | all the parts arrive in one pass and are then separated |

The same shape recurs at the outside edge: a directory (`CONTSCAN`), a
client-supplied manifest (`EXINSTREAM`), and a container's member list are all
**a set of named byte sources**. Treating them as three problems is what made
this look like three features.

**The constraint that shapes the fix.** `extract_each` yields one member at a
time on purpose: it is why the working set stays flat regardless of file size,
which is the property exav has over an engine that reads a >2 GB file as zero
bytes. Passing every member's *bytes* would trade that away — a 10 GB archive
with 10,000 members would be resident at once.

**But do not enumerate first.** An "list the cohort, then decide" pass is the
obvious design and it is wrong here:

- `tar` has no index — listing it means walking the whole file.
- A stream (gzip, `INSTREAM`) cannot be listed at all without decompressing.
- It forces a complete pass *before any scanning starts*, delaying detection —
  and [`crate::stream_members`] exists precisely so a large container never needs
  one.
- A container declaring ten million members makes the metadata the memory
  problem.

That would trade the streaming property away to serve a case that almost never
arises.

**React instead of enumerate.** The one-at-a-time visitor already sees every
member's *name* as it arrives. The moment a name parses as a volume member
(`volume::parse`), a set may exist — and only then is anything gathered. The cost
on a container with no volume members is one string match per name, and the
streaming default is untouched.

Ordering is the one wrinkle: `part2` can arrive before `part1`. A seekable source
seeks back. A pure stream cannot, so members whose names parse as volumes are
held (bounded by the existing `max_members` / `max_buffer`) until the set completes
or the container ends. A set that never completes reports exactly as it does
today.

Peak memory therefore becomes one *set* rather than one *file*, and only where a
set exists — never a whole member list.

**Where the change lives.** Not in the sixty-odd format modules; their `Sink`
signature is unchanged. The layer sits *above* `extract_each` — enumerate, group,
dispatch — in exav-core's recursion, plus a metadata-enumeration entry point for
the buffered path. The seekable `Archive` type already has the primitive.

This also supplies the in-memory VFS of §5.5 for free: that VFS *is* the cohort
at one recursion level. The sidecar case then falls out of the same design rather
than needing one of its own.

### 5.1 The gap

A multi-volume archive is one logical archive spread over several files —
`x.part1.rar`/`x.part2.rar`…, `x.rar`/`x.r00`/`x.r01`…, `x.7z.001`,
`x.zip`/`x.z01`, `x.a01`, and multi-cabinet CAB. A member's compressed stream
runs off the end of one file and continues in the next, so **no single file
decodes it**.

Every entry point exav has takes one buffer:

| Entry point | Shape |
|---|---|
| `exav_unpack::extract(fmt, data, budget)` | one `&[u8]` |
| `exav_unpack::extract_each(fmt, data, …)` | one `&[u8]` |
| `exav_unpack::stream_members(fmt, source, …)` | one `Read + Seek` |
| `Archive::open(reader)` | one reader |
| clamd `INSTREAM` / `EXINSTREAM` | one chunked stream |
| clamd `SCAN` | one path |
| `CONTSCAN` / `MULTISCAN` | a directory — but **each file scanned independently** |

So the capability was absent at every layer, and `CONTSCAN` is the interesting
one: it already receives a whole directory and threw the grouping away.

Since resolved for byte-split sets — see §5.4 for what each surface does now and
what is still open.

### 5.2 Measured

`unar` reports the fixture set as `RAR (4 volumes)` containing `text.bin`.
clamscan, with `--allmatch` and the alert flags, on each part in turn:

```
c4.part1.rar: OK    c4.part2.rar: OK    c4.part3.rar: OK    c4.part4.rar: OK
```

Four `OK`s. A payload spanning a volume set is invisible to it, and there is no
flag that changes this — the same shape as §1.

**exav does not share the silent part.** `formats/rar.rs` reads the
`LHD_SPLIT_BEFORE`/`LHD_SPLIT_AFTER` flags and emits *both* the readable prefix
and an `Entry::unsupported` saying `"RAR member continues in another volume;
only the part in this volume was scanned"`. So exav reports the gap plainly and
cannot close it. That is the correct failure mode, and it is still
a capability gap against 7-Zip, WinRAR and The Unarchiver — which is the bar
[the parity principle](/concepts/archive-extraction/#the-parity-principle) sets,
because the attacker picks the format the *victim* can open.

### 5.3 Design

Prior art exists and should be the starting point: an earlier worktree holds a
248-line `volumes.rs` plus a RAR volume-set implementation, unmerged. Its
security model is the part worth keeping verbatim.

**`exav-unpack` gains a trait, not a filesystem dependency.** The crate is
`#![forbid(unsafe_code)]`, WASM-targetable, and has no business opening files:

```rust
/// Supplies the sibling volumes of a multi-volume archive.
pub trait VolumeSet {
    /// Volume `n` (0 is the scanned file), or `None` when the set ends.
    fn volume(&mut self, n: usize) -> Option<&[u8]>;
    fn len(&self) -> usize;
}
```

It is a **byte supplier, not a callback into the scanner**, and that distinction
is what makes it safe to add. exav-core is already inside a `Sink` callback from
exav-unpack when a member is being decoded; a trait that re-entered the scan
would close a cycle. A dumb accessor does not, so there is no reentrancy to
reason about and no borrow tangle.

Only **format-aware** volumes need it. For a byte-split set the logical stream is
a plain concatenation, so a `Read + Seek` that stitches the parts is enough — and
[`crate::stream_members`] already takes exactly that, meaning **no decoder
changes at all**. RAR needs the trait because a member's data continues *past the
next volume's headers*, so the join is not concatenation and the skipping needs
format knowledge.

`extract_each_multi(fmt, set, budget, visit)` joins a split member's stream
across volumes; the single-buffer entry points stay as they are and keep
working. In a build with no volume source, behaviour is exactly today's — report
the split member.

**Resolution belongs to the caller, and only ever to a path.** `exav-core`
implements the trait against the filesystem under rules that are the whole
security argument:

- **Same directory only.** Sibling names are *generated* from the scanned file's
  own name by a parsed pattern — never read from archive content.
- **Strict naming.** Only the schemes the writers actually produce, preserving
  the scanned name's digit width.
- **`symlink_metadata`, regular files only.** A symlink named like the next
  volume is refused, not followed.
- **Capped** at `MAX_VOLUMES` (100) and the per-volume peak-buffer limit.

The one format that inverts this is **CAB**, whose header names the next cabinet
(`szCabinetNext`) *inside the file*. That string is attacker-controlled and must
be treated as a name to **match against a directory listing**, never as a path
to open — otherwise a cabinet chooses what exav reads. Worth stating explicitly
because it is the obvious implementation and it is a directory-traversal bug.

### 5.4 Protocol — *implemented for byte-split sets*

Three surfaces, and the ordering mattered:

1. **`CONTSCAN`/`MULTISCAN` grouping — no protocol change, biggest win.** The
   command already gets a directory. **Done.** Sets are grouped per directory and
   the rejoined archive is scanned once; the verdict is attributed to *every*
   part, so the reply stays exactly one line per file and existing clients get
   multi-volume support with no changes at all.

   The alternative — reporting under a synthetic set name — was rejected: clamd
   emits one line per file and a client counting lines against files would break.
   A part of an infected archive is not a clean file anyway, and it is the file
   the operator has to act on.
2. **`SCAN <path>`** — resolve siblings from the path, exactly as §5.3. Not yet
   done for the scanner; `exav-unpack list|extract` already does it.
3. **`INSTREAM` cannot be fixed, and should not be.** Its framing is
   `<u32 len><data>…<u32 0>`: one stream, no names, no boundaries. Retrofitting a
   manifest would break every existing client's framing. **`EXINSTREAM MULTI`
   was added instead** — a separate verb, so bare `EXINSTREAM` is untouched:

   ```
   EXINSTREAM MULTI
   <u32 name_len><name>  <u32 len><data>…<u32 0>     per file
   <u32 0>                                          ends the request
   ```

   The JSON manifest this section originally proposed was dropped. It would have
   put a parser in front of the framing for no gain: the name belongs *with* its
   chunk sequence, which the length-prefix above expresses directly, and a
   malformed manifest becomes a framing desync rather than a bad request.

   Names here are **labels for reporting and for volume ordering only** — they
   are never opened, so the traversal question does not arise.

   The reply is one line: `{"v":1,"files":[{"name":N,…verdict…},…]}`, one entry
   per file, with `"set"` present when the verdict came from a rejoined archive
   rather than from the file itself.

**What is not covered.** Only *byte-split* sets (`.001`, `.002`) rejoin, because
concatenation is the whole of their format. Format-aware volumes (RAR `.partN`,
ZIP `.zNN`) pass through unchanged and are still reported accurately per §5.2 —
each carries its own headers and a member's data resumes *past* the next
volume's header, so their join belongs inside the format's decoder.

**The join cannot happen mid-stream.** Nothing in a set's names records how many
parts it has, so `.001`+`.002` looks contiguous even when `.003` follows.
Joining on arrival emits a truncated prefix that *still parses as the archive*
and is then scanned as if it were whole — a silent partial scan wearing a valid
archive's costume. `volume::Collector` therefore always answers `Held` and
resolves only in `finish()`, when no further member can arrive. The cost is that
a split set is not scanned until its container ends; it is unavoidable.

### 5.5 The sidecar case, and why the emulator is not the answer

A related shape: a dropper `x.exe` that reads `x.dat` beside it and decrypts the
payload at runtime. Neither file is detectable alone — the executable carries no
payload, and the `.dat` is indistinguishable from noise. It is the same
"one logical object, several files" problem as a volume set, but the relationship
lives in *code* rather than in a naming convention.

**Would a PE-packer emulator reach the sidecar?** No, and it should not be
extended to.

exav's emulator (`exav-pe-emu`) runs an unpacking *stub*: self-contained code
that inflates a section of the file it is already in. Such a stub needs a
handful of APIs — allocate, protect, and enough `LoadLibrary`/`GetProcAddress`
to rebuild an import table — and **no file I/O at all**.

A dropper is a different program by orders of magnitude: `GetModuleFileNameW`,
`CreateFileW`, `ReadFile`, then arbitrary decryption, and commonly registry and
network before it does anything interesting. Emulating that is a sandbox, not a
stub emulator, and every scanner in the comparison set has the same blind spot.

**The obvious safe shape is an in-memory VFS over exactly the request's files**,
resolved by basename, with no syscall reaching a real filesystem — and that
disposes of most of the security worry rather than merely bounding it. The guest
cannot reach anything the caller did not already hand the scanner; a read
"succeeds" only into bytes exav is holding anyway. There is no escalation there,
just the same bytes by another route. It is the same discipline as §5.3: a name
from untrusted input is matched against a set the caller assembled, never turned
into a path.

exav is also an unusually good host for this. `#![forbid(unsafe_code)]`, no JIT,
budgets on every axis, and `catch_unwind` around each decoder mean an emulator
bug is a contained panic rather than the RCE class that has repeatedly hit C
engines with JITs. The historical reason to fear scanner emulators does not
transfer.

So the objection is **not safety, it is API breadth**. A packer stub needs about
a dozen calls; a dropper reaches for file, registry and network APIs, and dies at
the first one that is missing. That is an engineering-cost question with a known
mitigation — emulation need not run to completion. It runs until the program
*produces bytes*, and those bytes get scanned; the same checkpoint that makes
stub unpacking work. Partial execution with a "what did it write" trap is the
standard technique and degrades visibly: what it reaches is scanned, and what it
does not is reported.

The prerequisite is the same either way: the VFS can only contain the request's
files if a request can *carry* several files, which is what §5.4 builds. The
emulator stays a separate decision on top of that, and a defensible one.

### 5.6 What it does not change

The never-silent invariant is unaffected either way: an unresolvable volume is
reported now and would still be reported then. This is purely about turning a
reported gap into read content — worth doing because a split archive is a
completely ordinary way to move a large payload, and today every scanner in the
comparison set except the extractors themselves misses it.

---

## 6. What this does not solve

- A client that ignores `FOUND` for `Heuristics.*` names (some sites allowlist
  the whole prefix to cut noise) is back to silence. Nothing exav emits can fix
  a site that filters it out; the `--format=json` path is the answer for anyone
  who cares.
- `Heuristics.Exav.*` names are not in anyone's threat feed, so they will look
  like false positives until documented. The docs page must lead with "these are
  coverage reports, not detections".
- None of this narrows the gap itself. The eight rows in §1 shrink by writing
  decoders — which is what tasks #24 (AZO) and the remaining gap list are for.
  This plan only ensures the gap is *legible* while it exists.

---

## Reproducing the measurements

```sh
cargo build --release -p exav && cargo build -p exav-unpack
# For each container: exav extracts, members are hashed into an .hdb,
# clamscan rescans the untouched container with every alert flag.
scripts/clamav-reach.sh crates/exav-unpack/tests/fixtures/{lzw,wim,egg,alz}/*
```

The `.gz`-wrapped fixtures under `diskimage/` and `udf/` must be gunzipped
first — otherwise the measurement tests gzip, not the inner format, and reports
"reached all" for images ClamAV never opens. That mistake was made and caught
while producing the table above.
