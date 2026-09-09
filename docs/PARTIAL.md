# PARTIAL: the third verdict, and how it reaches every protocol

**Status: implemented.** Supersedes the decided parts of
[`VERDICT_PROTOCOL_PLAN.md`](VERDICT_PROTOCOL_PLAN.md), which asked the question
this answers.

Every claim about ClamAV was measured against a local **ClamAV 1.4.3**, and every
claim about exav against the built binary. Commands at the end.

---

## 1. One vocabulary

**Status** — four words, each naming the exit code it produces:

| Status | Exit | Meaning |
|---|---|---|
| `OK` | 0 | fully scanned, nothing matched |
| `FOUND` | 1 | a signature matched |
| `ERROR` | 2 | exav could not do its job — unreadable path, database that would not load |
| `PARTIAL` | 3 | exav worked, and something could not be fully examined |

**Category** — only under `PARTIAL`:

| Category | Raised when |
|---|---|
| `LIMITS-EXCEEDED` | a budget stopped the scan |
| `UNSCANNABLE` | the container could not be decoded |
| `PASSWORD-PROTECTED` | the content is encrypted and no configured password opened it |

**Reason** — free text.

One line grammar, everywhere: **`path: [reason ][CATEGORY ]STATUS`**, status last.

```
path: OK
path: Win.Trojan.Agent-1234 FOUND
path: file size 200000 exceeds max-scan-size 1024 LIMITS-EXCEEDED PARTIAL
path: Can't open file ERROR
```

### Why `PARTIAL`

Work happened in all three cases and stopped short of the end — a real prefix was
scanned, or the container was parsed and only its contents were out of reach.
`SKIPPED` was rejected because `--exclude` already skips files at **exit 0**, so
one word would have had two meanings with opposite codes; and because it claims
exav never looked.

### Why `2` and `3` are separate

They ask different things of a caller. A `2` says the scanner is broken and the
run's result cannot be trusted. A `3` says the scanner worked and *this object*
needs a decision. Before the split, exav returned `2` for both an unreadable path
and a password-protected zip, so an operator could not tell "my deployment is
misconfigured" from "someone uploaded an encrypted archive". `2` now means
exactly what it means in ClamAV.

### Precedence

`1` > `2` > `3` > `0`. A detection outranks everything — finding malware is
conclusive, and a limit hit elsewhere does not make the match less true. An error
outranks a partial, because it casts doubt on the whole run where a partial is a
fact about one object.

Within one file, a match in the scanned prefix wins:

```console
$ exav --max-input-bytes 1M early.bin      # EICAR in the first MB of a 3 MB file
early.bin: Eicar-Test-Signature FOUND
$ echo $?
1
```

---

## 2. `--partial-as`

```
--partial-as <STATUS>      [default: partial]      env: EXAV_PARTIAL_AS
```

The value **is** the status it reports as, and therefore the exit code:

```sh
exav --partial-as ok                                     # 0
exav --partial-as found                                  # 1
exav --partial-as error                                  # 2
exav --partial-as partial                                # 3, the default
exav --partial-as password-protected=ok,limits-exceeded=found   # per category
```

Categories: `limits-exceeded`, `unscannable`, `password-protected`. An
unrecognised one is a startup error, not a policy that silently never fires.

**`ok` is never silent.** The listener says so at startup, and every such object
is logged with its category and reason. That is what keeps [never a silent
clean](https://exav.org/concepts/design-principles/#never-a-silent-clean) intact
rather than switched off.

**A detection is never folded.** This governs only the three categories above.

**`--clamav-compat` implies `--partial-as ok`**, because that is what a stock
ClamAV build answers for this whole class. An explicit `--partial-as` still wins,
as every value in that preset does.

**Refused with `--connect`.** The policy belongs to whatever scans. A client only
sees the reply the daemon already decided, so the flag would have parsed, looked
in force, and done nothing — and it cannot be made to work, since once the daemon
has reported `OK` for something it folded, the fact is gone from the wire.

---

## 3. Every entry point

`LIMITS-EXCEEDED` on a 200 KB file with `--max-input-bytes 1K`. Measured.

### CLI

| `--partial-as` | stdout | Exit |
|---|---|---|
| `partial` | `big.bin: file size … LIMITS-EXCEEDED PARTIAL` | 3 |
| `ok` | *(no line; logged to stderr)* | 0 |
| `found` | `big.bin: Heuristics.Limits.Exceeded.MaxFileSize FOUND` | 1 |
| `error` | `big.bin: file size … LIMITS-EXCEEDED ERROR` | 2 |

### CLI `--json`

```json
{"category":"LIMITS-EXCEEDED","file":"big.bin","reason":"file size 200000 exceeds max-scan-size 1024…","status":"PARTIAL"}
```

`category` is present only under `PARTIAL` — the other statuses have nothing to
sub-classify. Key order is not part of the contract; keys serialise sorted.

### clamd wire — `SCAN` / `CONTSCAN` / `MULTISCAN` / `INSTREAM` / `FILDES` / `SCANURL`

```
path: file size 200000 exceeds max-scan-size 1024 LIMITS-EXCEEDED ERROR
```

Same grammar as stdout; **only the status word differs**, and it has to. See §4.

### clamd `EXINSTREAM` / `EXINSTREAM MULTI`

```json
{"v":1,"status":"PARTIAL","category":"LIMITS-EXCEEDED","reason":"…"}
```

The same three names the CLI JSON uses. This replaced `verdict`/`tag`/`message`,
whose `"verdict":"unscannable"` collided with the *category* of that name — a
`{"verdict":"unscannable","tag":"PASSWORD-PROTECTED"}` read as a contradiction.

### ICAP

| `--partial-as` | Response | Headers |
|---|---|---|
| `partial` / `error` | `200` + a `403` block page | `X-Exav-Status: PARTIAL`, `X-Exav-Category`, `X-Exav-Reason`, and `X-Infection-Found` under `Heuristics.Exav.*` |
| `found` | `200` + block page | `X-Infection-Found` under the `Heuristics.*` name |
| `ok` | `204` (or `200` echoing the message without `Allow: 204`) | the `X-Exav-*` trio, **never** `X-Infection-Found` |

`X-Exav-Status` is `PARTIAL` even under `--partial-as error`. ICAP has no exit
code — the only thing those two differ in — and answering `ERROR` would tell a
proxy the *scanner* failed. Squid counts service failures and eventually bypasses
the service, so relabelling an encrypted archive could take the scanner out of
rotation and start failing open.

`X-Infection-Found` on a *block* defaults on: a large class of ICAP client greps
that header alone and reads a `200` without it as a pass.
`--icap-infection-header detections` restricts it to database hits, at that cost.
On a *pass* it is always withheld — the object is being delivered, so claiming an
infection would be false and would make those clients block it anyway.

### Library (`exav-core`)

`VerdictCategory::Partial`. The engine always reports the truth; `--partial-as` is
a CLI concern applied in front of output.

---

## 4. Why the clamd wire says `ERROR`

Measured against real `clamdscan` 1.4.3, driven by a stub daemon:

```
reply ends in ERROR    -> clamdscan exit 2, line echoed verbatim
reply ends in PARTIAL  -> clamdscan exit 0, prints "f.txt: OK"
```

**It rewrites an unknown status to `OK`.** No `FOUND`, no `ERROR`, therefore
clean — it does not even echo the text.

So `PARTIAL` on this wire would make every existing clamd client report a file
exav could not scan as clean: the silent-clean failure exav exists to prevent,
reintroduced invisibly through the protocol, and worse than the status quo. The
protocol's vocabulary is `OK` / `FOUND` / `ERROR`, and `ERROR` is the only word in
it that fails closed. The category is still in the text for anything that reads
further.

---

## 5. ClamAV compatibility

ClamAV **does** report these — as detections, opt-in:

| Situation | ClamAV default | With its alert flag |
|---|---|---|
| over `--max-filesize` | `OK`, exit 0 | `--alert-exceeds-max=yes` → `Heuristics.Limits.Exceeded.MaxFileSize` FOUND, exit 1 |
| encrypted archive | `OK`, exit 0 | `--alert-encrypted=yes` → `Heuristics.Encrypted.Zip` FOUND, exit 1 |
| corrupt archive | `OK`, exit 0 | *no flag exists* |

Its whole answer is exav's `found`. It has no third category, no third exit code,
and nothing at all for the corrupt case.

**`--partial-as found` is therefore the ClamAV-compatible mode**, and a strict
superset. The names now match byte for byte:

```console
$ exav --max-input-bytes 1M --partial-as found big.bin
big.bin: Heuristics.Limits.Exceeded.MaxFileSize FOUND
$ clamscan --max-filesize=1M --alert-exceeds-max=yes big.bin
big.bin: Heuristics.Limits.Exceeded.MaxFileSize FOUND
```

That last part was a real gap: the top-level size check produced
`Heuristics.Exav.LimitsExceeded`, a name no ClamAV-shaped pipeline matches, for
the one limit ClamAV *does* name. It now passes the limit kind as a type into the
engine's own lookup, as every other budget already did.

ClamAV has **no structured category anywhere** — `--gen-json` emits file metadata
only (`Magic`, `RootFileType`, `FileName`, `FileType`, `FileSize`, `FileMD5`), no
verdict. Its only categorisation is the dotted signature name. exav keeps its own
flat categories for `PARTIAL`, and uses ClamAV's dotted namespace under
`--partial-as found`, where the object genuinely is being reported as a detection.

---

## Reproducing

```sh
head -c 3000000 /dev/urandom > big.bin
printf secret > s.txt && zip -P hunter2 enc.zip s.txt

clamscan --no-summary --max-filesize=1M big.bin;                         echo $?
clamscan --no-summary --max-filesize=1M --alert-exceeds-max=yes big.bin; echo $?
clamscan --no-summary --alert-encrypted=yes enc.zip;                     echo $?

for v in partial ok found error; do
  exav --allow-no-db --max-input-bytes 1K --partial-as $v big.bin; echo "$v -> $?"
done

exav --allow-no-db --max-input-bytes 1K --json big.bin
exav --listen clamd://127.0.0.1:3310 --max-input-bytes 1K &
printf 'nSCAN %s\n' "$PWD/big.bin" | nc 127.0.0.1 3310

# ICAP codes and headers: crates/exav/tests/icap_server.rs asserts them
cargo test -p exav --test icap_server
```
