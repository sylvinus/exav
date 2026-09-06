---
title: ClamAV flag matrix
description: Every clamscan, clamd and clamdscan flag against exav's equivalent — what is accepted, what is renamed, what behaves differently, and what is not supported.
---

A row-by-row comparison of ClamAV's command-line surface against exav's. Use it
to check a command line before you swap a binary, and to find the flags that
need translating.

The rest of the migration — signatures, sockets, service units — is in
[Migrating from ClamAV](/guides/migrating-from-clamav/). For exav's own flags in
their own right, see the [CLI reference](/reference/cli/).

## How to read this

exav's scanner is a `clamscan` counterpart, a `--listen clamd://…` a `clamd`
counterpart, and `--connect` a `clamdscan` counterpart. Each table covers one of
the three.

One binary plays all three parts, and the flags pick which — so the rows below
apply to a command line that already starts with `exav`:

| ClamAV binary | exav invocation | Selected by |
|---|---|---|
| `clamscan` | `exav PATH…` | paths, neither `--listen` nor `--connect` |
| `clamd` | `exav --listen ADDR` | `--listen` |
| `clamdscan` | `exav --connect ADDR PATH…` | `--connect` **and** paths |

Getting an existing `clamscan` / `clamdscan` command line there takes a wrapper
script on `PATH`, since exav does not dispatch on the name it was invoked
under:
[One binary, three roles](/guides/migrating-from-clamav/#one-binary-three-roles).

| Status | Meaning |
|---|---|
| **same** | exav accepts the same spelling and does the same thing. |
| **renamed** | exav has the capability under a different name. The exav column gives it. |
| **differs** | Accepted, behaviour deliberately different. The Notes column says how. |
| **absent** | Not accepted. exav exits **2** with a parse error naming the flag. |

**exav's flags are its own, and an unsupported flag stops the run.** There is no
catch-all that swallows unknown arguments, so a `clamscan` command line carrying
a flag exav does not implement fails loudly at startup instead of scanning under
settings the operator did not get. A migration finds these on the first run, not
in an incident.

Nothing here is a hidden alias, either: two names for one bound is two things to
document and one more way for a command line to be subtly wrong. A **renamed**
row means the old spelling is refused and the error names what exav calls it.

### The `=yes` / `=no` value form

`clamscan` spells most of its switches `--flag[=yes/no]`, so `--allmatch=yes`,
`--recursive=no` and `--scan-pe=no` are all valid there. exav's switches are
bare booleans: `--all-matches` is accepted, `--all-matches=yes` is not. Strip
the value when translating a command line, and note that the `=no` form has no
exav equivalent at all — a switch is on when given and off when omitted.
`--base64 on|off` is the one exception, and it takes a value precisely so an
explicit choice can beat the `--clamav-compat` preset.

## `clamscan`

Grouped in the order `clamscan --help` prints them.

### Output and reporting

| `clamscan` | What it does | exav | Status | Notes |
|---|---|---|---|---|
| `--help`, `-h` | Show help | same spelling | same | |
| `--version`, `-V` | Print version | same spelling | same | exav reports a `ClamAV <version>` string so `clamscan`-parsing tooling recognises the engine. |
| `--verbose`, `-v` | Be verbose | same spelling | differs | exav prints per-file informational findings (type, entropy, imphash, ML score) rather than progress chatter. |
| `--archive-verbose`, `-a` | Show filenames inside archives | — | absent | Member paths appear in the match location on a detection. |
| `--debug` | libclamav debug messages | — | absent | |
| `--quiet` | Only output error messages | `--quiet` | differs | exav still prints detection lines under `--quiet`; `clamscan` suppresses them too. exav's `--quiet` is the whole output dial: it drops the per-file `OK` lines *and* the summary. |
| `--stdout` | Write to stdout instead of stderr | — | absent | exav already writes every result line to stdout and reserves stderr for errors, which is what the flag asks for. |
| `--no-summary` | No summary at end | `--quiet` | renamed | One dial rather than three: `--quiet` suppresses the `OK` lines and the summary together. Separate switches for the two end up meaning the same thing without anyone noticing. |
| `--infected`, `-i` | Only print infected files | `--quiet` | renamed | Same dial — this and `--no-summary` gated the same output. |
| `--suppress-ok-results`, `-o` | Skip printing OK files | `--quiet` | renamed | Same again: `clamscan` has three spellings for one setting. |
| `--bell` | Sound bell on detection | same spelling | same | |

### Temporary files and metadata

| `clamscan` | What it does | exav | Status | Notes |
|---|---|---|---|---|
| `--tempdir=DIR` | Create temporary files in DIR | `--spill-dir` | renamed | exav's temporary files follow `TMPDIR` unless `--spill-dir` names somewhere else; `--spill-dir off` writes none at all. |
| `--leave-temps[=yes/no]` | Keep temporary files | — | absent | |
| `--force-to-disk[=yes/no]` | Spill nested scans to disk | — | absent | exav streams nested members rather than materializing them; `--max-object-bytes` bounds what it does materialize. A *streamed* object (`INSTREAM`, stdin, an ICAP body) does spill, and `--spill-dir` / `--spill-threshold-bytes` govern that. |
| `--gen-json[=yes/no]` | JSON scan metadata (testing) | — | absent | exav's `--json` is a different thing: newline-delimited scan *results*, not engine metadata. |

### Databases

| `clamscan` | What it does | exav | Status | Notes |
|---|---|---|---|---|
| `--database=FILE/DIR`, `-d` | Load database from FILE or DIR | same spelling | same | Also loads a prebuilt `.exavdb`. Distinct from `--sigs-dir`, which names the directory signatures *live in* and is written to. |
| `--official-db-only[=yes/no]` | Only load official signatures | — | absent | |
| `--fail-if-cvd-older-than=days` | Nonzero exit if database is stale | — | absent | |
| `--log=FILE`, `-l` | Save scan report to FILE | `--log` | same | The long spelling matches; **`-l` is absent**. |

### Targets, recursion and filters

| `clamscan` | What it does | exav | Status | Notes |
|---|---|---|---|---|
| `--recursive[=yes/no]`, `-r` | Scan subdirectories recursively | *(the default)* | differs | exav recurses into a named directory with no flag; `--no-recursive` is the opt-out. A directory scanned one level deep is a result that reads as clean — the files never opened look, in the output, exactly like files that were fine. |
| `--allmatch[=yes/no]`, `-z` | Keep scanning after a match | `--all-matches` | renamed | **`-z` is absent.** |
| `--cross-fs[=yes/no]` | Scan across filesystems | — | absent | exav's walk descends across mount points, matching `clamscan`'s default; the `=no` setting has no equivalent. |
| `--follow-dir-symlinks[=0/1/2]` | Follow directory symlinks | — | absent | exav follows a symlink named directly on the command line and does not descend into one found inside a tree — `clamscan`'s default (`1`). Modes `0` and `2` have no equivalent. |
| `--follow-file-symlinks[=0/1/2]` | Follow file symlinks | — | absent | Same default behaviour, same lack of a knob. A symlink found inside a directory is skipped by both; `clamscan` prints a `<path>: Symbolic link` line for it and exav passes over it in silence. |
| `--file-list=FILE`, `-f` | Scan files listed in FILE | `--files-from` | renamed | The spelling `xargs`, `tar`, `rsync` and `du` all use for the same idea. exav also skips blank lines and `#` comments, and merges the list with paths on the command line. **`-f` is absent.** |
| `--exclude=REGEX` | Skip file names matching REGEX | same spelling | same | Unanchored match against the whole path in both. Repeatable in exav. |
| `--exclude-dir=REGEX` | Skip directories matching REGEX | same spelling | same | Repeatable in exav; the directory is pruned before descent. |
| `--include=REGEX` | Only scan names matching REGEX | same spelling | same | Repeatable in exav. |
| `--include-dir=REGEX` | Only scan directories matching REGEX | — | absent | |

### Quarantine actions

| `clamscan` | What it does | exav | Status | Notes |
|---|---|---|---|---|
| `--remove[=yes/no]` | Delete infected files | — | absent | [Out of scope by design](/project/comparison-with-clamav/#out-of-scope-for-now): exav reports, your script acts. Exit codes are `clamscan`-compatible. |
| `--move=DIRECTORY` | Move infected files | — | absent | Same. |
| `--copy=DIRECTORY` | Copy infected files | — | absent | Same. |

### Bytecode, statistics and PUA

| `clamscan` | What it does | exav | Status | Notes |
|---|---|---|---|---|
| `--bytecode[=yes/no]` | Load bytecode from the database | — | absent | exav always loads and runs `.cbc` programs; there is no switch to disable them. |
| `--bytecode-unsigned[=yes/no]` | Load unsigned bytecode | — | absent | exav performs no bytecode signature check, so its behaviour is `clamscan --bytecode-unsigned=yes` with no way to tighten it. See [the gaps below](#gaps-this-matrix-surfaces). |
| `--bytecode-timeout=N` | Bytecode timeout (ms) | — | absent | |
| `--statistics[=none/bytecode/pcre]` | Print execution statistics | `--profile` | renamed | A different measurement: a per-matcher timing breakdown. Scanning files it is a CSV row per file; on a listener the same numbers come back through `STATS` as `MATCHERSTATS`. One flag, because which of those happens is a property of what exav was asked to do. |
| `--detect-pua[=yes/no]` | Detect Possibly Unwanted Applications | `--detect pua` | renamed | Loads `.??u` databases and keeps `PUA.*` names. Off by default in both. |
| `--exclude-pua=CAT` | Skip PUA signatures of category CAT | — | absent | PUA is all-or-nothing in exav. |
| `--include-pua=CAT` | Load PUA signatures of category CAT | — | absent | Same. |

### Structured data (DLP)

| `clamscan` | What it does | exav | Status | Notes |
|---|---|---|---|---|
| `--detect-structured[=yes/no]` | Detect SSNs / credit-card numbers | — | absent | exav turns the heuristic on by giving it a threshold — set `--alert-credit-cards` or `--alert-ssns`. A separate on/off switch beside a threshold is a second way to say the same thing. |
| `--structured-ssn-format=X` | SSN format (normal / stripped / both) | — | absent | |
| `--structured-ssn-count=N` | Minimum SSN count to alert | `--alert-ssns` | renamed | Needs a build with the `dlp` feature (on by default). Named `--alert-` rather than `--detect` because what it finds is the organisation's own data on its way somewhere, not malware. |
| `--structured-cc-count=N` | Minimum credit-card count to alert | `--alert-credit-cards` | renamed | Same feature note. |
| `--structured-cc-mode=X` | Credit-card mode | — | absent | |

### Parser toggles

`clamscan` can switch any single parser off. exav has no equivalent for any of
them — every parser it implements is always on.

| `clamscan` | What it does | exav | Status |
|---|---|---|---|
| `--scan-mail[=yes/no]` | Scan mail files | — | absent |
| `--phishing-sigs[=yes/no]` | Signature-based phishing detection | — | absent |
| `--phishing-scan-urls[=yes/no]` | URL signature phishing detection | — | absent |
| `--heuristic-alerts[=yes/no]` | Heuristic alerts | — | absent |
| `--heuristic-scan-precedence[=yes/no]` | Stop at the first heuristic match | — | absent |
| `--normalize[=yes/no]` | Normalize HTML, script and text | — | absent |
| `--scan-pe[=yes/no]` | Scan PE files | — | absent |
| `--scan-elf[=yes/no]` | Scan ELF files | — | absent |
| `--scan-ole2[=yes/no]` | Scan OLE2 containers | — | absent |
| `--scan-pdf[=yes/no]` | Scan PDF files | — | absent |
| `--scan-swf[=yes/no]` | Scan SWF files | — | absent |
| `--scan-html[=yes/no]` | Scan HTML files | — | absent |
| `--scan-xmldocs[=yes/no]` | Scan XML-based documents | — | absent |
| `--scan-hwp3[=yes/no]` | Scan HWP3 files | — | absent |
| `--scan-onenote[=yes/no]` | Scan OneNote files | — | absent |
| `--scan-archive[=yes/no]` | Scan archives | — | absent |
| `--scan-image[=yes/no]` | Scan graphics files | — | absent |
| `--scan-image-fuzzy-hash[=yes/no]` | Image fuzzy hashing | — | absent |

A migrating configuration that switched a parser off changes meaning under exav:
the parser runs. Since every one of these is **absent** rather than ignored, the
command line fails and the change is visible rather than silent.

### Alerts

ClamAV has a boolean per condition. exav has two dials: **`--detect`** says what
to look for, and **`--not-scanned`** says what becomes of an object it could
not fully examine. A boolean each cannot express "all of them" without the reader
knowing the whole set, and spreading one condition over several switches lets a
command line ask for two answers at once.

| `clamscan` | What it does | exav | Status | Notes |
|---|---|---|---|---|
| `--alert-broken[=yes/no]` | Alert on broken PE/ELF | `--detect broken` | renamed | exav also covers Mach-O. |
| `--alert-broken-media[=yes/no]` | Alert on broken JPEG/TIFF/PNG/GIF | `--detect broken-media` | renamed | |
| `--alert-encrypted[=yes/no]` | Alert on encrypted archives and documents | `--not-scanned password-protected=alert` | differs | exav reports an encrypted member as `PASSWORD-PROTECTED` **by default** (ClamAV returns a clean `OK`). `alert` converts that verdict into a `Heuristics.Encrypted.*` detection — a verdict question, which is why it is not under `--detect`. |
| `--alert-encrypted-archive[=yes/no]` | Alert on encrypted archives only | — | absent | The one policy covers archives and documents together. |
| `--alert-encrypted-doc[=yes/no]` | Alert on encrypted documents only | — | absent | Same. |
| `--alert-macros[=yes/no]` | Alert on VBA macros in OLE2 | `--detect macros` | renamed | exav also raises it for XLM and OOXML. |
| `--alert-exceeds-max[=yes/no]` | Alert on files exceeding a limit | `--not-scanned limits-exceeded=alert` | differs | exav reports a limit stop as `LIMITS-EXCEEDED` (exit 2) **by default** rather than as clean. `alert` converts it into a `Heuristics.Limits.Exceeded.*` detection, which is the form a ClamAV-shaped pipeline expects. |
| `--alert-phishing-ssl[=yes/no]` | Alert on SSL mismatches in email URLs | `--detect phishing` | renamed | Raises `Heuristics.Phishing.Email.SSL-Spoof` among others; there is no per-check switch. |
| `--alert-phishing-cloak[=yes/no]` | Alert on cloaked URLs in email | `--detect phishing` | renamed | Same one detector. |
| `--alert-partition-intersection[=yes/no]` | Alert on overlapping DMG partitions | `--detect partition-intersection` | renamed | exav also covers GPT, APM and MBR. |
| `--nocerts` | Disable Authenticode chain verification | — | absent | exav's Authenticode handling is parse- and blocklist-only, so there is no chain verification to disable. |
| `--dumpcerts` | Dump the Authenticode chain | — | absent | |

### Limits

| `clamscan` | What it does | exav | Status | Notes |
|---|---|---|---|---|
| `--max-scantime=#n` | Skip a scan longer than this (ms) | `--max-scan-secs` | differs | Seconds, Unix only, and a kernel-enforced wall-clock plus CPU budget per job rather than an in-engine check. Different unit and different mechanism. |
| `--max-filesize=#n` | Skip files larger than this | `--max-input-bytes` | renamed | exav's default is **no limit**; ClamAV's is 100M. `--clamav-compat` sets 100M. Over the limit exav reports `LIMITS-EXCEEDED`, never a clean `OK`. |
| `--max-scansize=#n` | Max data scanned per container | `--max-extracted-bytes` | renamed | exav's defaults are 256M deep-analysis / 1G extracted total; ClamAV's is 400M. `--clamav-compat` sets 400M for both. |
| `--max-files=#n` | Max files scanned per container | `--max-members` | renamed | exav's default is 100000 against ClamAV's 10000, because exav descends into nested archives ClamAV does not and so counts more members for the same file. `--clamav-compat` sets 10000. |
| `--max-recursion=#n` | Max archive recursion depth | `--max-depth` | renamed | Different default too: exav 16, ClamAV 17. `--clamav-compat` sets 17. |
| `--max-dir-recursion=#n` | Max directory recursion depth | — | absent | exav's directory walk has no depth cap. |
| `--max-embeddedpe=#n` | Max size checked for an embedded PE | — | absent | exav applies its global budgets instead of a per-subsystem cap. |
| `--max-htmlnormalize=#n` | Max HTML size to normalize | — | absent | Same. |
| `--max-htmlnotags=#n` | Max normalized-HTML size to scan | — | absent | Same. |
| `--max-scriptnormalize=#n` | Max script size to normalize | — | absent | Same. |
| `--max-ziptypercg=#n` | Max ZIP size to re-type | — | absent | Same. |
| `--max-partitions=#n` | Max partitions per disk image | — | absent | Same. |
| `--max-iconspe=#n` | Max icons per PE | — | absent | Same. |
| `--max-rechwp3=#n` | Max HWP3 parse recursion | — | absent | Same. |
| `--pcre-match-limit=#n` | Max PCRE match calls | — | absent | exav's PCRE path has a bounded backtrack budget that is not operator-tunable. |
| `--pcre-recmatch-limit=#n` | Max recursive PCRE match calls | — | absent | Same. |
| `--pcre-max-filesize=#n` | Max file size for PCRE subsignatures | — | absent | Same. |
| `--disable-cache` | Disable the clean-file hash cache | — | absent | exav has no scan cache, so there is nothing to disable. |

## `clamd`

`clamd` takes almost no command-line configuration: it reads
`/etc/clamav/clamd.conf` and everything operational lives there.

**exav does not read `clamd.conf`, and has no `--config-file`.** It is
configured with CLI flags and environment variables — see
[Configuration](/reference/configuration/). Translating the config once is the
deliberate trade against silently half-honouring a file: ignoring a tuning
directive costs performance, but ignoring `ExcludePath` or `OnAccessPrevention`
changes what an operator believes is running.

The wire protocol is a different matter and *is* compatible — see the
[daemon guide](/guides/daemon/). Existing clients keep working; the startup
configuration is what you rewrite.

### `clamd` command-line flags

| `clamd` | What it does | exav | Status | Notes |
|---|---|---|---|---|
| `--help`, `-h` | Show help | same spelling | same | |
| `--version`, `-V` | Print version | same spelling | same | |
| `--foreground`, `-F` | Do not daemonize | — | absent | exav's daemon always runs in the foreground; run it under systemd, a supervisor or `&`. |
| `--debug` | Enable debug mode | — | absent | |
| `--config-file=FILE`, `-c` | Read configuration from FILE | — | absent | exav reads no configuration file. |
| `--fail-if-cvd-older-than=days` | Nonzero exit on a stale database | — | absent | |
| `--datadir=DIRECTORY` | Load signatures from DIRECTORY | `-d` / `--sigs-dir` | renamed | Different spelling, same job. `--sigs-dir` defaults to `/var/lib/exav`. |
| `--pid=FILE`, `-p` | Write the pid to FILE | — | absent | Use the supervisor's own pid tracking. |

### `clamd.conf` directives

Every row below is a `clamd.conf` directive, so every row is **absent** as a
directive — the file is not read. The `exav` column gives the flag or
environment variable that does the same job where one exists, and `—` where
nothing does.

#### Sockets and process

| Directive | What it does | exav equivalent | Notes |
|---|---|---|---|
| `LocalSocket` | Unix socket path to listen on | `--listen PATH` | A leading `/` is a socket path; the protocol defaults to `clamd`. |
| `LocalSocketGroup` | Group owning the socket | — | The socket takes the daemon's own primary group; set that in the service unit (`Group=`) and pair it with `?mode=660`. |
| `LocalSocketMode` | Socket permission bits | `--listen 'clamd:///path?mode=660'` | Same octal values, carried by the address because they are a property of *that* socket. exav's default is **0600** where clamd's is whatever the umask leaves (`Default: disabled (socket is world accessible)`), so widening it is explicit. The socket is created with no permissions and given the mode before it can be reached, so it never exists more open than asked for. |
| `FixStaleSocket` | Remove a leftover socket at startup | default | exav removes a stale socket before binding. |
| `TCPSocket` | TCP port to listen on | `--listen ADDR` | One value carries protocol, host and port. |
| `TCPAddr` | Address to bind | `--listen ADDR` | |
| `MaxConnectionQueueLength` | Listen backlog | `?max-connections=` on the address | Concurrent connections rather than a backlog. Default 128; the same option bounds an `icap://` listener, which is why it lives on the address rather than in a per-protocol flag. Read only under `--workers threads` — the prefork pool bounds concurrency by its worker count. |
| `MaxThreads` | Worker thread count | `--workers N` | exav's default is one prefork **process** per CPU core; `--workers threads` selects the in-process thread model. |
| `MaxQueue` | Max queued scan jobs | — | |
| `IdleTimeout` | Idle thread timeout | — | |
| `ReadTimeout` | Per-read socket timeout | — | Fixed at 60 s on the clamd listener. (ICAP's is `--icap-idle-secs`.) |
| `CommandReadTimeout` | Command read timeout | — | Same 60 s. |
| `SendBufTimeout` | Send-buffer timeout | — | |
| `Foreground` | Do not daemonize | default | exav always runs in the foreground. |
| `User` | Drop privileges to this user | — | Set the user in the service unit. |
| `PidFile` | Write the pid here | — | |
| `ExitOnOOM` | Exit when out of memory | — | `--max-process-bytes` caps a worker's address space instead, and the pool restarts the worker. |
| `SelfCheck` | Database freshness check interval | — | The daemon hot-reloads when the signature source changes on disk, and `--auto-update` adds the scheduled re-fetch that changes it. |
| `ConcurrentDatabaseReload` | Reload without pausing scans | default | exav reloads into a new database and swaps it in. |

#### Logging

| Directive | What it does | exav equivalent | Notes |
|---|---|---|---|
| `LogFile` | Scan/status log path | `--log FILE` | Scan results only, one line per scan the daemon answers, under the daemon's own view of the target (`stream:` for `INSTREAM`, `fd:` for `FILDES`). clamd's log also carries startup, connection and reload lines; exav writes those to stderr for the supervisor to route. |
| `LogFileMaxSize` | Rotate at this size | — | |
| `LogFileUnlock` | Do not lock the log | — | |
| `LogRotate` | Rotate the log | — | |
| `LogTime` | Timestamp log lines | — | |
| `LogClean` | Log clean files too | — | |
| `LogSyslog` | Log to syslog | — | exav writes to stdout/stderr; the supervisor routes it. |
| `LogFacility` | Syslog facility | — | |
| `LogVerbose` | Verbose logging | — | |
| `ExtendedDetectionInfo` | Log extra detection detail | — | |
| `Debug` | Enable debug output | — | |

#### Database

| Directive | What it does | exav equivalent | Notes |
|---|---|---|---|
| `DatabaseDirectory` | Where signatures live | `-d` / `--sigs-dir DIR` | |
| `OfficialDatabaseOnly` | Load only official signatures | — | |
| `FailIfCvdOlderThan` | Refuse a stale database | — | |
| `DetectPUA` | Detect potentially unwanted applications | `--detect pua` | |
| `ExcludePUA` / `IncludePUA` | PUA category filters | — | PUA is all-or-nothing in exav. |

#### Scan limits

| Directive | What it does | exav equivalent | Notes |
|---|---|---|---|
| `MaxScanSize` | Max data scanned per container | `--max-extracted-bytes` | |
| `MaxFileSize` | Max file size scanned | `--max-input-bytes` | |
| `MaxRecursion` | Max archive recursion | `--max-depth` | |
| `MaxFiles` | Max files per container | `--max-members` | |
| `MaxScanTime` | Max scan time | `--max-scan-secs` | Kernel-enforced per job (seconds, Unix), not an in-engine check. |
| `MaxDirectoryRecursion` | Max directory depth | — | |
| `MaxEmbeddedPE`, `MaxHTMLNormalize`, `MaxHTMLNoTags`, `MaxScriptNormalize`, `MaxZipTypeRcg`, `MaxPartitions`, `MaxIconsPE`, `MaxRecHWP3` | Per-subsystem caps | — | exav applies its global budgets instead. |
| `PCREMatchLimit`, `PCRERecMatchLimit`, `PCREMaxFileSize` | PCRE bounds | — | Bounded internally, not tunable. |
| `StreamMaxLength` | Max `INSTREAM` upload | `--max-input-bytes`, `--max-spill-bytes` | clamd defaults to 25M and refuses more; exav has **no default scan limit** on a stream. `--max-spill-bytes` (2G) bounds the temp space one streamed object may occupy, which is the closest thing to a per-upload ceiling. Set `--max-input-bytes` if a client relied on the daemon to bound its uploads. |
| `StreamMinPort` / `StreamMaxPort` | Legacy `STREAM` port range | — | The `STREAM` command is removed from ClamAV too. |
| `CacheSize` / `DisableCache` | Clean-file hash cache | — | exav has no scan cache. |

#### Parser and alert toggles

| Directive | What it does | exav equivalent | Notes |
|---|---|---|---|
| `ScanPE`, `ScanELF`, `ScanOLE2`, `ScanPDF`, `ScanSWF`, `ScanHTML`, `ScanXMLDOCS`, `ScanHWP3`, `ScanOneNote`, `ScanMail`, `ScanArchive`, `ScanImage`, `ScanImageFuzzyHash` | Switch one parser off | — | Every parser exav implements is always on. |
| `ScanPartialMessages` | Reassemble partial mail messages | — | |
| `PhishingSignatures`, `PhishingScanURLs` | Phishing detection | — | |
| `HeuristicAlerts`, `HeuristicScanPrecedence` | Heuristic policy | — | |
| `AlertBrokenExecutables` | Alert on broken PE/ELF | `--detect broken` | |
| `AlertBrokenMedia` | Alert on broken graphics | `--detect broken-media` | |
| `AlertEncrypted` | Alert on encrypted content | `--not-scanned password-protected=alert` | exav reports encrypted members as `PASSWORD-PROTECTED` without it. |
| `AlertEncryptedArchive` / `AlertEncryptedDoc` | Split encrypted alerts | `--not-scanned password-protected=alert` | One policy covers both. |
| `AlertOLE2Macros` | Alert on VBA macros | `--detect macros` | |
| `AlertExceedsMax` | Alert on a limit stop | `--not-scanned limits-exceeded=alert` | exav reports `LIMITS-EXCEEDED` without it. |
| `AlertPartitionIntersection` | Alert on overlapping partitions | `--detect partition-intersection` | |
| `AlertPhishingSSLMismatch` / `AlertPhishingCloak` | Phishing alert detail | `--detect phishing` | One detector, no per-check switch. |
| `StructuredDataDetection` | Enable DLP detection | `--alert-credit-cards` / `--alert-ssns` | Giving a threshold enables it. |
| `StructuredMinCreditCardCount` | Credit-card threshold | `--alert-credit-cards` | |
| `StructuredMinSSNCount` | SSN threshold | `--alert-ssns` | |
| `StructuredCCOnly`, `StructuredSSNFormatNormal`, `StructuredSSNFormatStripped` | DLP format policy | — | |
| `DisableCertCheck` | Skip Authenticode verification | — | exav's Authenticode handling is parse- and blocklist-only. |
| `CrossFilesystems` | Scan across mount points | — | exav's walk crosses them, matching clamd's default. |
| `FollowDirectorySymlinks` / `FollowFileSymlinks` | Symlink policy | — | exav matches clamd's default (follow a directly-named link, do not descend into one found in a tree). |
| `ExcludePath` | Skip paths matching a regex | `--exclude` / `--exclude-dir` | |
| `Bytecode` | Run bytecode signatures | — | Always on in exav. |
| `BytecodeSecurity` | Bytecode trust level | — | |
| `BytecodeUnsigned` | Allow unsigned bytecode | — | exav performs no bytecode signature check. |
| `AllowAllMatchScan` | Permit `ALLMATCHSCAN` | default | Always permitted in exav. |
| `TemporaryDirectory` | Where temporary files go | `--spill-dir` | Defaults to `TMPDIR`; `--spill-dir off` writes none at all. |
| `ForceToDisk`, `LeaveTemporaryFiles` | Temporary-file policy | — | exav spills a streamed object past `--spill-threshold-bytes` and deletes it when the scan ends. |
| `GenerateMetadataJson` | Emit engine metadata JSON | — | `--json` emits scan results, a different thing. |

#### Not implemented at all

| Directive group | What it does | exav |
|---|---|---|
| `OnAccessMountPath`, `OnAccessIncludePath`, `OnAccessExcludePath`, `OnAccessExcludeUID`, `OnAccessExcludeUname`, `OnAccessExcludeRootUID`, `OnAccessMaxFileSize`, `OnAccessMaxThreads`, `OnAccessDisableDDD`, `OnAccessPrevention`, `OnAccessExtraScanning`, `OnAccessDenyOnError`, `OnAccessRetryAttempts` | Real-time on-access scanning (fanotify) | Not supported. Keep ClamAV if you depend on it — this is the one area where partial support would be dangerous. |
| `VirusEvent` | Run a command on detection | Not supported. Drive it from the daemon's reply or the scan output. |
| `PreludeEnable`, `PreludeAnalyzerName` | Prelude SIEM integration | Not supported. |

## `clamdscan`

exav acts as a daemon client when given `--connect` together with paths.

| `clamdscan` | What it does | exav | Status | Notes |
|---|---|---|---|---|
| `--help`, `-h` | Show help | same spelling | same | |
| `--version`, `-V` | Print version | same spelling | same | Answered locally, not by the daemon. |
| `--verbose`, `-v` | Be verbose | `--verbose` | differs | `clamdscan -v` prints nothing a plain run does not. exav's names the daemon that answered and the command sent per target (`  [daemon] unix:… ClamAV …`, `  [SCAN] /abs/path`). The informational findings `-v` adds to a local scan come from the scanner, and a daemon reply carries only a verdict. |
| `--quiet` | Only output error messages | `--quiet` | differs | Same difference as the scanner: exav still prints detections. |
| `--stdout` | Write to stdout instead of stderr | — | absent | exav already writes results to stdout. |
| `--log=FILE`, `-l` | Save scan report to FILE | `--log` | same | Client replies are mirrored into the log. **`-l` is absent.** |
| `--file-list=FILE`, `-f` | Scan files listed in FILE | `--files-from` | renamed | **`-f` is absent.** |
| `--ping`, `-p A[:I]` | Ping the daemon until it answers | — | absent | The daemon answers `PING` on the wire; there is no client flag to send one. |
| `--wait`, `-w` | Wait for the daemon to start | — | absent | |
| `--remove` | Delete infected files | — | absent | Out of scope by design. |
| `--move=DIRECTORY` | Move infected files | — | absent | Same. |
| `--copy=DIRECTORY` | Copy infected files | — | absent | Same. |
| `--config-file=FILE`, `-c` | Read configuration from FILE | — | absent | exav reads no configuration file; name the daemon with `--connect`. |
| `--allmatch`, `-z` | Keep scanning after a match | `--all-matches` | renamed | Sends `ALLMATCHSCAN`. **`-z` is absent**, and it cannot be combined with `--send-as contents`/`fd`: one `INSTREAM` gets one verdict back, so an all-match scan is not expressible over them. |
| `--multiscan`, `-m` | Force `MULTISCAN` mode | — | absent | exav's client sends one `SCAN` per file inside an `IDSESSION`. The daemon answers `MULTISCAN` on the wire. |
| `--infected`, `-i` | Only print infected files | `--quiet` | renamed | |
| `--no-summary` | No summary at end | `--quiet` | renamed | Same dial. |
| `--reload` | Ask the daemon to reload | — | absent | The daemon answers `RELOAD` on the wire; no client flag sends it. |
| `--fdpass` | Pass a file descriptor to the daemon | `--send-as fd` | renamed | Same `FILDES`/`SCM_RIGHTS` request. Over a TCP `--connect` exav **refuses** it: a descriptor cannot cross a TCP connection, and `clamdscan` silently sends the path instead — which scans whatever that path holds on the daemon's host. |
| `--stream` | Stream file contents to the daemon | `--send-as contents` | renamed | Same `INSTREAM` request, reported under the local name. One dial instead of two switches: the three transports are alternatives, so as switches every pair had to be refused and none could name the default (`--send-as path`). |
| `-` (stdin) | Scan standard input | `-` | differs | Both stream it. exav reports it as `stdin`, the name a local `exav -` uses, where `clamdscan` prints the daemon's own `stream:` (or `fd:`, when stdin is a regular file it can pass by descriptor). |

Two client-mode behaviours have no flag to name them:

- **Directories always recurse.** `clamdscan` has no `-r`: it hands the
  directory to the daemon, which walks it. exav walks it client-side instead and
  sends one `SCAN` per file, so `--exclude` / `--include` apply to the tree and
  every command has one reply to read. A directory holding the parts of a
  byte-split archive goes over whole as one `CONTSCAN`, because rejoining the
  parts takes the daemon that holds the database.
- **The name in a result line.** By path, exav reports the absolute path it
  sent, as `clamdscan` does. By content (`--send-as contents`/`fd`), it reports
  the path as it was written on the command line, where `clamdscan` resolves it.

## exav flags with no ClamAV counterpart

| exav flag | What it does |
|---|---|
| `--sigs-dir <DIR>` | The directory signatures live in and `--auto-update` writes to (default `/var/lib/exav`). |
| `--sig-sources <URL\|FILE>` | Where `--auto-update` fetches from: exact URLs, mirror bases (trailing `/`), or a file of either — which may be a `freshclam.conf`. |
| `--db-url <URL>` | A prebuilt `.exavdb` to pull and serve instead of signature files. |
| `--build-db <FILE>` | Compile the loaded signatures into a prebuilt `.exavdb` and exit. |
| `--build-shard-bytes <SIZE>` | Cap the per-shard automaton-build transient during `--build-db`. |
| `--listen <ADDR>` | Serve on this address. `clamd://` and `icap://`; naming both serves both from one process over one database. |
| `--connect <ADDR>` | Scan by handing each file to a daemon already running here. |
| `--send-as <WHAT>` | What that client hands over: `path`, `contents` or `fd`. |
| `--auto-update` | Bootstrap, refresh and hot-reload the signature source for as long as the process runs. With no `--listen` and no paths it is an updater and nothing else. |
| `--startup-wait-secs <SECS>` | How long to wait for a sidecar to populate an empty signature directory. |
| `--update-interval-secs <SECS>` | Seconds between signature source re-checks. |
| `--allow-no-db` | Run against the built-in EICAR-only baseline instead of refusing. Testing only. |
| `--workers <N\|threads>` | Prefork worker processes, or the in-process thread model. |
| `--max-jobs-per-worker <N>` | Recycle a worker process after this many jobs. |
| `--max-process-bytes <SIZE>` | Per-worker address-space cap (`RLIMIT_AS`). |
| `--allow-shutdown` | Honour the clamd `SHUTDOWN` command. Off by default — a scanner that is not running reports nothing, and a pipeline that reads no answer as a clean one passes everything. |
| `--max-object-bytes <SIZE>` | The most memory a single materialized object may use. |
| `--max-matcher-bytes <SIZE>` | Cumulative bytes fed to the matcher — a CPU bound, not a memory one. |
| `--spill-dir`, `--spill-threshold-bytes`, `--max-spill-bytes`, `--max-total-spill-bytes` | Where a streamed object waits while it is scanned, and how much RAM and temp space it may take. |
| `--not-scanned <POLICY>` | What becomes of an object exav could not fully examine: `block`, `alert` or `pass`, whole or per condition. |
| `--clamav-compat` | Preset reproducing a stock ClamAV build's limits and extractor set, for differential testing. Reduces detection on purpose. |
| `--base64 on\|off` | Decode base64-embedded executables in text and script files. On by default. |
| `--detect packed` | Report `Heuristics.Packed.*`, naming the packer wrapping an executable exav could not unpack. |
| `--detect phishing` | Report `Heuristics.Phishing.Email.*` for display-versus-href link spoofing. Covers the checks ClamAV splits across `--alert-phishing-ssl` and `--alert-phishing-cloak`. |
| `--detect heuristics` | Enable exav-exclusive structural / fuzzy / ML analysis. |
| `--passwords <PW>` | Password to try for encrypted members. Repeatable. |
| `--json` | Newline-delimited JSON results, one object per input plus a summary. |
| `--profile` | Per-matcher timing breakdown: a CSV row per file when scanning, `MATCHERSTATS` through `STATS` on a listener. |
| `--slow-scan-secs <SECS\|off>` | Log any scan taking longer, naming the object. |
| `--metrics-secs <SECS\|off>` | Seconds between a listener's scan-totals log lines. |
| `--icap-*` | The ICAP listener's settings — service names, preview, keep-alive, the `X-Infection-Found` policy. See the [ICAP guide](/guides/icap/). |

## Gaps this matrix surfaces

The rows worth acting on before a migration, rather than reading past:

- **No bytecode signature check.** exav loads and runs `.cbc` programs without
  verifying who signed them, which is ClamAV's `--bytecode-unsigned=yes`
  behaviour with no way to tighten it. Load bytecode only from sources you trust.
- **`INSTREAM` has no default size limit.** clamd caps a stream at
  `StreamMaxLength` (25M) and refuses more. exav bounds the *temp space* one
  streamed object may take (`--max-spill-bytes`, 2G) rather than the scan; set
  `--max-input-bytes` if a client relied on the daemon to bound its uploads.
- **The daemon's socket is 0600 unless you widen it.** A `clamd.conf` carrying
  `LocalSocketMode 660` becomes `--listen 'clamd:///path?mode=660'`, and the
  socket takes the daemon's own group, so the group the clients share is the
  one the service unit has to run under. Left at the default, a client under
  another UID gets `Permission denied`.
- **`--quiet` still prints detections.** A script that used `clamscan --quiet`
  to get silence on a clean tree gets output on a dirty one.
- **Every parser toggle is absent.** A configuration that switched a parser off
  cannot be expressed. The command line fails rather than scanning more than the
  operator asked for, so this surfaces immediately.
- **`--multiscan`, `--ping`, `--wait` and `--reload` are absent in the client.**
  The daemon answers `MULTISCAN`, `PING` and `RELOAD` on the wire, so a clamd
  client keeps working; it is exav's own client that has no flag to send them. A
  script built around `clamdscan --ping 1` as a health check needs another way
  to ask (`socat`, or the daemon's exit code on startup).
- **`--send-as fd` over a TCP `--connect` is refused, not degraded.** `clamdscan`
  accepts the equivalent combination and silently sends the path instead, so the
  daemon scans whatever that path holds on its own host. exav stops and says to
  use `--send-as contents`.
- **Every limit flag is renamed.** No `clamscan` spelling is accepted as a hidden
  alias, so a migrated command line carrying `--max-filesize` stops rather than
  scanning under a bound nobody set. The rename is mechanical and the error names
  a near match; the table above is the mapping.

## Sources

ClamAV's side of the `clamscan` and `clamdscan` tables is the `--help` output of
a locally installed **ClamAV 1.4.3**, with the behavioural rows run: `clamscan`
against the same trees as exav, and `clamdscan` against **exav's own daemon**
(`clamdscan -c <conf> --stream | --fdpass | -`), which speaks the protocol it
expects. `clamd`'s flags come from the `clamd.8` manual page and the directives
from `clamd.conf.sample`, both from the upstream `rel/1.4` branch, since no
`clamd` binary was installed to interrogate — every claim about a `clamd.conf`
directive's own behaviour is read from those, not run.

exav's side is read from the clap definitions in the `exav` crate and checked by
running the built binary against each flag.
