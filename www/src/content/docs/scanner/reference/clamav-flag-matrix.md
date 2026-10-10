---
title: ClamAV flag matrix
description: Every clamscan, clamd and clamdscan flag against exav's equivalent, with what is accepted, renamed, different, or not supported.
---

A row-by-row comparison of ClamAV's command-line surface against exav's, to check
a command line before swapping a binary. The rest of the migration (signatures,
sockets, service units) is in [Migrating from ClamAV](/scanner/guides/migrating-from-clamav/),
and exav's own flags are in the [CLI reference](/scanner/reference/cli/).

## How to read this

One binary plays all three parts, and the flags pick which, so the rows below
apply to a command line that already starts with `exav`:

| ClamAV binary | exav invocation | Selected by |
|---|---|---|
| `clamscan` | `exav PATH…` | paths, neither `--listen` nor `--connect` |
| `clamd` | `exav --listen ADDR` | `--listen` |
| `clamdscan` | `exav --connect ADDR PATH…` | `--connect` **and** paths |

exav does not dispatch on the name it was invoked under, so an existing
`clamscan` / `clamdscan` command line gets there through a wrapper script (see
[One binary, three roles](/scanner/guides/migrating-from-clamav/#one-binary-three-roles)).

| Status | Meaning |
|---|---|
| **same** | exav accepts the same spelling and does the same thing. |
| **renamed** | exav has the capability under a different name. The exav column gives it. |
| **differs** | Accepted, behaviour deliberately different. The Notes column says how. |
| **absent** | Not accepted. exav exits **2** with a parse error naming the flag. |

exav's flags are its own, and an unsupported flag stops the run at startup
instead of being swallowed, so a migration finds these on the first run. There
are no hidden aliases: a **renamed** row means the old spelling is refused and
the error names exav's.

### The `=yes` / `=no` value form

`clamscan` spells most switches `--flag[=yes/no]`. exav's switches are bare:
`--all-matches` is accepted, `--all-matches=yes` is not. Drop the value when
translating; a switch is on when given and off when omitted. Settings that are on
by default come as a pair of lists instead (`--decode` / `--no-decode`), so an
explicit choice can beat the `--clamav-compat` preset either way.

## `clamscan`

Grouped in the order `clamscan --help` prints them.

### Output and reporting

| `clamscan` | What it does | exav | Status | Notes |
|---|---|---|---|---|
| `--help`, `-h` | Show help | same spelling | same | |
| `--version`, `-V` | Print version | same spelling | differs | Prints `exav <version>`, naming what is actually running. The `ClamAV <version>` string tooling looks for is what the **daemon** answers to the wire `VERSION` command, so `clamdtop` and clamd client libraries see the engine they expect; a script grepping `clamscan --version` for `ClamAV` does not. |
| `--verbose`, `-v` | Be verbose | same spelling | differs | exav prints per-file informational findings (the detected type, and with `--detect exav-heuristics` the imphash, entropy and static score) rather than progress chatter. |
| `--archive-verbose`, `-a` | Show filenames inside archives | none | absent | Member paths appear in the match location on a detection. |
| `--debug` | libclamav debug messages | none | absent | |
| `--quiet` | Only output error messages | `--quiet` | differs | exav still prints detection lines under `--quiet`; `clamscan` suppresses them too. exav's `--quiet` is the whole output dial: it drops the per-file `OK` lines *and* the summary. |
| `--stdout` | Write to stdout instead of stderr | none | absent | exav already writes `OK`, `FOUND` and `PARTIAL` lines to stdout, and only `ERROR` lines and diagnostics to stderr. |
| `--no-summary` | No summary at end | `--quiet` | renamed | `--quiet` suppresses the `OK` lines and the summary together. |
| `--infected`, `-i` | Only print infected files | `--quiet` | renamed | Same setting. |
| `--suppress-ok-results`, `-o` | Skip printing OK files | `--quiet` | renamed | Same setting. |
| `--bell` | Sound bell on detection | same spelling | same | |

### Temporary files and metadata

| `clamscan` | What it does | exav | Status | Notes |
|---|---|---|---|---|
| `--tempdir=DIR` | Create temporary files in DIR | `--spill-dir` | renamed | exav's temporary files follow `TMPDIR` unless `--spill-dir` names somewhere else; `--spill-dir off` writes none at all. |
| `--leave-temps[=yes/no]` | Keep temporary files | none | absent | |
| `--force-to-disk[=yes/no]` | Spill nested scans to disk | none | absent | A member that decodes past `--max-object-bytes` goes to a spill file, as a streamed object (`INSTREAM`, stdin, an ICAP body) does past `--spill-threshold-bytes`; both are deleted when the scan ends. `--spill-dir` says where, or `off` for never. |
| `--gen-json[=yes/no]` | JSON scan metadata (testing) | none | absent | exav's `--json` is a different thing: newline-delimited scan *results*, not engine metadata. |

### Databases

| `clamscan` | What it does | exav | Status | Notes |
|---|---|---|---|---|
| `--database=FILE/DIR`, `-d` | Load database from FILE or DIR | same spelling | same | Also loads a prebuilt `.exavdb`, named as a file. Replaces `--sig-dir`, the default directory, and is what `--auto-update` writes to when given. |
| `--official-db-only[=yes/no]` | Only load official signatures | none | absent | |
| `--fail-if-cvd-older-than=days` | Nonzero exit if database is stale | none | absent | |
| `--log=FILE`, `-l` | Save scan report to FILE | `--log` | differs | The long spelling matches; **`-l` is absent**. `clamscan` logs detections, warnings and the summary; exav logs every result line, `OK` included, and every error, but not the summary. |

### Targets, recursion and filters

| `clamscan` | What it does | exav | Status | Notes |
|---|---|---|---|---|
| `--recursive[=yes/no]`, `-r` | Scan subdirectories recursively | *(the default)* | absent | Refused with a hint: exav recurses into a named directory with no flag; `--no-recursive` is the opt-out. |
| `--allmatch[=yes/no]`, `-z` | Keep scanning after a match | `--all-matches` | renamed | **`-z` is absent.** |
| `--cross-fs[=yes/no]` | Scan across filesystems | none | absent | exav's walk descends across mount points, matching `clamscan`'s default; the `=no` setting has no equivalent. |
| `--follow-dir-symlinks[=0/1/2]` | Follow directory symlinks | none | absent | exav follows a symlink named directly on the command line and does not descend into one found inside a tree, `clamscan`'s default (`1`). Modes `0` and `2` have no equivalent. |
| `--follow-file-symlinks[=0/1/2]` | Follow file symlinks | none | absent | Same default behaviour, same lack of a knob. A symlink found inside a directory is skipped by both; `clamscan` prints a `<path>: Symbolic link` line for it and exav passes over it in silence. |
| `--file-list=FILE`, `-f` | Scan files listed in FILE | `--files-from` | renamed | The spelling `tar` and `rsync` use for the same idea. exav also skips blank lines and `#` comments, and merges the list with paths on the command line. **`-f` is absent.** |
| `--exclude=REGEX` | Skip file names matching REGEX | same spelling | same | Unanchored match against the whole path in both. Repeatable in exav. |
| `--exclude-dir=REGEX` | Skip directories matching REGEX | same spelling | same | Repeatable in exav; the directory is pruned before descent. |
| `--include=REGEX` | Only scan names matching REGEX | same spelling | same | Repeatable in exav. |
| `--include-dir=REGEX` | Only scan directories matching REGEX | none | absent | |

### Quarantine actions

| `clamscan` | What it does | exav | Status | Notes |
|---|---|---|---|---|
| `--remove[=yes/no]` | Delete infected files | none | absent | [Out of scope by design](/scanner/reference/comparison-with-clamav/#out-of-scope-for-now): exav reports, your script acts. Read the exit code. |
| `--move=DIRECTORY` | Move infected files | none | absent | Same. |
| `--copy=DIRECTORY` | Copy infected files | none | absent | Same. |

### Bytecode, statistics and PUA

| `clamscan` | What it does | exav | Status | Notes |
|---|---|---|---|---|
| `--bytecode[=yes/no]` | Load bytecode from the database | none | absent | exav always loads and runs `.cbc` programs; there is no switch to disable them. |
| `--bytecode-unsigned[=yes/no]` | Load unsigned bytecode | none | absent | exav performs no bytecode signature check, so its behaviour is `clamscan --bytecode-unsigned=yes` with no way to tighten it. See [the gaps below](#gaps-this-matrix-surfaces). |
| `--bytecode-timeout=N` | Bytecode timeout (ms) | none | absent | |
| `--statistics[=none/bytecode/pcre]` | Print execution statistics | `--profile` | renamed | A different measurement: a per-matcher timing breakdown. Scanning files it is a CSV row per file; on a listener the same numbers come back through `STATS` as `MATCHERSTATS`. One flag, because which of those happens is a property of what exav was asked to do. |
| `--detect-pua[=yes/no]` | Detect Possibly Unwanted Applications | `--detect pua` | renamed | Loads `.??u` databases and keeps `PUA.*` names. Off by default in both. |
| `--exclude-pua=CAT` | Skip PUA signatures of category CAT | none | absent | PUA is all-or-nothing in exav. |
| `--include-pua=CAT` | Load PUA signatures of category CAT | none | absent | Same. |

### Structured data (DLP)

| `clamscan` | What it does | exav | Status | Notes |
|---|---|---|---|---|
| `--detect-structured[=yes/no]` | Detect SSNs / credit-card numbers | none | absent | exav turns the heuristic on by giving it a threshold: set `--dlp-credit-cards` or `--dlp-ssns`. |
| `--structured-ssn-format=X` | SSN format (normal / stripped / both) | none | absent | |
| `--structured-ssn-count=N` | Minimum SSN count to alert | `--dlp-ssns` | renamed | Needs a build with the `dlp` feature (on by default). Named `--dlp-` rather than `--detect` because what it finds is the organisation's own data on its way somewhere, not malware. |
| `--structured-cc-count=N` | Minimum credit-card count to alert | `--dlp-credit-cards` | renamed | Same feature note. |
| `--structured-cc-mode=X` | Credit-card mode | none | absent | |

### Parser toggles

`clamscan` can switch any single parser off. exav has no equivalent: every parser
it implements is always on.

| `clamscan` | What it does | exav | Status |
|---|---|---|---|
| `--scan-mail[=yes/no]` | Scan mail files | none | absent |
| `--phishing-sigs[=yes/no]` | Signature-based phishing detection | none | absent |
| `--phishing-scan-urls[=yes/no]` | URL signature phishing detection | none | absent |
| `--heuristic-alerts[=yes/no]` | Heuristic alerts | none | absent |
| `--heuristic-scan-precedence[=yes/no]` | Stop at the first heuristic match | none | absent |
| `--normalize[=yes/no]` | Normalize HTML, script and text | none | absent |
| `--scan-pe[=yes/no]` | Scan PE files | none | absent |
| `--scan-elf[=yes/no]` | Scan ELF files | none | absent |
| `--scan-ole2[=yes/no]` | Scan OLE2 containers | none | absent |
| `--scan-pdf[=yes/no]` | Scan PDF files | none | absent |
| `--scan-swf[=yes/no]` | Scan SWF files | none | absent |
| `--scan-html[=yes/no]` | Scan HTML files | none | absent |
| `--scan-xmldocs[=yes/no]` | Scan XML-based documents | none | absent |
| `--scan-hwp3[=yes/no]` | Scan HWP3 files | none | absent |
| `--scan-onenote[=yes/no]` | Scan OneNote files | none | absent |
| `--scan-archive[=yes/no]` | Scan archives | none | absent |
| `--scan-image[=yes/no]` | Scan graphics files | none | absent |
| `--scan-image-fuzzy-hash[=yes/no]` | Image fuzzy hashing | none | absent |

A configuration that switched a parser off would change meaning under exav, so
these flags are refused and the change is visible.

### Alerts

ClamAV has a boolean per condition. exav has two settings: `--detect` says what
to look for, and `--partial-as` says what becomes of an object it could not fully
examine.

| `clamscan` | What it does | exav | Status | Notes |
|---|---|---|---|---|
| `--alert-broken[=yes/no]` | Alert on broken PE/ELF | `--detect broken` | renamed | Both cover Mach-O too, although clamscan's help says PE and ELF. |
| `--alert-broken-media[=yes/no]` | Alert on broken JPEG/TIFF/PNG/GIF | `--detect broken-media` | renamed | |
| `--alert-encrypted[=yes/no]` | Alert on encrypted archives and documents | `--partial-as password-protected=found` | renamed | exav reports an encrypted member it cannot decrypt as `PASSWORD-PROTECTED` **by default** (ClamAV returns a clean `OK`). `found` reports any encryption as a `Heuristics.Encrypted.*` detection, decrypted or not, as ClamAV does. |
| `--alert-encrypted-archive[=yes/no]` | Alert on encrypted archives only | `--partial-as password-protected=found` | renamed | The one policy covers archives and documents together. |
| `--alert-encrypted-doc[=yes/no]` | Alert on encrypted documents only | `--partial-as password-protected=found` | renamed | Same. |
| `--alert-macros[=yes/no]` | Alert on VBA macros in OLE2 | `--detect macros` | renamed | exav also raises it for XLM and OOXML. |
| `--alert-exceeds-max[=yes/no]` | Alert on files exceeding a limit | `--partial-as limits-exceeded=found` | renamed | exav reports a limit stop as `LIMITS-EXCEEDED` (status `PARTIAL`, exit 3) **by default** rather than as clean. `found` converts it into a `Heuristics.Limits.Exceeded.*` detection, which is the form a ClamAV-shaped pipeline expects. |
| `--alert-phishing-ssl[=yes/no]` | Alert on SSL mismatches in email URLs | `--detect phishing` | renamed | Raises `Heuristics.Phishing.Email.SSL-Spoof` among others; there is no per-check switch. |
| `--alert-phishing-cloak[=yes/no]` | Alert on cloaked URLs in email | `--detect phishing` | renamed | Same one detector. |
| `--alert-partition-intersection[=yes/no]` | Alert on overlapping DMG partitions | `--detect partition-intersection` | renamed | exav also covers GPT, APM and MBR. |
| `--nocerts` | Disable Authenticode chain verification | none | absent | exav's Authenticode handling is parse- and blocklist-only, so there is no chain verification to disable. |
| `--dumpcerts` | Dump the Authenticode chain | none | absent | |

### Limits

| `clamscan` | What it does | exav | Status | Notes |
|---|---|---|---|---|
| `--max-scantime=#n` | Skip a scan longer than this (ms) | `--max-scan-secs` | renamed | Seconds, Unix only, and a kernel-enforced wall-clock plus CPU budget per job rather than an in-engine check. In a one-shot run it bounds the whole run, not each file. Refused on a listener outside the clamd worker pool (`--workers threads`, ICAP alone). |
| `--max-filesize=#n` | Skip files larger than this | `--max-input-bytes` | renamed | exav's default is **no limit**; ClamAV's is 100M. `--clamav-compat` sets 100M. Over the limit exav reports `LIMITS-EXCEEDED`, not a clean `OK`, unless `--partial-as ok` (which `--clamav-compat` sets). |
| `--max-scansize=#n` | Max data scanned per container | `--max-matcher-bytes` | renamed | exav's default is 10G, ClamAV's 400M. exav scans a streamed member without holding it, so this bounds CPU time rather than memory. What a scan holds is a fixed 1 GiB, lowered by `--max-process-bytes`; `--clamav-compat` makes it 400M. |
| `--max-files=#n` | Max files scanned per container | `--max-members` | renamed | exav's default is 100000 against ClamAV's 10000, because exav descends into nested archives ClamAV does not and so counts more members for the same file. `--clamav-compat` sets 10000. |
| `--max-recursion=#n` | Max archive recursion depth | `--max-unpack-depth` | renamed | Different default too: exav 16, ClamAV 17. `--clamav-compat` sets 17. `0` is refused. |
| `--max-dir-recursion=#n` | Max directory recursion depth | none | absent | exav's directory walk has no depth cap. |
| `--max-embeddedpe=#n` | Max size checked for an embedded PE | none | absent | exav applies its global budgets instead of a per-subsystem cap. |
| `--max-htmlnormalize=#n` | Max HTML size to normalize | none | absent | Same. |
| `--max-htmlnotags=#n` | Max normalized-HTML size to scan | none | absent | Same. |
| `--max-scriptnormalize=#n` | Max script size to normalize | none | absent | Same. |
| `--max-ziptypercg=#n` | Max ZIP size to re-type | none | absent | Same. |
| `--max-partitions=#n` | Max partitions per disk image | none | absent | Same. |
| `--max-iconspe=#n` | Max icons per PE | none | absent | Same. |
| `--max-rechwp3=#n` | Max HWP3 parse recursion | none | absent | Same. |
| `--pcre-match-limit=#n` | Max PCRE match calls | none | absent | exav's PCRE path has a bounded backtrack budget that is not operator-tunable. |
| `--pcre-recmatch-limit=#n` | Max recursive PCRE match calls | none | absent | Same. |
| `--pcre-max-filesize=#n` | Max file size for PCRE subsignatures | `--max-pcre-bytes` | renamed | Per object, as in ClamAV: a member under the limit is matched inside a larger archive. exav's default is no limit, since an object is matched without being copied; `--clamav-compat` makes it ClamAV's 100M. |
| `--disable-cache` | Disable the clean-file hash cache | none | absent | exav has no scan cache, so there is nothing to disable. |

## `clamd`

`clamd` takes almost no command-line configuration: it reads
`/etc/clamav/clamd.conf` and everything operational lives there.

exav does not read `clamd.conf` and has no `--config-file`; it is configured with
CLI flags and environment variables (see [Configuration](/scanner/reference/configuration/)).
The wire protocol is compatible
(see the [daemon guide](/scanner/guides/daemon/)), so existing clients keep working.

### `clamd` command-line flags

| `clamd` | What it does | exav | Status | Notes |
|---|---|---|---|---|
| `--help`, `-h` | Show help | same spelling | same | |
| `--version`, `-V` | Print version | same spelling | differs | Prints `exav <version>`; the wire `VERSION` command answers the `ClamAV <version>` string clients expect. |
| `--foreground`, `-F` | Do not daemonize | none | absent | exav's daemon always runs in the foreground; run it under systemd, a supervisor or `&`. |
| `--debug` | Enable debug mode | none | absent | |
| `--config-file=FILE`, `-c` | Read configuration from FILE | none | absent | exav reads no configuration file. |
| `--fail-if-cvd-older-than=days` | Nonzero exit on a stale database | none | absent | |
| `--datadir=DIRECTORY` | Load signatures from DIRECTORY | `-d` / `--sig-dir` | renamed | Different spelling, same job. `--sig-dir` defaults to `/var/lib/exav`. |
| `--pid=FILE`, `-p` | Write the pid to FILE | none | absent | Use the supervisor's own pid tracking. |

### `clamd.conf` directives

The file is not read, so every directive below is absent as such. The exav column
gives the flag or environment variable that does the same job, or "none".

#### Sockets and process

| Directive | What it does | exav equivalent | Notes |
|---|---|---|---|
| `LocalSocket` | Unix socket path to listen on | `--listen PATH` | A leading `/` is a socket path; the protocol defaults to `clamd`. |
| `LocalSocketGroup` | Group owning the socket | none | The socket takes the daemon's own primary group; set that in the service unit (`Group=`) and pair it with `?mode=660`. |
| `LocalSocketMode` | Socket permission bits | `--listen 'clamd:///path?mode=660'` | Same octal values, carried by the address because they are a property of *that* socket. exav's default is **0600** where clamd's is whatever the umask leaves (`Default: disabled (socket is world accessible)`), so widening it is explicit. The socket is created with no permissions and given the mode before it can be reached, so it never exists more open than asked for. |
| `FixStaleSocket` | Remove a leftover socket at startup | default | exav removes a stale socket before binding. |
| `TCPSocket` | TCP port to listen on | `--listen ADDR` | One value carries protocol, host and port. |
| `TCPAddr` | Address to bind | `--listen ADDR` | |
| `MaxConnectionQueueLength` | Listen backlog | `?max-connections=` on the address | Concurrent connections rather than a backlog. Default 128 (100 on ICAP). On the clamd listener it is read only under `--workers threads`: the prefork pool bounds concurrency by its worker count. ICAP always reads it. |
| `MaxThreads` | Worker thread count | `--workers N` | exav's default is one prefork **process** per CPU core; `--workers threads` selects the in-process thread model. |
| `MaxQueue` | Max queued scan jobs | none | |
| `IdleTimeout` | Idle thread timeout | none | |
| `ReadTimeout` | Per-read socket timeout | none | Fixed at 60 s on the clamd listener. (ICAP's is `--icap-idle-secs`.) |
| `CommandReadTimeout` | Command read timeout | none | Same 60 s. |
| `SendBufTimeout` | Send-buffer timeout | none | |
| `Foreground` | Do not daemonize | default | exav always runs in the foreground. |
| `User` | Drop privileges to this user | none | Set the user in the service unit. |
| `PidFile` | Write the pid here | none | |
| `ExitOnOOM` | Exit when out of memory | none | `--max-process-bytes` caps a worker's address space instead, and the pool restarts the worker. |
| `SelfCheck` | Database freshness check interval | none | The daemon hot-reloads when the signature source changes on disk, and `--auto-update` adds the scheduled re-fetch that changes it. |
| `ConcurrentDatabaseReload` | Reload without pausing scans | default | exav loads the new database, starts serving from it, and lets scans in progress finish on the old one. |

#### Logging

| Directive | What it does | exav equivalent | Notes |
|---|---|---|---|
| `LogFile` | Scan/status log path | `--log FILE` | Scan results only, one line per scan the daemon answers, under the daemon's own view of the target (`stream:` for `INSTREAM`, `fd:` for `FILDES`). clamd's log also carries startup, connection and reload lines; exav writes those to stderr for the supervisor to route. Reopened on `SIGHUP`, as clamd does. |
| `LogFileMaxSize` | Rotate at this size | none | |
| `LogFileUnlock` | Do not lock the log | none | |
| `LogRotate` | Rotate the log | none | Rotate with logrotate: exav reopens `--log` on `SIGHUP`. |
| `LogTime` | Timestamp log lines | none | |
| `LogClean` | Log clean files too | none | |
| `LogSyslog` | Log to syslog | none | exav writes to stdout/stderr; the supervisor routes it. |
| `LogFacility` | Syslog facility | none | |
| `LogVerbose` | Verbose logging | none | |
| `ExtendedDetectionInfo` | Log extra detection detail | none | |
| `Debug` | Enable debug output | none | |

#### Database

| Directive | What it does | exav equivalent | Notes |
|---|---|---|---|
| `DatabaseDirectory` | Where signatures live | `-d` / `--sig-dir DIR` | |
| `OfficialDatabaseOnly` | Load only official signatures | none | |
| `FailIfCvdOlderThan` | Refuse a stale database | none | |
| `DetectPUA` | Detect potentially unwanted applications | `--detect pua` | |
| `ExcludePUA` / `IncludePUA` | PUA category filters | none | PUA is all-or-nothing in exav. |

#### Scan limits

| Directive | What it does | exav equivalent | Notes |
|---|---|---|---|
| `MaxScanSize` | Max data scanned per container | `--max-matcher-bytes` | |
| `MaxFileSize` | Max file size scanned | `--max-input-bytes` | |
| `MaxRecursion` | Max archive recursion | `--max-unpack-depth` | |
| `MaxFiles` | Max files per container | `--max-members` | |
| `MaxScanTime` | Max scan time | `--max-scan-secs`, `--max-pe-emulation-steps` | `--max-scan-secs` is kernel-enforced per job (seconds, Unix), not an in-engine check, and only in the clamd worker pool: ICAP scans have no time bound. The in-engine CPU bounds are `--max-matcher-bytes` and `--max-pe-emulation-steps`; the latter reports as `Heuristics.Limits.Exceeded.MaxScanTime`. |
| `MaxDirectoryRecursion` | Max directory depth | none | |
| `MaxEmbeddedPE`, `MaxHTMLNormalize`, `MaxHTMLNoTags`, `MaxScriptNormalize`, `MaxZipTypeRcg`, `MaxPartitions`, `MaxIconsPE`, `MaxRecHWP3` | Per-subsystem caps | none | exav applies its global budgets instead. |
| `PCREMaxFileSize` | Max object size for PCRE subsignatures | `--max-pcre-bytes` | |
| `PCREMatchLimit`, `PCRERecMatchLimit` | PCRE backtracking bounds | none | Bounded internally, not tunable. |
| `StreamMaxLength` | Max `INSTREAM` upload | `--max-input-bytes`, `--max-spill-bytes` | clamd defaults to 100M and refuses more; exav has **no default scan limit** on a stream. `--max-spill-bytes` (2G) bounds the temp space one streamed object may occupy, which is the closest thing to a per-upload ceiling. Set `--max-input-bytes` if a client relied on the daemon to bound its uploads. |
| `StreamMinPort` / `StreamMaxPort` | Legacy `STREAM` port range | none | The `STREAM` command is removed from ClamAV too. |
| `CacheSize` / `DisableCache` | Clean-file hash cache | none | exav has no scan cache. |

#### Parser and alert toggles

| Directive | What it does | exav equivalent | Notes |
|---|---|---|---|
| `ScanPE`, `ScanELF`, `ScanOLE2`, `ScanPDF`, `ScanSWF`, `ScanHTML`, `ScanXMLDOCS`, `ScanHWP3`, `ScanOneNote`, `ScanMail`, `ScanArchive`, `ScanImage`, `ScanImageFuzzyHash` | Switch one parser off | none | Every parser exav implements is always on. |
| `ScanPartialMessages` | Reassemble partial mail messages | none | |
| `PhishingSignatures`, `PhishingScanURLs` | Phishing detection | none | |
| `HeuristicAlerts`, `HeuristicScanPrecedence` | Heuristic policy | none | |
| `AlertBrokenExecutables` | Alert on broken PE/ELF | `--detect broken` | |
| `AlertBrokenMedia` | Alert on broken graphics | `--detect broken-media` | |
| `AlertEncrypted` | Alert on encrypted content | `--partial-as password-protected=found` | Any encryption, decrypted or not. Without it, exav reports members it cannot decrypt as `PASSWORD-PROTECTED`. |
| `AlertEncryptedArchive` / `AlertEncryptedDoc` | Split encrypted alerts | `--partial-as password-protected=found` | One policy covers both. |
| `AlertOLE2Macros` | Alert on VBA macros | `--detect macros` | |
| `AlertExceedsMax` | Alert on a limit stop | `--partial-as limits-exceeded=found` | exav reports `LIMITS-EXCEEDED` without it. |
| `AlertPartitionIntersection` | Alert on overlapping partitions | `--detect partition-intersection` | |
| `AlertPhishingSSLMismatch` / `AlertPhishingCloak` | Phishing alert detail | `--detect phishing` | One detector, no per-check switch. |
| `StructuredDataDetection` | Enable DLP detection | `--dlp-credit-cards` / `--dlp-ssns` | Giving a threshold enables it. |
| `StructuredMinCreditCardCount` | Credit-card threshold | `--dlp-credit-cards` | |
| `StructuredMinSSNCount` | SSN threshold | `--dlp-ssns` | |
| `StructuredCCOnly`, `StructuredSSNFormatNormal`, `StructuredSSNFormatStripped` | DLP format policy | none | |
| `DisableCertCheck` | Skip Authenticode verification | none | exav's Authenticode handling is parse- and blocklist-only. |
| `CrossFilesystems` | Scan across mount points | none | exav's walk crosses them, matching clamd's default. |
| `FollowDirectorySymlinks` / `FollowFileSymlinks` | Symlink policy | none | exav matches clamd's default (follow a directly-named link, do not descend into one found in a tree). |
| `ExcludePath` | Skip paths matching a regex | `--exclude` / `--exclude-dir` | |
| `Bytecode` | Run bytecode signatures | none | Always on in exav. |
| `BytecodeSecurity` | Bytecode trust level | none | |
| `BytecodeUnsigned` | Allow unsigned bytecode | none | exav performs no bytecode signature check. |
| `AllowAllMatchScan` | Permit `ALLMATCHSCAN` | default | Always permitted in exav. |
| `TemporaryDirectory` | Where temporary files go | `--spill-dir` | Defaults to `TMPDIR`; `--spill-dir off` writes none at all. |
| `ForceToDisk`, `LeaveTemporaryFiles` | Temporary-file policy | none | A streamed object past `--spill-threshold-bytes`, and a member that decodes past `--max-object-bytes`, go to a spill file, deleted when the scan ends. |
| `GenerateMetadataJson` | Emit engine metadata JSON | none | `--json` emits scan results, a different thing. |

#### Not implemented at all

| Directive group | What it does | exav |
|---|---|---|
| `OnAccessMountPath`, `OnAccessIncludePath`, `OnAccessExcludePath`, `OnAccessExcludeUID`, `OnAccessExcludeUname`, `OnAccessExcludeRootUID`, `OnAccessMaxFileSize`, `OnAccessMaxThreads`, `OnAccessDisableDDD`, `OnAccessPrevention`, `OnAccessExtraScanning`, `OnAccessDenyOnError`, `OnAccessRetryAttempts` | Real-time on-access scanning (fanotify) | Not supported. Keep ClamAV if you depend on it. |
| `VirusEvent` | Run a command on detection | Not supported. Drive it from the daemon's reply or the scan output. |
| `PreludeEnable`, `PreludeAnalyzerName` | Prelude SIEM integration | Not supported. |

## `clamdscan`

exav acts as a daemon client when given `--connect` together with paths.

| `clamdscan` | What it does | exav | Status | Notes |
|---|---|---|---|---|
| `--help`, `-h` | Show help | same spelling | same | |
| `--version`, `-V` | Print version | same spelling | differs | Answered locally (`exav <version>`), where `clamdscan` asks the daemon and prints its `ClamAV <version>` reply. Use `--ping` to check the daemon is there; the wire `VERSION` still answers the ClamAV string to anything that speaks the protocol. |
| `--verbose`, `-v` | Be verbose | `--verbose` | differs | `clamdscan -v` prints nothing a plain run does not. exav's names the daemon that answered and the command sent per target (`  [daemon] unix:… ClamAV …`, `  [SCAN] /abs/path`). The informational findings `-v` adds to a local scan come from the scanner, and a daemon reply carries only a verdict. |
| `--quiet` | Only output error messages | `--quiet` | differs | Same difference as the scanner: exav still prints detections. |
| `--stdout` | Write to stdout instead of stderr | none | absent | exav already writes results to stdout. |
| `--log=FILE`, `-l` | Save scan report to FILE | `--log` | same | Client replies are mirrored into the log. **`-l` is absent.** |
| `--file-list=FILE`, `-f` | Scan files listed in FILE | `--files-from` | renamed | **`-f` is absent.** |
| `--ping`, `-p A[:I]` | Ping the daemon until it answers | `--ping` | differs | One probe, not `A` attempts at `I` seconds; a supervisor or `HEALTHCHECK` owns the retrying. With no `--connect` it probes the listener this configuration serves, so a container health check needs no address, and it speaks the protocol it finds there: `PING` on clamd, `OPTIONS` on ICAP. |
| `--wait`, `-w` | Wait for the daemon to start | none | absent | |
| `--remove` | Delete infected files | none | absent | Out of scope by design. |
| `--move=DIRECTORY` | Move infected files | none | absent | Same. |
| `--copy=DIRECTORY` | Copy infected files | none | absent | Same. |
| `--config-file=FILE`, `-c` | Read configuration from FILE | none | absent | exav reads no configuration file; name the daemon with `--connect`. |
| `--allmatch`, `-z` | Keep scanning after a match | `--all-matches` | renamed | Sends `ALLMATCHSCAN`. **`-z` is absent**, and it cannot be combined with `--send-as contents`/`fd`: one `INSTREAM` gets one verdict back, so an all-match scan is not expressible over them. |
| `--multiscan`, `-m` | Force `MULTISCAN` mode | none | absent | exav's client sends one `SCAN` per file inside an `IDSESSION`. The daemon answers `MULTISCAN` on the wire. |
| `--infected`, `-i` | Only print infected files | `--quiet` | renamed | |
| `--no-summary` | No summary at end | `--quiet` | renamed | Same dial. |
| `--reload` | Ask the daemon to reload | none | absent | The daemon answers `RELOAD` on the wire; no client flag sends it. |
| `--fdpass` | Pass a file descriptor to the daemon | `--send-as fd` | renamed | Same `FILDES`/`SCM_RIGHTS` request. Over a TCP `--connect` exav **refuses** it: a descriptor cannot cross a TCP connection, and `clamdscan` silently sends the path instead, which scans whatever that path holds on the daemon's host. |
| `--stream` | Stream file contents to the daemon | `--send-as contents` | renamed | Same `INSTREAM` request, reported under the local name. |
| `-` (stdin) | Scan standard input | `-` | differs | Both stream it. exav reports it as `stdin`, the name a local `exav -` uses, where `clamdscan` prints the daemon's own `stream:` (or `fd:`, when stdin is a regular file it can pass by descriptor). |

Two client-mode behaviours have no flag:

- **Directories always recurse.** `clamdscan` hands a directory to the daemon to
  walk; exav walks it client-side and sends one `SCAN` per file, so `--exclude` /
  `--include` apply and each command has one reply. A directory holding the parts
  of a byte-split archive goes over whole as one `CONTSCAN`, so the daemon can
  rejoin them.
- **The name in a result line.** By path, exav reports the absolute path it sent,
  as `clamdscan` does. By content (`--send-as contents`/`fd`), it reports the path
  as written on the command line, where `clamdscan` resolves it.

## exav flags with no ClamAV counterpart

| exav flag | What it does |
|---|---|
| `--sig-dir <DIR>` | The directory signatures live in, loaded and (by `--auto-update`) written to unless `-d` is given (default `/var/lib/exav`). |
| `--sig-sources <URL\|FILE>` | Where `--auto-update` fetches from: exact URLs, mirror bases (trailing `/`), or a file of either, which may be a `freshclam.conf`. |
| `--db-url <URL>` | A prebuilt `.exavdb` to pull and serve instead of signature files. |
| `--build-db <FILE>` | Compile the loaded signatures into a prebuilt `.exavdb` and exit. |
| `--listen <ADDR>` | Serve on this address. `clamd://` and `icap://`; naming both serves both from one process over one database. |
| `--connect <ADDR>` | Scan by handing each file to a daemon already running here. |
| `--send-as <WHAT>` | What that client hands over: `path`, `contents` or `fd`. |
| `--auto-update` | Bootstrap, refresh and hot-reload the signature source for as long as the process runs. With no `--listen` and no paths it is an updater and nothing else. |
| `--startup-wait-secs <SECS\|off>` | How long to wait for a sidecar to populate an empty signature directory. |
| `--update-interval-secs <SECS\|off>` | Seconds between signature source re-checks. |
| `--allow-no-db` | Run against the built-in EICAR-only baseline instead of refusing. Testing only. |
| `--workers <N\|threads>` | Prefork worker processes, or the in-process thread model. |
| `--max-jobs-per-worker <N\|off>` | Recycle a worker process after this many jobs. |
| `--max-process-bytes <SIZE\|off>` | Address-space cap (`RLIMIT_AS`): per worker in the clamd pool, the whole process otherwise. |
| `--allow-shutdown` | Honour the clamd `SHUTDOWN` command. Off by default. |
| `--allow-http-scan` | Fetch `http(s)://` scan targets, one-shot or through `SCANURL`. Off by default. |
| `--max-object-bytes <SIZE\|off>` | The most memory a single decoded object may use. |
| `--max-matcher-bytes <SIZE\|off>` | Cumulative bytes fed to the matcher: a CPU bound, not a memory one. |
| `--max-pe-emulation-steps <N\|off>` | Instructions the PE unpacking emulator may run across one top-level file. |
| `--spill-dir`, `--spill-threshold-bytes`, `--max-spill-bytes`, `--max-total-spill-bytes` | Where a streamed object, or an archive member past `--max-object-bytes`, waits while it is scanned, and how much RAM and temp space it may take. |
| `--partial-as <POLICY>` | What becomes of an object exav could not fully examine: `partial` (default), `ok`, `found` or `error`, whole or per condition (`limits-exceeded=`, `unscannable=`, `password-protected=`). |
| `--clamav-compat` | Preset reproducing a stock ClamAV build's limits and extractor set, for differential testing. Reduces detection on purpose. |
| `--decode <LIST>` / `--no-decode <LIST>` | Encodings to recover a payload from before scanning it: `base64` today, meaning both a run long enough to hold an executable and the base64 assets a markup document embeds. On by default, unlike `--detect`. |
| `--detect packed` | Report `Heuristics.Packed.*`, naming the packer wrapping an executable exav could not unpack. |
| `--detect phishing` | Report `Heuristics.Phishing.Email.*` for display-versus-href link spoofing. Covers the checks ClamAV splits across `--alert-phishing-ssl` and `--alert-phishing-cloak`. |
| `--detect exav-heuristics` | Enable exav-exclusive structural / fuzzy / ML analysis. |
| `--no-detect <LIST>` | Detectors to leave off, subtracted from `--detect`. |
| `--passwords <PW>` | Password to try for encrypted members. Repeatable. |
| `--passwords-from <FILE>` | Passwords from a file, one per line, kept out of process listings. |
| `--json` | Newline-delimited JSON results, one object per input plus a summary. |
| `--profile` | Per-matcher timing breakdown: a CSV row per file when scanning, `MATCHERSTATS` through `STATS` on a listener. |
| `--slow-scan-secs <SECS\|off>` | Log any scan taking longer, naming the object. |
| `--metrics-secs <SECS\|off>` | Seconds between a listener's scan-totals log lines. |
| `--icap-*` | The ICAP listener's settings: service names, preview, keep-alive, the `X-Infection-Found` policy. See the [ICAP guide](/scanner/guides/icap/). |

## Gaps this matrix surfaces

The rows worth acting on before a migration:

- **No bytecode signature check.** exav runs `.cbc` programs without verifying who
  signed them, ClamAV's `--bytecode-unsigned=yes` behaviour with no way to tighten
  it. Load bytecode only from sources you trust.
- **`INSTREAM` has no default size limit.** clamd caps a stream at
  `StreamMaxLength` (100M); exav bounds the temp space one streamed object may take
  (`--max-spill-bytes`, 2G). Set `--max-input-bytes` if a client relied on the
  daemon to bound its uploads.
- **The daemon's socket is 0600 unless widened.** `LocalSocketMode 660` becomes
  `--listen 'clamd:///path?mode=660'`, and the socket takes the daemon's own group,
  so the service unit must run under the group the clients share.
- **`--quiet` still prints detections**, where `clamscan --quiet` is silent.
- **Every parser toggle is absent**, so a configuration that switched one off
  fails at startup.
- **`--multiscan`, `--wait` and `--reload` are absent in the client.** The daemon
  answers `MULTISCAN` and `RELOAD` on the wire, so clamd clients keep working;
  exav's own client has no flag to send them. `--ping` exists, for health checks.
- **`--send-as fd` over a TCP `--connect` is refused.** `clamdscan` silently sends
  the path instead, so the daemon scans whatever that path holds on its host.
- **Every limit flag with an exav equivalent is renamed**, and the error names
  the exav flag.

## Sources

ClamAV's side of the `clamscan` and `clamdscan` tables is the `--help` output of
ClamAV 1.4.3, with the behavioural rows run: `clamscan` against the same trees as
exav, and `clamdscan` against exav's own daemon
(`clamdscan -c <conf> --stream | --fdpass | -`). `clamd`'s flags come from the
`clamd.8` manual page and the directives from `clamd.conf.sample`, both from the
upstream `rel/1.4` branch; claims about a `clamd.conf` directive's own behaviour
are read from those, not run.

exav's side is read from the clap definitions in the `exav` crate and checked by
running the built binary against each flag.
