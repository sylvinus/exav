---
title: Streaming & memory
description: Where exav holds a file in memory, where it streams, what each path matches, and why the database, not the file, is what uses memory.
---

Every file gets the same scan whatever its size, except the few checks that
parse it whole (below):

- every `.ndb` form: wildcards, gaps, anchored offsets, file-type targets;
- `.ldb` logical signatures, with their regexes and byte comparisons;
- the normalised views of HTML, text and scripts that those signatures are
  written against;
- YARA rules, bytecode programs, whole-file hashes;
- archives decoded as they are read, embedded files, heuristics.

What changes with size is where the file is while that runs.

## Can a file be larger than the RAM?

Most can. A file on disk is never loaded past `--max-object-bytes`, so what a
scan holds does not grow with the file: a 20 GiB file with a signature at
19.5 GB was matched in 33 seconds with a 24 MB peak, using a one-signature
database. A real database is the larger part of the memory:
[sizing a server](/scanner/guides/sizing/) works through a 4 GiB machine.

What happens past `--max-object-bytes` (256 MiB), by kind of input:

| Input | Held in memory | Needs disk | A 20 GB input |
|---|---|---|---|
| A file on disk: executable, script, document, raw disk or filesystem image | Block cache, 8 MiB | No | Scanned in full. A PE, ELF or .NET file skips the [checks that need it whole](#past-it-through-a-block-cache) and, if nothing is found, is reported `LIMITS-EXCEEDED` |
| ZIP, tar, CAB, ISO, LHA, `ar`, cpio, 7z, WIM, xar, the single-stream compressors, self-extracting executables, and the formats built on them | One member, up to 256 MiB | Only for a member over 256 MiB, up to `--max-spill-bytes` (2 GiB) | Scanned member by member. A member past the spill ceiling, or any member with `--spill-dir off`, is not scanned and the file is `LIMITS-EXCEEDED`. A 7z folder with an encrypted coder or several packed streams (BCJ2) is decoded whole, under 256 MiB |
| Disk images (VHD, VHDX, QCOW2, VMDK, DMG) and the filesystems inside them or on their own: FAT, exFAT, NTFS, ext, SquashFS, cramfs, romfs, EROFS, HFS+, APFS | A cache of up to 32 MiB (8 MiB for a raw image), and one file up to 256 MiB | Only for a file over 256 MiB, up to `--max-spill-bytes` (2 GiB) | Walked in place, each file read from where the volume has it, and one past 256 MiB goes to a spill file as a ZIP member does. A file stored compressed by the filesystem (HFS+, APFS, NTFS, EROFS) is decoded whole under the limit and reported past it. A raw image's own bytes are matched as part of the image |
| RAR, OLE, PDF, CHM, ARJ, email and the other formats [read whole](/scanner/reference/formats/#size-what-is-read-as-it-goes-and-what-is-read-whole) | Not held: the container is not opened | No | The file's own bytes are scanned, its members are not unpacked, and the result is `LIMITS-EXCEEDED` unless something is found. Raising `--max-object-bytes` to cover it takes that much RAM |
| Stdin, `INSTREAM`, an ICAP body | 16 MiB | Yes: the stream is written to a temporary file to make it seekable | The first 2 GiB is scanned and the result is `LIMITS-EXCEEDED PARTIAL`. With `--spill-dir off`, the first 16 MiB. Raise `--max-spill-bytes` and give it the disk, or hand the daemon a path instead |
| An `http(s)://` URL | See [HTTP sources](#http-sources) | No | Scanned in full, over the network about twice |

Two other limits apply whatever the memory. `--max-scan-secs` stops a daemon
job after 120 seconds by default (a one-shot run has no time limit), and a
file past `--max-object-bytes` is read several times over, so a very large one
can reach it. `--max-matcher-bytes` (10 GiB) counts what members and carved
objects feed to the matcher, not the top-level file, so it did not stop the 20
GiB file above. It does count the files of an archive or a disk image, and the
holes of a sparse file, which read as zeros: an archive or image holding more
than that is scanned as far as it, then reported `LIMITS-EXCEEDED`, and raising
the limit takes it further.

## Up to `--max-object-bytes`: in memory

A file up to `--max-object-bytes` (256 MiB by default) is read into memory, and
so is an HTTP source that size. Memory is roughly the file's size, plus a
lowercase copy when a case-insensitive signature has to be checked and, for
text, one normalised copy at a time. The deobfuscated
JavaScript view stops at 32 MiB; a script whose view is longer is reported
`LIMITS-EXCEEDED` unless something is found, though its raw bytes are still
scanned in full.

## Past it: through a block cache

A larger file is read through a cache of 1 MiB blocks, of which at most 8 MiB
are held, least recently used dropped first. So are an HTTP source of that size
and a spill file (below). Verifying a match can still look anywhere in the
file: the cache bounds what is held at once, not how far a check may reach, and
a block that was dropped is read again when it is needed. The scan is the same
one, with the same results, only slower, since the file is read a few times
over: once for format detection's search, carving and the digests (when a hash
signature has its size), once for the signature sweep (every anchor at once),
twice more for YARA's prefilter when rules are loaded, and again in the parts a
check needs. [The block cache](#the-block-cache) below says how it works and
what its three settings trade.

<div class="diagram">
<svg viewBox="0 0 790 392" role="img" aria-labelledby="bcn bcd" style="width:100%;height:auto;max-width:790px">
  <title id="bcn">One source, read through a block cache</title>
  <desc id="bcd">A file or an HTTP source past --max-object-bytes, or a spill
  file, is read through a block cache of 1 MiB blocks holding 8 MiB. Every
  check asks it for bytes at an offset: the signature sweep a chunk at a time
  in order, verification and the container walk at any offset, the regexes
  stepped through, the hashes, typing's search and carving in one shared pass.
  The checks that parse an object whole run only when it fits within
  --max-object-bytes.</desc>
  <defs>
    <marker id="bc-arrow" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="7" markerHeight="7" orient="auto">
      <path d="M0 0 L8 4 L0 8 z" fill="currentColor"/>
    </marker>
  </defs>
  <g fill="currentColor" font-family="system-ui, sans-serif" font-size="11" font-weight="600" letter-spacing=".08em" opacity="0.6">
    <text x="8" y="16">SOURCES</text>
    <text x="520" y="16">WHAT READS IT</text>
  </g>
  <g fill="none" stroke="currentColor" stroke-width="1.5">
    <rect x="8" y="28" width="170" height="48" rx="6"/>
    <rect x="8" y="96" width="170" height="48" rx="6"/>
    <rect x="8" y="164" width="170" height="48" rx="6"/>
    <rect x="230" y="84" width="230" height="136" rx="6"/>
    <rect x="520" y="28" width="262" height="44" rx="6"/>
    <rect x="520" y="84" width="262" height="44" rx="6"/>
    <rect x="520" y="140" width="262" height="44" rx="6"/>
    <rect x="520" y="196" width="262" height="44" rx="6"/>
    <rect x="520" y="252" width="262" height="44" rx="6"/>
    <rect x="520" y="324" width="262" height="56" rx="6" stroke-dasharray="4 4"/>
  </g>
  <g fill="currentColor" font-family="ui-monospace, SFMono-Regular, Menlo, monospace" font-size="13" font-weight="600">
    <text x="93" y="50" text-anchor="middle">file</text>
    <text x="93" y="118" text-anchor="middle">HTTP range</text>
    <text x="93" y="186" text-anchor="middle">spill file</text>
    <text x="345" y="112" text-anchor="middle">BlockCache</text>
    <text x="532" y="48">signature sweep</text>
    <text x="532" y="104">verification</text>
    <text x="532" y="160">regexes</text>
    <text x="532" y="216">hashes · typing · carving</text>
    <text x="532" y="272">container walk</text>
    <text x="532" y="346">whole-object checks</text>
  </g>
  <g fill="currentColor" font-family="system-ui, sans-serif" font-size="11.5" opacity="0.72">
    <text x="93" y="66" text-anchor="middle">past --max-object-bytes</text>
    <text x="93" y="134" text-anchor="middle">past the limit too</text>
    <text x="93" y="202" text-anchor="middle">a large member or view</text>
    <text x="345" y="136" text-anchor="middle">1 MiB blocks, 8 MiB held,</text>
    <text x="345" y="154" text-anchor="middle">least recently used dropped;</text>
    <text x="345" y="172" text-anchor="middle">bytes at any offset, or in</text>
    <text x="345" y="190" text-anchor="middle">1 MiB chunks in order</text>
    <text x="532" y="64">chunks in order, one pass</text>
    <text x="532" y="120">windows at any offset</text>
    <text x="532" y="176">lazy DFAs stepped through</text>
    <text x="532" y="232">one shared pass; start and end</text>
    <text x="532" y="288">headers and members, by offset</text>
    <text x="532" y="366">held whole only: PE, RAR, OLE</text>
  </g>
  <g fill="none" stroke="currentColor" stroke-width="1.5" marker-end="url(#bc-arrow)">
    <path d="M178 52 H200 V120 H226"/>
    <path d="M178 120 H226"/>
    <path d="M178 188 H200 V150 H226"/>
    <path d="M460 120 H490 V50 H516"/>
    <path d="M490 106 H516"/>
    <path d="M490 120 V162 H516"/>
    <path d="M490 162 V218 H516"/>
    <path d="M490 218 V274 H516"/>
  </g>
</svg>
</div>

A few things need the file whole and are not done past the limit:

- the structure of a PE: entry-point and section offsets, section hashes,
  imports, icons, the Authenticode signature, UPX and packer unpacking;
- YARA's `pe`, `elf` and `dotnet` modules;
- a PCRE subsignature with a lookaround or a backreference, and the
  `fuzzy_img` image hash;
- containers whose format is read whole (RAR, OLE, PDF, CHM, ARJ, email and
  others; see
  [Supported formats](/scanner/reference/formats/#size-what-is-read-as-it-goes-and-what-is-read-whole)).

A file for which one of these applied is reported `LIMITS-EXCEEDED`, naming
`--max-object-bytes`, unless something is found. Raise the limit to have them
run, at the cost of memory.

The normalised views of a large text file are as large as the file, so they go
to a [spill file](#spill-files).

## The block cache

Picture a window of a few large blocks sliding over the object, with a short
memory of the blocks it has just left.

- **What it is.** Each object read in place (a file, an HTTP source, a spill
  file) has one cache. It cuts the object into aligned blocks of
  `--object-cache-block-bytes` (1 MiB) and keeps up to `--object-cache-bytes`
  (8 MiB) of them, so 8 blocks by default. Never fewer than two.
- **A read.** Every check asks for bytes at an offset. If the block holding them
  is held, the bytes are copied out of memory. If not, the whole block is read
  from the source, in one request over HTTP, and the least recently used block
  is dropped to make room. A read that spans two blocks takes both.
- **Two kinds of read.** The sweeps (signature sweep, hashes, typing, carving)
  go through the object in order, so each block is read once per pass and is
  never asked for again. Verifying a match, reading a ZIP's directory and then
  its members, or stepping a regex, ask at scattered offsets, and each miss
  costs a whole block, however few bytes it needed.
- **Over HTTP, runs are merged.** A read that goes on from where the last
  request stopped asks for twice as much as that one did, from one block up to
  `--http-request-bytes` (8 MiB). A pass over a large object costs one request
  per 8 MiB, not one per block, while scattered reads stay one block each.
- **Passes.** An object larger than the cache is read again from the source at
  each pass, as the blocks of the previous pass have been dropped by the time it
  ends. An object that fits in the cache is read from the source once and held,
  so every pass after the first costs no request at all.
- **What it costs in memory.** The cache's size for each object being scanned in
  place, plus up to one request held by the HTTP reader while it is read, plus
  a copy of the bytes a check is looking at (a 1 MiB chunk for the sweep).
  Objects nested in one another each have their own cache: an archive on HTTP
  whose big member is spilled to disk holds two. A daemon with
  `--max-process-bytes` lowers the cache and the request to an eighth of a job's
  memory each, at most.
- **What it does not do.** It reads nothing ahead of the block asked for (apart
  from the doubling of HTTP requests above), shares nothing between objects,
  does not write, and does not change what the scan finds, only how many reads
  of the source it takes.

Which setting to change:

| Setting | Raise it when | What it costs |
|---|---|---|
| `--object-cache-block-bytes` | requests are slow (HTTP, network storage) and there are many small misses: fewer requests for the same scattered reads | each miss moves a whole block: 1 MiB to verify a 100-byte match. Past about 1 MiB the misses stop falling and the bytes fetched keep growing |
| `--object-cache-bytes` | the object is not much bigger than the cache: every pass but the first is then free, and a few more blocks hold more of the places verification goes back to | that much memory per object being scanned in place, nested ones included |
| `--http-request-bytes` | a pass over a large object is bound by round trips, not bandwidth | that much memory held while the object is read |

What each setting did against a local server that waits before answering each
request, so the delay stands for the round trip. The first object is a 300 MB
file under a database with a pattern, a logical signature with a gap and the
hash of that size. It is read about 4.5 times over, and 300 MB is past
`--max-object-bytes`, so it goes through the cache. Block, cache and request
sizes in the first three columns, defaults in bold:

| Block | Cache | Request | Requests | Fetched | No delay | 20 ms | 100 ms |
|---|---|---|---|---|---|---|---|
| 64K | 8M | 8M | 1,080 | 1.34 GB | 4.7 s | 26.3 s | 112.7 s |
| 256K | 8M | 8M | 764 | 1.37 GB | 4.5 s | 20.0 s | 81.0 s |
| **1M** | **8M** | **8M** | 431 | 1.42 GB | 4.5 s | 13.5 s | 47.6 s |
| 4M | 8M | 8M | 417 | 2.73 GB | 4.5 s | 13.3 s | 46.7 s |
| 1M | 32M | 8M | 375 | 1.38 GB | 4.3 s | 11.9 s | 42.3 s |
| 1M | 8M | 1M | 1,324 | 1.38 GB | 4.6 s | 31.6 s | 138.2 s |
| 1M | 8M | 32M | 343 | 1.42 GB | 4.2 s | 11.3 s | 38.9 s |

The second is a 20 MB ZIP of 2,000 small members, read in place (with
`--max-object-bytes 1M`, as a much larger archive would be). The cache is
smaller than the file, so the archive is read six times over; a cache that holds
it reads it once:

| Block | Cache | Requests | Fetched | No delay | 20 ms | 100 ms |
|---|---|---|---|---|---|---|
| 64K | 8M | 56 | 121 MB | 0.7 s | 1.8 s | 6.3 s |
| **1M** | **8M** | 32 | 122 MB | 0.7 s | 1.3 s | 4.0 s |
| 4M | 8M | 20 | 125 MB | 0.7 s | 1.1 s | 2.7 s |
| 64K | 32M | 10 | 20 MB | 0.6 s | 0.8 s | 1.7 s |
| 1M | 32M | 6 | 20 MB | 0.6 s | 0.7 s | 1.3 s |

On a local disk the block size changed nothing measurable (the operating
system's page cache absorbs it), so the defaults are chosen for the network. The
tables measure round trips, not bandwidth: a server on the same host answered
at several GB/s.

## HTTP sources

An `http(s)://` target (`--allow-http-scan`, and `SCANURL` on the daemon) is
read by range requests and never written to disk. It takes the same two paths
as a file, with the network in place of the disk:

- **Up to `--max-object-bytes`:** fetched in full into memory, once. A 100 MiB
  object cost 20 requests, 1.0 times its size on the wire, and a 140 MB peak.
- **Past it:** read through the [block cache](#the-block-cache), so every pass
  over the file fetches it again. A 3 GiB object cost 2.0 times its size on the
  wire (6.4 GB) with a 54 MB peak, against a one-signature database. A database
  with a hash of that size, a gap signature and a pattern made it 4.7 times for
  a 300 MB object (1.42 GB in 431 requests). Rules that need more passes
  (YARA's prefilter reads the file twice more) transfer more, so a 20 GB object
  is 40 GB to 100 GB of egress. To pay in disk instead,
  [download it and scan the file](/scanner/guides/scanning/#scanning-over-http).
  `--object-cache-block-bytes`, `--object-cache-bytes` and `--http-request-bytes`
  set how many requests that takes.

What the source must and must not do:

- It must answer range requests with `206` and a `Content-Range` that carries
  the total size. A server that does not is an error, not a fallback to a full
  download.
- The transfer has no timeout of its own. Only `--max-scan-secs` bounds it
  (set by default for a daemon job, off for a one-shot run).
- Up to 10 redirects are followed, and the destination is not filtered, so a
  daemon with `--allow-http-scan` fetches any address it is given, including
  ones only it can reach.
- The object is not pinned. exav does not check an `ETag` or `Last-Modified`
  between ranges, so a server can answer differently on each pass. What was
  scanned is then not what a later download receives. For an object from a
  server you do not control, download it once and scan the file.

## Archive members

Archives decoded as they are read (ZIP, tar, CAB, ISO/UDF, LHA, `ar`, cpio, 7z,
WIM, xar, the disk images and filesystems, the single-stream compressors,
self-extracting executables) are walked member by member at any size and any
depth. Such a member is held in memory up to the same limit, and past it written
to a temporary file and scanned from there. With `--spill-dir off`, or past
`--max-spill-bytes`, it is not scanned and the file is `LIMITS-EXCEEDED`.

A member that has to be decoded whole (an encrypted ZIP member, a 7z folder with
an encrypted coder, a file a filesystem stores compressed, a member of a format
read whole) is `LIMITS-EXCEEDED` past `--max-object-bytes`.

## Stdin, `INSTREAM` and ICAP bodies

Container formats need to seek (a ZIP's directory is at its end), so a stream is
buffered before it is scanned: in memory up to `--spill-threshold-bytes`
(16 MiB), then in a temporary file up to `--max-spill-bytes` (2 GiB). The
buffered stream then goes through the same scan as a file. A stream past
`--max-input-bytes` or the spill ceiling is scanned as far as it was held and is
`LIMITS-EXCEEDED` unless that finds something, as a file past
`--max-input-bytes` is. See
[buffering a stream](/scanner/reference/cli/#buffering-a-stream-spill).

## Spill files

<div class="diagram">
<svg viewBox="0 0 790 330" role="img" aria-labelledby="spn spd" style="width:100%;height:auto;max-width:790px">
  <title id="spn">The two uses of spill files</title>
  <desc id="spd">Before a scan, a stream (stdin, INSTREAM, ICAP) is held in
  memory up to --spill-threshold-bytes and then in a temporary file up to
  --max-spill-bytes, and becomes a seekable source for the scan. Inside a scan,
  a streamed archive member that decodes past --max-object-bytes, and the normalised
  text views of a large text file, are written to spill files and read back
  through a block cache. A stream past its budget, or past the threshold with
  --spill-dir off, has what was held scanned; with --spill-dir off, such a
  member or view is not scanned. Either way a scan that finds nothing is
  LIMITS-EXCEEDED.</desc>
  <defs>
    <marker id="sp-arrow" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="7" markerHeight="7" orient="auto">
      <path d="M0 0 L8 4 L0 8 z" fill="currentColor"/>
    </marker>
  </defs>
  <g fill="currentColor" font-family="system-ui, sans-serif" font-size="11" font-weight="600" letter-spacing=".08em" opacity="0.6">
    <text x="8" y="16">BEFORE THE SCAN: A STREAM</text>
    <text x="8" y="176">INSIDE THE SCAN: WHAT IT MAKES</text>
  </g>
  <g fill="none" stroke="currentColor" stroke-width="1.5">
    <rect x="8" y="28" width="170" height="60" rx="6"/>
    <rect x="214" y="28" width="170" height="60" rx="6"/>
    <rect x="420" y="28" width="170" height="60" rx="6"/>
    <rect x="626" y="28" width="156" height="60" rx="6"/>
    <rect x="8" y="188" width="250" height="60" rx="6"/>
    <rect x="8" y="258" width="250" height="60" rx="6"/>
    <rect x="310" y="222" width="190" height="60" rx="6"/>
    <rect x="552" y="222" width="230" height="60" rx="6"/>
  </g>
  <g fill="currentColor" font-family="ui-monospace, SFMono-Regular, Menlo, monospace" font-size="13" font-weight="600" text-anchor="middle">
    <text x="93" y="52">stdin · INSTREAM</text>
    <text x="299" y="52">RAM</text>
    <text x="505" y="52">temp file</text>
    <text x="704" y="52">the scan</text>
    <text x="133" y="212">member past the limit</text>
    <text x="133" y="282">text views, large file</text>
    <text x="405" y="246">spill file</text>
    <text x="667" y="246">scanned from there</text>
  </g>
  <g fill="currentColor" font-family="system-ui, sans-serif" font-size="11.5" opacity="0.72" text-anchor="middle">
    <text x="93" y="72">ICAP bodies</text>
    <text x="299" y="72">--spill-threshold-bytes</text>
    <text x="505" y="72">--max-spill-bytes</text>
    <text x="704" y="72">a seekable source</text>
    <text x="133" y="232">decoded past --max-object-bytes</text>
    <text x="133" y="302">HTML, text, JS normalised</text>
    <text x="405" y="266">written as it is made</text>
    <text x="667" y="266">through a block cache</text>
  </g>
  <g fill="none" stroke="currentColor" stroke-width="1.5" marker-end="url(#sp-arrow)">
    <path d="M178 58 H210"/>
    <path d="M384 58 H416"/>
    <path d="M590 58 H622"/>
    <path d="M258 218 H284 V248 H306"/>
    <path d="M258 288 H284 V256 H306"/>
    <path d="M500 252 H548"/>
  </g>
  <g fill="currentColor" font-family="system-ui, sans-serif" font-size="11.5" opacity="0.72">
    <text x="8" y="116">Past --max-spill-bytes, or past the threshold with --spill-dir off, what was held is</text>
    <text x="8" y="134">scanned and the stream is LIMITS-EXCEEDED unless that finds something.</text>
    <text x="8" y="152">--max-total-spill-bytes bounds every spill file of a process together.</text>
  </g>
</svg>
</div>

The library never writes to disk itself: the host hands a scan somewhere to
spill (the `exav` binary passes its `--spill-dir` files and budgets). Only a
member decoded as it is read can spill; one decoded whole is bounded by
`--max-object-bytes`. Without a spill, a member that decodes past
`--max-object-bytes` is not scanned, the normalised views of a text file that
large are skipped, and a scan that found nothing is `LIMITS-EXCEEDED` rather
than `OK`.

## The database, not the file, is what uses memory

Building the signature index from raw ClamAV databases briefly takes more memory
than the index itself. A [prebuilt `.exavdb`](/scanner/guides/prebuilt-database/#what-it-costs)
is built once on a capable host and loads at about its final size.

## Tuning

`--max-object-bytes` (256M) is the most memory one object may use, a file, a
decompressed member, an LZ window or a decrypted blob; several such buffers are
alive at once across nesting levels, so it does not bound the total. What
formats decoded whole hold across one top-level file is charged against 1G, and
`--max-process-bytes` keeps both inside the memory a scan gets. Every bound, and
which one to change, is in [Limits and tuning](/scanner/reference/limits/); a
worked example is in [Sizing a server](/scanner/guides/sizing/).
