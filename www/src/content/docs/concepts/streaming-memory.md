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

## Up to `--max-object-bytes`: in memory

A file up to `--max-object-bytes` (256 MiB by default) is read into memory, and
so is an HTTP source that size. Memory is roughly the file's size, plus a
lowercase copy when a case-insensitive signature has to be checked and, for
text, one normalised copy at a time. The deobfuscated
JavaScript view stops at 32 MiB; a script whose view is longer is reported
`LIMITS-EXCEEDED` unless something is found, though its raw bytes are still
scanned in full.

## Past it: through a block cache

A larger file is read through a cache of 64 KiB blocks, of which at most 8 MiB
are held, least recently used dropped first. So are an HTTP source of that size
and a spill file (below). Verifying a match can still look anywhere in the
file: the cache bounds what is held at once, not how far a check may reach, and
a block that was dropped is read again when it is needed. The scan is the same
one, with the same results, only slower, since the file is read a few times
over: once for format detection's search, carving and the digests (when a hash
signature has its size), once for the signature sweep (every anchor at once),
twice more for YARA's prefilter when rules are loaded, and again in the parts a
check needs.

<svg viewBox="0 0 790 392" role="img" aria-labelledby="bcn bcd" style="width:100%;height:auto;max-width:790px">
  <title id="bcn">One source, read through a block cache</title>
  <desc id="bcd">A file or an HTTP source past --max-object-bytes, or a spill
  file, is read through a block cache of 64 KiB blocks holding 8 MiB. Every
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
    <text x="345" y="136" text-anchor="middle">64 KiB blocks, 8 MiB held,</text>
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

A few things need the file whole and are not done past the limit:

- the structure of a PE: entry-point and section offsets, section hashes,
  imports, icons, the Authenticode signature, UPX and packer unpacking;
- YARA's `pe`, `elf` and `dotnet` modules;
- a PCRE subsignature with a backreference, and the `fuzzy_img` image hash;
- containers whose format is read whole (7z, RAR, OLE, PDF, the virtual-disk and
  filesystem images and others; see
  [Supported formats](/reference/formats/#size-what-is-read-as-it-goes-and-what-is-read-whole)).

A file for which one of these applied is reported `LIMITS-EXCEEDED`, naming
`--max-object-bytes`, unless something is found. Raise the limit to have them
run, at the cost of memory.

The normalised views of a large text file are as large as the file, so they go
to a [spill file](#spill-files).

## Archive members

Archives decoded as they are read (ZIP, tar, CAB, ISO/UDF, DMG, LHA, `ar`, cpio,
the single-stream compressors, self-extracting executables) are walked member by
member at any size and any depth. Such a member is held in memory up to the same
limit, and past it written to a temporary file and scanned from there. With
`--spill-dir off`, or past `--max-spill-bytes`, it is not scanned and the file is
`LIMITS-EXCEEDED`. 7z members stream the same way once the container is read.

A member that has to be decoded whole (an encrypted ZIP member, a file inside a
DMG, a member of a format read whole) is `LIMITS-EXCEEDED` past
`--max-object-bytes`.

## Stdin, `INSTREAM` and ICAP bodies

Container formats need to seek (a ZIP's directory is at its end), so a stream is
buffered before it is scanned: in memory up to `--spill-threshold-bytes`
(16 MiB), then in a temporary file up to `--max-spill-bytes` (2 GiB). The
buffered stream then goes through the same scan as a file. A stream past
`--max-input-bytes` or the spill ceiling is scanned as far as it was held and is
`LIMITS-EXCEEDED` unless that finds something, as a file past
`--max-input-bytes` is. See
[buffering a stream](/reference/cli/#buffering-a-stream-spill).

## Spill files

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

The library never writes to disk itself: the host hands a scan somewhere to
spill (the `exav` binary passes its `--spill-dir` files and budgets). Only a
member decoded as it is read can spill; one decoded whole is bounded by
`--max-object-bytes`. Without a spill, a member that decodes past
`--max-object-bytes` is not scanned, the normalised views of a text file that
large are skipped, and a scan that found nothing is `LIMITS-EXCEEDED` rather
than `OK`.

## The database, not the file, is what uses memory

Building the signature index from raw ClamAV databases briefly takes more memory
than the index itself. A [prebuilt `.exavdb`](/guides/prebuilt-database/#what-it-costs)
is built once on a capable host and loads at about its final size.

## Tuning

Memory and CPU budgets are separate flags:

- **`--max-object-bytes`** (256M): the most memory one object may use (a file, a
  decompressed member, an LZ window, a decrypted blob); past it an object is read
  through the block cache or a temporary file. Several such buffers are alive at
  once across nesting levels, so it does not bound the total.
- **`--max-process-bytes`** (2G per worker in the pool): the memory a scan may
  use. What formats decoded whole hold across one top-level file is charged
  cumulatively against 1G. That total and `--max-object-bytes` are both kept
  within half of `--max-process-bytes`, so reaching them is reported as a limit
  instead of the scan being killed. Streamed members
  are not charged there: they are bounded by `--max-object-bytes` and the spill
  budgets.
- **`--max-matcher-bytes`** (10G): the most bytes fed to the matcher across one
  top-level file. A CPU bound, not a memory one.
- **`--max-pe-emulation-steps`** (1,000,000,000): the instructions the PE
  unpacking emulator may run across one top-level file.

See [Limits](/reference/limits/) and [Configuration](/reference/configuration/)
for the full set.
